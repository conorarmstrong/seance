use crate::entry_path::{resolve_sevenz_entry_path, EntryPath};
use crate::status::expansion_failed_status;
use seance_core::credential::{self, CredentialKind, RunCredential};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::SourceCursor,
    io::{read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use sevenz_rust2::{ArchiveReader, BlockDecoder, EncoderMethod, Password};
use std::sync::Arc;
use tracing::{debug, warn};

/// The 7z file signature.
const SEVENZ_MAGIC: &[u8; 6] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// The `scheme` an encrypted 7z record carries, so the attention queue groups
/// 7z's AES apart from ZIP's schemes.
const SEVENZ_AES_SCHEME: &str = "7z_aes256_sha256";

pub struct SevenZipExpanderModule;

/// A record saying this 7z's header is encrypted, so nothing inside it could be
/// listed without the password.
///
/// It carries both halves of the incompleteness pair with the `encrypted`
/// reason: the listing is short (no entry could be named) and so is the content.
fn encrypted_header_status(artifact: &Artifact, name: &str, error: &str) -> Artifact {
    let detail = format!(
        "The 7z archive's header is AES-256 encrypted (created with a password and header \
         encryption), so not even the names of its entries can be read without the password. \
         Its contents are unknown, not absent. The password can be supplied for this archive \
         from the Needs attention queue, which re-runs the listing with it. Decoder: {error}"
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "ArchiveScanStatus",
            "record_type": "archive_scan_status",
            "name": format!("{} (encrypted, not expanded)", name),
            "container": "7z",
            "container_path": name,
            "encrypted": true,
            "encrypted_header": true,
            "scheme": SEVENZ_AES_SCHEME,
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "entries_recovered": 0,
            "content_incomplete_detail": detail,
            "inventory_incomplete_detail": detail,
            "detail": detail,
            "message": "This 7z archive is password-protected, header included: nothing inside \
                        it could be listed, and its contents are unknown, not absent",
        }),
    )
    .with_parent(artifact.id)
}

/// Above this, a password for a content-only-encrypted archive is checked on
/// the first `PASSWORD_PREFIX_BYTES` of the entry's decoded stream rather than
/// the whole entry and its CRC, so one huge first entry cannot turn a password
/// check into a full decompression.
const PASSWORD_CRC_CHECK_MAX_BYTES: u64 = 64 * 1024 * 1024;
const PASSWORD_PREFIX_BYTES: u64 = 1024 * 1024;

/// How a supplied password was found to open an AES block.
enum PasswordCheck {
    /// The first entry of the first encrypted block decoded in full and its
    /// CRC-32 matched.
    Crc32 { entry: String },
    /// The entry is larger than [`PASSWORD_CRC_CHECK_MAX_BYTES`]: its first
    /// bytes decoded without a decoder error. Weaker than a CRC, and said so.
    DecoderPrefix { entry: String },
}

/// Decode the first entry of the first AES block with `password`.
fn verify_content_password(
    data_source: &Arc<dyn seance_core::data_source::DataSource>,
    archive: &sevenz_rust2::Archive,
    encrypted_blocks: &[bool],
    password: &Password,
) -> Result<Option<PasswordCheck>, String> {
    let Some(block_index) = encrypted_blocks.iter().position(|e| *e) else {
        return Ok(None);
    };
    let mut cursor = SourceCursor::new(data_source.clone());
    let decoder = BlockDecoder::new(1, block_index, archive, password, &mut cursor);
    let mut check = None;
    let result = decoder.for_each_entries(&mut |entry, reader| {
        if !entry.has_stream() || entry.size() == 0 {
            return Ok(true);
        }
        let name = entry.name().to_string();
        if entry.size() <= PASSWORD_CRC_CHECK_MAX_BYTES {
            std::io::copy(reader, &mut std::io::sink())?;
            check = Some(PasswordCheck::Crc32 { entry: name });
        } else {
            std::io::copy(
                &mut std::io::Read::take(reader, PASSWORD_PREFIX_BYTES),
                &mut std::io::sink(),
            )?;
            check = Some(PasswordCheck::DecoderPrefix { entry: name });
        }
        Ok(false)
    });
    match result {
        Ok(_) => Ok(check),
        Err(e) => Err(e.to_string()),
    }
}

/// The record saying a supplied password opened this archive.
fn password_status(
    artifact: &Artifact,
    name: &str,
    status: &str,
    detail: String,
    extra: serde_json::Value,
) -> Artifact {
    let mut metadata = json!({
        "type": "ArchiveScanStatus",
        "record_type": "archive_scan_status",
        "name": format!("{name} (password supplied: {status})"),
        "container": "7z",
        "container_path": name,
        "encrypted": true,
        "scheme": SEVENZ_AES_SCHEME,
        "status": status,
        "credential_kind": CredentialKind::SevenZipPassword.as_str(),
        "credential_source": "supplied_for_this_run",
        "detail": detail,
    });
    if let (Some(obj), Some(more)) = (metadata.as_object_mut(), extra.as_object()) {
        for (k, v) in more {
            obj.insert(k.clone(), v.clone());
        }
    }
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
}

impl ForensicsModule for SevenZipExpanderModule {
    fn id(&self) -> &str {
        "container.7z_expander"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Container, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Fast path: check subtype
        if let Some(subtype) = artifact.subtype() {
            if subtype != "7z" {
                return Ok(Vec::new());
            }
        } else {
            let name = artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or_default()
                .to_lowercase();
            if !name.ends_with(".7z") {
                return Ok(Vec::new());
            }
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown.7z")
            .to_string();

        debug!("SevenZipExpanderModule processing: {}", name);

        let data_source = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("7z module requires data source".to_string())
        })?;

        // Is this actually a 7z archive? The gate above accepts an extension,
        // which a file may carry without being 7z at all.
        let mut magic = [0u8; 6];
        let read = read_full(data_source.as_ref(), 0, &mut magic);
        let claims_7z = read == SEVENZ_MAGIC.len() && &magic == SEVENZ_MAGIC;

        let cursor = SourceCursor::new(data_source.clone());

        // A password an examiner supplied for this archive and this run
        // (HUNT-171 / HUNT-120). The library keeps its own UTF-16 copy of it,
        // which is freed with the reader, not zeroed.
        let run_credential: Option<Arc<RunCredential>> =
            credential::for_artifact(artifact.id, &[CredentialKind::SevenZipPassword]);
        let password = run_credential
            .as_ref()
            .map(|c| Password::from(c.expose_secret()))
            .unwrap_or_else(Password::empty);

        let archive = match ArchiveReader::new(cursor, password.clone()) {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to open 7z archive {}: {}", name, e);
                if !claims_7z {
                    // No signature: this file was simply never ours.
                    return Ok(Vec::new());
                }
                if let Some(c) = run_credential.as_ref() {
                    c.rejected(format!("the 7z header did not decrypt with it: {e}"));
                }
                // A header the AES coder guards is not a damaged header: it is
                // an archive a password would open, and it has to say so with
                // the `encrypted` reason the attention queue keys on. Recorded
                // under the damaged-archive reason it never reached the queue
                // and nothing said a password stood in the way (HUNT-171).
                if matches!(
                    e,
                    sevenz_rust2::Error::PasswordRequired
                        | sevenz_rust2::Error::MaybeBadPassword(_)
                ) {
                    return Ok(vec![encrypted_header_status(
                        artifact,
                        &name,
                        &e.to_string(),
                    )]);
                }
                // A signed archive we could not open is not an empty archive
                // (B3-031, same class as gzip/bzip2/xz): a corrupt archive must
                // not ingest as "nothing inside".
                return Ok(vec![expansion_failed_status(
                    artifact,
                    "7z",
                    &name,
                    "sevenz_unreadable",
                    &e.to_string(),
                )]);
            }
        };

        let mut produced_artifacts = Vec::new();
        let header_was_encrypted = run_credential.is_some()
            && ArchiveReader::new(SourceCursor::new(data_source.clone()), Password::empty())
                .is_err();

        // Which folders (7z "blocks") pass through the AES coder. `7z a -p…`
        // without `-mhe=on` leaves the names readable and encrypts the content,
        // so the listing succeeds and only the content is locked (HUNT-171).
        let listing = archive.archive();
        let encrypted_blocks: Vec<bool> = listing
            .blocks
            .iter()
            .map(|block| {
                block
                    .coders
                    .iter()
                    .any(|c| c.encoder_method_id() == EncoderMethod::ID_AES256_SHA256)
            })
            .collect();

        // A password supplied for an archive whose header was plain: the
        // entries were listed at ingest and are not listed again. The password
        // is checked against the first encrypted entry, and a status record
        // says what that established.
        if let (Some(c), false) = (run_credential.as_ref(), header_was_encrypted) {
            return Ok(
                match verify_content_password(data_source, listing, &encrypted_blocks, &password) {
                    Ok(None) => {
                        // Nothing in this archive is encrypted: the password
                        // was not used, and the orchestrator records that.
                        Vec::new()
                    }
                    Ok(Some(check)) => {
                        c.accepted();
                        let (method, entry, strength) = match check {
                            PasswordCheck::Crc32 { entry } => {
                                ("crc32", entry, "decoded in full and its CRC-32 matched")
                            }
                            PasswordCheck::DecoderPrefix { entry } => (
                                "decoder_prefix",
                                entry,
                                "is too large to decode for a check; its first mebibyte \
                                 decoded without error, which is weaker than a CRC",
                            ),
                        };
                        vec![password_status(
                            artifact,
                            &name,
                            "password_verified",
                            format!(
                                "The supplied password opens this archive's AES-256 content: \
                                 entry '{entry}' {strength}. The entries were already listed; \
                                 their content is still not in the case, because this build \
                                 does not extract 7z content, encrypted or not. The password \
                                 itself is not recorded."
                            ),
                            json!({"password_check": method, "checked_entry": entry}),
                        )]
                    }
                    Err(e) => {
                        c.rejected(format!("the encrypted content did not decode with it: {e}"));
                        Vec::new()
                    }
                },
            );
        }
        if let Some(c) = run_credential.as_ref() {
            c.accepted();
            produced_artifacts.push(password_status(
                artifact,
                &name,
                "unlocked",
                "The supplied password decrypted this archive's header, so its entries are \
                 listed with their names and sizes. Their content is not in the case: this \
                 build does not extract 7z content, encrypted or not. The password itself is \
                 not recorded."
                    .to_string(),
                json!({"encrypted_header": true}),
            ));
        }

        for (index, entry) in listing.files.iter().enumerate() {
            let entry_name = entry.name().to_string();
            let is_dir = entry.is_directory();
            let size = if entry.has_stream() { entry.size() } else { 0 };

            // Entry names belong to the archive, not to us. A 7z name may carry
            // `..`, an absolute root, or the Windows `..\` form — the vector
            // RUSTSEC-2026-0245 was filed for — and a stored path that keeps one
            // states a location outside the archive that the file tree, the
            // `/files` API and the export manifest would then render as fact.
            // Resolve within the archive root exactly as the TAR and ZIP
            // extractors do (BUG-036), keeping the stored name as evidence of the
            // attempt and as the name that still addresses the entry in the 7z.
            let EntryPath {
                full_path,
                parent_path,
                name: base,
                original,
                escapes_root,
            } = resolve_sevenz_entry_path(&entry_name);

            let mut metadata = json!({
                "name": base,
                "path": full_path,
                "parent_path": parent_path,
                "size": size,
                "is_directory": is_dir,
                "container": "7z",
                "container_path": name,
            });
            if let Some(original) = original {
                metadata["original_name"] = json!(original);
            }
            if escapes_root {
                metadata["path_traversal"] = json!(true);
            }

            // A sized FileEntry with no bytes and no explanation reads as an
            // empty file. Say plainly that the content is still compressed and
            // was never decoded, so a hash, a preview or an export that comes
            // back empty is understood as "not extracted", not "was empty"
            // (B3-030, same class).
            let encrypted = listing
                .stream_map
                .file_block_index
                .get(index)
                .copied()
                .flatten()
                .and_then(|b| encrypted_blocks.get(b).copied())
                .unwrap_or(false);
            if encrypted && run_credential.is_some() {
                // The password was supplied and opened the header; the bytes
                // are still not extracted, and that is the 7z limit every
                // entry shares, not a password standing in the way.
                metadata["encrypted"] = json!(true);
                metadata["scheme"] = json!(SEVENZ_AES_SCHEME);
                metadata["password_supplied"] = json!(true);
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] =
                    json!(IncompleteReason::Compressed.as_str());
                metadata["content_incomplete_detail"] = json!(
                    "This entry is AES-256 encrypted inside the 7z archive; the password was \
                     supplied and opened the archive, but 7z content is not extracted by this \
                     ingest, so its name and size are listed and its bytes are not"
                );
            } else if encrypted {
                // Encrypted says more than compressed, and it is the one of the
                // two a person can act on: the queue asks about it.
                metadata["encrypted"] = json!(true);
                metadata["scheme"] = json!(SEVENZ_AES_SCHEME);
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] = json!(IncompleteReason::Encrypted.as_str());
                metadata["content_incomplete_detail"] = json!(
                    "This entry's content is AES-256 encrypted inside the 7z archive and was not \
                     decrypted: its name and size are listed, its bytes are not. A password \
                     supplied for the archive is verified against it, but 7z content is not \
                     extracted by this ingest in any case"
                );
            } else if !is_dir && size > 0 {
                let reason = IncompleteReason::Compressed.as_str();
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] = json!(reason);
                metadata["content_incomplete_detail"] = json!(
                    "7z uses solid compression; per-entry content is not extracted by this ingest"
                );
            }

            // BUG-096 (DEFERRED for 7z): content is intentionally not attached.
            // 7z uses solid compression — multiple files share one compressed
            // "folder" stream — so there is no per-entry random access to window
            // over (unlike ZIP/TAR). Attaching real content requires decompressing
            // whole folders (LZMA/LZMA2/BCJ filters) to temp storage and mapping
            // each entry's offset/size within the decoded folder, with its own
            // bomb-cap design. `sevenz-rust2` does expose per-name access
            // (`ArchiveReader::read_file`), but on a solid archive that decodes
            // every entry ahead of the one asked for and returns it whole in
            // memory, so it is not a content source in itself. That is a large
            // change, tracked separately.
            // OLE2 (same bug id) is fixed here since its streams are randomly
            // addressable. Until then, 7z yields metadata-only FileEntries.
            let child = Artifact::new(artifact.case_id, ArtifactType::FileEntry, None, metadata)
                .with_parent(artifact.id);

            produced_artifacts.push(child);
        }

        debug!(
            "Extracted metadata for {} entries from 7z archive {}",
            produced_artifacts.len(),
            name
        );

        Ok(produced_artifacts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::DataSource;
    use std::sync::Arc;
    use uuid::Uuid;

    #[derive(Debug)]
    struct MemorySource {
        data: Vec<u8>,
    }

    impl DataSource for MemorySource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let start = offset as usize;
            if start >= self.data.len() {
                return Ok(0);
            }
            let end = (start + buf.len()).min(self.data.len());
            let len = end - start;
            buf[..len].copy_from_slice(&self.data[start..end]);
            Ok(len)
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[test]
    fn test_7z_skip_non_7z() {
        let module = SevenZipExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "file.txt"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_7z_skip_wrong_subtype() {
        let module = SevenZipExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            None,
            json!({"name": "file.zip", "subtype": "zip"}),
        );
        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn test_7z_no_data_source() {
        let module = SevenZipExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            None,
            json!({"name": "file.7z", "subtype": "7z"}),
        );
        let result = module.process(&artifact);
        assert!(result.is_err());
    }

    /// A file carrying the 7z signature that will not open must be recorded.
    ///
    /// What an examiner learns: this archive exists and could not be read, so
    /// its contents are unknown. The wrong answer this guards against is an
    /// empty success, which is what a file that was never a 7z produces — a
    /// corrupt or header-encrypted archive would then read as "held nothing".
    #[test]
    fn test_7z_corrupted_is_reported_not_silent() {
        let module = SevenZipExpanderModule;
        // 7z magic but corrupted
        let mut data = vec![0u8; 512];
        data[0..6].copy_from_slice(SEVENZ_MAGIC);

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "bad.7z", "subtype": "7z"}),
        );

        let results = module.process(&artifact).unwrap();
        assert_eq!(
            results.len(),
            1,
            "a signed-but-unreadable 7z must be recorded"
        );
        assert_eq!(
            results[0].metadata["record_type"],
            json!("archive_scan_status")
        );
        assert_eq!(results[0].metadata["content_incomplete"], json!(true));
        assert_eq!(
            results[0].metadata["content_incomplete_reason"],
            json!("sevenz_unreadable")
        );
    }

    /// Build a 7z archive whose entries carry exactly the given names.
    ///
    /// The names are written verbatim: a hostile archive is not produced by a
    /// well-behaved writer, and the traversal names below are the point.
    fn build_7z_with_entry_names(names: &[&str]) -> Vec<u8> {
        use std::io::Cursor;

        let mut backing = Cursor::new(Vec::new());
        {
            let mut writer = sevenz_rust2::ArchiveWriter::new(&mut backing).expect("7z writer");
            for name in names {
                writer
                    .push_archive_entry(
                        sevenz_rust2::ArchiveEntry::new_file(name),
                        Some(Cursor::new(b"x".to_vec())),
                    )
                    .expect("push entry");
            }
            writer.finish().expect("finish archive");
        }
        backing.into_inner()
    }

    /// The produced entry whose `name` is `base`. Missing is a failure, not an
    /// empty result: an entry that vanished from the listing is the bug.
    fn find_entry<'a>(results: &'a [Artifact], base: &str) -> &'a Artifact {
        results
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some(base))
            .unwrap_or_else(|| panic!("{base} must still be listed"))
    }

    /// B3-030 (same class): 7z entries are listed with their real size but
    /// their bytes are never extracted, so every entry must carry the standard
    /// incompleteness pair.
    ///
    /// What an examiner learns: this file was inside the archive, it is this
    /// long, and its content was not decoded here. The wrong answer this guards
    /// against is a sized FileEntry with no bytes and no explanation, which is
    /// indistinguishable from a file that was genuinely empty.
    #[test]
    fn test_7z_entries_declare_content_not_extracted() {
        use std::io::Cursor;

        let payload = b"seven zip entry payload".to_vec();
        let mut backing = Cursor::new(Vec::new());
        {
            let mut writer = sevenz_rust2::ArchiveWriter::new(&mut backing).expect("7z writer");
            writer
                .push_archive_entry(
                    sevenz_rust2::ArchiveEntry::new_file("notes.txt"),
                    Some(Cursor::new(payload.clone())),
                )
                .expect("push entry");
            writer.finish().expect("finish archive");
        }
        let data = backing.into_inner();

        let module = SevenZipExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "notes.7z", "subtype": "7z"}),
        );

        let results = module.process(&artifact).unwrap();
        let entry = results
            .iter()
            .find(|a| a.metadata["name"] == json!("notes.txt"))
            .expect("the archived entry must be listed");
        assert_eq!(entry.metadata["size"], json!(payload.len()));
        assert!(
            entry.data.is_none(),
            "7z content is not extracted by this ingest"
        );
        assert_eq!(entry.metadata["content_incomplete"], json!(true));
        assert_eq!(
            entry.metadata["content_incomplete_reason"],
            json!("compressed")
        );
    }

    /// RUSTSEC-2026-0245: a 7z entry name that escapes the archive root must
    /// never be stored as the entry's location.
    ///
    /// What an examiner learns: this entry was inside the archive, it sits at
    /// this resolved path, the archive stored *that* name for it, and the name
    /// reached outside the archive. The wrong answer this guards against is a
    /// path built from the attacker's name — `../escape.txt` or `..\..\x` —
    /// which every consumer of the flat model (file tree, `/files`, export
    /// manifest) renders as the file's real location, and which an export would
    /// then follow off the extraction root. The Windows form matters as much as
    /// the POSIX one: 7z carries backslash-separated names, and the advisory's
    /// own regression covers exactly that vector.
    #[test]
    fn test_7z_entry_paths_do_not_escape_the_archive_root() {
        let data = build_7z_with_entry_names(&[
            "../escape.txt",
            "a/../../deep_escape.txt",
            "/etc/passwd",
            "..\\..\\windows_escape.exe",
            "docs/notes.txt",
        ]);

        let module = SevenZipExpanderModule;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "hostile.7z", "subtype": "7z"}),
        );

        let results = module.process(&artifact).unwrap();
        let paths: Vec<&str> = results
            .iter()
            .filter_map(|a| a.metadata.get("path").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(paths.len(), 5, "every entry must still be listed");
        for path in &paths {
            assert!(
                !path.split('/').any(|seg| seg == "..")
                    && !path.contains('\\')
                    && !path.starts_with("//"),
                "no stored path may keep a traversal or a doubled separator: {path}"
            );
        }

        let escape = find_entry(&results, "escape.txt");
        assert_eq!(escape.metadata["path"], json!("/escape.txt"));
        assert_eq!(escape.metadata["parent_path"], json!("/"));
        assert_eq!(escape.metadata["original_name"], json!("../escape.txt"));
        assert_eq!(escape.metadata["path_traversal"], json!(true));

        // `..` inside the name is applied, then clamped at the root.
        let deep = find_entry(&results, "deep_escape.txt");
        assert_eq!(deep.metadata["path"], json!("/deep_escape.txt"));
        assert_eq!(
            deep.metadata["original_name"],
            json!("a/../../deep_escape.txt")
        );
        assert_eq!(deep.metadata["path_traversal"], json!(true));

        // An absolute stored name reaches outside an extraction root too.
        let passwd = find_entry(&results, "passwd");
        assert_eq!(passwd.metadata["path"], json!("/etc/passwd"));
        assert_eq!(passwd.metadata["parent_path"], json!("/etc"));
        assert_eq!(passwd.metadata["original_name"], json!("/etc/passwd"));
        assert_eq!(passwd.metadata["path_traversal"], json!(true));

        // The Windows-authored form escapes on every platform.
        let windows = find_entry(&results, "windows_escape.exe");
        assert_eq!(windows.metadata["path"], json!("/windows_escape.exe"));
        assert_eq!(
            windows.metadata["original_name"],
            json!("..\\..\\windows_escape.exe")
        );
        assert_eq!(windows.metadata["path_traversal"], json!(true));

        // An ordinary entry is untouched: nothing was rewritten, so nothing is
        // recorded as rewritten.
        let notes = find_entry(&results, "notes.txt");
        assert_eq!(notes.metadata["path"], json!("/docs/notes.txt"));
        assert_eq!(notes.metadata["parent_path"], json!("/docs"));
        assert!(notes.metadata.get("original_name").is_none());
        assert!(notes.metadata.get("path_traversal").is_none());
    }

    fn fixture_artifact(name: &str, bytes: &[u8]) -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Container,
            Some(Arc::new(MemorySource {
                data: bytes.to_vec(),
            }) as Arc<dyn DataSource>),
            json!({"name": name, "subtype": "7z"}),
        )
    }

    /// HUNT-171. Real `7z a -p… -mhe=on` output: the header itself is
    /// AES-encrypted, so not even the names can be listed without the
    /// password. It was recorded as `sevenz_unreadable` — the reason a damaged
    /// archive gets — so it never reached the attention queue (which keys on
    /// `encrypted`) and nothing said a password would open it.
    #[test]
    fn a_header_encrypted_7z_is_recorded_as_encrypted_not_unreadable() {
        let data = include_bytes!("../tests/fixtures/header_encrypted.7z");
        let out = SevenZipExpanderModule
            .process(&fixture_artifact("locked.7z", data))
            .unwrap();
        assert_eq!(out.len(), 1, "{out:?}");
        let m = &out[0].metadata;
        assert_eq!(m["record_type"], json!("archive_scan_status"));
        assert_eq!(m["content_incomplete"], json!(true));
        assert_eq!(m["content_incomplete_reason"], json!("encrypted"));
        assert_eq!(m["inventory_incomplete"], json!(true));
        assert_eq!(m["inventory_incomplete_reason"], json!("encrypted"));
        assert_eq!(m["encrypted"], json!(true));
        assert_eq!(m["encrypted_header"], json!(true));
        assert!(
            m["detail"].as_str().unwrap().contains("password"),
            "the record must say what would open it: {m}"
        );
    }

    /// HUNT-171, the other shape real `7z a -p…` makes by default
    /// (`-mhe=off`): the names are listable, the content is AES-encrypted.
    /// Each entry said only that its content was `compressed` — true of every
    /// 7z — and never that a password stands between the examiner and it.
    #[test]
    fn entries_in_an_aes_folder_are_recorded_as_encrypted() {
        let data = include_bytes!("../tests/fixtures/content_encrypted.7z");
        let out = SevenZipExpanderModule
            .process(&fixture_artifact("locked.7z", data))
            .unwrap();
        let entry = find_entry(&out, "secret.txt");
        assert_eq!(entry.metadata["size"], json!(16));
        assert_eq!(entry.metadata["encrypted"], json!(true));
        assert_eq!(entry.metadata["content_incomplete"], json!(true));
        assert_eq!(
            entry.metadata["content_incomplete_reason"],
            json!("encrypted")
        );
    }

    /// The counterpart, also real `7z` output: an unencrypted archive's
    /// entries stay `compressed`, so `encrypted` means something when present.
    #[test]
    fn entries_of_a_plain_7z_are_not_called_encrypted() {
        let data = include_bytes!("../tests/fixtures/plain.7z");
        let out = SevenZipExpanderModule
            .process(&fixture_artifact("plain.7z", data))
            .unwrap();
        let entry = find_entry(&out, "other.txt");
        assert!(entry.metadata.get("encrypted").is_none());
        assert_eq!(
            entry.metadata["content_incomplete_reason"],
            json!("compressed")
        );
    }

    // ── a password supplied for this archive and this run (HUNT-171/120) ──
    //
    // Both fixtures are real `7z a -psevenz-fixture-2291` output (p7zip 16.02)
    // over `alpha.txt` (22 bytes) and `docs/beta.txt` (18 bytes):
    // `password_header.7z` with `-mhe=on`, `password_content.7z` with
    // `-mhe=off`. The password is a fixture's, not a secret.

    const FIXTURE_PASSWORD: &str = "sevenz-fixture-2291";

    fn run_with_password(
        name: &str,
        bytes: &[u8],
        password: &str,
    ) -> (
        Vec<Artifact>,
        Option<seance_core::credential::CredentialOutcome>,
    ) {
        use seance_core::credential::{self, CredentialKind, RunCredential};
        let artifact = fixture_artifact(name, bytes);
        let cred = Arc::new(RunCredential::new(
            artifact.id,
            CredentialKind::SevenZipPassword,
            password.to_string(),
            "erin",
        ));
        let out = credential::scoped(Some(cred.clone()), || {
            SevenZipExpanderModule.process(&artifact).unwrap()
        });
        (out, cred.outcome())
    }

    /// The header-encrypted archive listed nothing at ingest. With the
    /// password supplied for this run, its entries are named and sized, and a
    /// status record says the header was opened — that record is what
    /// supersedes the earlier "encrypted, not expanded" one on a re-run.
    #[test]
    fn a_password_supplied_for_this_run_lists_a_header_encrypted_archive() {
        use seance_core::credential::CredentialOutcome;
        let data = include_bytes!("../tests/fixtures/password_header.7z");
        let (out, outcome) = run_with_password("locked.7z", data, FIXTURE_PASSWORD);
        assert_eq!(outcome, Some(CredentialOutcome::Accepted));
        let alpha = find_entry(&out, "alpha.txt");
        assert_eq!(alpha.metadata["size"], json!(22));
        assert_eq!(alpha.metadata["encrypted"], json!(true));
        // The password is known now; what keeps the bytes out of the case is
        // that this build does not extract 7z content at all (BUG-096).
        assert_eq!(
            alpha.metadata["content_incomplete_reason"],
            json!("compressed")
        );
        let beta = find_entry(&out, "beta.txt");
        assert_eq!(beta.metadata["path"], json!("/docs/beta.txt"));
        let status = out
            .iter()
            .find(|a| a.metadata["type"] == json!("ArchiveScanStatus"))
            .expect("a status record says the header was opened");
        assert_eq!(status.metadata["status"], json!("unlocked"));
        assert_eq!(status.metadata["credential_kind"], json!("sevenz_password"));
        assert!(status.metadata.get("content_incomplete").is_none());
        for a in &out {
            assert!(!a.metadata.to_string().contains(FIXTURE_PASSWORD));
        }
    }

    #[test]
    fn a_wrong_password_for_a_header_encrypted_archive_is_rejected() {
        use seance_core::credential::CredentialOutcome;
        let data = include_bytes!("../tests/fixtures/password_header.7z");
        let (out, outcome) = run_with_password("locked.7z", data, "not-the-password");
        assert!(
            matches!(outcome, Some(CredentialOutcome::Rejected { .. })),
            "{outcome:?}"
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["encrypted_header"], json!(true));
    }

    /// A content-only archive already listed its entries; the password is
    /// verified by decoding the first encrypted entry against its CRC, and a
    /// status record says so. The entries are not listed twice.
    #[test]
    fn a_password_for_a_content_encrypted_archive_is_verified_by_crc() {
        use seance_core::credential::CredentialOutcome;
        let data = include_bytes!("../tests/fixtures/password_content.7z");
        let (out, outcome) = run_with_password("locked.7z", data, FIXTURE_PASSWORD);
        assert_eq!(outcome, Some(CredentialOutcome::Accepted));
        assert_eq!(out.len(), 1, "{out:?}");
        assert_eq!(out[0].metadata["type"], json!("ArchiveScanStatus"));
        assert_eq!(out[0].metadata["status"], json!("password_verified"));
        assert_eq!(out[0].metadata["password_check"], json!("crc32"));
    }

    #[test]
    fn a_wrong_password_for_a_content_encrypted_archive_is_rejected() {
        use seance_core::credential::CredentialOutcome;
        let data = include_bytes!("../tests/fixtures/password_content.7z");
        let (_out, outcome) = run_with_password("locked.7z", data, "not-the-password");
        assert!(
            matches!(outcome, Some(CredentialOutcome::Rejected { .. })),
            "{outcome:?}"
        );
    }

    /// The counterpart: a `.7z` name with no 7z signature was never ours and
    /// must not be reported as a failed archive.
    #[test]
    fn test_7z_without_signature_is_silent() {
        let module = SevenZipExpanderModule;
        let data = b"this is not a 7z archive at all".to_vec();

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "notreally.7z"}),
        );

        let results = module.process(&artifact).unwrap();
        assert!(results.is_empty());
    }
}
