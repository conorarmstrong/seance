#![forbid(unsafe_code)]
use anyhow::Result;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, SourceCursor},
    io::{read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::{Arc, Mutex};
use tracing::{info, warn};
use zip::ZipArchive;

pub mod crack;
pub use crack::{has_encrypted_entry, verify_zip_password, ZipCracker, ZipVerdict};

/// Hard cap on how many bytes a single ZIP entry may materialise into memory.
/// Mirrors the archive crates' `MAX_DECOMPRESSED_SIZE` guard; here 4 GiB, since
/// a ZIP entry is held wholly in memory rather than spilled to a temp file. A
/// lying central directory or a zip bomb cannot push us past this.
const MAX_ENTRY_SIZE: u64 = 4 * 1024 * 1024 * 1024;

/// A lazily-materialised [`DataSource`] over one ZIP entry. The entry is
/// decompressed into memory on first read and cached. Because parsers gate on
/// filename before touching bytes, only entries a parser actually consumes are
/// ever materialised, so a large archive is never held in memory wholesale.
struct ZipEntrySource {
    parent: Arc<dyn DataSource>,
    /// The archive, already opened: its central directory is parsed once, when
    /// the container is listed, and shared by every entry through the `Arc`
    /// inside `ZipArchive`. A clone is a cursor and a reference count, not a
    /// second parse. Re-opening per entry re-read the whole directory on the
    /// first read of every file — 12 to 40 seconds each on a 125,327-entry
    /// archive, forty-three days for one ingest (HUNT-068).
    archive: ZipArchive<SourceCursor>,
    entry_name: String,
    size: u64,
    // Cached materialisation outcome: `Some(Ok(bytes))` once decompressed,
    // `Some(Err(msg))` if the entry could not be read. A failure is cached and
    // surfaced as an error on every read; it is never served as an empty
    // full-size buffer (which would fabricate all-EOF evidence at the claimed
    // uncompressed size).
    cache: Mutex<Option<Result<Arc<Vec<u8>>, String>>>,
}

impl std::fmt::Debug for ZipEntrySource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZipEntrySource")
            .field("entry_name", &self.entry_name)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

impl ZipEntrySource {
    fn new(
        parent: Arc<dyn DataSource>,
        archive: ZipArchive<SourceCursor>,
        entry_name: String,
        size: u64,
    ) -> Self {
        Self {
            parent,
            archive,
            entry_name,
            size,
            cache: Mutex::new(None),
        }
    }

    /// Decompress the entry once and cache the outcome. A read/decompress
    /// failure is cached and re-raised as an error on every read: a failed read
    /// must never be served as an empty full-size buffer, which would fabricate
    /// all-EOF evidence at the entry's claimed uncompressed size.
    fn materialize(&self) -> std::io::Result<Arc<Vec<u8>>> {
        let mut guard = self.cache.lock().unwrap_or_else(|e| e.into_inner());
        if guard.is_none() {
            *guard = Some(match self.read_entry() {
                Ok(bytes) => Ok(Arc::new(bytes)),
                Err(e) => Err(e.to_string()),
            });
        }
        match guard.as_ref().expect("cache populated above") {
            Ok(arc) => Ok(arc.clone()),
            Err(msg) => Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                msg.clone(),
            )),
        }
    }

    fn read_entry(&self) -> std::io::Result<Vec<u8>> {
        self.read_entry_capped(MAX_ENTRY_SIZE)
    }

    /// Read the entry, hard-capping the in-memory materialisation at `cap` bytes.
    /// Reads one byte past `cap` so an over-cap entry is detected and fails
    /// closed rather than being silently truncated. (`cap` is a parameter only
    /// so the cap behaviour is testable without allocating gigabytes.)
    fn read_entry_capped(&self, cap: u64) -> std::io::Result<Vec<u8>> {
        use std::io::{Error, ErrorKind, Read};
        // A clone shares the parsed directory and owns its own cursor.
        let mut archive = self.archive.clone();
        let f = archive.by_name(&self.entry_name).map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("open ZIP entry {}: {e}", self.entry_name),
            )
        })?;
        let mut buf = Vec::with_capacity(self.size.min(64 * 1024 * 1024) as usize);
        f.take(cap + 1).read_to_end(&mut buf)?;
        if buf.len() as u64 > cap {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("ZIP entry {} exceeds {}-byte cap", self.entry_name, cap),
            ));
        }
        // The materialised length must match the size we advertise via `size()`
        // (the central-directory uncompressed size). A shorter (or longer)
        // materialisation means the directory lied or the entry is corrupt;
        // serving it would misreport length and hand out truncated content as if
        // complete. Fail closed rather than reconcile silently.
        if buf.len() as u64 != self.size {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "ZIP entry {} materialised to {} bytes but its directory claims {}",
                    self.entry_name,
                    buf.len(),
                    self.size
                ),
            ));
        }
        Ok(buf)
    }
}

impl DataSource for ZipEntrySource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let data = self.materialize()?;
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = buf.len().min(data.len() - off);
        buf[..n].copy_from_slice(&data[off..off + n]);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.size
    }

    /// A zip entry knows exactly what else is in its own archive, so it can
    /// answer both questions `open_sibling` is asked: whether the neighbour is
    /// there, and whether looking was possible at all (HUNT-101).
    fn supports_siblings(&self) -> bool {
        true
    }

    /// Open an entry at a path relative to this entry's directory in the same
    /// archive — `54/54e5…` beside a backup's `Manifest.db` (HUNT-109).
    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        if !seance_core::data_source::relative_path_is_plain(relative) {
            return None;
        }
        let dir = match self.entry_name.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/"),
            None => String::new(),
        };
        let target = format!("{dir}{relative}");
        let mut archive = self.archive.clone();
        let size = archive.by_name(&target).ok()?.size();
        Some(Arc::new(ZipEntrySource::new(
            self.parent.clone(),
            self.archive.clone(),
            target,
            size,
        )))
    }

    fn supports_ancestors(&self) -> bool {
        true
    }

    /// Open an entry `levels` directories above this entry's own, then down a
    /// plain relative path — a unified log's `../<XX>/<rest>` in a zipped
    /// `.logarchive` (ROADMAP §1.6). The climb stays inside the archive.
    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        if !seance_core::data_source::relative_path_is_plain(relative) {
            return None;
        }
        let prefix = seance_core::data_source::ancestor_prefix(&self.entry_name, levels)?;
        let target = format!("{prefix}{relative}");
        let mut archive = self.archive.clone();
        let size = archive.by_name(&target).ok()?.size();
        Some(Arc::new(ZipEntrySource::new(
            self.parent.clone(),
            self.archive.clone(),
            target,
            size,
        )))
    }

    /// The files directly in a directory `levels` above this entry's own, in
    /// the same archive (HUNT-272). A name with no entry under it is not a
    /// directory here, and answers `None`.
    fn list_from_ancestor(&self, levels: usize, relative_dir: &str) -> Option<Vec<String>> {
        if !(relative_dir.is_empty()
            || seance_core::data_source::relative_path_is_plain(relative_dir))
        {
            return None;
        }
        let prefix = seance_core::data_source::ancestor_prefix(&self.entry_name, levels)?;
        let dir = if relative_dir.is_empty() {
            prefix
        } else {
            format!("{prefix}{relative_dir}/")
        };
        let mut present = false;
        let mut names = Vec::new();
        for full in self.archive.file_names() {
            // A name `zip` cannot decode is an error and cannot sit under this directory's
            // plain-ASCII prefix.
            let Ok(full) = full else {
                continue;
            };
            let Some(rest) = full.strip_prefix(dir.as_str()) else {
                continue;
            };
            present = true;
            if rest.is_empty() || rest.contains('/') {
                continue;
            }
            names.push(rest.to_string());
            if names.len() > seance_core::data_source::MAX_LISTED_NAMES {
                return None;
            }
        }
        if !present {
            return None;
        }
        names.sort();
        names.dedup();
        Some(names)
    }

    /// Open a sibling entry in the same archive whose name is this entry's name
    /// with `suffix` appended — e.g. `1.db` -> `1.db-wal`. This lets the SQLite
    /// parser pull a database's write-ahead log / journal even when both live
    /// inside the ZIP (where a filesystem-path lookup cannot reach them).
    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        let sibling_name = format!("{}{}", self.entry_name, suffix);
        // The shared directory says whether the sibling exists and how big it
        // is; the bytes themselves stay lazy.
        let mut archive = self.archive.clone();
        let size = archive.by_name(&sibling_name).ok()?.size();
        Some(Arc::new(ZipEntrySource::new(
            self.parent.clone(),
            self.archive.clone(),
            sibling_name,
            size,
        )))
    }
}

pub struct ZipContainerModule;

/// An MS-DOS date/time from a ZIP entry as an RFC 3339 string.
///
/// ZIP stores local wall-clock time with no zone and two-second resolution.
/// The value is rendered with a `+00:00` offset because RFC 3339 requires one,
/// and the record that carries it also carries `timezone: "local"` so nothing
/// downstream reads the offset as a fact about the archive. A value the zip
/// crate cannot make a date of (0 means "not recorded", and DOS cannot express
/// a year before 1980) yields `None` rather than a fabricated 1980-01-01.
/// An entry's stored name. `zip` 9 reports a name it cannot decode as an error; the entry is still
/// listed, under the lossy reading of its raw bytes, so it is never dropped from the inventory.
fn entry_name<R: std::io::Read>(f: &zip::read::ZipFile<'_, R>) -> String {
    f.name()
        .map(|n| n.into_owned())
        .unwrap_or_else(|_| String::from_utf8_lossy(f.name_raw()).into_owned())
}

fn dos_datetime_rfc3339(dt: &zip::DateTime) -> Option<String> {
    let (y, mo, d, h, mi, s) = (
        dt.year(),
        dt.month(),
        dt.day(),
        dt.hour(),
        dt.minute(),
        dt.second(),
    );
    if y < 1980 || mo == 0 || d == 0 {
        return None;
    }
    // The DOS epoch itself is what a writer stores when it has no time to
    // store — it is the zero of this format, exactly as 0 is tar's. A file
    // dated to it is a file with no recorded time, and putting 1980-01-01 on
    // the timeline of every such entry would be a date nothing in the evidence
    // supports.
    if (y, mo, d, h, mi, s) == (1980, 1, 1, 0, 0, 0) {
        return None;
    }
    let date = chrono::NaiveDate::from_ymd_opt(y as i32, mo as u32, d as u32)?;
    let time = chrono::NaiveTime::from_hms_opt(h as u32, mi as u32, s as u32)?;
    Some(
        chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
            chrono::NaiveDateTime::new(date, time),
            chrono::Utc,
        )
        .to_rfc3339(),
    )
}

impl ForensicsModule for ZipContainerModule {
    fn id(&self) -> &str {
        "container.zip_extractor"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // FileEntry too, so a .zip or ZIP-based office document *inside* a
        // filesystem is expanded recursively — otherwise images embedded in
        // archives/documents are never surfaced ("find all images" gap).
        vec![ArtifactType::Container, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let mut produced_artifacts = Vec::new();

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        let lower = name.to_lowercase();

        // AFF4 evidence containers are ZIP-based but have a dedicated reader —
        // don't double-process them here as plain archives.
        if lower.ends_with(".aff4") || artifact.subtype() == Some("aff4") {
            return Ok(produced_artifacts);
        }

        // ZIP archives and ZIP-based office documents (.docx/.xlsx/.pptx and
        // friends). Expanding the office formats is what surfaces media buried
        // inside documents (e.g. word/media/*.jpg).
        const ZIP_EXTS: [&str; 13] = [
            ".zip", ".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm", ".jar", ".apk", ".odt",
            ".ods", ".odp",
            // Cellebrite UFDR mobile extraction reports are ZIP archives; expand
            // them so the mobile parsers see the extracted device files inside.
            ".ufdr",
        ];
        let zip_subtype = matches!(artifact.subtype(), Some("zip" | "docx" | "xlsx" | "pptx"));
        let looks_zip_by_name = zip_subtype || ZIP_EXTS.iter().any(|e| lower.ends_with(e));

        // A present, non-zip subtype means another handler owns this format
        // (e01/vmdk/…); skip cheaply without needing a data source.
        if artifact.subtype().is_some() && !zip_subtype && !looks_zip_by_name {
            return Ok(produced_artifacts);
        }

        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => {
                // A zip-looking artifact with no data is caller error; anything
                // else simply is not ours.
                return if looks_zip_by_name {
                    Err(ModuleError::InvalidInputFormat(
                        "ZIP module requires data source".to_string(),
                    ))
                } else {
                    Ok(produced_artifacts)
                };
            }
        };

        // Content gate: confirm a real ZIP local-file header (PK\x03\x04, or the
        // empty/spanned variants) so a non-zip FileEntry reaching us via the
        // subscription is ignored, and a renamed/extension-less archive is not.
        // `read_full` loops: one `read_at` returning two bytes is ordinary for a
        // windowed or container-backed source, and taking that as "not a ZIP"
        // would skip the whole archive without a word anywhere.
        let mut magic = [0u8; 4];
        let read = read_full(data_source.as_ref(), 0, &mut magic);
        let is_zip = read >= 4
            && &magic[..2] == b"PK"
            && matches!(magic[2..4], [0x03, 0x04] | [0x05, 0x06] | [0x07, 0x08]);
        if !is_zip {
            // An artifact that reached us only through the FileEntry
            // subscription simply is not ours, and staying silent is correct.
            // A file the case already calls a `.zip` / `.docx` / `.ufdr` is a
            // different matter: its header is short or wrong, which means
            // truncated or damaged. Returning nothing there makes a truncated
            // mobile extraction report look like an archive that held no files
            // (B6-022).
            if looks_zip_by_name {
                let detail = if read < 4 {
                    format!(
                        "only {read} byte(s) could be read where a 4-byte ZIP local-file \
                         header is required"
                    )
                } else {
                    format!(
                        "the first four bytes {:02x?} are not a ZIP signature",
                        &magic[..4]
                    )
                };
                warn!("ZIP {}: named as an archive but {}", name, detail);
                return Ok(vec![archive_status(
                    artifact,
                    name,
                    0,
                    0,
                    "zip_magic_unreadable",
                    &detail,
                )]);
            }
            return Ok(produced_artifacts);
        }

        info!("ZipContainerModule processing: {}", name);

        // Need a Read + Seek cursor. SourceCursor implements this.
        let cursor = SourceCursor::new(data_source.clone());

        let mut archive = match ZipArchive::new(cursor) {
            Ok(a) => a,
            Err(e) => {
                warn!("Failed to open ZIP archive {}: {}", name, e);
                // An archive we could not open is not an empty archive: an
                // examiner who sees no entries must not read that as "the
                // archive held nothing".
                return Ok(vec![archive_status(
                    artifact,
                    name,
                    0,
                    0,
                    "zip_unreadable",
                    &e.to_string(),
                )]);
            }
        };

        // Central-directory entries that would not parse. Each one is a file
        // the archive lists and this listing does not (B2-158).
        let mut skipped = 0usize;
        let mut first_error: Option<String> = None;
        // Encrypted entries are NOT unreadable-corrupt: they are password
        // protected and recoverable with `seance crack-zip`. Count them apart so
        // an examiner is told the archive is encrypted, not that it is damaged.
        let mut encrypted = 0usize;
        let mut encrypted_idx: Vec<usize> = Vec::new();

        for i in 0..archive.len() {
            let file = match archive.by_index(i) {
                Ok(f) => f,
                Err(zip::result::ZipError::UnsupportedArchive(msg))
                    if msg == zip::result::ZipError::PASSWORD_REQUIRED =>
                {
                    encrypted += 1;
                    encrypted_idx.push(i);
                    continue;
                }
                Err(e) => {
                    skipped += 1;
                    first_error.get_or_insert_with(|| e.to_string());
                    continue;
                }
            };

            let fname = entry_name(&file);
            let size = file.size();
            let compressed_size = file.compressed_size();
            let is_dir = file.is_dir();
            // The entry's own timestamp and permission bits: on an archive-
            // sourced case they are the only record of either (HUNT-094). ZIP
            // stores an MS-DOS date and time — local wall clock, in a zone the
            // archive does not carry, at two-second resolution — so it is
            // written with the `timezone: local` qualification the FAT readers
            // use for the same shape of value, never as if it were UTC.
            let dos_modified = file.last_modified();
            let unix_mode = file.unix_mode();
            // `file` borrows the archive mutably; everything needed from it is
            // copied out above, so the borrow can end before the archive is
            // cloned into the entry's source.
            drop(file);

            // Zip entry names are the full internal path (e.g. "dir/file.txt").
            // Split into the flat-model contract so the file tree can group
            // entries: name = basename, path = "/"-prefixed full path,
            // parent_path = the containing directory. The path is resolved
            // within the archive first (BUG-036); for the entries where that
            // changed the name, `original_name` carries the stored name that
            // addresses the entry inside the archive.
            let EntryPath {
                full_path,
                parent_path,
                name: base,
                original,
                escapes_root,
            } = resolve_entry_path(&fname);

            let mut metadata = json!({
                "name": base,
                "path": full_path,
                "parent_path": parent_path,
                "size": size,
                "compressed_size": compressed_size,
                "is_directory": is_dir,
                "container": "zip",
                "container_path": name
            });
            if let Some(original) = original {
                metadata["original_name"] = json!(original);
            }
            if escapes_root {
                metadata["path_traversal"] = json!(true);
            }
            if let Some(modified) = dos_modified.as_ref().and_then(dos_datetime_rfc3339) {
                metadata["modified"] = json!(modified);
                // The zone is not in the archive, and presenting a local wall
                // clock as UTC would move every file in it by the examiner's
                // own offset.
                metadata["timezone"] = json!("local");
            }
            if let Some(mode) = unix_mode {
                metadata["mode"] = json!(format!("{:o}", mode & 0o7777));
            }

            // Attach a lazy data source for files so the downstream parsers
            // (office, mobile messengers, hashing, EXIF, ...) run on the archive
            // contents. Directories have no content.
            let entry_data: Option<Arc<dyn DataSource>> = if is_dir {
                None
            } else {
                Some(Arc::new(ZipEntrySource::new(
                    data_source.clone(),
                    archive.clone(),
                    fname.clone(),
                    size,
                )))
            };

            let entry_artifact = Artifact::new(
                artifact.case_id,
                ArtifactType::FileEntry,
                entry_data,
                metadata,
            )
            .with_parent(artifact.id);

            produced_artifacts.push(entry_artifact);
        }

        info!(
            "Extracted metadata for {} files from ZIP",
            produced_artifacts.len()
        );

        if skipped > 0 {
            warn!(
                "ZIP {}: {} of {} central-directory entries could not be read",
                name,
                skipped,
                archive.len()
            );
            let recovered = produced_artifacts.len();
            let detail = first_error.unwrap_or_default();
            produced_artifacts.push(archive_status(
                artifact,
                name,
                recovered,
                skipped,
                "zip_entry_unreadable",
                &detail,
            ));
        }

        // Surface the archive's crackability: an examiner (in the API, TUI or
        // GUI) sees that the archive is password-protected and how to recover it,
        // rather than an entry that failed to list.
        if encrypted > 0 {
            info!("ZIP {}: {} encrypted entries", name, encrypted);
            // Every encrypted entry still gets a FileEntry: its name, path and
            // size come from the central directory (no password needed via
            // by_index_raw), so an examiner can see and search for the file even
            // though its content is locked (B2-158 — a name you cannot see is
            // read as a file that was not there). No data source is attached: the
            // bytes are encrypted, and a decrypted view is a crack-zip step away.
            // A bounded sample of names for the summary, built inline (never a full
            // second copy of every name just to keep the first 50).
            let mut sample: Vec<String> = Vec::new();
            for &i in &encrypted_idx {
                // Name/size/attributes come from the central directory via
                // by_index_raw (no password needed). If even that fails, still emit
                // a placeholder entry: a counted encrypted file that produced no
                // FileEntry would read as a file that was not there (B2-158), and
                // the summary count must never exceed the entries actually surfaced.
                let (fname, size, compressed_size, is_dir) = match archive.by_index_raw(i) {
                    Ok(raw) => (
                        entry_name(&raw),
                        raw.size(),
                        Some(raw.compressed_size()),
                        raw.is_dir(),
                    ),
                    Err(_) => (format!("(encrypted entry #{i})"), 0, None, false),
                };
                if sample.len() < 50 {
                    sample.push(fname.clone());
                }
                let EntryPath {
                    full_path,
                    parent_path,
                    name: base,
                    original,
                    escapes_root,
                } = resolve_entry_path(&fname);
                // Mirror the plaintext-entry schema so consumers render encrypted
                // and readable siblings uniformly: same keys, is_directory from the
                // entry itself, compressed_size when the directory recorded it —
                // and the same resolved path, since an encrypted entry's stored
                // name is no more trustworthy than a readable one's (BUG-036).
                let mut meta = json!({
                    "name": base,
                    "path": full_path,
                    "parent_path": parent_path,
                    "size": size,
                    "is_directory": is_dir,
                    "container": "zip",
                    "container_path": name,
                    "encrypted": true,
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
                    "content_incomplete_detail":
                        "zip entry is password-protected (ZipCrypto or WinZip AES)",
                });
                if let (Some(cs), Some(obj)) = (compressed_size, meta.as_object_mut()) {
                    obj.insert("compressed_size".into(), json!(cs));
                }
                if let Some(original) = original {
                    meta["original_name"] = json!(original);
                }
                if escapes_root {
                    meta["path_traversal"] = json!(true);
                }
                produced_artifacts.push(
                    Artifact::new(
                        artifact.case_id,
                        ArtifactType::FileEntry,
                        None, // content is encrypted; no readable data source
                        meta,
                    )
                    .with_parent(artifact.id),
                );
            }
            produced_artifacts.push(encrypted_archive_record(artifact, name, encrypted, &sample));
        }

        Ok(produced_artifacts)
    }
}

/// The flat-model path fields for one archive entry, derived from its stored
/// name.
#[derive(Debug)]
struct EntryPath {
    /// `/`-prefixed path, resolved within the archive root.
    full_path: String,
    /// Containing directory (`/` at the archive root).
    parent_path: String,
    /// Basename.
    name: String,
    /// The stored name, verbatim, when resolution changed it. The traversal
    /// attempt is evidence in its own right, so it is kept rather than dropped
    /// — and it is the name that still addresses the entry in the archive.
    original: Option<String>,
    /// The stored name reaches outside the archive root: it is absolute, or a
    /// `..` walks past the root.
    escapes_root: bool,
}

/// Resolve a stored archive entry name into the flat-model `name` / `path` /
/// `parent_path` trio.
///
/// Entry names come from the archive, not from us: `..`, absolute names and
/// doubled separators all occur in hostile archives, and a stored path that
/// keeps them states a location the entry does not occupy — the file tree, the
/// `/files` API and the export manifest all render that path as fact (BUG-036).
/// Empty and `.` segments are dropped, `..` is applied within the archive and
/// clamped at its root. Nothing is destroyed: a name that changed is kept in
/// `original`, and a name that reached outside the root is flagged.
///
/// The same rule is applied to tar entries in `seance_container_archive`; both
/// feed one flat-model path contract, so they must agree.
fn resolve_entry_path(raw: &str) -> EntryPath {
    // Backslashes are separators here, before anything else looks at the
    // name. This split only on `/`, so an entry named `..\\..\\payload` was one
    // segment rather than two `..`s: `escapes_root` stayed false and the entry
    // was placed at the root with the traversal still inside its name — which
    // a Linux host treats as a filename and a Windows host treats as a path.
    // `seance_container_archive` normalises the same way for the same reason
    // (RUSTSEC-2026-0245); this crate had not been brought with it.
    let normalised = raw.replace('\\', "/");
    let raw = normalised.as_str();
    let trimmed = raw.trim_end_matches('/');
    // An absolute name escapes an extraction root exactly as `..` does.
    let mut escapes_root = trimmed.starts_with('/');
    let mut segments: Vec<&str> = Vec::new();
    for segment in trimmed.split('/') {
        match segment {
            "" | "." => {}
            ".." => {
                if segments.pop().is_none() {
                    escapes_root = true;
                }
            }
            other => segments.push(other),
        }
    }
    let resolved = segments.join("/");
    let (parent_path, name) = match resolved.rfind('/') {
        Some(i) => (
            format!("/{}", &resolved[..i]),
            resolved[i + 1..].to_string(),
        ),
        None if !resolved.is_empty() => ("/".to_string(), resolved.clone()),
        // Nothing survived resolution (a name that is only `.` or `..`): the
        // entry sits at the root, but its stored basename stays visible — a
        // nameless row reads as a file that was not there.
        None => (
            "/".to_string(),
            trimmed.rsplit('/').next().unwrap_or_default().to_string(),
        ),
    };
    EntryPath {
        full_path: format!("/{resolved}"),
        parent_path,
        name,
        original: (resolved != trimmed).then(|| raw.to_string()),
        escapes_root,
    }
}

/// A record surfacing that the archive is password-protected, and how to recover
/// it. Emitted as a `ParsedRecord` so it reaches the analysis, search, timeline,
/// API, TUI and GUI surfaces like any other finding — the examiner learns the
/// archive is encrypted and crackable, not that entries failed to list.
fn encrypted_archive_record(
    artifact: &Artifact,
    name: &str,
    encrypted_entries: usize,
    sample_names: &[String],
) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "EncryptedArchive",
            "subtype": "zip_encrypted",
            "name": format!("Encrypted archive: {name}"),
            "archive": name,
            "encrypted_entries": encrypted_entries,
            "sample_entry_names": sample_names,
            "recoverable_with": "seance crack-zip",
            "evidence_grade": "scanned",
            "note": "This ZIP has password-protected entries (ZipCrypto or WinZip AES). \
                     Each encrypted entry is surfaced as its own FileEntry (name, path \
                     and size from the central directory) but its contents stay locked \
                     until decrypted. Recover them with `seance crack-zip --archive \
                     <path>` (off by default, dictionary/mask, proven by a real decrypt).",
        }),
    )
    .with_parent(artifact.id)
}

/// A record saying this archive was only partly enumerated.
///
/// Files an examiner cannot see in a listing are read as files the archive did
/// not contain. When entries were dropped that conclusion is wrong, and a
/// warning in the server log never reaches the person drawing it (B2-158).
fn archive_status(
    artifact: &Artifact,
    name: &str,
    entries_recovered: usize,
    entries_skipped: usize,
    reason: &'static str,
    detail: &str,
) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "ArchiveScanStatus",
            "record_type": "archive_scan_status",
            "name": format!("{} (partially extracted)", name),
            "container": "zip",
            "container_path": name,
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            "entries_recovered": entries_recovered,
            "entries_skipped": entries_skipped,
            "content_incomplete_detail": detail,
            "detail": detail,
            "message": "This archive was only partly enumerated: entries missing from \
                        the listing are not evidence that the archive did not contain them",
        }),
    )
    .with_parent(artifact.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::DataSource;
    use std::io::{Cursor, Write};
    use std::sync::Arc;
    use uuid::Uuid;
    use zip::write::SimpleFileOptions as FileOptions;
    use zip::ZipWriter;

    /// A backslash is a separator, and a traversal spelled with them escapes
    /// the root exactly as one spelled with slashes does.
    ///
    /// The resolver split only on `/`, so `..\..\payload` was ONE segment: no
    /// `..` was seen, `escapes_root` stayed false, and the entry was placed at
    /// the root with the traversal still inside its name — a filename on a
    /// Linux host and a path on a Windows one. `seance_container_archive`
    /// normalises for the same reason (RUSTSEC-2026-0245).
    #[test]
    fn a_backslash_traversal_escapes_the_root_like_a_slash_one() {
        let slashes = resolve_entry_path("../../payload");
        let backslashes = resolve_entry_path("..\\..\\payload");
        assert!(slashes.escapes_root);
        assert!(
            backslashes.escapes_root,
            "the backslash spelling must be seen as the same traversal: {backslashes:?}"
        );
        assert_eq!(backslashes.full_path, slashes.full_path);

        // And an ordinary Windows-style path is an ordinary path.
        let plain = resolve_entry_path("folder\\sub\\file.txt");
        assert!(!plain.escapes_root);
        assert_eq!(plain.full_path, "/folder/sub/file.txt");
        assert_eq!(plain.parent_path, "/folder/sub");
        assert_eq!(plain.name, "file.txt");

        // Mixed, with a traversal in the middle that resolves inside the root.
        let mixed = resolve_entry_path("a\\b/..\\c");
        assert!(!mixed.escapes_root);
        assert_eq!(mixed.full_path, "/a/c");
    }

    use seance_core::data_source::ByteSliceDataSource;

    /// Build a tiny in-memory ZIP with the given entries.
    /// Each entry is (path, body); path ending in '/' is treated as a directory.
    fn build_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Cursor::new(Vec::new());
        {
            let mut zw = ZipWriter::new(&mut buf);
            let opts: FileOptions =
                FileOptions::default().compression_method(zip::CompressionMethod::Deflated);
            for (name, body) in entries {
                if name.ends_with('/') {
                    zw.add_directory(*name, opts).unwrap();
                } else {
                    zw.start_file(*name, opts).unwrap();
                    zw.write_all(body).unwrap();
                }
            }
            zw.finish().unwrap();
        }
        buf.into_inner()
    }

    /// A parent source that counts how many times its end-of-central-directory
    /// region is read: that region is read when an archive is *opened* and
    /// nowhere else, so the count is the number of times the directory was
    /// parsed.
    #[derive(Debug)]
    struct CountingSource {
        bytes: Vec<u8>,
        tail_reads: std::sync::atomic::AtomicUsize,
    }

    impl DataSource for CountingSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = offset as usize;
            if off >= self.bytes.len() {
                return Ok(0);
            }
            // The EOCD record is the last 22 bytes; anything touching them is a
            // directory open.
            if off + buf.len() > self.bytes.len().saturating_sub(22) {
                self.tail_reads
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            let n = buf.len().min(self.bytes.len() - off);
            buf[..n].copy_from_slice(&self.bytes[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.bytes.len() as u64
        }
    }

    /// HUNT-068. Every entry source re-opened the archive — re-reading and
    /// re-parsing the whole central directory — the first time a parser read
    /// it. On the 125,327-entry Cellebrite zip of the Android 14 reference
    /// image that cost 12–40 seconds per entry, before any parser saw a byte:
    /// forty-three days for one ingest. The directory is parsed once, when the
    /// archive is listed, and every entry shares it.
    #[test]
    fn materialising_every_entry_parses_the_central_directory_once() {
        let entries: Vec<(String, Vec<u8>)> = (0..64)
            .map(|i| (format!("dir/file{i}.txt"), format!("body {i}").into_bytes()))
            .collect();
        let refs: Vec<(&str, &[u8])> = entries
            .iter()
            .map(|(n, b)| (n.as_str(), b.as_slice()))
            .collect();
        let bytes = build_zip(&refs);
        let counting = Arc::new(CountingSource {
            bytes,
            tail_reads: std::sync::atomic::AtomicUsize::new(0),
        });
        let parent: Arc<dyn DataSource> = counting.clone();

        let out = ZipContainerModule
            .process(&make_artifact("big.zip", Some("zip"), Some(parent)))
            .unwrap();
        let opens_after_listing = counting
            .tail_reads
            .load(std::sync::atomic::Ordering::Relaxed);
        assert!(opens_after_listing >= 1, "listing opens the archive once");

        // Read the first byte of every entry, as the first parser to touch
        // each one does.
        let mut read = 0;
        for a in &out {
            if let Some(ds) = a.data.as_ref() {
                let mut b = [0u8; 1];
                if ds.read_at(0, &mut b).unwrap() == 1 {
                    read += 1;
                }
            }
        }
        assert_eq!(read, 64);
        let opens_after_reads = counting
            .tail_reads
            .load(std::sync::atomic::Ordering::Relaxed);
        assert_eq!(
            opens_after_reads,
            opens_after_listing,
            "reading the entries must not re-open the archive: the directory was parsed \
             {} more times for 64 entries",
            opens_after_reads - opens_after_listing
        );
    }

    fn make_artifact(
        name: &str,
        subtype: Option<&str>,
        data: Option<Arc<dyn DataSource>>,
    ) -> Artifact {
        let mut meta = json!({ "name": name });
        if let Some(s) = subtype {
            meta["subtype"] = serde_json::Value::String(s.to_string());
        }
        Artifact::new(Uuid::new_v4(), ArtifactType::Container, data, meta)
    }

    #[test]
    fn module_identity() {
        let m = ZipContainerModule;
        assert_eq!(m.id(), "container.zip_extractor");
        assert!(!m.version().is_empty());
        assert_eq!(
            m.subscribes_to(),
            vec![ArtifactType::Container, ArtifactType::FileEntry]
        );
    }

    #[test]
    fn surfaces_an_encrypted_archive_as_a_crackable_record() {
        // An encrypted ZIP must be reported as password-protected and crackable
        // (via crack-zip), not as unreadable/corrupt entries. Build one with
        // `zip -e`; skip if the tool is unavailable.
        let dir = std::env::temp_dir().join(format!("seance_zipenc_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let plain = dir.join("secret.txt");
        std::fs::write(&plain, b"top secret contents").unwrap();
        let archive = dir.join("enc.zip");
        let built = std::process::Command::new("zip")
            .args([
                "-j",
                "-e",
                "-P",
                "pw",
                archive.to_str().unwrap(),
                plain.to_str().unwrap(),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        let bytes = if built {
            std::fs::read(&archive).ok()
        } else {
            None
        };
        let _ = std::fs::remove_dir_all(&dir);
        let Some(bytes) = bytes else {
            eprintln!("skipping: `zip` not available");
            return;
        };

        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("locked.zip", None, Some(src));
        let out = ZipContainerModule.process(&art).unwrap();
        let rec = out
            .iter()
            .find(|a| a.metadata.get("type").and_then(|v| v.as_str()) == Some("EncryptedArchive"))
            .expect("an encrypted archive must surface an EncryptedArchive record");
        assert!(rec.metadata["encrypted_entries"].as_u64().unwrap() >= 1);
        assert_eq!(rec.metadata["recoverable_with"], json!("seance crack-zip"));
        assert_eq!(rec.metadata["evidence_grade"], json!("scanned"));

        // The encrypted entry still surfaces as a searchable FileEntry (name from
        // the central directory), marked encrypted, so it is not read as absent.
        let fe = out
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata.get("encrypted").and_then(|v| v.as_bool()) == Some(true)
            })
            .expect("an encrypted entry must still be listed as a FileEntry");
        assert_eq!(fe.metadata["name"], json!("secret.txt"));
        assert!(fe.data.is_none(), "encrypted content must not be served");
        // Canonical incompleteness reason (round-trippable), with the specifics in
        // the detail field.
        assert_eq!(
            fe.metadata["content_incomplete_reason"],
            json!(IncompleteReason::Encrypted.as_str())
        );
        // Schema parity with plaintext entries: is_directory present (a file here)
        // and compressed_size carried from the central directory.
        assert_eq!(fe.metadata["is_directory"], json!(false));
        assert!(
            fe.metadata.get("compressed_size").is_some(),
            "encrypted FileEntry must carry compressed_size like plaintext siblings"
        );
    }

    #[test]
    fn expands_ooxml_document_and_surfaces_embedded_media() {
        // A .docx is a ZIP; its embedded image lives at word/media/image1.jpg.
        // Expanding it is what lets "find all images" reach document media.
        let bytes = build_zip(&[
            ("[Content_Types].xml", b"<xml/>"),
            ("word/document.xml", b"<w:document/>"),
            ("word/media/image1.jpg", &[0xff, 0xd8, 0xff, 0xe0, 0, 0]),
        ]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        // No explicit subtype; recognised as a zip by content (the .docx name
        // only hints). A FileEntry inside a filesystem would arrive the same way.
        let art = make_artifact("report.docx", None, Some(src));

        let out = ZipContainerModule.process(&art).unwrap();
        let names: Vec<&str> = out
            .iter()
            .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
            .collect();
        assert!(
            names.contains(&"image1.jpg"),
            "embedded image1.jpg must be surfaced, got {names:?}"
        );
    }

    #[test]
    fn expands_ufdr_mobile_extraction_report() {
        // A Cellebrite UFDR is a ZIP; expanding it surfaces the extracted device
        // files (here a Viber DB) so the mobile parsers can read them. The child
        // surfaces under its basename, which is exactly what the parsers gate on.
        let bytes = build_zip(&[
            ("report.xml", b"<ufdr/>"),
            (
                "data/data/com.viber.voip/databases/viber_messages",
                b"SQLite format 3\0",
            ),
        ]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("extraction.ufdr", None, Some(src));

        let out = ZipContainerModule.process(&art).unwrap();
        let names: Vec<&str> = out
            .iter()
            .filter_map(|a| a.metadata.get("name").and_then(|v| v.as_str()))
            .collect();
        assert!(
            names.contains(&"viber_messages"),
            "UFDR inner files must be surfaced, got {names:?}"
        );
    }

    #[test]
    fn extracted_entry_has_readable_lazy_data_source() {
        // The child must carry a data source that materialises the entry bytes,
        // so the downstream parsers can actually read archive contents.
        let body: &[u8] = b"SQLite format 3\0the rest of a db body";
        let bytes = build_zip(&[("data/data/com.viber.voip/viber_messages", body)]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("extraction.zip", None, Some(src));

        let out = ZipContainerModule.process(&art).unwrap();
        let child = out
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("viber_messages"))
            .expect("viber_messages child present");
        let ds = child.data.as_ref().expect("child carries a data source");
        assert_eq!(ds.size(), body.len() as u64);
        let mut buf = vec![0u8; body.len()];
        let n = ds.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], body, "lazy source must return the entry bytes");
    }

    #[test]
    fn non_zip_fileentry_is_ignored() {
        // A plain FileEntry that is not a ZIP (no PK magic) must produce nothing
        // even though we now subscribe to FileEntry.
        let src: Arc<dyn DataSource> =
            Arc::new(ByteSliceDataSource::new(b"not a zip at all".to_vec()));
        let mut meta = json!({ "name": "notes.txt" });
        meta["dummy"] = json!(true);
        let art = Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, Some(src), meta);
        assert!(ZipContainerModule.process(&art).unwrap().is_empty());
    }

    #[test]
    fn non_zip_subtype_short_circuits() {
        // A Container artifact with subtype="e01" must produce nothing,
        // even with no data source attached.
        let art = make_artifact("evidence.e01", Some("e01"), None);
        let out = ZipContainerModule.process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn no_subtype_and_non_zip_extension_short_circuits() {
        let art = make_artifact("evidence.bin", None, None);
        let out = ZipContainerModule.process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn missing_data_source_with_zip_extension_is_invalid_input() {
        // If we look like a zip but have no data, that's caller error,
        // not a silent skip — verify InvalidInputFormat surfaces.
        let art = make_artifact("archive.zip", Some("zip"), None);
        match ZipContainerModule.process(&art) {
            Err(ModuleError::InvalidInputFormat(_)) => {}
            other => panic!("expected InvalidInputFormat, got {:?}", other),
        }
    }

    #[test]
    fn extracts_file_entries_from_real_zip() {
        let bytes = build_zip(&[
            ("hello.txt", b"hello, world\n"),
            ("nested/dir/", b""),
            ("nested/dir/inner.bin", &[0u8, 1, 2, 3, 4, 5]),
        ]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("archive.zip", Some("zip"), Some(src));

        let out = ZipContainerModule.process(&art).unwrap();
        assert_eq!(out.len(), 3, "expected 3 zip entries (file, dir, file)");

        // All produced artifacts must be FileEntry, parented to the container,
        // and tagged with container=zip.
        for entry in &out {
            assert_eq!(entry.artifact_type, ArtifactType::FileEntry);
            assert_eq!(entry.parent_id, Some(art.id));
            assert_eq!(
                entry.metadata.get("container").and_then(|v| v.as_str()),
                Some("zip")
            );
            assert_eq!(
                entry
                    .metadata
                    .get("container_path")
                    .and_then(|v| v.as_str()),
                Some("archive.zip")
            );
        }

        // Entries follow the flat-model contract: name = basename, path =
        // "/"-prefixed full path (so the file tree can group them).
        let dir_entry = out
            .iter()
            .find(|a| a.metadata.get("path").and_then(|v| v.as_str()) == Some("/nested/dir"))
            .expect("missing directory entry");
        assert_eq!(
            dir_entry.metadata.get("name").and_then(|v| v.as_str()),
            Some("dir")
        );
        assert_eq!(
            dir_entry
                .metadata
                .get("is_directory")
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        // Spot-check a file entry: basename, full path, parent path, size.
        let inner = out
            .iter()
            .find(|a| {
                a.metadata.get("path").and_then(|v| v.as_str()) == Some("/nested/dir/inner.bin")
            })
            .expect("missing inner file");
        assert_eq!(
            inner.metadata.get("name").and_then(|v| v.as_str()),
            Some("inner.bin")
        );
        assert_eq!(
            inner.metadata.get("parent_path").and_then(|v| v.as_str()),
            Some("/nested/dir")
        );
        assert_eq!(inner.metadata.get("size").and_then(|v| v.as_u64()), Some(6));
        assert_eq!(
            inner.metadata.get("is_directory").and_then(|v| v.as_bool()),
            Some(false)
        );
    }

    #[test]
    fn zip_entry_opens_wal_sibling_in_same_archive() {
        // A database and its write-ahead log packed side by side in one archive.
        let wal = b"\x37\x7f\x06\x82 fake wal frames";
        let bytes = build_zip(&[
            ("data/1.db", b"SQLite format 3\x00 body"),
            ("data/1.db-wal", wal),
            ("data/1.db-shm", b"shm index"),
        ]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("archive.zip", Some("zip"), Some(src));

        let out = ZipContainerModule.process(&art).unwrap();
        let db = out
            .iter()
            .find(|a| a.metadata.get("path").and_then(|v| v.as_str()) == Some("/data/1.db"))
            .expect("missing db entry");

        // The db entry can reach its `-wal` sibling through the archive.
        let sibling = db
            .data
            .as_ref()
            .expect("db has a data source")
            .open_sibling("-wal")
            .expect("wal sibling should be found in the same archive");
        assert_eq!(sibling.size(), wal.len() as u64);
        let mut buf = vec![0u8; wal.len()];
        let n = sibling.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], wal);

        // A sibling that does not exist is None, not an error.
        assert!(db.data.as_ref().unwrap().open_sibling("-nope").is_none());
    }

    /// ROADMAP §1.6: a unified log inside a zipped `.logarchive` reaches its
    /// format strings one directory up (`../<XX>/<rest>`), within the archive
    /// and no further.
    #[test]
    fn zip_entry_reaches_its_tree_from_an_ancestor_directory() {
        let bytes = build_zip(&[
            ("case/a.logarchive/Persist/1.tracev3", b"log"),
            ("case/a.logarchive/AB/CDEF", b"strings"),
            ("top.txt", b"top"),
        ]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let out = ZipContainerModule
            .process(&make_artifact("archive.zip", Some("zip"), Some(src)))
            .unwrap();
        let log = out
            .iter()
            .find(|a| {
                a.metadata.get("path").and_then(|v| v.as_str())
                    == Some("/case/a.logarchive/Persist/1.tracev3")
            })
            .and_then(|a| a.data.clone())
            .expect("the log entry");
        assert!(log.supports_ancestors());
        let strings = log.open_from_ancestor(1, "AB/CDEF").expect("one up");
        let mut buf = [0u8; 7];
        assert_eq!(strings.read_at(0, &mut buf).unwrap(), 7);
        assert_eq!(&buf, b"strings");
        assert!(log.open_from_ancestor(3, "top.txt").is_some());
        assert!(
            log.open_from_ancestor(4, "top.txt").is_none(),
            "past the bound"
        );
        assert!(
            log.open_from_ancestor(1, "../top.txt").is_none(),
            "not plain"
        );
        assert!(log.open_from_ancestor(1, "AB/none").is_none());
    }

    /// HUNT-272: a zipped `.logarchive` lists its `timesync/` directory, so a
    /// timesync file far along its sequence is found without guessing names.
    #[test]
    fn zip_entry_lists_a_directory_under_an_ancestor() {
        let bytes = build_zip(&[
            ("a.logarchive/Persist/1.tracev3", b"log"),
            ("a.logarchive/timesync/00000000000001f4.timesync", b"b"),
            ("a.logarchive/timesync/0000000000000040.timesync", b"a"),
            ("a.logarchive/timesync/deeper/x.timesync", b"c"),
        ]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let out = ZipContainerModule
            .process(&make_artifact("archive.zip", Some("zip"), Some(src)))
            .unwrap();
        let log = out
            .iter()
            .find(|a| {
                a.metadata.get("path").and_then(|v| v.as_str())
                    == Some("/a.logarchive/Persist/1.tracev3")
            })
            .and_then(|a| a.data.clone())
            .expect("the log entry");
        assert_eq!(
            log.list_from_ancestor(1, "timesync"),
            Some(vec![
                "0000000000000040.timesync".to_string(),
                "00000000000001f4.timesync".to_string()
            ])
        );
        assert_eq!(
            log.list_from_ancestor(0, ""),
            Some(vec!["1.tracev3".to_string()])
        );
        assert_eq!(log.list_from_ancestor(1, "absent"), None);
        assert_eq!(log.list_from_ancestor(1, "../timesync"), None);
        assert_eq!(
            log.list_from_ancestor(3, "timesync"),
            None,
            "above the archive"
        );
    }

    /// B6-022: the case already calls this file a `.zip`. Random bytes where the
    /// local-file header should be mean truncated or damaged, not empty — and a
    /// truncated `.ufdr` mobile extraction that lists no files reads to an
    /// examiner as a phone with nothing on it. Must not panic and must not
    /// error the pipeline, but must not stay silent either.
    #[test]
    fn a_named_archive_with_a_wrong_magic_reports_itself_not_nothing() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xDE; 128]));
        let art = make_artifact("not_really.zip", Some("zip"), Some(src));
        let out = ZipContainerModule.process(&art).unwrap();
        assert_eq!(out.len(), 1, "a named archive must not vanish silently");
        let md = &out[0].metadata;
        assert_eq!(md["record_type"], json!("archive_scan_status"));
        assert_eq!(md["content_incomplete"], json!(true));
        assert_eq!(
            md["content_incomplete_reason"],
            json!("zip_magic_unreadable")
        );
        assert_eq!(md["entries_recovered"], json!(0));
    }

    /// The same for a named archive too short to even hold a header.
    #[test]
    fn a_named_archive_shorter_than_its_magic_reports_the_short_read() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(b"PK".to_vec()));
        let art = make_artifact("cut.ufdr", None, Some(src));
        let out = ZipContainerModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].metadata["content_incomplete_reason"],
            json!("zip_magic_unreadable")
        );
        assert!(out[0].metadata["detail"]
            .as_str()
            .unwrap_or("")
            .contains("2 byte"));
    }

    /// The counterweight: a file that is not ours by name must still be ignored
    /// in silence, or every ordinary FileEntry would raise a false alarm.
    #[test]
    fn a_non_archive_name_is_still_ignored_silently() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xDE; 128]));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(src),
            json!({ "name": "photo.jpg" }),
        );
        assert!(ZipContainerModule.process(&art).unwrap().is_empty());
    }

    /// B2-158: an archive that cannot be opened, or whose central-directory
    /// entries will not parse, used to yield an empty listing with only a log
    /// line. An examiner reads an empty listing as "the archive held nothing".
    #[test]
    fn an_unreadable_archive_publishes_an_incomplete_record_not_an_empty_listing() {
        // A real ZIP with its central directory / end-of-central-directory cut
        // off: the local-file-header magic still passes the content gate, so
        // this reaches ZipArchive::new and fails there.
        let mut bytes = build_zip(&[("hello.txt", b"hello, world\n")]);
        bytes.truncate(40);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("cut.zip", Some("zip"), Some(src));

        let out = ZipContainerModule.process(&art).unwrap();
        let status = out
            .iter()
            .find(|a| {
                a.metadata.get("record_type").and_then(|v| v.as_str())
                    == Some("archive_scan_status")
            })
            .expect("an unopenable archive must say so, not report zero files");
        assert_eq!(status.metadata["content_incomplete"], json!(true));
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            json!("zip_unreadable")
        );

        // A readable archive publishes no such record, so the record keeps its
        // meaning.
        let bytes = build_zip(&[("hello.txt", b"hello, world\n")]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("ok.zip", Some("zip"), Some(src));
        let out = ZipContainerModule.process(&art).unwrap();
        assert!(out.iter().all(|a| a.metadata.get("record_type").is_none()));
    }

    #[test]
    fn empty_zip_produces_no_entries() {
        let bytes = build_zip(&[]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("empty.zip", Some("zip"), Some(src));
        let out = ZipContainerModule.process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn missing_subtype_with_zip_extension_still_processes() {
        // The module's fallback path: no subtype, but filename ends in .zip.
        let bytes = build_zip(&[("a.txt", b"x")]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("archive.zip", None, Some(src));
        let out = ZipContainerModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
    }

    /// Open an archive over a parent source the way the listing does.
    fn opened(parent: &Arc<dyn DataSource>) -> ZipArchive<SourceCursor> {
        ZipArchive::new(SourceCursor::new(parent.clone())).expect("archive opens")
    }

    #[test]
    fn failed_entry_read_surfaces_error_not_empty_fullsize() {
        // BUG-002: a lazy entry whose backing bytes cannot be read must fail
        // closed on read, never return a silent empty buffer at the claimed
        // full size (which would fabricate all-EOF evidence). The archive's
        // directory is intact — that is what let the entry be listed — and the
        // entry's compressed bytes are then corrupted underneath it.
        // Incompressible content, so the deflate stream is long enough to damage
        // without reaching the central directory behind it.
        let body: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
            .collect();
        let mut bytes = build_zip(&[("whatever.bin", &body)]);
        // The local header is 30 bytes plus the name and extra fields it
        // declares; the compressed stream starts right after. Corrupt that.
        let name_len = u16::from_le_bytes([bytes[26], bytes[27]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[28], bytes[29]]) as usize;
        let data_start = 30 + name_len + extra_len;
        for b in bytes[data_start..data_start + 16].iter_mut() {
            *b = 0xDE;
        }
        let corrupted: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let archive = opened(&corrupted);
        let src = ZipEntrySource::new(corrupted, archive, "whatever.bin".to_string(), 4096);
        // size() still advertises the claimed uncompressed size...
        assert_eq!(src.size(), 4096);
        // ...but a read must error rather than serve fabricated-empty content.
        let mut buf = [0u8; 16];
        let err = src.read_at(0, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn missing_entry_in_valid_archive_surfaces_error() {
        // BUG-002: a valid archive but an entry name that is not present must
        // error on read, not return an empty full-size buffer.
        let bytes = build_zip(&[("present.txt", b"hi")]);
        let parent: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let archive = opened(&parent);
        let src = ZipEntrySource::new(parent, archive, "absent.bin".to_string(), 512);
        let mut buf = [0u8; 8];
        let err = src.read_at(0, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn claimed_size_larger_than_materialised_fails_closed() {
        // BUG-050: `size()` advertises the central-directory uncompressed size,
        // but the entry materialises to fewer bytes (lying/corrupt directory).
        // A read must fail closed, not serve short content under the claimed size
        // (which would early-EOF vs Content-Length or invite zero-padding).
        let bytes = build_zip(&[("a.txt", b"hi")]); // real content is 2 bytes
        let parent: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let archive = opened(&parent);
        let src = ZipEntrySource::new(parent, archive, "a.txt".to_string(), 100); // claims 100
        assert_eq!(src.size(), 100);
        let mut buf = [0u8; 8];
        let err = src.read_at(0, &mut buf).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn oversized_entry_fails_closed_at_cap() {
        // BUG-003: an entry whose real content exceeds the cap must fail closed,
        // not silently truncate. A small cap stands in for the 4 GiB constant so
        // the test needn't allocate gigabytes.
        let body = vec![b'Z'; 4096];
        let bytes = build_zip(&[("big.bin", &body[..])]);
        let parent: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let archive = opened(&parent);
        let src = ZipEntrySource::new(parent, archive, "big.bin".to_string(), body.len() as u64);

        // Under the real (4 GiB) cap the entry reads back verbatim.
        let mut buf = vec![0u8; body.len()];
        let n = src.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf[..n], &body[..]);

        // With a tiny cap the same entry exceeds it and must error, not truncate.
        let err = src.read_entry_capped(1024).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn entry_path_metadata_does_not_escape_the_archive_root() {
        // BUG-036: stored names are the archive's, not ours. The path an
        // examiner reads must say where the entry lives inside the archive,
        // while the name the archive stored survives as evidence of the
        // traversal attempt.
        let bytes = build_zip(&[
            ("../escape.txt", b"a"),
            ("a/../../deep_escape.txt", b"b"),
            ("/etc/passwd", b"c"),
            ("docs/notes.txt", b"d"),
        ]);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("hostile.zip", Some("zip"), Some(src));
        let out = ZipContainerModule.process(&art).unwrap();

        let paths: Vec<&str> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .filter_map(|a| a.metadata.get("path").and_then(|v| v.as_str()))
            .collect();
        assert_eq!(paths.len(), 4, "every entry must still be listed");
        assert!(
            paths
                .iter()
                .all(|p| !p.split('/').any(|seg| seg == "..") && !p.starts_with("//")),
            "no stored path may keep a traversal or a doubled root: {paths:?}"
        );

        let escape = out
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("escape.txt"))
            .expect("the escaping entry must still be listed");
        assert_eq!(escape.metadata["path"], json!("/escape.txt"));
        assert_eq!(escape.metadata["parent_path"], json!("/"));
        assert_eq!(escape.metadata["original_name"], json!("../escape.txt"));
        assert_eq!(escape.metadata["path_traversal"], json!(true));

        // `..` inside the name is applied, then clamped at the root.
        let deep = out
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("deep_escape.txt"))
            .expect("the deeply escaping entry must still be listed");
        assert_eq!(deep.metadata["path"], json!("/deep_escape.txt"));
        assert_eq!(
            deep.metadata["original_name"],
            json!("a/../../deep_escape.txt")
        );
        assert_eq!(deep.metadata["path_traversal"], json!(true));

        // An absolute stored name reaches outside an extraction root too, and
        // used to produce a doubled-slash path.
        let passwd = out
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("passwd"))
            .expect("the absolutely-named entry must still be listed");
        assert_eq!(passwd.metadata["path"], json!("/etc/passwd"));
        assert_eq!(passwd.metadata["parent_path"], json!("/etc"));
        assert_eq!(passwd.metadata["original_name"], json!("/etc/passwd"));
        assert_eq!(passwd.metadata["path_traversal"], json!(true));

        // An ordinary entry is untouched: nothing was rewritten, so nothing is
        // recorded as rewritten.
        let notes = out
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some("notes.txt"))
            .expect("the ordinary entry must be listed");
        assert_eq!(notes.metadata["path"], json!("/docs/notes.txt"));
        assert_eq!(notes.metadata["parent_path"], json!("/docs"));
        assert!(notes.metadata.get("original_name").is_none());
        assert!(notes.metadata.get("path_traversal").is_none());
    }

    #[test]
    fn encrypted_entry_path_metadata_does_not_escape_the_archive_root() {
        // The encrypted listing builds its FileEntry rows from the central
        // directory on its own code path; it must resolve stored names exactly
        // as the readable siblings do, or BUG-036 returns by the other door.
        let mut bytes = build_zip(&[("../escape.txt", b"a")]);
        mark_entries_encrypted(&mut bytes);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let art = make_artifact("locked.zip", Some("zip"), Some(src));
        let out = ZipContainerModule.process(&art).unwrap();

        let fe = out
            .iter()
            .find(|a| {
                a.artifact_type == ArtifactType::FileEntry
                    && a.metadata.get("encrypted").and_then(|v| v.as_bool()) == Some(true)
            })
            .expect("the encrypted entry must still be listed as a FileEntry");
        assert_eq!(fe.metadata["name"], json!("escape.txt"));
        assert_eq!(fe.metadata["path"], json!("/escape.txt"));
        assert_eq!(fe.metadata["parent_path"], json!("/"));
        assert_eq!(fe.metadata["original_name"], json!("../escape.txt"));
        assert_eq!(fe.metadata["path_traversal"], json!(true));
    }

    /// Set the "encrypted" general-purpose flag on every central-directory
    /// record of an otherwise ordinary ZIP. `by_index` then reports
    /// PASSWORD_REQUIRED exactly as a real password-protected archive does, so
    /// the encrypted-entry listing can be tested without shelling out to
    /// `zip -e` (and without skipping wherever that tool is absent).
    fn mark_entries_encrypted(bytes: &mut [u8]) {
        let eocd = bytes
            .windows(4)
            .rposition(|w| w.starts_with(b"PK\x05\x06"))
            .expect("end-of-central-directory record");
        let cd_offset =
            u32::from_le_bytes(bytes[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
        let mut pos = cd_offset;
        while pos + 46 <= bytes.len() && bytes[pos..].starts_with(b"PK\x01\x02") {
            bytes[pos + 8] |= 1; // general-purpose bit 0 = encrypted
            let name_len =
                u16::from_le_bytes(bytes[pos + 28..pos + 30].try_into().unwrap()) as usize;
            let extra_len =
                u16::from_le_bytes(bytes[pos + 30..pos + 32].try_into().unwrap()) as usize;
            let comment_len =
                u16::from_le_bytes(bytes[pos + 32..pos + 34].try_into().unwrap()) as usize;
            pos += 46 + name_len + extra_len + comment_len;
        }
    }
}

#[cfg(test)]
mod entry_metadata_tests {
    use super::*;

    fn zip_with(name: &str, when: zip::DateTime, mode: u32) -> Vec<u8> {
        let mut buf = std::io::Cursor::new(Vec::new());
        {
            let mut writer = zip::ZipWriter::new(&mut buf);
            let options = zip::write::SimpleFileOptions::default()
                .last_modified_time(when)
                .unix_permissions(mode);
            writer.start_file(name, options).unwrap();
            use std::io::Write;
            writer.write_all(b"data").unwrap();
            writer.finish().unwrap();
        }
        buf.into_inner()
    }

    /// HUNT-094, the ZIP half. A nested APK, a Takeout export and half the
    /// mobile extractions in the world are ZIPs, and their entries carried no
    /// time at all.
    #[test]
    fn the_entry_time_and_mode_reach_the_file_entry() {
        let when = zip::DateTime::from_date_and_time(2022, 2, 12, 16, 43, 14).unwrap();
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(zip_with(
                    "DCIM/Camera/MVIMG_20220212_164314.jpg",
                    when,
                    0o644,
                )),
            )),
            serde_json::json!({"name": "takeout.zip"}),
        );
        let out = ZipContainerModule.process(&artifact).expect("zip parsed");
        let file = out
            .iter()
            .find(|a| a.metadata["name"] == "MVIMG_20220212_164314.jpg")
            .expect("the entry is produced");

        // Rendered with an offset because RFC 3339 demands one — and qualified,
        // because ZIP stores local wall clock and the archive does not say
        // which zone. Presenting it as UTC would move every file in the archive
        // by the examiner's own offset.
        assert_eq!(file.metadata["modified"], "2022-02-12T16:43:14+00:00");
        assert_eq!(file.metadata["timezone"], "local");
        assert_eq!(file.metadata["mode"], "644");
    }

    /// The DOS epoch is this format's zero, the way 0 is tar's: it is what a
    /// writer stores when it has no time to store. Dating every unstamped entry
    /// to 1980-01-01 would put a wall of events on the timeline that nothing in
    /// the evidence supports.
    #[test]
    fn a_date_dos_cannot_express_is_absent_not_1980() {
        assert!(dos_datetime_rfc3339(&zip::DateTime::default()).is_none());
        // One second later IS a recorded time, and is kept.
        let real = zip::DateTime::from_date_and_time(1980, 1, 1, 0, 0, 2).unwrap();
        assert_eq!(
            dos_datetime_rfc3339(&real).as_deref(),
            Some("1980-01-01T00:00:02+00:00")
        );
    }
}

#[cfg(test)]
mod sibling_tests {
    use super::*;

    /// HUNT-101. A SQLite database inside an archive keeps its `-wal` in the
    /// same archive, and the newest rows live there: on the Magnet 2022 iOS
    /// image the location cache's main file stops on 2022-02-12, and the
    /// phone's last recorded position — two days later — is in the WAL.
    ///
    /// A zip entry could already open its neighbour. What it could not do was
    /// say so: `open_sibling` returning `None` meant both "there is no `-wal`"
    /// (the database is checkpointed and whole) and "this source cannot look"
    /// (the newest rows are missing and nothing says so).
    /// An iOS backup inside a ZIP keeps its stored blobs in two-hex shard
    /// folders beside `Manifest.db`. A neighbour that is not a suffix of the
    /// entry's own name is reached by path relative to the entry's directory
    /// (HUNT-109); a path that climbs is refused, whatever the archive holds.
    #[test]
    fn a_zip_entry_can_open_a_neighbour_by_relative_path_but_not_climb() {
        let bytes = {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut writer = zip::ZipWriter::new(&mut buf);
                let options = zip::write::SimpleFileOptions::default();
                use std::io::Write;
                writer
                    .start_file("Backup/518e8d76/Manifest.db", options)
                    .unwrap();
                writer.write_all(b"manifest").unwrap();
                writer
                    .start_file(
                        "Backup/518e8d76/3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28",
                        options,
                    )
                    .unwrap();
                writer.write_all(b"sms database").unwrap();
                writer.start_file("Backup/secret.txt", options).unwrap();
                writer.write_all(b"above the backup").unwrap();
                writer.finish().unwrap();
            }
            buf.into_inner()
        };

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(bytes),
            )),
            serde_json::json!({"name": "mac.zip"}),
        );
        let out = ZipContainerModule.process(&artifact).expect("zip parsed");
        let manifest = out
            .iter()
            .find(|a| a.metadata["name"] == "Manifest.db")
            .expect("the manifest entry is produced");
        let source = manifest.data.as_ref().expect("the entry carries its bytes");

        let blob = source
            .open_relative("3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28")
            .expect("the stored blob in its shard folder beside the manifest");
        let mut buf = vec![0u8; blob.size() as usize];
        blob.read_at(0, &mut buf).unwrap();
        assert_eq!(buf, b"sms database");

        assert!(source.open_relative("3d/missing").is_none());
        assert!(
            source.open_relative("../secret.txt").is_none(),
            "a relative open must not climb out of the entry's directory"
        );
        assert!(source.open_relative("/Backup/secret.txt").is_none());
    }

    #[test]
    fn a_zip_entry_can_open_its_wal_sibling_and_says_it_can_look() {
        let bytes = {
            let mut buf = std::io::Cursor::new(Vec::new());
            {
                let mut writer = zip::ZipWriter::new(&mut buf);
                let options = zip::write::SimpleFileOptions::default();
                use std::io::Write;
                writer
                    .start_file("/private/var/Cache.sqlite", options)
                    .unwrap();
                writer.write_all(b"main database").unwrap();
                writer
                    .start_file("/private/var/Cache.sqlite-wal", options)
                    .unwrap();
                writer.write_all(b"write ahead log").unwrap();
                writer.finish().unwrap();
            }
            buf.into_inner()
        };

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(bytes),
            )),
            serde_json::json!({"name": "extraction.zip"}),
        );
        let out = ZipContainerModule.process(&artifact).expect("zip parsed");
        let db = out
            .iter()
            .find(|a| a.metadata["name"] == "Cache.sqlite")
            .expect("the database entry is produced");
        let source = db.data.as_ref().expect("the entry carries its bytes");

        assert!(
            source.supports_siblings(),
            "a zip entry knows what else is in its own archive"
        );
        let wal = source
            .open_sibling("-wal")
            .expect("the -wal beside it in the archive");
        let mut buf = vec![0u8; wal.size() as usize];
        wal.read_at(0, &mut buf).unwrap();
        assert_eq!(&buf, b"write ahead log");

        // A sibling that is not there is absent, not an error: a checkpointed
        // database with no WAL is the ordinary case.
        assert!(source.open_sibling("-journal").is_none());
    }
}
