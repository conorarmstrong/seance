//! An iOS backup that lives **inside** an image, not on the examiner's disk.
//!
//! The backup parser next door walks a directory on the host filesystem: it
//! calls `path.is_dir()`, opens `Manifest.plist` by path and reads `Manifest.db`
//! with SQLite. A backup found inside a disk image has no such path — its files
//! are artifacts in the case — so the commonest way a phone's contents reach a
//! laptop, `~/Library/Application Support/MobileSync/Backup/<40 hex>/`, produced
//! no record of any kind: not the device, not the date, not even the fact that a
//! phone had been backed up to this machine (found grading the Magnet 2021 macOS
//! image, which asks for the IMEI of the phone backed up to the Mac).
//!
//! This reader answers two questions from the bytes the case already holds.
//! From `Manifest.plist` or `Info.plist`: **whose phone was backed up here, and
//! when**. From `Manifest.db` (HUNT-109): **which stored file is which** — each
//! `Files` row names a hashed blob beside the manifest and the domain and path
//! it had on the device, and when the evidence source can open its neighbours
//! (a host directory, a ZIP entry) every such blob is re-emitted as a
//! `FileEntry` under its device path, so `sms.db` is findable as `sms.db` and
//! the parsers that key on that name run over it. When the source cannot look
//! — a file inside a disk-image filesystem — the record says so, and when a
//! row's stored blob is ciphertext (an encrypted backup) it is described and
//! not attached; the keybag and a password are the second piece.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

use crate::manifest_db::ManifestDb;
use crate::manifest_plist::ManifestPlist;
use crate::IosBackupParser;

/// Ceiling on a backup manifest. A real `Info.plist` with app icons in it runs
/// to a few megabytes; this bounds a hostile one without capping a genuine one.
const MAX_MANIFEST_BYTES: usize = 64 * 1024 * 1024;

/// Ceiling on a `Manifest.db`. A backup of a full 256 GB phone carries a
/// manifest in the low hundreds of megabytes; this bounds a hostile one.
const MAX_MANIFEST_DB_BYTES: u64 = 1024 * 1024 * 1024;

/// Which of the backup manifests this file is, by name.
fn manifest_kind(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "manifest.plist" => Some("Manifest.plist"),
        "info.plist" => Some("Info.plist"),
        "manifest.db" => Some("Manifest.db"),
        _ => None,
    }
}

/// Where a backup stores the blob for `file_id`, relative to the manifest:
/// iOS 10+ shards by the first two hex digits (`54/54e5…`); older backups are
/// flat (`54e5…`). Both are tried, in that order.
fn stored_blob_candidates(file_id: &str) -> Vec<String> {
    if file_id.is_empty() || !file_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(2);
    if file_id.len() >= 2 {
        out.push(format!("{}/{}", &file_id[..2], file_id));
    }
    out.push(file_id.to_string());
    out
}

/// Does this path sit in a backup directory?
///
/// iTunes and Finder name the backup folder after the device's UDID: 40 hex
/// characters, or the newer `00008030-001259123E50802E` form. `Info.plist` is
/// one of the commonest file names on a Mac — every application bundle has
/// one — so the folder is what makes this file a backup manifest, and a file
/// that only *looks* like one is checked against its content as well.
pub fn in_backup_directory(path: &str) -> bool {
    let normalised = path.replace('\\', "/");
    let mut parts = normalised.rsplit('/');
    let _file = parts.next();
    let Some(folder) = parts.next() else {
        return false;
    };
    let hex40 = folder.len() == 40 && folder.chars().all(|c| c.is_ascii_hexdigit());
    let udid = folder.len() == 25
        && folder.as_bytes().get(8) == Some(&b'-')
        && folder.chars().enumerate().all(|(i, c)| {
            if i == 8 {
                c == '-'
            } else {
                c.is_ascii_hexdigit()
            }
        });
    hex40 || udid
}

/// Reads the manifest of an iOS backup that is inside the evidence.
#[derive(Debug, Default)]
pub struct IosBackupManifestParser;

impl IosBackupManifestParser {
    pub fn new() -> Self {
        Self
    }
}

impl ForensicsModule for IosBackupManifestParser {
    fn id(&self) -> &str {
        "plugin.mobile.ios_backup_manifest"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let Some(kind) = manifest_kind(name) else {
            return Ok(Vec::new());
        };
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(name);
        if !in_backup_directory(path) {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        if kind == "Manifest.db" {
            return Self::reparent_from_manifest_db(artifact, path, data.as_ref());
        }

        let size = data.size() as usize;
        let want = size.min(MAX_MANIFEST_BYTES);
        let mut buf = vec![0u8; want];
        let read = data
            .read_at(0, &mut buf)
            .map_err(|e| ModuleError::ParsingError(format!("reading {path}: {e}")))?;
        buf.truncate(read);

        let manifest = match ManifestPlist::from_bytes(&buf) {
            Ok(manifest) => manifest,
            Err(e) => {
                debug!("{path} is in a backup folder and did not parse: {e}");
                return Ok(Vec::new());
            }
        };
        // A backup manifest names the device. A property list in a backup folder
        // that names no device and carries no keybag is some other file that
        // happens to live there, and claiming it would put an empty device on
        // the summary.
        if manifest.display_name.is_none()
            && manifest.product_type.is_none()
            && manifest.serial_number.is_none()
            && manifest.unique_identifier.is_none()
            && manifest.imei.is_none()
        {
            return Ok(Vec::new());
        }

        let backup_path = path
            .rsplit_once('/')
            .map(|(folder, _)| folder.to_string())
            .unwrap_or_else(|| path.to_string());

        let mut metadata = json!({
            "type": "IosBackupInfo",
            "subtype": "manifest_in_evidence",
            "name": format!(
                "iOS backup of {}",
                manifest.display_name.as_deref().unwrap_or("an unnamed device")
            ),
            "source_file": path,
            "source_kind": kind,
            "backup_path": backup_path,
            "device_name": manifest.display_name,
            "product_type": manifest.product_type,
            "product_version": manifest.product_version,
            "build_version": manifest.build_version,
            "serial_number": manifest.serial_number,
            "unique_identifier": manifest.unique_identifier,
            "imei": manifest.imei,
            "encrypted": manifest.is_encrypted,
            "backup_version": manifest.version,
            // Read from the manifest this machine holds, not walked: the backup's
            // own files are in the case under the hashed names the backup gives
            // them, and nothing here has put them back at their device paths.
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "inventory_incomplete_detail":
                "this record names the device and nothing else: it was read from the backup's \
                 property list, which carries no file inventory. The inventory is the \
                 manifest_db_in_evidence record for the same backup_path, produced from the \
                 Manifest.db beside this file when the case holds it and the source can be \
                 read",
        });
        if let Some(date) = manifest.date {
            let stamp: std::time::SystemTime = date.into();
            let stamp: chrono::DateTime<chrono::Utc> = stamp.into();
            metadata["date"] = json!(stamp.to_rfc3339());
        }

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            metadata,
        )
        .with_parent(artifact.id)])
    }
}

impl IosBackupManifestParser {
    /// `Manifest.db` found inside the evidence: put the stored blobs back at
    /// their device paths (HUNT-109).
    ///
    /// Every `Files` row is re-emitted as a `FileEntry` named by its device
    /// path, with its data being the hashed blob beside the manifest, opened
    /// through [`DataSource::open_relative`]. The summary record counts what was
    /// re-parented, what the manifest lists that the source did not hold, and
    /// what could not be attached because it is ciphertext — and when the
    /// source cannot look for neighbours at all it says that instead of
    /// reporting every file missing.
    fn reparent_from_manifest_db(
        artifact: &Artifact,
        path: &str,
        data: &dyn DataSource,
    ) -> Result<Vec<Artifact>, ModuleError> {
        let backup_path = path
            .rsplit_once('/')
            .map(|(folder, _)| folder.to_string())
            .unwrap_or_else(|| path.to_string());
        let mut summary = json!({
            "type": "IosBackupInfo",
            "subtype": "manifest_db_in_evidence",
            "name": "iOS backup file inventory (from Manifest.db in the evidence)",
            "source_file": path,
            "source_kind": "Manifest.db",
            "backup_path": backup_path,
        });

        if data.size() > MAX_MANIFEST_DB_BYTES {
            summary["inventory_incomplete"] = json!(true);
            summary["inventory_incomplete_reason"] = json!(IncompleteReason::CapReached.as_str());
            summary["inventory_incomplete_detail"] = json!(format!(
                "this Manifest.db is {} bytes, past the {} byte ceiling this reader accepts; \
                 no file from this backup has been put back at its device path",
                data.size(),
                MAX_MANIFEST_DB_BYTES
            ));
            return Ok(vec![Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                summary,
            )
            .with_parent(artifact.id)]);
        }

        let mut bytes = vec![0u8; data.size() as usize];
        let read = data
            .read_at(0, &mut bytes)
            .map_err(|e| ModuleError::ParsingError(format!("reading {path}: {e}")))?;
        bytes.truncate(read);
        let records = match ManifestDb::parse_from_bytes(&bytes) {
            Ok(records) => records,
            Err(e) => {
                // A `Manifest.db` that is not a backup manifest — the name is not
                // unique to iTunes — produces nothing rather than an empty backup.
                debug!("{path} is in a backup folder and did not parse as a manifest: {e}");
                return Ok(Vec::new());
            }
        };

        let can_look = data.supports_siblings();
        let mut out = Vec::with_capacity(records.len() + 1);
        let (mut reparented, mut missing, mut ciphertext, mut directories, mut symlinks) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        let mut undecodable_metadata = 0u64;

        for record in &records {
            let mut metadata = json!({
                "type": "IosBackupFile",
                "subtype": "reparented_from_evidence",
                "name": IosBackupParser::file_basename(&record.relative_path),
                "path": format!("{}/{}/{}", backup_path, record.domain, record.relative_path),
                "file_id": record.file_id,
                "domain": record.domain,
                "relative_path": record.relative_path,
                "flags": record.flags,
                "is_directory": record.is_directory(),
                "size": record.size,
                "mode": record.mode,
                "last_modified": record.last_modified,
                "birth": record.birth,
                "modified": record.last_modified,
                "created": record.birth,
                "inode": record.inode_number,
                "user_id": record.user_id,
                "group_id": record.group_id,
                "protection_class": record.protection_class,
                "backup_path": backup_path,
            });
            if let Some(err) = &record.metadata_error {
                undecodable_metadata += 1;
                IosBackupParser::mark_metadata_undecodable(&mut metadata, err);
            }

            let (artifact_type, source) = if record.is_directory() {
                directories += 1;
                (ArtifactType::ParsedRecord, None)
            } else if record.is_symlink() {
                symlinks += 1;
                metadata["is_symlink"] = json!(true);
                metadata["content_omitted"] = json!("symlink_has_no_stored_content");
                (ArtifactType::FileEntry, None)
            } else if record
                .encryption_key
                .as_ref()
                .is_some_and(|k| !k.is_empty())
            {
                // The stored blob is wrapped ciphertext. Nothing here holds the
                // keybag or a password, so it is described and not attached.
                ciphertext += 1;
                IosBackupParser::mark_content_encrypted(&mut metadata);
                metadata["message"] = json!(
                    "The manifest gives this file a per-file encryption key, so its stored copy \
                     beside the manifest is ciphertext. Reading it needs this backup's keybag \
                     and its password, neither of which this reader has; the bytes are not \
                     attached because they are not this file's content"
                );
                (ArtifactType::FileEntry, None)
            } else if !can_look {
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] =
                    json!(IncompleteReason::UnresolvedStructure.as_str());
                metadata["content_omitted"] = json!("source_cannot_open_neighbours");
                metadata["message"] = json!(
                    "The manifest lists this file and names its stored blob, but the evidence \
                     source this manifest was read from cannot open files beside it, so the \
                     blob was not attached. It is in the case under its hashed name"
                );
                (ArtifactType::FileEntry, None)
            } else {
                let mut opened: Option<(String, std::sync::Arc<dyn DataSource>)> = None;
                for candidate in stored_blob_candidates(&record.file_id) {
                    if let Some(src) = data.open_relative(&candidate) {
                        opened = Some((candidate, src));
                        break;
                    }
                }
                match opened {
                    Some((stored, src)) => {
                        reparented += 1;
                        metadata["stored_path"] = json!(format!("{backup_path}/{stored}"));
                        (ArtifactType::FileEntry, Some(src))
                    }
                    None => {
                        missing += 1;
                        IosBackupParser::mark_content_absent(
                            &mut metadata,
                            "no stored blob for this fileID beside the manifest",
                        );
                        (ArtifactType::FileEntry, None)
                    }
                }
            };
            out.push(
                Artifact::new(artifact.case_id, artifact_type, source, metadata)
                    .with_parent(artifact.id),
            );
        }

        summary["manifest_entries"] = json!(records.len());
        summary["files_reparented"] = json!(reparented);
        summary["files_missing_from_evidence"] = json!(missing);
        summary["files_ciphertext"] = json!(ciphertext);
        summary["directories"] = json!(directories);
        summary["symlinks"] = json!(symlinks);
        summary["entries_with_undecodable_metadata"] = json!(undecodable_metadata);
        summary["encrypted"] = json!(ciphertext > 0);
        let stated_files = records.len() as u64 - directories - symlinks;
        if !can_look && stated_files > ciphertext {
            summary["inventory_incomplete"] = json!(true);
            summary["inventory_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
            summary["inventory_incomplete_detail"] = json!(format!(
                "this Manifest.db names {} stored files, but the evidence source it was read \
                 from cannot open files beside it, so none was put back at its device path; \
                 they are in the case under their hashed names, and each entry here names its \
                 fileID",
                stated_files
            ));
        } else if missing > 0 {
            summary["inventory_incomplete"] = json!(true);
            summary["inventory_incomplete_reason"] =
                json!(IncompleteReason::UnresolvedStructure.as_str());
            summary["inventory_incomplete_detail"] = json!(format!(
                "{} of the {} files this Manifest.db lists have no stored blob beside it in \
                 the evidence; their content is absent from this case, which is not evidence \
                 they were empty",
                missing, stated_files
            ));
        } else if ciphertext > 0 {
            summary["content_incomplete"] = json!(true);
            summary["content_incomplete_reason"] = json!(IncompleteReason::Encrypted.as_str());
            summary["content_incomplete_detail"] = json!(format!(
                "{} of the {} files this backup lists are stored as ciphertext; each is placed \
                 at its device path here with its size and dates, and none has content until \
                 the backup's keybag and password are supplied",
                ciphertext, stated_files
            ));
        }

        out.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, summary)
                .with_parent(artifact.id),
        );
        Ok(out)
    }
}

#[cfg(test)]
#[path = "tests_resident.rs"]
mod tests;
