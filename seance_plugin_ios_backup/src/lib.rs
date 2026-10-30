#![forbid(unsafe_code)]
//! iOS Backup Parser Module
//!
//! Parses iOS backup directories created by iTunes/Finder, extracting file metadata
//! from Manifest.db (SQLite) or legacy Manifest.mbdb (binary format).
//!
//! Supports both encrypted and unencrypted backups, with PBKDF2/AES key unwrapping
//! for encrypted backups when a password is provided.
//!
//! ## iOS Backup Format
//!
//! An iOS backup directory contains:
//! - `Manifest.plist` - Backup metadata (encrypted flag, date, device info)
//! - `Manifest.db` - SQLite database with file metadata (iOS 10+)
//! - `Manifest.mbdb` - Binary file metadata (iOS 3-9, legacy)
//! - `Info.plist` - Device and backup information
//! - Hashed files (SHA-1 of domain + relative path)
//!
//! ## Manifest.db Schema
//!
//! ```sql
//! CREATE TABLE Files (
//!     fileID TEXT PRIMARY KEY,      -- SHA-1 hash
//!     domain TEXT,                   -- e.g., "HomeDomain", "AppDomain-com.app.id"
//!     relativePath TEXT,             -- Path within domain
//!     flags INTEGER,                 -- 0x2 = directory
//!     file BLOB                      -- Binary plist with file metadata
//! );
//! ```
//!
//! ## File Metadata (BLOB format)
//!
//! The `file` BLOB column contains a binary plist with:
//! - LastModified (Date)
//! - LastStatusChange (Date)
//! - Birth (Date) - File creation time
//! - Size (Integer)
//! - InodeNumber (Integer)
//! - UserID (Integer)
//! - GroupID (Integer)
//! - Mode (Integer) - Unix permissions
//! - ProtectionClass (Integer) - iOS data protection class
//! - ExtendedAttributes (optional Dict)
//! - Digest (optional Data) - SHA-1 of file content
//!
//! ## Encryption
//!
//! Encrypted backups use:
//! 1. **Keybag** in Manifest.plist - Encrypted class keys
//! 2. **PBKDF2** - Derives unwrapping key from password
//! 3. **AES-CBC** - Per-file encryption with class keys
//!
//! References:
//! - <https://github.com/horrorho/InflatableDonkey>
//! - <https://github.com/jsharkey/iPhone-dataprotection>
//! - <https://www.theiphonewiki.com/wiki/ITunes_Backup>

use anyhow::{anyhow, Result};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    credential::{self, CredentialKind, RunCredential},
    data_source::{ByteSliceDataSource, FileDataSource},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info, warn};

mod crypto;
mod der;
mod gcm;
mod keychain_backup;
mod manifest_db;
mod manifest_mbdb;
mod manifest_plist;
pub mod reread;
pub mod resident;

pub use crypto::ClassKeyState;
pub use reread::{
    open_backup_file_plaintext, unlock_backup, KeychainSecret, UnlockError, UnlockedBackup,
};
pub use resident::IosBackupManifestParser;

use manifest_db::ManifestDb;
use manifest_mbdb::ManifestMbdb;
use manifest_plist::ManifestPlist;

/// Why one encrypted backup file could not be opened: the label and
/// incompleteness reason its "not decrypted" record carries, and the message.
#[derive(Debug)]
pub(crate) struct FileOpenFailure {
    pub(crate) label: &'static str,
    pub(crate) reason: IncompleteReason,
    pub(crate) message: String,
}

pub struct IosBackupParser {
    /// Optional password for encrypted backups
    password: Option<String>,
}

/// Epoch seconds as RFC 3339, for the timestamp keys the rest of the app reads.
fn epoch_to_rfc3339(secs: i64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0).map(|d| d.to_rfc3339())
}

/// The backup password did not unwrap the keybag's class keys (RFC 3394
/// integrity failure): the one failure reported as a verdict on the password.
/// It cannot rule out a corrupt wrapped key, and the rejection says so.
#[derive(Debug)]
struct WrongPassword(String);

impl std::fmt::Display for WrongPassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for WrongPassword {}

impl IosBackupParser {
    pub fn new() -> Self {
        Self { password: None }
    }

    /// The password to try for this artifact: the one an examiner supplied
    /// for this run through the credential route (`POST …/credential`, kind
    /// `ios_backup_password`) if there is one, else the process-level secret
    /// this parser was built with. The per-run credential wins, because it is
    /// the more specific answer and the one the examiner just typed.
    ///
    /// **SEC-204.** The password used to arrive as artifact metadata, merged in
    /// by `run_module`'s `secrets` map: a plain `String`, copied into the
    /// artifact, never zeroed and never audited for its outcome. That channel is
    /// retired; a password found in metadata is ignored.
    fn run_credential(artifact: &Artifact) -> Option<Arc<RunCredential>> {
        credential::for_artifact(artifact.id, &[CredentialKind::IosBackupPassword])
            .filter(|c| !c.expose_secret().is_empty())
    }

    pub fn with_password(password: String) -> Self {
        Self {
            password: Some(password),
        }
    }

    /// Detect if this is an iOS backup directory
    fn is_ios_backup(&self, path: &Path) -> bool {
        // Check for Manifest.plist (required)
        let manifest_plist = path.join("Manifest.plist");
        if !manifest_plist.exists() {
            return false;
        }

        // Check for either Manifest.db or Manifest.mbdb
        let manifest_db = path.join("Manifest.db");
        let manifest_mbdb = path.join("Manifest.mbdb");

        manifest_db.exists() || manifest_mbdb.exists()
    }

    /// Parse iOS backup directory and emit FileEntry artifacts
    fn parse_backup(
        &self,
        backup_path: &Path,
        password: Option<&str>,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
    ) -> Result<Vec<Artifact>> {
        let mut artifacts = Vec::new();

        // Read Manifest.plist for metadata
        let manifest_plist_path = backup_path.join("Manifest.plist");
        let manifest_plist = ManifestPlist::from_file(&manifest_plist_path)?;

        info!("iOS Backup detected:");
        info!(
            "  Device: {} ({})",
            manifest_plist.display_name.as_deref().unwrap_or("Unknown"),
            manifest_plist.product_type.as_deref().unwrap_or("Unknown")
        );
        info!("  Date: {:?}", manifest_plist.date);
        info!("  Encrypted: {}", manifest_plist.is_encrypted);
        info!("  Version: {}", manifest_plist.version);

        // Check if backup is encrypted
        if manifest_plist.is_encrypted {
            if password.is_none() {
                warn!("Backup is encrypted but no password provided");

                // Nothing from this backup reaches the case. Without the standard
                // incompleteness pair the completeness census and the court
                // report's "not recovered" section never see it, and a device
                // whose whole backup is present-but-unreadable is reported as a
                // device with no backup data (B6-018).
                let metadata = json!({
                    "type": "IosBackupInfo",
                    "subtype": "ios_backup_incomplete",
                    "status": "encrypted_no_password",
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
                    "inventory_incomplete": true,
                    "inventory_incomplete_reason": IncompleteReason::Encrypted.as_str(),
                    "message": "iOS backup is encrypted and no password was provided: no files \
                                from it are in this case. Provide the password to decrypt and \
                                extract them.",
                    "name": "iOS backup (encrypted, not extracted)",
                    "device_name": manifest_plist.display_name,
                    "product_type": manifest_plist.product_type,
                    // Whose phone this is does not need the password: the
                    // device names itself in the clear in the same manifest.
                    "product_version": manifest_plist.product_version,
                    "build_version": manifest_plist.build_version,
                    "serial_number": manifest_plist.serial_number,
                    "unique_identifier": manifest_plist.unique_identifier,
                    "version": manifest_plist.version,
                    "date": manifest_plist.date.map(|d| format!("{:?}", d)),
                    "is_encrypted": true,
                });

                artifacts.push(
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id),
                );

                return Ok(artifacts);
            }

            let password = password.expect("checked just above");
            return self.parse_encrypted_backup(
                backup_path,
                password,
                &manifest_plist,
                case_id,
                parent_id,
            );
        }

        // Unencrypted backup path
        self.parse_manifest_files(backup_path, None, case_id, parent_id)
    }

    /// Parse an encrypted iOS backup: derive keys, decrypt manifest, decrypt files.
    fn parse_encrypted_backup(
        &self,
        backup_path: &Path,
        password: &str,
        manifest_plist: &ManifestPlist,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
    ) -> Result<Vec<Artifact>> {
        // 1-3. Keybag, passcode key, class keys: the one unlock path, shared
        // with re-reading after ingest (`reread::unlock_backup`, BUG-026).
        let (keybag, unwrapped) = Self::unlock_keybag(manifest_plist, password)?;
        // SEC-204: when the password came from a credential supplied for this
        // run, say it opened the backup — but only if a passcode-wrapped class
        // key actually tested it. A keybag with none never tried the password,
        // so no verdict is reported (`not_used`). `parent_id` is the artifact
        // the run targets, so this finds only that run's credential.
        if unwrapped > 0 {
            if let Some(cred) =
                credential::for_artifact(parent_id, &[CredentialKind::IosBackupPassword])
            {
                cred.accepted();
            }
        }

        // 4-5. Decrypt and parse Manifest.db.
        let records = Self::decrypt_manifest_records(backup_path, manifest_plist, &keybag)?;

        // 6. Process each file: decrypt and create artifacts
        let mut artifacts = Vec::new();
        let mut decrypt_errors = 0u64;

        for record in &records {
            if record.is_directory() {
                let mut metadata = json!({
                    "type": "IosBackupFile",
                    "name": Self::file_basename(&record.relative_path),
                    "file_id": record.file_id,
                    "domain": record.domain,
                    "relative_path": record.relative_path,
                    "flags": record.flags,
                    "is_directory": true,
                    "size": record.size,
                    "mode": record.mode,
                    "last_modified": record.last_modified,
                    "birth": record.birth,
                    // Also under the conventional keys the rest of the app
                    // reads (the file grid's generated columns, sorting and the
                    // timeline all look for `modified`/`created`).
                    "modified": record.last_modified,
                    "created": record.birth,
                    "inode": record.inode_number,
                    "user_id": record.user_id,
                    "group_id": record.group_id,
                    "protection_class": record.protection_class,
                    "backup_path": backup_path.to_string_lossy().to_string(),
                    "encrypted": true,
                });
                if let Some(err) = &record.metadata_error {
                    Self::mark_metadata_undecodable(&mut metadata, err);
                }

                artifacts.push(
                    Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
                        .with_parent(parent_id),
                );
                continue;
            }

            // Locate the backup file on disk (stored by SHA-1 hash prefix). An
            // ID that is not a bare name is refused here, before anything is
            // opened, and the entry says so.
            let file_path = match Self::resolve_backup_file_path(backup_path, &record.file_id) {
                Ok(p) => p,
                Err(detail) => {
                    warn!(
                        "Refusing manifest entry {}/{}: {}",
                        record.domain, record.relative_path, detail
                    );
                    decrypt_errors += 1;
                    artifacts.push(Self::undecrypted_file_record(
                        backup_path,
                        record,
                        case_id,
                        parent_id,
                        "InvalidFileId",
                        IncompleteReason::UnresolvedStructure,
                        &format!("This entry was not read: {detail}"),
                    ));
                    continue;
                }
            };

            // Everything from here down is ciphertext: this backup declared
            // itself encrypted, so nothing in it is stored in the clear. Each
            // ingredient of the decryption is therefore resolved BEFORE any
            // bytes are attached, and a missing ingredient ends the entry at
            // `undecrypted_file_record` — never at "attach the stored bytes and
            // stamp them decrypted" (B8-026).
            let Some(enc_key) = record.encryption_key.as_ref().filter(|k| !k.is_empty()) else {
                // A symlink's content *is* the target path the manifest carries:
                // the backup stores no file for it and the manifest gives it no
                // per-file key. That is the ordinary, complete case, not a
                // decryption failure — counting it would put "partially
                // decrypted: N file(s) not recovered" on every encrypted backup,
                // and a warning that fires on every case is one an examiner
                // learns to skip. `parse_manifest_files` already says this for
                // unencrypted backups; the two paths must agree.
                if record.is_symlink() {
                    let mut metadata = json!({
                        "type": "IosBackupFile",
                        "name": Self::file_basename(&record.relative_path),
                        "file_id": record.file_id,
                        "domain": record.domain,
                        "relative_path": record.relative_path,
                        "flags": record.flags,
                        "is_directory": false,
                        "is_symlink": true,
                        "content_omitted": "symlink_has_no_stored_content",
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
                        "backup_path": backup_path.to_string_lossy().to_string(),
                        "encrypted": true,
                    });
                    if let Some(err) = &record.metadata_error {
                        Self::mark_metadata_undecodable(&mut metadata, err);
                    }
                    artifacts.push(
                        Artifact::new(case_id, ArtifactType::FileEntry, None, metadata)
                            .with_parent(parent_id),
                    );
                    continue;
                }

                let detail = record.encryption_key_error.clone().unwrap_or_else(|| {
                    "the manifest entry carries no per-file EncryptionKey".to_string()
                });
                debug!(
                    "No usable per-file key for {}/{}: {}",
                    record.domain, record.relative_path, detail
                );
                decrypt_errors += 1;
                artifacts.push(Self::undecrypted_file_record(
                    backup_path,
                    record,
                    case_id,
                    parent_id,
                    "NoFileKey",
                    IncompleteReason::Encrypted,
                    &format!(
                        "This file could not be decrypted: {detail}. Its stored bytes are \
                         ciphertext and are not attached"
                    ),
                ));
                continue;
            };

            // Which class key unwraps this file's key. The manifest states the
            // protection class twice — the metadata blob's `ProtectionClass`
            // field, and the 4-byte prefix on the wrapped key — so the second
            // answers when the first is absent. A class neither carrier gives is
            // UNKNOWN. It is never 0 ("no protection"), which is what used to
            // send ciphertext through as recovered content.
            let Some((protection_class, class_source)) = Self::record_protection_class(record)
            else {
                debug!(
                    "No protection class for {}/{}",
                    record.domain, record.relative_path
                );
                decrypt_errors += 1;
                artifacts.push(Self::undecrypted_file_record(
                    backup_path,
                    record,
                    case_id,
                    parent_id,
                    "UnknownProtectionClass",
                    IncompleteReason::Encrypted,
                    "This file could not be decrypted: the manifest gives no protection class \
                     for it, neither in its metadata nor on its wrapped key, so no class key \
                     could be chosen. Its stored bytes are ciphertext and are not attached",
                ));
                continue;
            };

            // The one per-file open, shared with the re-read path
            // (`reread::UnlockedBackup::open_file`), so a fix here reaches both.
            let data_source =
                match Self::open_encrypted_file(&file_path, enc_key, protection_class, &keybag) {
                    Ok(ds) => ds,
                    Err(failure) => {
                        debug!(
                            "Could not open {}/{} ({}): {}",
                            record.domain, record.relative_path, failure.label, failure.message
                        );
                        decrypt_errors += 1;
                        artifacts.push(Self::undecrypted_file_record(
                            backup_path,
                            record,
                            case_id,
                            parent_id,
                            failure.label,
                            failure.reason,
                            &failure.message,
                        ));
                        continue;
                    }
                };

            let mut metadata = json!({
                "type": "IosBackupFile",
                "name": Self::file_basename(&record.relative_path),
                "file_id": record.file_id,
                "domain": record.domain,
                "relative_path": record.relative_path,
                "flags": record.flags,
                "is_directory": false,
                "size": record.size,
                "mode": record.mode,
                "last_modified": record.last_modified,
                "birth": record.birth,
                // The conventional keys the file grid, sorting and the timeline
                // read.
                "modified": record.last_modified,
                "created": record.birth,
                "inode": record.inode_number,
                "user_id": record.user_id,
                "group_id": record.group_id,
                "protection_class": record.protection_class,
                // Which class actually chose the key, and which of the
                // manifest's two carriers stated it. `protection_class` above is
                // the metadata blob's own field and stays null when the blob
                // never gave one.
                "protection_class_used": protection_class,
                "protection_class_source": class_source,
                "backup_path": backup_path.to_string_lossy().to_string(),
                "encrypted": true,
                // Reached only after `decrypt_file` / `DecryptedFileDataSource`
                // returned plaintext for this file. Every other outcome above
                // leaves via `undecrypted_file_record`.
                "decrypted": true,
            });
            // B6-036 on the encrypted path: the manifest blob is the same blob,
            // and an entry whose size/times would not decode must not present
            // them as absent here either.
            if let Some(err) = &record.metadata_error {
                Self::mark_metadata_undecodable(&mut metadata, err);
            }

            // The device keychain (HUNT-111): read here, while the keybag
            // that opens its items is in scope, and parented to its file.
            let keychain_source =
                keychain_backup::is_keychain_backup(&record.domain, &record.relative_path)
                    .then(|| data_source.clone());
            let file_artifact = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                Some(data_source),
                metadata,
            )
            .with_parent(parent_id);
            let file_artifact_id = file_artifact.id;
            artifacts.push(file_artifact);
            if let Some(source) = keychain_source {
                artifacts.extend(Self::read_keychain_backup(
                    source.as_ref(),
                    &keybag,
                    backup_path,
                    &record.file_id,
                    case_id,
                    file_artifact_id,
                ));
            }
        }

        if decrypt_errors > 0 {
            warn!("{} files could not be decrypted or read", decrypt_errors);
            artifacts.push(Self::decrypt_gap_summary(
                backup_path,
                case_id,
                parent_id,
                records.len(),
                decrypt_errors,
            ));
        }

        // A backup that was ingested without a password left a record saying no
        // files from it are in this case. That was true when it was written and
        // is false the moment a password opens the backup, and nothing retracts
        // it. Say so here, in the case, rather than leaving the two statements
        // side by side for the examiner to reconcile (HUNT-090).
        artifacts.push(Self::decrypted_summary(
            backup_path,
            case_id,
            parent_id,
            records.len(),
            decrypt_errors,
            &crypto::class_key_states(&keybag),
        ));

        info!(
            "Produced {} artifacts from encrypted backup",
            artifacts.len()
        );
        Ok(artifacts)
    }

    /// Read the decrypted `KeychainDomain/keychain-backup.plist` into one
    /// `IosKeychainItem` record per item and an `IosKeychainSummary`
    /// (`keychain_backup`). A file that cannot be read as a keychain gives a
    /// summary that says so, never silence.
    fn read_keychain_backup(
        source: &dyn seance_core::data_source::DataSource,
        keybag: &crypto::Keybag,
        backup_path: &Path,
        file_id: &str,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
    ) -> Vec<Artifact> {
        let provenance = |mut meta: serde_json::Value| {
            if let Some(m) = meta.as_object_mut() {
                m.insert(
                    "backup_path".into(),
                    json!(backup_path.to_string_lossy().to_string()),
                );
                m.insert("source_file_id".into(), json!(file_id));
                m.insert(
                    "source_relative_path".into(),
                    json!(format!(
                        "{}/{}",
                        keychain_backup::KEYCHAIN_DOMAIN,
                        keychain_backup::KEYCHAIN_BACKUP_PATH
                    )),
                );
            }
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, meta).with_parent(parent_id)
        };
        let not_read = |reason: String| {
            warn!("keychain-backup.plist not read: {reason}");
            vec![provenance(json!({
                "type": "IosKeychainSummary",
                "name": "iOS keychain (from the encrypted backup, not read)",
                "state": "not_read",
                "content_incomplete": true,
                "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                "statement": format!(
                    "The backup's keychain file decrypted but was not read: {reason}. \
                     No keychain items from it are in this case."
                ),
            }))]
        };

        let bytes = match keychain_backup::read_whole(source) {
            Ok(b) => b,
            Err(reason) => return not_read(reason),
        };
        match keychain_backup::read(&bytes, keybag) {
            Ok(out) => {
                info!(
                    "Keychain: {} item(s) listed from keychain-backup.plist",
                    out.items.len()
                );
                out.items
                    .into_iter()
                    .chain(std::iter::once(out.summary))
                    .map(provenance)
                    .collect()
            }
            Err(e) => not_read(e.to_string()),
        }
    }

    /// Parse the keybag, derive the passcode key from `password` and unwrap
    /// the class keys. Returns the keybag holding the unwrapped keys and how
    /// many passcode-wrapped class keys the password actually tested.
    ///
    /// Only an RFC 3394 integrity failure is a verdict on the password (and
    /// even that cannot rule out a corrupt wrapped key); it comes back as a
    /// [`WrongPassword`]. A malformed keybag is an ordinary error.
    pub(crate) fn unlock_keybag(
        manifest_plist: &ManifestPlist,
        password: &str,
    ) -> Result<(crypto::Keybag, usize)> {
        let keybag_data = manifest_plist
            .keybag_data
            .as_ref()
            .ok_or_else(|| anyhow!("Encrypted backup missing BackupKeyBag in Manifest.plist"))?;
        let mut keybag = crypto::parse_keybag(keybag_data)?;

        info!(
            "Parsed keybag: {} class keys, uuid={}, iOS 10.2+ DPSL: {}",
            keybag.class_keys.len(),
            hex::encode(&keybag.uuid),
            keybag.dpsl.is_some()
        );

        info!("Deriving passcode key (this may take a moment for high iteration counts)...");
        let passcode_key = zeroize::Zeroizing::new(crypto::derive_passcode_key(password, &keybag)?);

        let unwrapped = crypto::unwrap_class_keys(&mut keybag, &passcode_key).map_err(|e| {
            if e.downcast_ref::<crypto::ClassKeyIntegrityFailed>()
                .is_some()
            {
                anyhow::Error::new(WrongPassword(e.to_string()))
            } else {
                e
            }
        })?;
        info!("Unwrapped {unwrapped} passcode-wrapped class key(s)");
        Ok((keybag, unwrapped))
    }

    /// Decrypt `Manifest.db` with the unlocked keybag and parse its records.
    pub(crate) fn decrypt_manifest_records(
        backup_path: &Path,
        manifest_plist: &ManifestPlist,
        keybag: &crypto::Keybag,
    ) -> Result<Vec<manifest_db::ManifestRecord>> {
        let manifest_key = manifest_plist
            .manifest_key
            .as_ref()
            .ok_or_else(|| anyhow!("Encrypted backup missing ManifestKey in Manifest.plist"))?;

        let manifest_db_path = backup_path.join("Manifest.db");
        let encrypted_db = std::fs::read(&manifest_db_path)?;
        let decrypted_db = crypto::decrypt_manifest_db(&encrypted_db, manifest_key, keybag)?;
        info!("Decrypted Manifest.db ({} bytes)", decrypted_db.len());

        let records = ManifestDb::parse_from_bytes(&decrypted_db)?;
        info!("Found {} files in decrypted Manifest.db", records.len());
        Ok(records)
    }

    /// Which protection class unwraps this record's key, and which of the
    /// manifest's two carriers stated it. `None` when neither did.
    ///
    /// The manifest states a file's class twice — the metadata blob's
    /// `ProtectionClass` field, and the 4-byte prefix on the wrapped key — so
    /// the second answers when the first is absent. A class neither carrier
    /// gives is unknown; it is never 0 ("no protection"), which is what used to
    /// send ciphertext through as recovered content (B8-026).
    /// Open one encrypted backup file to its plaintext: the per-file step of
    /// both the ingest run and the re-read path (`reread`). A file larger
    /// than [`crypto::STREAMING_THRESHOLD`] is decrypted as it is read
    /// ([`crypto::DecryptedFileDataSource`]); a smaller one is read and
    /// decrypted whole. The class key and the unwrapped per-file key used for
    /// a streaming open are zeroed when this returns; the AES key schedule
    /// inside the streaming source lives as long as the source.
    pub(crate) fn open_encrypted_file(
        file_path: &Path,
        wrapped_key: &[u8],
        protection_class: u32,
        keybag: &crypto::Keybag,
    ) -> std::result::Result<Arc<dyn seance_core::data_source::DataSource>, FileOpenFailure> {
        let fail =
            |label: &'static str, reason: IncompleteReason, message: String| FileOpenFailure {
                label,
                reason,
                message,
            };
        // An unreadable size falls through to the whole-file read, which then
        // reports the read failure.
        let file_size = std::fs::metadata(file_path).map(|m| m.len()).unwrap_or(0);
        if file_size > crypto::STREAMING_THRESHOLD {
            let class_key = zeroize::Zeroizing::new(
                crypto::get_class_key_for_streaming(keybag, protection_class).map_err(|e| {
                    fail(
                        "NoClassKey",
                        IncompleteReason::Encrypted,
                        format!("No protection-class key available for this file: {e}"),
                    )
                })?,
            );
            let file_key = zeroize::Zeroizing::new(
                crypto::unwrap_file_key_for_streaming(wrapped_key, &class_key).map_err(|e| {
                    fail(
                        "KeyUnwrapFailed",
                        IncompleteReason::Encrypted,
                        format!("Per-file key could not be unwrapped: {e}"),
                    )
                })?,
            );
            let ds = crypto::DecryptedFileDataSource::new(file_path.to_path_buf(), &file_key)
                .map_err(|e| {
                    fail(
                        "DecryptFailed",
                        IncompleteReason::Encrypted,
                        format!("Streaming decryption failed: {e}"),
                    )
                })?;
            Ok(Arc::new(ds))
        } else {
            let ciphertext = std::fs::read(file_path).map_err(|e| {
                fail(
                    "ReadFailed",
                    IncompleteReason::ShortRead,
                    format!("Backup file could not be read: {e}"),
                )
            })?;
            let plain = crypto::decrypt_file(&ciphertext, wrapped_key, protection_class, keybag)
                .map_err(|e| {
                    fail(
                        "DecryptFailed",
                        IncompleteReason::Encrypted,
                        format!("Decryption failed: {e}"),
                    )
                })?;
            Ok(Arc::new(ByteSliceDataSource::new(plain)))
        }
    }

    pub(crate) fn record_protection_class(
        record: &manifest_db::ManifestRecord,
    ) -> Option<(u32, &'static str)> {
        let class_from_field = record
            .protection_class
            .and_then(|c| u32::try_from(c).ok())
            .filter(|c| *c != 0);
        if let Some(c) = class_from_field {
            return Some((c, "manifest_protection_class_field"));
        }
        record
            .key_class
            .filter(|c| *c != 0)
            .map(|c| (c, "encryption_key_class_prefix"))
    }

    /// A record for a manifest entry whose content could not be recovered.
    ///
    /// Forensic meaning: the file **was** in the backup — the manifest names it,
    /// dates it and sizes it — but this tool could not produce its bytes. Without
    /// this record the entry simply vanishes, and a backup file list that is
    /// missing a photo, a chat database or a keychain item looks exactly like a
    /// device that never held one. An examiner could then testify that the data
    /// never existed, when in truth it was merely never decrypted.
    fn undecrypted_file_record(
        backup_path: &Path,
        record: &manifest_db::ManifestRecord,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        status: &str,
        reason: seance_core::io::IncompleteReason,
        message: &str,
    ) -> Artifact {
        let metadata = json!({
            "type": "IosBackupFile",
            "subtype": "ios_backup_undecrypted",
            "status": status,
            "name": Self::file_basename(&record.relative_path),
            "file_id": record.file_id,
            "domain": record.domain,
            "relative_path": record.relative_path,
            "flags": record.flags,
            "is_directory": false,
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
            "backup_path": backup_path.to_string_lossy().to_string(),
            "encrypted": true,
            "decrypted": false,
            "content_incomplete": true,
            "content_incomplete_reason": reason.as_str(),
            "message": message,
        });
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
    }

    /// The backup-level statement that this encrypted backup was opened.
    ///
    /// An encrypted backup ingested with no password emits an
    /// `encrypted_no_password` record whose message says no files from it are in
    /// this case. Supplying the password later is exactly the action that record
    /// asks for, and it leaves that sentence standing and false. This record is
    /// the answer to it: it names the password as the thing that opened the
    /// backup, counts what came out, and says in as many words which earlier
    /// statement it supersedes.
    fn decrypted_summary(
        backup_path: &Path,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        manifest_entries: usize,
        failed: u64,
        class_states: &[(u32, crypto::ClassKeyState)],
    ) -> Artifact {
        let recovered = (manifest_entries as u64).saturating_sub(failed);
        let in_state = |want: crypto::ClassKeyState| {
            class_states
                .iter()
                .filter(|(_, st)| *st == want)
                .map(|(c, _)| *c)
                .collect::<Vec<u32>>()
        };
        let usable = in_state(crypto::ClassKeyState::Usable);
        let device_bound = in_state(crypto::ClassKeyState::DeviceBound);
        let not_unwrapped = in_state(crypto::ClassKeyState::NotUnwrapped);
        // Which protection classes the password opened. A device-bound class
        // (keybag WRAP & 1) is wrapped under the device's hardware key as well
        // as the password; a backup does not carry that key, so no password
        // opens it. Class numbers only: no key byte is recorded.
        let keybag_classes = json!({
            "total": class_states.len(),
            "usable": usable,
            "device_bound": device_bound,
            "not_unwrapped": not_unwrapped,
            "statement": format!(
                "The password opened {} of the keybag's {} class keys. {} class key(s) \
                 are device-bound: they are wrapped under the device's hardware key as well \
                 as the password, which a backup does not carry, so anything protected by \
                 them (the ThisDeviceOnly keychain items) cannot be read from this backup.",
                usable.len(),
                class_states.len(),
                device_bound.len()
            ),
        });
        let metadata = json!({
            "type": "IosBackupInfo",
            "subtype": "ios_backup_decrypted",
            "status": "decrypted",
            "supersedes_status": "encrypted_no_password",
            "is_encrypted": true,
            // Deliberately no `decrypted: true` here. On this parser that key
            // means "these bytes were decrypted and are attached", and it is
            // asserted per file entry; a backup-level record has no bytes, and
            // an invariant test holds every record carrying it to producing
            // them. `status` says what this record says.
            "manifest_entries": manifest_entries,
            "keybag_classes": keybag_classes,
            "files_recovered": recovered,
            "files_not_recovered": failed,
            "backup_path": backup_path.to_string_lossy().to_string(),
            "message": "This backup is encrypted and was decrypted with a password supplied for \
                        this run: its files are in this case. A record stating that no files from \
                        it are present describes the state before the password was given.",
            "name": "iOS backup (encrypted, decrypted with supplied password)",
        });
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
    }

    /// The backup-level statement that the extracted file set has holes in it.
    fn decrypt_gap_summary(
        backup_path: &Path,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        manifest_entries: usize,
        failed: u64,
    ) -> Artifact {
        let metadata = json!({
            "type": "IosBackupInfo",
            "subtype": "ios_backup_incomplete",
            "status": "PartialDecryption",
            "content_incomplete": true,
            "content_incomplete_reason": seance_core::io::IncompleteReason::Encrypted.as_str(),
            "manifest_entries": manifest_entries,
            "files_not_recovered": failed,
            "backup_path": backup_path.to_string_lossy().to_string(),
            "message": "Some files listed in the backup manifest could not be read or decrypted; their content is absent from this case",
            "name": format!("iOS backup (partially decrypted: {failed} file(s) not recovered)"),
        });
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
    }

    /// Parse unencrypted manifest files (Manifest.db or Manifest.mbdb).
    ///
    /// If a keybag is provided, it's used for decrypting individual files
    /// (not needed for unencrypted backups).
    fn parse_manifest_files(
        &self,
        backup_path: &Path,
        _keybag: Option<&crypto::Keybag>,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
    ) -> Result<Vec<Artifact>> {
        let mut artifacts = Vec::new();

        let manifest_db_path = backup_path.join("Manifest.db");
        let manifest_mbdb_path = backup_path.join("Manifest.mbdb");

        // Manifest entries whose stored blob is not on disk (or will not open).
        // Counted so the backup itself can state that its file set has holes.
        let mut missing_blobs = 0u64;
        let mut undecodable_metadata = 0u64;
        // Manifest entries carrying a per-file EncryptionKey inside a backup
        // that did not declare itself encrypted: their stored blob is
        // ciphertext, so no content is attached for them.
        let mut ciphertext_entries = 0u64;
        // Assigned by whichever manifest form is present; never read before then.
        let manifest_entries: usize;

        if manifest_db_path.exists() {
            info!("Parsing Manifest.db (SQLite format)");
            let records = ManifestDb::parse(&manifest_db_path)?;

            info!("Found {} files in Manifest.db", records.len());
            manifest_entries = records.len();

            for record in records {
                let mut metadata = json!({
                    "type": "IosBackupFile",
                    "name": Self::file_basename(&record.relative_path),
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
                    "backup_path": backup_path.to_string_lossy().to_string(),
                });

                // B6-036: the size/MACB fields above are null because the blob
                // that holds them would not decode, not because the backup
                // stored none. Say which.
                if let Some(err) = &record.metadata_error {
                    undecodable_metadata += 1;
                    Self::mark_metadata_undecodable(&mut metadata, err);
                }

                let (artifact_type, data_source) = if record.is_directory() {
                    (ArtifactType::ParsedRecord, None)
                } else if record
                    .encryption_key
                    .as_ref()
                    .is_some_and(|k| !k.is_empty())
                {
                    // This backup's Manifest.plist did not declare itself
                    // encrypted, yet the manifest gives this entry a per-file
                    // EncryptionKey — so its stored blob is wrapped ciphertext.
                    // No password was taken for a backup that said it needed
                    // none, so nothing here can unwrap it. Attaching the stored
                    // bytes would exhibit ciphertext as the file's recovered
                    // content, which is what B8-026 was (this is the same class
                    // on the path the product actually runs).
                    ciphertext_entries += 1;
                    Self::mark_content_encrypted(&mut metadata);
                    (ArtifactType::FileEntry, None)
                } else {
                    match Self::file_data_source(backup_path, &record.file_id) {
                        Ok(ds) => (ArtifactType::FileEntry, Some(ds)),
                        // A symlink stores no file in the backup: its content is
                        // the target path in the manifest. Say so on the entry,
                        // but do not count it as a missing blob — otherwise the
                        // gap summary fires on ordinary backups.
                        Err(_) if record.is_symlink() => {
                            metadata["is_symlink"] = json!(true);
                            metadata["content_omitted"] = json!("symlink_has_no_stored_content");
                            (ArtifactType::FileEntry, None)
                        }
                        Err(e) => {
                            missing_blobs += 1;
                            Self::mark_content_absent(&mut metadata, &e);
                            (ArtifactType::FileEntry, None)
                        }
                    }
                };

                artifacts.push(
                    Artifact::new(case_id, artifact_type, data_source, metadata)
                        .with_parent(parent_id),
                );
            }
        } else if manifest_mbdb_path.exists() {
            info!("Parsing Manifest.mbdb (legacy binary format)");
            let parsed = ManifestMbdb::parse(&manifest_mbdb_path)?;

            info!("Found {} files in Manifest.mbdb", parsed.records.len());
            manifest_entries = parsed.records.len();

            for record in parsed.records {
                let mut metadata = json!({
                    "type": "IosBackupFileLegacy",
                    "name": Self::file_basename(&record.relative_path),
                    "file_id": record.file_id,
                    "domain": record.domain,
                    "relative_path": record.relative_path,
                    "is_directory": record.is_directory,
                    "size": record.size,
                    "mode": record.mode,
                    "last_modified": record.last_modified,
                    "modified": epoch_to_rfc3339(record.last_modified as i64),
                    "inode": record.inode,
                    "user_id": record.user_id,
                    "group_id": record.group_id,
                    "link_target": record.link_target,
                    "has_encryption_key": record.encryption_key.is_some(),
                    "has_data_hash": record.data_hash.is_some(),
                    "backup_path": backup_path.to_string_lossy().to_string(),
                    "format": "mbdb_legacy",
                });

                let (artifact_type, data_source) = if record.is_directory {
                    (ArtifactType::ParsedRecord, None)
                } else if record
                    .encryption_key
                    .as_ref()
                    .is_some_and(|k| !k.is_empty())
                {
                    // Same as the Manifest.db branch above: a per-file key means
                    // the stored blob is ciphertext, and `has_encryption_key`
                    // alone is a boolean nothing keys off. Attaching those bytes
                    // would put ciphertext in the case as this file's recovered
                    // content (the B8-026 class).
                    ciphertext_entries += 1;
                    Self::mark_content_encrypted(&mut metadata);
                    (ArtifactType::FileEntry, None)
                } else {
                    match Self::file_data_source(backup_path, &record.file_id) {
                        Ok(ds) => (ArtifactType::FileEntry, Some(ds)),
                        // A symlink stores no file in the backup: its content is
                        // `link_target`, already on the record above. Expected,
                        // so not counted as a hole.
                        Err(_) if record.link_target.is_some() => {
                            metadata["is_symlink"] = json!(true);
                            metadata["content_omitted"] = json!("symlink_has_no_stored_content");
                            (ArtifactType::FileEntry, None)
                        }
                        Err(e) => {
                            missing_blobs += 1;
                            Self::mark_content_absent(&mut metadata, &e);
                            (ArtifactType::FileEntry, None)
                        }
                    }
                };

                artifacts.push(
                    Artifact::new(case_id, artifact_type, data_source, metadata)
                        .with_parent(parent_id),
                );
            }

            // B6-019: the walk stopped mid-record, so the list above is a prefix
            // of the backup's file set. Files after the desync were never listed
            // and their absence from this case says nothing about the device.
            if let Some((offset, err)) = parsed.stopped_at {
                warn!(
                    "Manifest.mbdb desynced at offset {} after {} records",
                    offset, manifest_entries
                );
                artifacts.push(Self::manifest_truncated_record(
                    backup_path,
                    case_id,
                    parent_id,
                    manifest_entries,
                    offset,
                    &err,
                ));
            }
        } else {
            return Err(anyhow!(
                "No manifest file found (neither Manifest.db nor Manifest.mbdb)"
            ));
        }

        // B6-006: the backup lists files whose stored blob this tool could not
        // open. Each one is flagged above; state it once at backup level too, so
        // the completeness census counts a partially-inventoried backup rather
        // than a fully inventoried one.
        if missing_blobs > 0 || undecodable_metadata > 0 {
            warn!(
                "iOS backup: {} file(s) had no readable stored blob, {} had undecodable metadata",
                missing_blobs, undecodable_metadata
            );
            artifacts.push(Self::backup_gap_summary(
                backup_path,
                case_id,
                parent_id,
                manifest_entries,
                missing_blobs,
                undecodable_metadata,
            ));
        }

        // B8-026 class: entries whose stored blob is wrapped ciphertext. Their
        // content is absent from the case, so the backup must say so at backup
        // level too — otherwise the file list looks complete and the missing
        // bytes read as files that held nothing.
        if ciphertext_entries > 0 {
            warn!(
                "iOS backup: {} entr(ies) carry a per-file encryption key in a backup that did \
                 not declare itself encrypted; their content is ciphertext and was not attached",
                ciphertext_entries
            );
            artifacts.push(Self::decrypt_gap_summary(
                backup_path,
                case_id,
                parent_id,
                manifest_entries,
                ciphertext_entries,
            ));
        }

        Ok(artifacts)
    }

    /// Stamp a manifest entry whose stored blob could not be opened.
    ///
    /// The entry keeps its manifest size and path — it existed on the device —
    /// but carries no bytes. Unflagged, a FileEntry of size 40960 with no
    /// content opens as an empty file, and a partial backup presents as a fully
    /// inventoried one.
    /// Stamp an entry whose manifest metadata blob would not decode.
    ///
    /// Its size, mode and MACB times are all `null` — and `null` there reads as
    /// "the backup stored none", which is a claim about the device. It is not:
    /// they could not be determined (B6-036). Used on both the encrypted and the
    /// unencrypted manifest paths, because the blob is the same blob.
    fn mark_metadata_undecodable(metadata: &mut serde_json::Value, error: &str) {
        metadata["inventory_incomplete"] = json!(true);
        metadata["inventory_incomplete_reason"] =
            json!(IncompleteReason::UnresolvedStructure.as_str());
        metadata["metadata_parse_error"] = json!(error);
        metadata["message"] = json!(
            "This entry's size and timestamps could not be determined: the manifest's \
             metadata blob for it would not decode. They are unknown, not absent"
        );
    }

    fn mark_content_absent(metadata: &mut serde_json::Value, error: &str) {
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] =
            json!(IncompleteReason::UnresolvedStructure.as_str());
        metadata["content_omitted"] = json!("backup_blob_unreadable");
        metadata["open_error"] = json!(error);
        metadata["message"] = json!(
            "The backup manifest lists this file, but its stored copy could not be opened. \
             Its content is absent from this case; that is not evidence the file was empty"
        );
    }

    /// Stamp an entry whose stored blob is wrapped ciphertext.
    ///
    /// The manifest gave this file a per-file `EncryptionKey`, so the bytes on
    /// disk are the encrypted form. Nothing here can unwrap them: the backup did
    /// not declare itself encrypted, so no password was taken for it. Attaching
    /// them anyway would put ciphertext in the case as this file's recovered
    /// content — an examiner would hash and exhibit it as the file (B8-026).
    fn mark_content_encrypted(metadata: &mut serde_json::Value) {
        metadata["content_incomplete"] = json!(true);
        metadata["content_incomplete_reason"] = json!(IncompleteReason::Encrypted.as_str());
        metadata["content_omitted"] = json!("stored_blob_is_ciphertext");
        metadata["message"] = json!(
            "The manifest gives this file a per-file encryption key, so its stored copy is \
             ciphertext. This backup did not declare itself encrypted, so no password was \
             taken for it and the bytes could not be decrypted. They are not attached: they \
             are not this file's content"
        );
    }

    /// The backup-level statement that the extracted file set has holes in it
    /// (unencrypted backups; the encrypted path has its own summary).
    fn backup_gap_summary(
        backup_path: &Path,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        manifest_entries: usize,
        missing_blobs: u64,
        undecodable_metadata: u64,
    ) -> Artifact {
        let metadata = json!({
            "type": "IosBackupInfo",
            "subtype": "ios_backup_incomplete",
            "status": "PartialExtraction",
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "manifest_entries": manifest_entries,
            "files_without_content": missing_blobs,
            "entries_without_metadata": undecodable_metadata,
            "backup_path": backup_path.to_string_lossy().to_string(),
            "message": "Some entries listed in this backup's manifest could not be opened, or \
                        their stored metadata could not be decoded; their content and times are \
                        absent from this case",
            "name": format!("iOS backup (partially extracted: {missing_blobs} file(s) without content)"),
        });
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
    }

    /// The record stating that a legacy `Manifest.mbdb` walk ended early, so the
    /// file list above it is a prefix of the backup rather than the whole of it.
    fn manifest_truncated_record(
        backup_path: &Path,
        case_id: uuid::Uuid,
        parent_id: uuid::Uuid,
        records_recovered: usize,
        stopped_offset: usize,
        error: &str,
    ) -> Artifact {
        let metadata = json!({
            "type": "IosBackupInfo",
            "subtype": "ios_backup_incomplete",
            "status": "ManifestTruncated",
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "records_recovered": records_recovered,
            "stopped_at_offset": stopped_offset,
            "parse_error": error,
            "backup_path": backup_path.to_string_lossy().to_string(),
            "message": "Manifest.mbdb could not be read to its end: the file list for this \
                        backup stops at the offset given and the entries after it were never \
                        enumerated",
            "name": "iOS backup (manifest truncated)",
        });
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id)
    }

    /// Resolve the on-disk path for a backup file given its file ID (SHA-1 hash).
    ///
    /// Modern iOS backups (iOS 10+) store files in subdirectories named by the
    /// first 2 hex chars: `<backup_path>/<ab>/<abcdef0123456789...>`.
    /// Older backups use a flat layout: `<backup_path>/<abcdef0123456789...>`.
    /// We try the modern 2-level path first, then fall back to the flat path.
    ///
    /// The file ID comes from the backup's own manifest, which is evidence and
    /// therefore untrusted. It is joined onto the backup directory only if it
    /// is a bare name — ASCII letters and digits, as every real SHA-1 ID is.
    /// Joined unchecked, `../../etc/shadow` walked out of the evidence root and
    /// an absolute ID replaced the backup path outright, so a manifest could
    /// have the server read any file it can open into the case as "backup
    /// content"; and `&file_id[..2]` panicked on an ID whose first character
    /// was not ASCII (SEC-011).
    pub(crate) fn resolve_backup_file_path(
        backup_path: &Path,
        file_id: &str,
    ) -> Result<std::path::PathBuf, String> {
        if file_id.is_empty() || !file_id.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(format!(
                "manifest fileID {file_id:?} is not a backup file name (a hexadecimal SHA-1 \
                 is expected); it is not resolved against the backup directory"
            ));
        }
        if file_id.len() >= 2 {
            let two_level = backup_path.join(&file_id[..2]).join(file_id);
            if two_level.exists() {
                return Ok(two_level);
            }
        }
        // Fallback: flat layout (older backups)
        Ok(backup_path.join(file_id))
    }

    /// Basename of a backup file's `relative_path`.
    ///
    /// Downstream parsers (iMessage, WhatsApp, browser history, ...) identify
    /// their target databases by the artifact's `metadata["name"]`, so every
    /// emitted FileEntry must carry the on-device filename (e.g. `sms.db`).
    /// Falls back to the full `relative_path` if it has no final component.
    fn file_basename(relative_path: &str) -> String {
        Path::new(relative_path)
            .file_name()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_else(|| relative_path.to_string())
    }

    /// Build a file-backed `DataSource` over an unencrypted backup file so the
    /// extracted database bytes chain to downstream parsers.
    ///
    /// Returns `Err` with the open error when the on-disk file is missing or
    /// cannot be opened. The caller still emits the FileEntry (the manifest
    /// proves the file existed on the device) but must flag it: an entry with a
    /// non-zero manifest size and no bytes otherwise opens as an empty file
    /// (B6-006).
    fn file_data_source(
        backup_path: &Path,
        file_id: &str,
    ) -> Result<Arc<dyn seance_core::data_source::DataSource>, String> {
        let file_path = Self::resolve_backup_file_path(backup_path, file_id)?;
        match FileDataSource::new(file_path) {
            Ok(ds) => Ok(Arc::new(ds)),
            Err(e) => {
                debug!("Could not open backup file {}: {}", file_id, e);
                Err(e.to_string())
            }
        }
    }
}

impl Default for IosBackupParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "test-support"))]
pub mod test_support;

impl ForensicsModule for IosBackupParser {
    fn id(&self) -> &str {
        "plugin.mobile.ios_backup"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::RawEvidence]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::FilePath
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Get path from artifact
        let path_str = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                ModuleError::InvalidInputFormat("iOS backup parser requires file path".to_string())
            })?;

        let path = Path::new(path_str);

        // Check if this looks like an iOS backup directory
        if !path.is_dir() {
            return Ok(Vec::new());
        }

        if !self.is_ios_backup(path) {
            return Ok(Vec::new());
        }

        info!("iOS backup directory detected: {}", path.display());

        // Parse backup. The password may come with a credential supplied for
        // this run (SEC-204) or from the process-level secret; the per-run one
        // wins (HUNT-085).
        let run_credential = Self::run_credential(artifact);
        let password = run_credential
            .as_deref()
            .map(RunCredential::expose_secret)
            .or(self.password.as_deref());
        match self.parse_backup(path, password, artifact.case_id, artifact.id) {
            Ok(records) => Ok(records),
            // A supplied password that does not unwrap the keybag is a verdict
            // on the secret, not a module fault: report it and return, so the
            // orchestrator audits the refusal and the record saying the backup
            // is locked still stands. The reason is our own words — never the
            // password.
            Err(e) if run_credential.is_some() && e.downcast_ref::<WrongPassword>().is_some() => {
                if let Some(cred) = run_credential {
                    cred.rejected(
                        "the password did not unwrap the backup keybag's class keys \
                         (RFC 3394 integrity check failed): the password is wrong, or the \
                         keybag's wrapped class key is corrupt — the check cannot tell the \
                         two apart",
                    );
                }
                Ok(Vec::new())
            }
            Err(e) => Err(ModuleError::ParsingError(format!(
                "Failed to parse iOS backup: {}",
                e
            ))),
        }
    }
}
