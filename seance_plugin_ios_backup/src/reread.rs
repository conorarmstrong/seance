//! Re-reading an encrypted backup's files after ingest (`BUG-026`).
//!
//! # Why this exists
//!
//! An encrypted iTunes / Finder backup stores every file as ciphertext. At
//! ingest the password (supplied for that one run through the credential
//! route) unwraps the keybag's class keys, and each file's plaintext is
//! attached to its record as an in-memory data source. Once the run ends, the
//! keys are gone, and stream, hex, export and re-hash of those files have to
//! refuse: the only bytes on disk are ciphertext (`HUNT-004`).
//!
//! This module is the **unlock-to-read** half: the examiner types the backup
//! password again, [`unlock_backup`] checks it against the keybag through the
//! **same** code the ingest run uses (`IosBackupParser::unlock_keybag` and
//! `decrypt_manifest_records`), and returns an [`UnlockedBackup`] that opens a
//! file of the backup to its plaintext on demand through the **same** per-file
//! step as well (`IosBackupParser::open_encrypted_file`: streaming threshold,
//! class-key choice, key unwrap, decrypt). A file that ingest could not open —
//! no per-file key, no protection class, no class key for its class — cannot
//! be opened here either; the open is an error, never empty or ciphertext.
//!
//! Like ingest, the unlock writes the decrypted `Manifest.db` (file names,
//! domains and **wrapped** per-file keys; not the class keys, not the
//! password) to a temporary file in the system temp directory for SQLite to
//! open, and deletes it before [`unlock_backup`] returns (a crash in between
//! can leave it behind).
//!
//! # What is held
//!
//! An [`UnlockedBackup`] holds the unwrapped class keys (zeroed on drop; see
//! [`crypto::ClassKey`]) and, per file, its manifest-declared protection class
//! and **wrapped** per-file key — which is not secret without a class key. It
//! is not `Clone` or `Serialize`, and its `Debug` prints counts and the backup
//! path only. Holding it, for how long and for whom is the caller's decision
//! (the API keeps it in a process-memory keyring scoped to one case, with a
//! TTL, and never on disk).
//!
//! # What it cannot do
//!
//! The per-file key unwrapped for a small (whole-file) read is an ordinary
//! buffer while that decrypt runs, and the AES key schedule inside a streaming
//! data source lives for as long as that read's data source does; neither is
//! zeroed by this module. A file whose manifest entry carries no key or
//! no protection class cannot be opened here any more than at ingest.

use crate::{crypto, manifest_db::ManifestRecord, IosBackupParser, WrongPassword};
use anyhow::{anyhow, Result};
use seance_core::data_source::DataSource;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Why an unlock did not succeed.
#[derive(Debug)]
pub enum UnlockError {
    /// The password did not unwrap the keybag's class keys (RFC 3394 integrity
    /// failure). It cannot rule out a corrupt wrapped class key. The text is
    /// this module's own words and never contains the password.
    WrongPassword(String),
    /// The backup's `Manifest.plist` does not declare it encrypted: its files
    /// are stored in the clear and need no unlock.
    NotEncrypted,
    /// Anything else: an unreadable or malformed manifest or keybag.
    Other(anyhow::Error),
}

impl std::fmt::Display for UnlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WrongPassword(r) => write!(f, "the backup password was refused: {r}"),
            Self::NotEncrypted => f.write_str("the backup is not encrypted"),
            Self::Other(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for UnlockError {}

/// One manifest entry's key material as the manifest states it.
struct FileKeyEntry {
    /// `None` when neither carrier states a class.
    protection_class: Option<u32>,
    /// The wrapped per-file key, `None` when the entry carries none.
    wrapped_key: Option<Vec<u8>>,
}

/// An encrypted backup unlocked with its password.
///
/// Not `Clone`, `Serialize` or `Display`; `Debug` is redacted.
pub struct UnlockedBackup {
    backup_path: PathBuf,
    keybag: crypto::Keybag,
    files: HashMap<String, FileKeyEntry>,
}

impl std::fmt::Debug for UnlockedBackup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedBackup")
            .field("backup_path", &self.backup_path)
            .field("class_keys", &format_args!("<redacted>"))
            .field("files", &self.files.len())
            .finish()
    }
}

impl UnlockedBackup {
    /// The backup directory this unlock opens.
    pub fn backup_path(&self) -> &Path {
        &self.backup_path
    }

    /// Each keybag class with its state (usable, device-bound, not
    /// unwrapped), in keybag order. Class numbers only, never key bytes.
    pub fn class_key_states(&self) -> Vec<(u32, crypto::ClassKeyState)> {
        crypto::class_key_states(&self.keybag)
    }

    /// How many manifest entries the unlocked `Manifest.db` lists.
    pub fn file_count(&self) -> usize {
        self.files.len()
    }

    /// Open one backup file, by its manifest `fileID`, to its plaintext.
    ///
    /// Errors — never empty or ciphertext content — when the ID is not in the
    /// manifest, the entry has no per-file key or protection class, or the
    /// decryption fails.
    pub fn open_file(&self, file_id: &str) -> Result<Arc<dyn DataSource>> {
        let entry = self.files.get(file_id).ok_or_else(|| {
            anyhow!("file {file_id:?} is not in this backup's manifest (Manifest.db)")
        })?;
        let wrapped = entry
            .wrapped_key
            .as_deref()
            .ok_or_else(|| anyhow!("the manifest entry for {file_id:?} carries no per-file key"))?;
        let class = entry
            .protection_class
            .ok_or_else(|| anyhow!("the manifest gives no protection class for {file_id:?}"))?;
        let path = IosBackupParser::resolve_backup_file_path(&self.backup_path, file_id)
            .map_err(|e| anyhow!(e))?;

        // The same per-file open the ingest run uses.
        IosBackupParser::open_encrypted_file(&path, wrapped, class, &self.keybag)
            .map_err(|f| anyhow!("backup file {file_id:?}: {} ({})", f.message, f.label))
    }
}

/// One keychain item's secret, re-derived for the audited reveal (HUNT-111).
///
/// Zeroed on drop; `Debug` prints its length class only, never a byte. Not
/// `Clone`, `Serialize` or `Display`: the caller exposes it once, after the
/// audit row is written.
pub struct KeychainSecret(zeroize::Zeroizing<Vec<u8>>);

impl KeychainSecret {
    /// The secret's bytes. Call only after the reveal is on the audit log.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl std::fmt::Debug for KeychainSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KeychainSecret(<redacted>)")
    }
}

impl UnlockedBackup {
    /// Re-derive one keychain item's secret from the backup's
    /// `keychain-backup.plist` (manifest `fileID` `keychain_file_id`), by the
    /// item's table and position and, when given, its `v_PersistentRef` —
    /// which must match. Nothing is cached: each call decrypts the file and
    /// the item again, so no plaintext secret outlives the call's result.
    ///
    /// Errors, in this module's own words, when the file will not open, the
    /// item is not there or is not the one named, the item is device-bound or
    /// did not authenticate, or it carries no secret.
    pub fn keychain_secret(
        &self,
        keychain_file_id: &str,
        table: &str,
        index: usize,
        persistent_ref_hex: Option<&str>,
    ) -> Result<KeychainSecret> {
        let source = self.open_file(keychain_file_id)?;
        let bytes = crate::keychain_backup::read_whole(source.as_ref())
            .map_err(|r| anyhow!("the keychain file was not read: {r}"))?;
        crate::keychain_backup::secret_of(&bytes, &self.keybag, table, index, persistent_ref_hex)
            .map(KeychainSecret)
    }
}

/// Check `password` against the backup's keybag and, if it unwraps the class
/// keys, decrypt `Manifest.db` and return the unlocked backup.
pub fn unlock_backup(backup_path: &Path, password: &str) -> Result<UnlockedBackup, UnlockError> {
    let manifest_plist = crate::ManifestPlist::from_file(&backup_path.join("Manifest.plist"))
        .map_err(UnlockError::Other)?;
    if !manifest_plist.is_encrypted {
        return Err(UnlockError::NotEncrypted);
    }
    let (keybag, _unwrapped) =
        IosBackupParser::unlock_keybag(&manifest_plist, password).map_err(|e| match e
            .downcast::<WrongPassword>()
        {
            Ok(_) => UnlockError::WrongPassword(
                "the password did not unwrap the backup keybag's class keys (RFC 3394 \
                 integrity check failed): the password is wrong, or the keybag's wrapped \
                 class key is corrupt — the check cannot tell the two apart"
                    .to_string(),
            ),
            Err(e) => UnlockError::Other(e),
        })?;
    let records = IosBackupParser::decrypt_manifest_records(backup_path, &manifest_plist, &keybag)
        .map_err(UnlockError::Other)?;
    let files = records
        .iter()
        .filter(|r| !r.is_directory())
        .map(|r: &ManifestRecord| {
            (
                r.file_id.clone(),
                FileKeyEntry {
                    protection_class: IosBackupParser::record_protection_class(r).map(|(c, _)| c),
                    wrapped_key: r.encryption_key.clone().filter(|k| !k.is_empty()),
                },
            )
        })
        .collect();
    Ok(UnlockedBackup {
        backup_path: backup_path.to_path_buf(),
        keybag,
        files,
    })
}

/// Unlock the backup and open one file: the one-shot form of
/// [`unlock_backup`] + [`UnlockedBackup::open_file`].
pub fn open_backup_file_plaintext(
    backup_path: &Path,
    file_id: &str,
    password: &str,
) -> Result<Arc<dyn DataSource>> {
    let unlocked = unlock_backup(backup_path, password).map_err(|e| anyhow!("{e}"))?;
    unlocked.open_file(file_id)
}
