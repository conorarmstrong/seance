//! Manifest.db (SQLite) parser for iOS 10+ backups
//!
//! Parses the SQLite database that contains file metadata for iOS backups.

use anyhow::{anyhow, Context, Result};
use rusqlite::Connection;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ManifestRecord {
    pub file_id: String,
    pub domain: String,
    pub relative_path: String,
    pub flags: i64,
    pub size: Option<i64>,
    pub mode: Option<i64>,
    pub last_modified: Option<String>,
    pub birth: Option<String>,
    pub inode_number: Option<i64>,
    pub user_id: Option<i64>,
    pub group_id: Option<i64>,
    pub protection_class: Option<i64>,
    /// Per-file encryption key (from NSKeyedArchiver blob, encrypted backups only)
    pub encryption_key: Option<Vec<u8>>,
    /// Protection class carried by the 4-byte little-endian prefix of the
    /// wrapped `EncryptionKey` blob.
    ///
    /// The manifest states a file's protection class twice: in the metadata
    /// blob's `ProtectionClass` field, and as this prefix on the key itself.
    /// The prefix used to be stripped and thrown away, so a record whose
    /// `ProtectionClass` field was absent had no class at all and was treated
    /// as unprotected — which routed its ciphertext out as file content
    /// (B8-026). It is kept so the second carrier can answer when the first
    /// cannot.
    pub key_class: Option<u32>,
    /// Why no per-file key could be taken from this record, when the manifest
    /// did carry an `EncryptionKey` entry for it.
    ///
    /// An absent key reads downstream as "this file was not encrypted", so a
    /// key that was present but unusable must not leave the same trace as a key
    /// that was never there.
    pub encryption_key_error: Option<String>,
    /// Why this record's size / MACB times / mode are absent, when they are.
    ///
    /// The `file` BLOB is the only place a Manifest.db keeps a file's size and
    /// timestamps. When it fails to parse, every one of those fields stays
    /// `None` and the row renders exactly like a row for a file the backup
    /// stored no metadata for. They are not the same thing, so the failure is
    /// carried on the record instead of being dropped (B6-036).
    pub metadata_error: Option<String>,
}

impl ManifestRecord {
    pub fn is_directory(&self) -> bool {
        const FLAG_DIRECTORY: i64 = 0x2;
        self.flags & FLAG_DIRECTORY != 0
    }

    /// True for a symbolic-link entry (`flags & 0x4`).
    ///
    /// A symlink's content *is* its target path, which the manifest carries in
    /// the metadata blob; the backup stores no file on disk for it. So a symlink
    /// with no stored blob is the normal, complete case, and must not be counted
    /// as a hole — a completeness warning that fires on every ordinary backup
    /// teaches an examiner to ignore it.
    pub fn is_symlink(&self) -> bool {
        const FLAG_SYMLINK: i64 = 0x4;
        self.flags & FLAG_SYMLINK != 0
    }
}

pub struct ManifestDb;

impl ManifestDb {
    /// Parse Manifest.db from decrypted bytes (encrypted backups).
    ///
    /// Writes the decrypted data to a temporary file and opens it with rusqlite,
    /// since rusqlite requires a file path.
    pub fn parse_from_bytes(db_bytes: &[u8]) -> Result<Vec<ManifestRecord>> {
        use std::io::Write;
        let mut tmp = tempfile::NamedTempFile::new()
            .context("Failed to create temp file for decrypted Manifest.db")?;
        tmp.write_all(db_bytes)
            .context("Failed to write decrypted Manifest.db to temp file")?;
        tmp.flush()?;
        Self::parse(tmp.path())
    }

    /// Parse Manifest.db and return all file records
    pub fn parse(db_path: &Path) -> Result<Vec<ManifestRecord>> {
        let conn = Connection::open(db_path).context("Failed to open Manifest.db")?;

        // Query all files from the Files table
        let mut stmt =
            conn.prepare("SELECT fileID, domain, relativePath, flags, file FROM Files")?;

        let mut records = Vec::new();

        let rows = stmt.query_map([], |row| {
            let file_id: String = row.get(0)?;
            let domain: Option<String> = row.get(1)?;
            let relative_path: Option<String> = row.get(2)?;
            let flags: i64 = row.get(3)?;
            let file_blob: Option<Vec<u8>> = row.get(4)?;

            Ok((file_id, domain, relative_path, flags, file_blob))
        })?;

        for row in rows {
            let (file_id, domain, relative_path, flags, file_blob) = row?;

            // Parse the file blob (binary plist) if present
            let mut record = ManifestRecord {
                file_id,
                domain: domain.unwrap_or_default(),
                relative_path: relative_path.unwrap_or_default(),
                flags,
                size: None,
                mode: None,
                last_modified: None,
                birth: None,
                inode_number: None,
                user_id: None,
                group_id: None,
                protection_class: None,
                encryption_key: None,
                key_class: None,
                encryption_key_error: None,
                metadata_error: None,
            };

            if let Some(blob) = file_blob {
                match Self::parse_file_metadata(&blob) {
                    Ok(metadata) => {
                        record.size = metadata.size;
                        record.mode = metadata.mode;
                        record.last_modified = metadata.last_modified;
                        record.birth = metadata.birth;
                        record.inode_number = metadata.inode_number;
                        record.user_id = metadata.user_id;
                        record.group_id = metadata.group_id;
                        record.protection_class = metadata.protection_class;
                        record.encryption_key = metadata.encryption_key;
                        record.key_class = metadata.key_class;
                        record.encryption_key_error = metadata.encryption_key_error;
                    }
                    Err(e) => {
                        // The blob exists but will not decode. Leaving the row
                        // with null size and null timestamps would present the
                        // backup as having stored none — say instead that they
                        // could not be determined.
                        record.metadata_error = Some(e.to_string());
                    }
                }
            }

            records.push(record);
        }

        Ok(records)
    }

    /// Parse the binary plist file metadata blob.
    ///
    /// The blob is an NSKeyedArchiver plist with a `$objects` array. The root
    /// object (referenced by `$top.root`) is a dictionary encoded as class
    /// references. Simple metadata (Size, Mode, etc.) is at the top level of
    /// the root object. `EncryptionKey` is an NSMutableData instance stored
    /// as a referenced object in `$objects`, with the raw key bytes in its
    /// `NS.data` field.
    fn parse_file_metadata(blob: &[u8]) -> Result<FileMetadata> {
        let plist_value = plist::from_bytes::<plist::Value>(blob)
            .context("Failed to parse file metadata plist")?;

        let mut metadata = FileMetadata::default();

        if let plist::Value::Dictionary(ref root_dict) = plist_value {
            // Check if this is an NSKeyedArchiver plist
            let is_keyed_archiver = root_dict
                .get("$archiver")
                .and_then(|v| v.as_string())
                .map(|s| s == "NSKeyedArchiver")
                .unwrap_or(false);

            if is_keyed_archiver {
                // NSKeyedArchiver format: navigate $objects array. A blob that
                // does not yield a root dictionary yielded *nothing* — every
                // field null — which is the same shape as a file the backup
                // stored no metadata for. Say it could not be read instead
                // (B6-036).
                let Some(plist::Value::Array(objects)) = root_dict.get("$objects") else {
                    return Err(anyhow!(
                        "NSKeyedArchiver metadata blob has no $objects array"
                    ));
                };

                // Find the root object index from $top.root
                let root_idx = root_dict
                    .get("$top")
                    .and_then(|v| v.as_dictionary())
                    .and_then(|d| d.get("root"))
                    .and_then(Self::uid_value)
                    .unwrap_or(1); // Default: index 1 (index 0 is usually "$null")

                let Some(plist::Value::Dictionary(obj_dict)) = objects.get(root_idx as usize)
                else {
                    return Err(anyhow!(
                        "NSKeyedArchiver metadata blob has no dictionary at root object {root_idx}"
                    ));
                };

                let read_fields = Self::extract_metadata_from_dict(obj_dict, &mut metadata);

                // Extract EncryptionKey: it's a UID reference to an
                // NSMutableData object in $objects
                if let Some(enc_ref) = obj_dict.get("EncryptionKey") {
                    Self::extract_encryption_key(enc_ref, objects, &mut metadata);
                }

                // A dictionary in which nothing at all was recognised is a shape
                // this parser does not understand. Reporting every field as null
                // would state that the backup recorded no size and no times for
                // the file, which is a claim about the device.
                if !read_fields
                    && metadata.encryption_key.is_none()
                    && metadata.encryption_key_error.is_none()
                {
                    return Err(anyhow!(
                        "NSKeyedArchiver root object {root_idx} carries none of the \
                         expected file-metadata keys"
                    ));
                }
            } else {
                // Plain plist dictionary (non-archiver format, e.g. unencrypted
                // backups). A dictionary carrying none of the file-metadata keys
                // is a shape this parser does not understand; reporting every
                // field as null would state that the backup recorded no size and
                // no times for the file, which is a claim about the device.
                if !Self::extract_metadata_from_dict(root_dict, &mut metadata) {
                    return Err(anyhow!(
                        "metadata blob is a plist dictionary carrying none of the \
                         expected file-metadata keys"
                    ));
                }
            }
        } else {
            return Err(anyhow!("metadata blob's root is not a plist dictionary"));
        }

        Ok(metadata)
    }

    /// Take the per-file wrapped key out of an `EncryptionKey` reference.
    ///
    /// The referenced `NSMutableData` object holds, under `NS.data`, a 4-byte
    /// little-endian protection class followed by the RFC 3394 wrapped key. Both
    /// halves are kept: the prefix is the manifest's second statement of the
    /// file's protection class, and it is the only one left when the metadata
    /// blob's own `ProtectionClass` field is missing (B8-026).
    ///
    /// Every way this can fail is recorded rather than dropped. A record with no
    /// key reads downstream as a file that needed no decryption, so "the key was
    /// there but unusable" must not leave the same trace as "there was no key".
    fn extract_encryption_key(
        enc_ref: &plist::Value,
        objects: &[plist::Value],
        metadata: &mut FileMetadata,
    ) {
        let Some(enc_idx) = Self::uid_value(enc_ref) else {
            metadata.encryption_key_error =
                Some("EncryptionKey is not an object reference".to_string());
            return;
        };
        let Some(plist::Value::Dictionary(enc_dict)) = objects.get(enc_idx as usize) else {
            metadata.encryption_key_error = Some(format!(
                "EncryptionKey references object {enc_idx}, which is not a dictionary"
            ));
            return;
        };
        let Some(plist::Value::Data(key_data)) = enc_dict.get("NS.data") else {
            metadata.encryption_key_error =
                Some("EncryptionKey object carries no NS.data byte string".to_string());
            return;
        };
        if key_data.len() <= 4 {
            metadata.encryption_key_error = Some(format!(
                "EncryptionKey blob is {} byte(s): too short to hold the 4-byte \
                 protection-class prefix and a wrapped key",
                key_data.len()
            ));
            return;
        }
        metadata.key_class = Some(u32::from_le_bytes([
            key_data[0],
            key_data[1],
            key_data[2],
            key_data[3],
        ]));
        metadata.encryption_key = Some(key_data[4..].to_vec());
    }

    /// Extract standard metadata fields from a plist dictionary.
    ///
    /// Returns whether the dictionary yielded any of them, so a caller can tell
    /// "the backup recorded nothing" apart from "this parser read nothing".
    fn extract_metadata_from_dict(dict: &plist::Dictionary, metadata: &mut FileMetadata) -> bool {
        if let Some(plist::Value::Integer(size)) = dict.get("Size") {
            metadata.size = size.as_signed();
        }
        if let Some(plist::Value::Integer(mode)) = dict.get("Mode") {
            metadata.mode = mode.as_signed();
        }
        metadata.last_modified = plist_timestamp(dict.get("LastModified"));
        metadata.birth = plist_timestamp(dict.get("Birth"));
        if let Some(plist::Value::Integer(inode)) = dict.get("InodeNumber") {
            metadata.inode_number = inode.as_signed();
        }
        if let Some(plist::Value::Integer(uid)) = dict.get("UserID") {
            metadata.user_id = uid.as_signed();
        }
        if let Some(plist::Value::Integer(gid)) = dict.get("GroupID") {
            metadata.group_id = gid.as_signed();
        }
        if let Some(plist::Value::Integer(pclass)) = dict.get("ProtectionClass") {
            metadata.protection_class = pclass.as_signed();
        }

        metadata.size.is_some()
            || metadata.mode.is_some()
            || metadata.last_modified.is_some()
            || metadata.birth.is_some()
            || metadata.inode_number.is_some()
            || metadata.user_id.is_some()
            || metadata.group_id.is_some()
            || metadata.protection_class.is_some()
    }

    /// Extract a UID value from a plist value.
    ///
    /// In NSKeyedArchiver plists, object references are encoded as UID values.
    /// The plist crate represents these as `Value::Uid`.
    fn uid_value(value: &plist::Value) -> Option<u64> {
        if let plist::Value::Uid(uid) = value {
            Some(uid.get())
        } else if let plist::Value::Integer(i) = value {
            i.as_unsigned()
        } else {
            None
        }
    }
}

/// A timestamp from a Manifest.db file record, as RFC 3339.
///
/// iOS writes these as unix epoch **integers** inside the archived plist, not as
/// plist dates; reading only `Value::Date` silently dropped every file
/// timestamp in the backup. Both forms are accepted.
fn plist_timestamp(value: Option<&plist::Value>) -> Option<String> {
    use chrono::{DateTime, Utc};
    match value {
        Some(plist::Value::Integer(i)) => {
            let secs = i.as_signed()?;
            DateTime::<Utc>::from_timestamp(secs, 0).map(|d| d.to_rfc3339())
        }
        Some(plist::Value::Real(f)) => {
            DateTime::<Utc>::from_timestamp(*f as i64, 0).map(|d| d.to_rfc3339())
        }
        Some(plist::Value::Date(d)) => {
            let sys: std::time::SystemTime = (*d).into();
            let dt: DateTime<Utc> = sys.into();
            Some(dt.to_rfc3339())
        }
        _ => None,
    }
}

#[derive(Debug, Default)]
struct FileMetadata {
    size: Option<i64>,
    mode: Option<i64>,
    last_modified: Option<String>,
    birth: Option<String>,
    inode_number: Option<i64>,
    user_id: Option<i64>,
    group_id: Option<i64>,
    protection_class: Option<i64>,
    encryption_key: Option<Vec<u8>>,
    key_class: Option<u32>,
    encryption_key_error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_backup_dir() -> PathBuf {
        // CARGO_MANIFEST_DIR points to the crate root; test_data is at workspace root
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent()
            .unwrap()
            .join("test_data")
            .join("ios_backup")
    }

    #[test]
    fn test_parse_real_manifest_db() {
        let db_path = test_backup_dir().join("Manifest.db");
        if !db_path.exists() {
            eprintln!(
                "Skipping test_parse_real_manifest_db: {:?} not found",
                db_path
            );
            return;
        }

        let records = ManifestDb::parse(&db_path).unwrap();

        // Should have a significant number of records
        assert!(
            records.len() > 100,
            "Expected >100 records, got {}",
            records.len()
        );

        // Check that we have both files and directories
        let dirs = records.iter().filter(|r| r.is_directory()).count();
        let files = records.iter().filter(|r| !r.is_directory()).count();
        assert!(dirs > 0, "Expected some directories");
        assert!(files > 0, "Expected some files");

        // Check that domains are parsed (not empty)
        let with_domain = records.iter().filter(|r| !r.domain.is_empty()).count();
        assert!(
            with_domain > records.len() / 2,
            "Expected most records to have domains, got {}/{}",
            with_domain,
            records.len()
        );

        // Check that file IDs look like SHA-1 hashes (40 hex chars)
        for record in records.iter().take(10) {
            assert_eq!(
                record.file_id.len(),
                40,
                "File ID should be 40 hex chars, got '{}' (len={})",
                record.file_id,
                record.file_id.len()
            );
        }

        // Check metadata was parsed from NSKeyedArchiver blobs
        let with_size = records.iter().filter(|r| r.size.is_some()).count();
        let with_mode = records.iter().filter(|r| r.mode.is_some()).count();
        let with_protection = records
            .iter()
            .filter(|r| r.protection_class.is_some())
            .count();
        assert!(with_size > 0, "Expected some records with parsed size");
        assert!(with_mode > 0, "Expected some records with parsed mode");
        assert!(
            with_protection > 0,
            "Expected some records with parsed protection class"
        );

        eprintln!(
            "Parsed {} records ({} dirs, {} files) from real Manifest.db",
            records.len(),
            dirs,
            files
        );
        eprintln!(
            "  With size: {}, with mode: {}, with protection_class: {}",
            with_size, with_mode, with_protection
        );
    }

    #[test]
    fn test_manifest_db_known_domains() {
        let db_path = test_backup_dir().join("Manifest.db");
        if !db_path.exists() {
            eprintln!(
                "Skipping test_manifest_db_known_domains: {:?} not found",
                db_path
            );
            return;
        }

        let records = ManifestDb::parse(&db_path).unwrap();

        // iOS backups should contain standard domains
        let domains: std::collections::HashSet<&str> =
            records.iter().map(|r| r.domain.as_str()).collect();

        // HomeDomain is almost always present
        assert!(
            domains.contains("HomeDomain"),
            "Expected HomeDomain in backup, found domains: {:?}",
            domains.iter().take(10).collect::<Vec<_>>()
        );
    }

    fn fixture_dir() -> PathBuf {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent()
            .unwrap()
            .join("test_data")
            .join("ios_backup_fixtures")
    }

    #[test]
    fn test_fixture_sqlite_basic() {
        let db_path = fixture_dir().join("sqlite_basic").join("Manifest.db");
        let records = ManifestDb::parse(&db_path).unwrap();

        assert_eq!(records.len(), 2, "Fixture should have exactly 2 records");

        // First record is a directory
        let dir = &records[0];
        assert_eq!(dir.domain, "AppDomain-com.example.notes");
        assert_eq!(dir.relative_path, "");
        assert!(dir.is_directory(), "First record should be a directory");
        assert_eq!(dir.file_id, "aa0bb1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8");

        // Second record is a file
        let file = &records[1];
        assert_eq!(file.domain, "AppDomain-com.example.notes");
        assert_eq!(file.relative_path, "Documents/note.txt");
        assert!(!file.is_directory(), "Second record should be a file");
        assert_eq!(file.file_id, "bb1cc2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9");
        assert!(
            file.metadata_error.is_none(),
            "a well-formed blob must not be flagged"
        );
    }

    /// B6-036: an undecodable `file` BLOB used to be dropped with the `Err`
    /// ignored, and the row went out with null size and null MACB times — the
    /// same shape as a row whose backup genuinely stored none.
    #[test]
    fn undecodable_file_blob_is_recorded_not_ignored() {
        let dir = std::env::temp_dir().join(format!("seance_manifestdb_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("Manifest.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE Files (fileID TEXT PRIMARY KEY, domain TEXT, \
                 relativePath TEXT, flags INTEGER, file BLOB);",
            )
            .unwrap();
            // A BLOB that is present but is not a plist at all.
            conn.execute(
                "INSERT INTO Files VALUES ('aa', 'HomeDomain', 'Library/sms.db', 1, ?1)",
                [b"not-a-plist".as_slice()],
            )
            .unwrap();
        }

        let records = ManifestDb::parse(&db_path).unwrap();
        assert_eq!(records.len(), 1);
        let r = &records[0];
        assert!(r.size.is_none() && r.last_modified.is_none());
        assert!(
            r.metadata_error.is_some(),
            "an undecodable metadata blob must not render as 'the backup stored no metadata'"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
