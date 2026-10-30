//! Manifest.mbdb (binary) parser for legacy iOS 3-9 backups
//!
//! Binary format structure:
//! - Header: "mbdb" (4 bytes) + version (2 bytes, big-endian)
//! - Records: Repeated entries with:
//!   - Domain (length-prefixed string)
//!   - Filename (length-prefixed string)
//!   - 3x extended strings (linktarget, datahash, enckey)
//!   - Mode (2 bytes)
//!   - Various metadata fields (4-8 bytes each)
//!   - Properties (key-value pairs)
//!
//! File IDs are resolved from the companion Manifest.mbdx index file. When the
//! index is missing or a record is not found in it, the ID is derived as
//! SHA-1(domain + "-" + filename), matching the algorithm used by iTunes.

use anyhow::{anyhow, Context, Result};
use byteorder::{BigEndian, ReadBytesExt};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Seek};
use std::path::Path;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct MbdbRecord {
    /// SHA-1 file ID (from mbdx index or derived from domain+path)
    pub file_id: String,
    pub domain: String,
    pub relative_path: String,
    pub is_directory: bool,
    pub mode: u16,
    pub inode: u64,
    pub user_id: u32,
    pub group_id: u32,
    pub last_modified: u32,
    pub size: u64,
    /// Per-file encryption key (from 3rd extended string, encrypted backups)
    pub encryption_key: Option<Vec<u8>>,
    /// Data hash / checksum (from 2nd extended string)
    pub data_hash: Option<Vec<u8>>,
    /// Symbolic link target (from 1st extended string)
    pub link_target: Option<String>,
}

/// The outcome of walking a `Manifest.mbdb`.
///
/// The parse can stop mid-stream on a desync, in which case `records` is a
/// PREFIX of the backup's file list. Returning the bare `Vec` made that prefix
/// indistinguishable from a complete inventory, and a backup listing missing a
/// chat database reads to an examiner as a device that never had one (B6-019).
#[derive(Debug, Default)]
pub struct MbdbParse {
    pub records: Vec<MbdbRecord>,
    /// Set when the walk stopped before the end of the file: `(byte offset,
    /// parse error)`. `None` means a clean end on a record boundary.
    pub stopped_at: Option<(usize, String)>,
}

pub struct ManifestMbdb;

impl ManifestMbdb {
    /// Parse Manifest.mbdb and return all file records, plus whether the walk
    /// ended cleanly.
    ///
    /// Automatically loads the companion Manifest.mbdx index from the same
    /// directory if present. Falls back to SHA-1 derived file IDs otherwise.
    pub fn parse(mbdb_path: &Path) -> Result<MbdbParse> {
        // Try to load the mbdx index from the same directory
        let mbdx_mapping = if let Some(dir) = mbdb_path.parent() {
            let mbdx_path = dir.join("Manifest.mbdx");
            if mbdx_path.exists() {
                Self::load_mbdx_mapping(&mbdx_path).unwrap_or_default()
            } else {
                HashMap::new()
            }
        } else {
            HashMap::new()
        };

        let file = File::open(mbdb_path).context("Failed to open Manifest.mbdb")?;
        let mut reader = BufReader::new(file);

        // Read and validate header
        let mut signature = [0u8; 4];
        reader.read_exact(&mut signature)?;

        if &signature != b"mbdb" {
            return Err(anyhow!("Invalid Manifest.mbdb signature"));
        }

        let _version = reader.read_u16::<BigEndian>()?;

        let mut records = Vec::new();
        let mut stopped_at: Option<(usize, String)> = None;

        // Track byte offset for mbdx mapping (offset within record stream,
        // relative to start of file including the 6-byte header)
        // A clean end-of-file is only "normal" when it falls on a record
        // boundary. Track the offset before each record so a parse error mid-way
        // (a desync) can be told apart from a genuine end, and never silently
        // drops the rest of the manifest.
        loop {
            // Current position in file = offset used for mbdx lookup
            let record_offset = reader.stream_position().unwrap_or(0) as usize;
            let at_eof = reader.fill_buf().map(|b| b.is_empty()).unwrap_or(true);
            if at_eof {
                break; // clean end on a record boundary
            }

            match Self::parse_record(&mut reader) {
                Ok(mut record) => {
                    // Resolve file_id: prefer mbdx mapping, fall back to SHA-1 derivation
                    // mbdx offsets are stored as (offset_in_mbdb + 6) in the index
                    record.file_id = if let Some(id) = mbdx_mapping.get(&record_offset) {
                        id.clone()
                    } else {
                        Self::derive_file_id(&record.domain, &record.relative_path)
                    };
                    records.push(record);
                }
                Err(e) => {
                    // We were mid-record (not at EOF) — a parse desync. Surface it
                    // instead of silently truncating the rest of the manifest.
                    warn!(
                        "Manifest.mbdb parse stopped after {} records at offset {}: {}",
                        records.len(),
                        record_offset,
                        e
                    );
                    stopped_at = Some((record_offset, e.to_string()));
                    break;
                }
            }
        }

        Ok(MbdbParse {
            records,
            stopped_at,
        })
    }

    /// Derive the file ID as SHA-1(domain + "-" + filename), matching iTunes behavior.
    fn derive_file_id(domain: &str, filename: &str) -> String {
        let mut hasher = Sha1::new();
        hasher.update(domain.as_bytes());
        hasher.update(b"-");
        hasher.update(filename.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Load the Manifest.mbdx index file.
    ///
    /// Format: "mbdx" (4B) + version (2B) + record_count (4B) +
    /// repeated [file_id (20B) + mbdb_offset (4B) + mode (2B)]
    fn load_mbdx_mapping(mbdx_path: &Path) -> Result<HashMap<usize, String>> {
        let data = std::fs::read(mbdx_path).context("Failed to read Manifest.mbdx")?;

        if data.len() < 4 || &data[..4] != b"mbdx" {
            return Err(anyhow!("Invalid Manifest.mbdx signature"));
        }

        // Skip signature (4) + version (2) + record_count (4) = 10 bytes header
        let mut offset = 10;
        let mut mapping = HashMap::new();

        while offset + 26 <= data.len() {
            // 20-byte file ID (SHA-1 hash)
            let file_id = hex::encode(&data[offset..offset + 20]);
            offset += 20;

            // 4-byte offset into Manifest.mbdb (big-endian)
            let mbdb_offset = u32::from_be_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            // 2-byte mode (skip)
            offset += 2;

            // The mbdx offset is relative to the start of the mbdb file
            // (includes the 6-byte header), matching stream_position()
            mapping.insert(mbdb_offset, file_id);
        }

        Ok(mapping)
    }

    fn parse_record<R: Read>(reader: &mut R) -> Result<MbdbRecord> {
        // Read domain (length-prefixed string)
        let domain = Self::read_string(reader)?;

        // Read filename/relative path
        let relative_path = Self::read_string(reader)?;

        // Read 3 extended strings
        let link_target_raw = Self::read_string_raw(reader)?;
        let data_hash_raw = Self::read_string_raw(reader)?;
        let enc_key_raw = Self::read_string_raw(reader)?;

        // Read mode (2 bytes, big-endian)
        let mode = reader.read_u16::<BigEndian>()?;

        // Metadata fields:
        // inode (4), unknown (4), userid (4), groupid (4),
        // mtime (4), atime (4), ctime (4), file_length (8), flag (1)
        let inode = reader.read_u32::<BigEndian>()? as u64;
        let _unknown = reader.read_u32::<BigEndian>()?;
        let user_id = reader.read_u32::<BigEndian>()?;
        let group_id = reader.read_u32::<BigEndian>()?;
        let last_modified = reader.read_u32::<BigEndian>()?; // mtime
        let _atime = reader.read_u32::<BigEndian>()?;
        let _ctime = reader.read_u32::<BigEndian>()?;
        let size = reader.read_u64::<BigEndian>()?;
        let _flag = reader.read_u8()?;

        // Read number of properties
        let num_props = reader.read_u8()?;

        // Skip properties (key-value pairs). Values may be arbitrary binary
        // (e.g. on Media/PhotoStreams records), so read them as raw bytes — a
        // UTF-8 decode here would desync and silently drop the rest of the
        // manifest (which previously lost ~60% of files on some backups).
        for _ in 0..num_props {
            Self::read_string_raw(reader)?; // key
            Self::read_string_raw(reader)?; // value
        }

        // Determine if directory based on mode
        const S_IFDIR: u16 = 0x4000;
        let is_directory = (mode & 0xF000) == S_IFDIR;

        // Process extended strings
        let link_target = if link_target_raw.is_empty() {
            None
        } else {
            String::from_utf8(link_target_raw).ok()
        };

        let data_hash = if data_hash_raw.is_empty() {
            None
        } else {
            Some(data_hash_raw)
        };

        // Encryption key: strip first 4 bytes (protection class prefix),
        // same as the NS.data format in SQLite manifests
        let encryption_key = if enc_key_raw.len() > 4 {
            Some(enc_key_raw[4..].to_vec())
        } else {
            None
        };

        Ok(MbdbRecord {
            file_id: String::new(), // Resolved by caller after parse
            domain,
            relative_path,
            is_directory,
            mode,
            inode,
            user_id,
            group_id,
            last_modified,
            size,
            encryption_key,
            data_hash,
            link_target,
        })
    }

    /// Read a length-prefixed string (2 bytes length + UTF-8 data)
    fn read_string<R: Read>(reader: &mut R) -> Result<String> {
        let raw = Self::read_string_raw(reader)?;
        if raw.is_empty() {
            return Ok(String::new());
        }
        String::from_utf8(raw).context("Invalid UTF-8 in MBDB string")
    }

    /// Read a length-prefixed byte string (2 bytes length + raw data)
    fn read_string_raw<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
        let len = reader.read_u16::<BigEndian>()?;

        if len == 0xFFFF {
            // Special value indicating empty/null string
            return Ok(Vec::new());
        }

        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn fixture_dir() -> PathBuf {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent()
            .unwrap()
            .join("test_data")
            .join("ios_backup_fixtures")
    }

    #[test]
    fn test_fixture_mbdb_basic() {
        let mbdb_path = fixture_dir().join("mbdb_basic").join("Manifest.mbdb");
        let parsed = ManifestMbdb::parse(&mbdb_path).unwrap();
        assert!(
            parsed.stopped_at.is_none(),
            "a well-formed manifest must report a clean end"
        );
        let records = parsed.records;

        assert_eq!(records.len(), 2, "MBDB fixture should have 2 records");

        // First record is a directory
        let dir = &records[0];
        assert_eq!(dir.domain, "AppDomain-com.example.legacy");
        assert_eq!(dir.relative_path, "");
        assert!(dir.is_directory, "First record should be a directory");
        // File ID should be resolved (from mbdx or derived)
        assert_eq!(
            dir.file_id.len(),
            40,
            "File ID should be 40 hex chars, got '{}'",
            dir.file_id
        );

        // Second record is a file
        let file = &records[1];
        assert_eq!(file.domain, "AppDomain-com.example.legacy");
        assert_eq!(file.relative_path, "Documents/item.dat");
        assert!(!file.is_directory, "Second record should be a file");
        assert_eq!(
            file.file_id.len(),
            40,
            "File ID should be 40 hex chars, got '{}'",
            file.file_id
        );
    }

    #[test]
    fn test_fixture_mbdb_with_mbdx() {
        // The fixture includes Manifest.mbdx — verify file IDs come from the index
        let mbdb_path = fixture_dir().join("mbdb_basic").join("Manifest.mbdb");
        let records = ManifestMbdb::parse(&mbdb_path).unwrap().records;

        // The second file's ID from mbdx should be the 40-zero-then-02 hash
        let file = &records[1];
        assert_eq!(
            file.file_id, "0000000000000000000000000000000000000002",
            "File ID should come from mbdx index"
        );
    }

    #[test]
    fn test_derive_file_id() {
        let id = ManifestMbdb::derive_file_id("HomeDomain", "Library/Preferences/test.plist");
        assert_eq!(id.len(), 40, "Derived ID should be 40 hex chars");

        // Same inputs should produce same ID
        let id2 = ManifestMbdb::derive_file_id("HomeDomain", "Library/Preferences/test.plist");
        assert_eq!(id, id2, "Derived IDs should be deterministic");

        // Different inputs should produce different ID
        let id3 = ManifestMbdb::derive_file_id("HomeDomain", "Library/Preferences/other.plist");
        assert_ne!(id, id3, "Different paths should produce different IDs");
    }

    /// B6-019: a manifest that desyncs mid-record yields a PREFIX of the file
    /// list. The parser must say so; a caller that cannot tell a prefix from a
    /// whole inventory publishes a backup listing that is silently short.
    #[test]
    fn mid_stream_desync_is_reported_not_swallowed() {
        let mbdb_path = fixture_dir().join("mbdb_basic").join("Manifest.mbdb");
        let whole = std::fs::read(&mbdb_path).expect("fixture readable");
        let clean = ManifestMbdb::parse(&mbdb_path).unwrap();
        assert!(clean.stopped_at.is_none());
        assert_eq!(clean.records.len(), 2);

        // Cut the file inside its final record: header + first record survive,
        // the second cannot be read to its end.
        let dir = std::env::temp_dir().join(format!("seance_mbdb_trunc_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let truncated = dir.join("Manifest.mbdb");
        std::fs::write(&truncated, &whole[..whole.len() - 8]).unwrap();

        let parsed = ManifestMbdb::parse(&truncated).unwrap();
        assert!(
            parsed.records.len() < clean.records.len(),
            "the truncated manifest must yield fewer records"
        );
        let (offset, err) = parsed
            .stopped_at
            .expect("a mid-record stop must be reported, not returned as a clean end");
        assert!(offset > 0, "the stop offset locates the desync");
        assert!(!err.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_load_mbdx_mapping() {
        let mbdx_path = fixture_dir().join("mbdb_basic").join("Manifest.mbdx");
        let mapping = ManifestMbdb::load_mbdx_mapping(&mbdx_path).unwrap();

        // Should have at least one entry
        assert!(!mapping.is_empty(), "MBDX mapping should not be empty");

        // All file IDs should be 40 hex chars
        for id in mapping.values() {
            assert_eq!(
                id.len(),
                40,
                "MBDX file ID should be 40 hex chars, got '{}'",
                id
            );
        }
    }
}
