use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// SQLite database file signature detector.
/// Header: "SQLite format 3\x00" (16 bytes at offset 0)
/// Page size at offset 16 (2 bytes, big-endian), page count at offset 28 (4 bytes, big-endian).
/// File size = page_size * page_count.
/// Ref: https://www.sqlite.org/fileformat.html
struct SqliteSignature;

impl FileSignature for SqliteSignature {
    fn name(&self) -> &str {
        "SQLite"
    }

    fn extensions(&self) -> &[&str] {
        &["sqlite", "db", "sqlitedb"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 100 {
            return None;
        }
        if &buf[0..16] != b"SQLite format 3\x00" {
            return None;
        }

        // Page size: 2 bytes big-endian at offset 16
        // Value of 1 means 65536
        let raw_page_size = u16::from_be_bytes([buf[16], buf[17]]);
        let page_size: u64 = if raw_page_size == 1 {
            65536
        } else {
            raw_page_size as u64
        };

        // Page size must be a power of 2 between 512 and 65536
        if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
            return None;
        }

        // Page count: 4 bytes big-endian at offset 28
        let page_count = u32::from_be_bytes([buf[28], buf[29], buf[30], buf[31]]) as u64;

        if page_count == 0 {
            // "in-header database size" may be zero for older DBs; fall back to max-size scan
            return Some(RecoveryInit {
                min_filesize: page_size, // at least one page
                extension: "sqlite".to_string(),
                calculated_file_size: None,
            });
        }

        let file_size = page_size * page_count;
        if file_size > self.max_file_size() {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: page_size,
            extension: "sqlite".to_string(),
            calculated_file_size: Some(file_size),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // For zero-page-count DBs we just keep scanning until max size.
        // SQLite has no footer marker, so we rely on max_file_size cutoff.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2 * 1024 * 1024 * 1024 // 2 GB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, b"SQLite format 3\x00", Arc::new(SqliteSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_sqlite_header(page_size: u16, page_count: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 100];
        buf[0..16].copy_from_slice(b"SQLite format 3\x00");
        buf[16..18].copy_from_slice(&page_size.to_be_bytes());
        buf[28..32].copy_from_slice(&page_count.to_be_bytes());
        buf
    }

    #[test]
    fn test_sqlite_header_match() {
        let sig = SqliteSignature;
        let buf = make_sqlite_header(4096, 10);
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.calculated_file_size, Some(40960));
        assert_eq!(init.extension, "sqlite");
    }

    #[test]
    fn test_sqlite_page_size_65536() {
        let sig = SqliteSignature;
        // page_size=1 means 65536
        let buf = make_sqlite_header(1, 2);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(131072));
    }

    #[test]
    fn test_sqlite_zero_page_count() {
        let sig = SqliteSignature;
        let buf = make_sqlite_header(4096, 0);
        let init = sig.header_check(&buf, 0).unwrap();
        assert!(init.calculated_file_size.is_none());
    }

    #[test]
    fn test_sqlite_invalid_page_size() {
        let sig = SqliteSignature;
        // 100 is not a power of 2
        let buf = make_sqlite_header(100, 10);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_sqlite_no_match() {
        let sig = SqliteSignature;
        let buf = vec![0u8; 100];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_sqlite_too_short() {
        let sig = SqliteSignature;
        let buf = b"SQLite format 3\x00";
        assert!(sig.header_check(buf, 0).is_none());
    }
}
