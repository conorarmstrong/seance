use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MySQL (MyISAM index / table definition) carving signature. The layouts
/// are read from files written by the MySQL and MariaDB servers, not ported
/// from any source: see the fixtures in `tests/fixtures/carve015/`.
/// Two headers at offset 0:
///   - {0xfe,0xfe,0x07,0x01} -> MyISAM index file (.MYI). Big-endian
///     fields: u16 header_length at 6, u16 state_info_length at 8, u16
///     base_info_length at 10, u16 base_pos at 12, and u64 key_file_length
///     at 0x3c, which is the length of the whole index file.
///   - {0xfe,0x01} -> MySQL table definition file, version 7..10 (.frm),
///     validated by buffer[2] in 0x07..=0x0A, buffer[3]==0x09, buffer[5]==0.
struct MysqlSignature;

const MYSQL_MYI_MAGIC: &[u8] = &[0xfe, 0xfe, 0x07, 0x01];
const MYSQL_DEF_MAGIC: &[u8] = &[0xfe, 0x01];

/// The index file length a MyISAM header states, or None when the header's
/// own fields contradict each other. Held on every file written by MariaDB
/// 10.11 and MySQL 8.0 that was sampled (see the tests): the base block
/// lies inside the header, and the length is a whole number of 1024-byte
/// index blocks that holds the header. A file the server did not close
/// cleanly may state a stale length; that is a limit of the field.
fn myi_key_file_length(buf: &[u8]) -> Option<u64> {
    const LEN_AT: usize = 0x3c;
    if buf.len() < LEN_AT + 8 {
        return None;
    }
    let u16_at = |at: usize| u64::from(u16::from_be_bytes([buf[at], buf[at + 1]]));
    let header_length = u16_at(6);
    let state_info_length = u16_at(8);
    let base_info_length = u16_at(10);
    let base_pos = u16_at(12);
    if !(32..=8192).contains(&header_length)
        || state_info_length < 64
        || base_info_length < 32
        || base_pos + base_info_length > header_length
    {
        return None;
    }
    let mut len = [0u8; 8];
    len.copy_from_slice(&buf[LEN_AT..LEN_AT + 8]);
    let key_file_length = u64::from_be_bytes(len);
    if key_file_length < header_length
        || key_file_length % 1024 != 0
        || key_file_length > MYSQL_MAX_INDEX
    {
        return None;
    }
    Some(key_file_length)
}

const MYSQL_MAX_INDEX: u64 = 512 * 1024 * 1024;

impl FileSignature for MysqlSignature {
    fn name(&self) -> &str {
        "MySQL"
    }

    fn extensions(&self) -> &[&str] {
        &["MYI", "frm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // MYISAM compressed data file.
        if buf.len() >= 4 && &buf[0..4] == MYSQL_MYI_MAGIC {
            let key_file_length = myi_key_file_length(buf)?;
            return Some(RecoveryInit {
                min_filesize: 4,
                extension: "MYI".to_string(),
                calculated_file_size: Some(key_file_length),
            });
        }
        // MySQL table definition file (.frm), version 7 up to 10.
        if buf.len() >= 6
            && buf[0] == 0xfe
            && buf[1] == 0x01
            && (0x07..=0x0A).contains(&buf[2])
            && buf[3] == 0x09
            && buf[5] == 0
        {
            return Some(RecoveryInit {
                min_filesize: 6,
                extension: "frm".to_string(),
                calculated_file_size: None,
            });
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        512 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MYSQL_MYI_MAGIC, Arc::new(MysqlSignature));
    registry.register(0, MYSQL_DEF_MAGIC, Arc::new(MysqlSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mysql_header_match() {
        let sig = MysqlSignature;
        // frm table definition.
        assert_eq!(
            sig.header_check(&[0xfe, 0x01, 0x08, 0x09, 0x00, 0x00], 0)
                .map(|r| r.extension),
            Some("frm".to_string())
        );
    }

    #[test]
    fn test_mysql_no_match() {
        let sig = MysqlSignature;
        // frm-like but buffer[3] wrong.
        assert!(sig
            .header_check(&[0xfe, 0x01, 0x08, 0x00, 0x00, 0x00], 0)
            .is_none());
        // Unrelated bytes.
        assert!(sig
            .header_check(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
            .is_none());
    }

    // Synthetic table files written by mariadb 10.11.19 and mysql 8.0 under
    // docker (MyISAM tables of a few rows). Not case evidence: they grade the
    // header check on files the servers wrote, and no real-world claim.
    const MARIADB_NOKEY: &[u8] =
        include_bytes!("../../tests/fixtures/carve015/myisam_mariadb_nokey.MYI");
    const MYSQL8_A: &[u8] = include_bytes!("../../tests/fixtures/carve015/myisam_mysql8_a.MYI");
    const MARIADB_MANY_HEAD: &[u8] =
        include_bytes!("../../tests/fixtures/carve015/myisam_mariadb_many_head.bin");

    #[test]
    fn server_written_myi_headers_pass_and_state_the_file_length() {
        let sig = MysqlSignature;
        for (name, file) in [("mariadb nokey", MARIADB_NOKEY), ("mysql8 a", MYSQL8_A)] {
            let init = sig.header_check(&file[..512], 0).expect(name);
            assert_eq!(init.extension, "MYI");
            assert_eq!(init.calculated_file_size, Some(file.len() as u64), "{name}");
        }
        // A 14 MB index with five keys: header 551 bytes.
        let init = sig.header_check(MARIADB_MANY_HEAD, 0).expect("many");
        assert_eq!(init.calculated_file_size, Some(14_090_240));
    }

    #[test]
    fn the_myi_magic_alone_is_refused() {
        let sig = MysqlSignature;
        for filler in [0x00u8, 0xff, b'a'] {
            let mut buf = vec![filler; 512];
            buf[..4].copy_from_slice(MYSQL_MYI_MAGIC);
            assert!(sig.header_check(&buf, 0).is_none(), "filler {filler:#x}");
        }
        assert!(sig.header_check(MYSQL_MYI_MAGIC, 0).is_none());
        // A real header whose length field is not a whole index block.
        let mut bad = MARIADB_NOKEY[..512].to_vec();
        bad[0x3c + 7] = 0x01;
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
