use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MS Backup file (.bkf) carving signature. Header: Microsoft Tape Format DBLK type "TAPE" at
/// offset 0, validated by the
/// mtf_db_hdr fields (fla==0, cbId==0, strType<=2, off>=52). PhotoRec's file_check
/// searches for the "SFMB" soft-file-mark footer with 0x400-block padding; that
/// backward footer search is not reproduced here (see note).
struct BkfSignature;

/// 4-byte header magic "TAPE".
const BKF_HEADER: [u8; 4] = *b"TAPE";

impl FileSignature for BkfSignature {
    fn name(&self) -> &str {
        "MS Backup file"
    }

    fn extensions(&self) -> &[&str] {
        &["bkf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 52 || buf[..BKF_HEADER.len()] != BKF_HEADER {
            return None;
        }
        let off = u16::from_le_bytes([buf[8], buf[9]]);
        let fla = u64::from_le_bytes([
            buf[20], buf[21], buf[22], buf[23], buf[24], buf[25], buf[26], buf[27],
        ]);
        let cb_id = u32::from_le_bytes([buf[36], buf[37], buf[38], buf[39]]);
        let str_type = buf[48];
        // Reject unless the tape-format invariants hold.
        if fla != 0 || cb_id != 0 || str_type > 2 || (off as usize) < 52 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 52,
            extension: "bkf".to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, &BKF_HEADER, Arc::new(BkfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_header() -> Vec<u8> {
        let mut buf = vec![0u8; 64];
        buf[..BKF_HEADER.len()].copy_from_slice(&BKF_HEADER);
        buf[8..10].copy_from_slice(&52u16.to_le_bytes()); // off >= 52
                                                          // fla (offset 20), cbId (offset 36), strType (offset 48) already zero
        buf
    }

    #[test]
    fn test_bkf_header_match() {
        let sig = BkfSignature;
        assert!(sig.header_check(&valid_header(), 0).is_some());
    }

    #[test]
    fn test_bkf_no_match() {
        let sig = BkfSignature;
        // off < 52 rejects
        let mut buf = valid_header();
        buf[8..10].copy_from_slice(&10u16.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // wrong magic rejects
        let mut buf2 = valid_header();
        buf2[0] = 0x00;
        assert!(sig.header_check(&buf2, 0).is_none());
        assert!(sig.header_check(&[0u8; 4], 0).is_none());
    }
}
