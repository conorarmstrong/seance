use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Sisporto SP3/SPM carving signature. Header: 0x03 0x01 0x00 00 00 00 00 00 or 0x03 0x02 00 00 00
/// 00 00 00 at
/// offset 0.
/// NOTE: PhotoRec validates an embedded exam date/time and computes the exact
/// size from ~30 POS/LEN fields defined in file_sp3.h (struct SP3FileInfo). That
/// elaborate header parser is not implemented here; this is a faithful header-magic +
/// minimum-size signature (min 10240 bytes, matching PhotoRec's min_filesize).
struct Sp3Signature;

impl FileSignature for Sp3Signature {
    fn name(&self) -> &str {
        "SP3"
    }
    fn extensions(&self) -> &[&str] {
        &["sp3"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        // 0x03 0x01 .. or 0x03 0x02 .. followed by six zero bytes.
        if buf[0] == 0x03
            && (buf[1] == 0x01 || buf[1] == 0x02)
            && buf[2..8] == [0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        {
            return Some(RecoveryInit {
                min_filesize: 10240,
                extension: "sp3".to_string(),
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
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        Arc::new(Sp3Signature),
    );
    registry.register(
        0,
        &[0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        Arc::new(Sp3Signature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sp3_header_match() {
        let sig = Sp3Signature;
        assert!(sig
            .header_check(&[0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
            .is_some());
        assert!(sig
            .header_check(&[0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
            .is_some());
    }

    #[test]
    fn test_sp3_no_match() {
        let sig = Sp3Signature;
        // wrong second byte
        assert!(sig
            .header_check(&[0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 0)
            .is_none());
        // non-zero tail
        assert!(sig
            .header_check(&[0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01], 0)
            .is_none());
        // too short
        assert!(sig.header_check(&[0x03, 0x01], 0).is_none());
    }
}
