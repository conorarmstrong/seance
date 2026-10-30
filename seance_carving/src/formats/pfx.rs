use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PKCS#12 keystore (PFX) carving signature. Header: the pkcs7-data OID 06 09 2a 86 48 86 f7 0d 01
/// 07 01 (11 bytes) at
/// offset 11, wrapped by the ASN.1 DER SEQUENCE/INTEGER prefix at offset 0. The
/// 2-byte definite length at offset 2 gives the exact file size (length + 4).
struct PfxSignature;

const PFX_MAGIC: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,
];
const PFX_MAGIC_OFFSET: usize = 11;

impl FileSignature for PfxSignature {
    fn name(&self) -> &str {
        "PFX"
    }

    fn extensions(&self) -> &[&str] {
        &["pfx"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let magic_end = PFX_MAGIC_OFFSET + PFX_MAGIC.len();
        if buf.len() < magic_end {
            return None;
        }
        // ASN.1 DER prefix: SEQUENCE (30 82 XX XX), INTEGER version 3 (02 01 03),
        // then inner SEQUENCE (30 82).
        if !(buf[0] == 0x30
            && buf[1] == 0x82
            && buf[4] == 0x02
            && buf[5] == 0x01
            && buf[6] == 0x03
            && buf[7] == 0x30
            && buf[8] == 0x82)
        {
            return None;
        }
        if &buf[PFX_MAGIC_OFFSET..magic_end] != PFX_MAGIC {
            return None;
        }
        let size = ((buf[2] as u64) << 8) + buf[3] as u64 + 4;
        if size < 22 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 22,
            extension: "pfx".to_string(),
            calculated_file_size: Some(size),
        })
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
    registry.register(PFX_MAGIC_OFFSET as u16, PFX_MAGIC, Arc::new(PfxSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal valid PFX header with a definite length of 0x0100.
    fn valid_pfx() -> Vec<u8> {
        let mut buf = vec![0u8; PFX_MAGIC_OFFSET + PFX_MAGIC.len()];
        buf[0] = 0x30;
        buf[1] = 0x82;
        buf[2] = 0x01; // length high byte
        buf[3] = 0x00; // length low byte -> size = 0x0100 + 4
        buf[4] = 0x02;
        buf[5] = 0x01;
        buf[6] = 0x03;
        buf[7] = 0x30;
        buf[8] = 0x82;
        buf[PFX_MAGIC_OFFSET..].copy_from_slice(PFX_MAGIC);
        buf
    }

    #[test]
    fn test_pfx_header_match() {
        let sig = PfxSignature;
        let init = sig.header_check(&valid_pfx(), 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x0100 + 4));
    }

    #[test]
    fn test_pfx_no_match() {
        let sig = PfxSignature;
        // Wrong ASN.1 prefix byte.
        let mut bad = valid_pfx();
        bad[0] = 0x31;
        assert!(sig.header_check(&bad, 0).is_none());
        // Missing pkcs7-data OID.
        let mut bad2 = valid_pfx();
        bad2[PFX_MAGIC_OFFSET] = 0x00;
        assert!(sig.header_check(&bad2, 0).is_none());
    }
}
