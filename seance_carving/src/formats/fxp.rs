use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FX Preset (.fxp) carving signature. Header at offset 0: "CcnK". The size field (be32 at offset
/// 4) must be >= 60
/// (sizeof header less the 8 bytes it excludes), and the inner magic at offset 8
/// must be "FPCh". The size field (byteSize in the VST FXP layout) counts the
/// bytes that follow it, not the "CcnK" magic and the field itself, so the file
/// is size + 8 bytes. PhotoRec takes the field as the file size and so loses the
/// last 8 bytes; that is not ported.
struct FxpSignature;

const FXP_MAGIC: &[u8] = b"CcnK";

impl FileSignature for FxpSignature {
    fn name(&self) -> &str {
        "FXP"
    }
    fn extensions(&self) -> &[&str] {
        &["fxp"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 12 && &buf[0..4] == FXP_MAGIC {
            let size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
            // sizeof(struct fxp_header) == 60, of which byteSize does not
            // count the first 8 bytes (the magic and itself).
            let file_size = size as u64 + 8;
            if file_size < 60 {
                return None;
            }
            if &buf[8..12] != b"FPCh" {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 60,
                extension: "fxp".to_string(),
                calculated_file_size: Some(file_size),
            })
        } else {
            None
        }
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
    registry.register(0, FXP_MAGIC, Arc::new(FxpSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fxp_header_match() {
        let sig = FxpSignature;
        let mut buf = FXP_MAGIC.to_vec();
        buf.extend_from_slice(&100u32.to_be_bytes()); // size = 100
        buf.extend_from_slice(b"FPCh");
        let init = sig.header_check(&buf, 0).unwrap();
        // byteSize 100 counts the bytes after the size field: the file is 108.
        assert_eq!(init.calculated_file_size, Some(108));
    }

    #[test]
    fn test_fxp_no_match() {
        let sig = FxpSignature;
        // size too small: 51 + 8 is 59, under the 60-byte header
        let mut small = FXP_MAGIC.to_vec();
        small.extend_from_slice(&51u32.to_be_bytes());
        small.extend_from_slice(b"FPCh");
        assert!(sig.header_check(&small, 0).is_none());
        // the smallest whole file: byteSize 52 is the 60-byte header alone
        let mut least = FXP_MAGIC.to_vec();
        least.extend_from_slice(&52u32.to_be_bytes());
        least.extend_from_slice(b"FPCh");
        assert_eq!(
            sig.header_check(&least, 0).unwrap().calculated_file_size,
            Some(60)
        );
        // wrong inner magic
        let mut bad = FXP_MAGIC.to_vec();
        bad.extend_from_slice(&100u32.to_be_bytes());
        bad.extend_from_slice(b"XXXX");
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
