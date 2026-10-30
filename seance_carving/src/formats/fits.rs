use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// FITS (Flexible Image Transport System) carving signature. Header: "SIMPLE =" (two spaces before
/// '=') at offset 0. PhotoRec
/// computes the exact size by parsing 80-byte header cards (BITPIX/NAXIS) and walking
/// XTENSION HDUs across a double buffer. That size computation would undercarve valid
/// multi-extension files if approximated per-block, so it is degraded to a validated
/// header-magic + max-size carve (min 2880-byte block).
struct FitsSignature;

impl FitsSignature {
    const MAGIC: &'static [u8] = b"SIMPLE  =";
}

impl FileSignature for FitsSignature {
    fn name(&self) -> &str {
        "FITS"
    }

    fn extensions(&self) -> &[&str] {
        &["fits"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= Self::MAGIC.len() && &buf[0..Self::MAGIC.len()] == Self::MAGIC {
            Some(RecoveryInit {
                min_filesize: 2880,
                extension: "fits".to_string(),
                calculated_file_size: None,
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
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, FitsSignature::MAGIC, Arc::new(FitsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fits_header_match() {
        let sig = FitsSignature;
        assert!(sig
            .header_check(b"SIMPLE  =                    T", 0)
            .is_some());
    }

    #[test]
    fn test_fits_no_match() {
        let sig = FitsSignature;
        // Only one space before '=' is not a FITS primary header.
        assert!(sig.header_check(b"SIMPLE = ", 0).is_none());
        assert!(sig.header_check(b"NOTFITS", 0).is_none());
    }
}
