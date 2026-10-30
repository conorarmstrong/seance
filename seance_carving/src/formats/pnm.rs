use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Netpbm (PBM/PGM/PPM) carving signature. Header: "P1\n# " .. "P6\n# " at offset 0, followed by
/// three printable bytes.
/// No footer; extension derived from the magic number (P1/P4 pbm, P2/P5 pgm, P3/P6 ppm).
struct PnmSignature;

fn is_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

impl FileSignature for PnmSignature {
    fn name(&self) -> &str {
        "PNM"
    }

    fn extensions(&self) -> &[&str] {
        &["pnm", "pbm", "pgm", "ppm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 || buf[0] != b'P' {
            return None;
        }
        let ext = match buf[1] {
            b'1' | b'4' => "pbm",
            b'2' | b'5' => "pgm",
            b'3' | b'6' => "ppm",
            _ => return None,
        };
        if buf[2] != b'\n' || buf[3] != b'#' || buf[4] != b' ' {
            return None;
        }
        if !is_print(buf[5]) || !is_print(buf[6]) || !is_print(buf[7]) {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 8,
            extension: ext.to_string(),
            calculated_file_size: None,
        })
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
    registry.register(0, b"P1\n# ", Arc::new(PnmSignature));
    registry.register(0, b"P2\n# ", Arc::new(PnmSignature));
    registry.register(0, b"P3\n# ", Arc::new(PnmSignature));
    registry.register(0, b"P4\n# ", Arc::new(PnmSignature));
    registry.register(0, b"P5\n# ", Arc::new(PnmSignature));
    registry.register(0, b"P6\n# ", Arc::new(PnmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pnm_header_match() {
        let sig = PnmSignature;
        let init = sig.header_check(b"P3\n# abc", 0).unwrap();
        assert_eq!(init.extension, "ppm");
        let init = sig.header_check(b"P4\n# xyz", 0).unwrap();
        assert_eq!(init.extension, "pbm");
    }

    #[test]
    fn test_pnm_no_match() {
        let sig = PnmSignature;
        // Wrong magic digit.
        assert!(sig.header_check(b"P7\n# abc", 0).is_none());
        // Non-printable trailing byte.
        assert!(sig.header_check(b"P1\n# \x00bc", 0).is_none());
        // Too short.
        assert!(sig.header_check(b"P1\n#", 0).is_none());
    }
}
