use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PostScript / Encapsulated PostScript carving signature. Header: "%!PS-Adobe-" at offset 0.
/// Footer: "%%EOF" plus one trailing byte.
/// Extension is "eps" when "EPSF-" appears in the first line, else "ps".
struct PsSignature;

const PS_MAGIC: &[u8] = b"%!PS-Adobe-";
const PS_FOOTER: &[u8] = b"%%EOF";

impl FileSignature for PsSignature {
    fn name(&self) -> &str {
        "PS"
    }

    fn extensions(&self) -> &[&str] {
        &["ps", "eps"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < PS_MAGIC.len() || &buf[..PS_MAGIC.len()] != PS_MAGIC {
            return None;
        }
        let mut ext = "ps";
        let end = buf.len().min(20);
        let mut i = PS_MAGIC.len();
        while i < end {
            match buf[i] {
                b'\n' => break,
                b'E' if i + 5 <= buf.len() && &buf[i..i + 5] == b"EPSF-" => {
                    ext = "eps";
                    break;
                }
                _ => {}
            }
            i += 1;
        }
        Some(RecoveryInit {
            min_filesize: PS_MAGIC.len() as u64,
            extension: ext.to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // file_search_footer with extra_length 1: keep one byte past "%%EOF".
        match footer_end_spanning(buf, recovery, PS_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end + 1),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, PS_MAGIC, Arc::new(PsSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ps_header_match() {
        let sig = PsSignature;
        let init = sig.header_check(b"%!PS-Adobe-3.0\n", 0).unwrap();
        assert_eq!(init.extension, "ps");
        let init = sig.header_check(b"%!PS-Adobe-3.0 EPSF-3.0\n", 0).unwrap();
        assert_eq!(init.extension, "eps");
    }

    #[test]
    fn test_ps_no_match() {
        let sig = PsSignature;
        assert!(sig.header_check(b"%!PDF-Adobe-", 0).is_none());
        assert!(sig.header_check(b"%!PS", 0).is_none());
    }

    #[test]
    fn test_ps_footer_detection() {
        let sig = PsSignature;
        let mut recovery = FileRecovery {
            extension: "ps".to_string(),
            file_size: 200,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 11,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let buf = b"data%%EOF\n";
        let result = sig.data_check(buf, &mut recovery);
        // 200 + pos(4) + footer(5) + extra(1) = 210
        assert_eq!(result, DataCheckResult::Stop(210));
    }
}
