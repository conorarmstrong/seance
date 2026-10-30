use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pro/ENGINEER ToolPath (.tph) carving signature. Ported from file_tph.c.
/// Header: "#UGC:2 MFG_TOOL_PATH" (20 bytes) at offset 0, and bytes 20..24 must be
/// printable ASCII. Footer: "#END_OF_UGC" plus one trailing byte.
struct TphSignature;

const MAGIC: &[u8] = b"#UGC:2 MFG_TOOL_PATH";
const FOOTER: &[u8] = b"#END_OF_UGC";

fn is_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

impl FileSignature for TphSignature {
    fn name(&self) -> &str {
        "TPH"
    }

    fn extensions(&self) -> &[&str] {
        &["tph"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 24
            && &buf[0..20] == MAGIC
            && is_print(buf[20])
            && is_print(buf[21])
            && is_print(buf[22])
            && is_print(buf[23])
        {
            Some(RecoveryInit {
                min_filesize: 24,
                extension: "tph".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // PhotoRec adds a 1-byte extra_length after the footer.
        if let Some(pos) = buf.windows(FOOTER.len()).position(|w| w == FOOTER) {
            return DataCheckResult::Stop(
                recovery.file_size + pos as u64 + FOOTER.len() as u64 + 1,
            );
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MAGIC, Arc::new(TphSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tph_header_match() {
        let sig = TphSignature;
        let mut buf = MAGIC.to_vec();
        buf.extend_from_slice(b"ABCD");
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_tph_no_match() {
        let sig = TphSignature;
        // Correct magic but non-printable trailing bytes.
        let mut buf = MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(&[0x41u8; 24], 0).is_none());
    }
}
