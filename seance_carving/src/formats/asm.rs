use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pro/ENGINEER Assembly carving signature. Header: "#UGC:2 ASSEMBLY " at offset 0, followed by
/// four printable bytes.
/// Footer: "#END_OF_UGC" scanned with extra_length 1.
struct AsmSignature;

const ASM_MAGIC: &[u8] = b"#UGC:2 ASSEMBLY ";
const ASM_FOOTER: &[u8] = b"#END_OF_UGC";

fn is_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

impl FileSignature for AsmSignature {
    fn name(&self) -> &str {
        "ASM"
    }

    fn extensions(&self) -> &[&str] {
        &["asm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 20 || &buf[0..16] != ASM_MAGIC {
            return None;
        }
        if !is_print(buf[16]) || !is_print(buf[17]) || !is_print(buf[18]) || !is_print(buf[19]) {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 20,
            extension: "asm".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Footer scan: "#END_OF_UGC" plus 1 extra byte (PhotoRec extra_length).
        match footer_end_spanning(buf, recovery, ASM_FOOTER, 0) {
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
    registry.register(0, ASM_MAGIC, Arc::new(AsmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asm_header_match() {
        let mut buf = Vec::new();
        buf.extend_from_slice(ASM_MAGIC);
        buf.extend_from_slice(b"abcd"); // printable
        assert!(AsmSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_asm_no_match() {
        // Wrong magic.
        assert!(AsmSignature.header_check(b"#UGC:2 PART xx", 0).is_none());
        // Correct magic but non-printable trailing bytes.
        let mut buf = Vec::new();
        buf.extend_from_slice(ASM_MAGIC);
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        assert!(AsmSignature.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_asm_footer() {
        let mut recovery = FileRecovery {
            extension: "asm".to_string(),
            file_size: 40,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 20,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0x00, 0x00, 0x00];
        buf.extend_from_slice(ASM_FOOTER);
        let result = AsmSignature.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(40 + 3 + ASM_FOOTER.len() as u64 + 1)
        );
    }
}
