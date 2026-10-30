use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pro/ENGINEER Drawing Form carving signature. Header at offset 0: "#UGC:2 DWGFORM" (14 bytes);
/// bytes 14..18 must be printable.
/// Footer: "#END_OF_UGC" plus 1 trailing byte.
struct FrmSignature;

const FRM_MAGIC: &[u8] = b"#UGC:2 DWGFORM";
const FRM_FOOTER: &[u8] = b"#END_OF_UGC";

impl FileSignature for FrmSignature {
    fn name(&self) -> &str {
        "FRM"
    }
    fn extensions(&self) -> &[&str] {
        &["frm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 18 && &buf[0..14] == FRM_MAGIC {
            let printable = |b: u8| (0x20..=0x7e).contains(&b);
            if !printable(buf[14])
                || !printable(buf[15])
                || !printable(buf[16])
                || !printable(buf[17])
            {
                return None;
            }
            Some(RecoveryInit {
                min_filesize: 25,
                extension: "frm".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // +1 for the extra_length byte PhotoRec keeps after the footer.
        match footer_end_spanning(buf, recovery, FRM_FOOTER, 0) {
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
    registry.register(0, FRM_MAGIC, Arc::new(FrmSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_frm_header_match() {
        let sig = FrmSignature;
        let mut buf = FRM_MAGIC.to_vec();
        buf.extend_from_slice(b"ABCD"); // printable bytes 14..18
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_frm_no_match() {
        let sig = FrmSignature;
        // wrong magic
        assert!(sig.header_check(b"#UGC:2 XXXXXXXXXXX", 0).is_none());
        // correct magic but non-printable trailing bytes
        let mut buf = FRM_MAGIC.to_vec();
        buf.extend_from_slice(&[0x00, 0x01, 0x02, 0x03]);
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_frm_footer_detection() {
        let sig = FrmSignature;
        let mut recovery = FileRecovery {
            extension: "frm".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 25,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 3];
        buf.extend_from_slice(FRM_FOOTER);
        buf.push(0x00);
        let result = sig.data_check(&buf, &mut recovery);
        // 100 + pos(3) + footer(11) + extra(1) = 115
        assert_eq!(result, DataCheckResult::Stop(115));
    }
}
