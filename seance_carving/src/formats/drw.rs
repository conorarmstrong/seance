use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Pro/ENGINEER Drawing carving signature. Header: "#UGC:2 DRAWING" at offset 0, followed by four
/// printable bytes at
/// offsets 14-17. Footer: "#END_OF_UGC" (file terminates 1 byte past it).
struct DrwSignature;

const DRW_FOOTER: &[u8] = b"#END_OF_UGC";

fn is_print(b: u8) -> bool {
    (0x20..=0x7e).contains(&b)
}

impl FileSignature for DrwSignature {
    fn name(&self) -> &str {
        "DRW"
    }

    fn extensions(&self) -> &[&str] {
        &["drw"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 18
            && &buf[0..14] == b"#UGC:2 DRAWING"
            && is_print(buf[14])
            && is_print(buf[15])
            && is_print(buf[16])
            && is_print(buf[17])
        {
            Some(RecoveryInit {
                min_filesize: DRW_FOOTER.len() as u64,
                extension: "drw".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // PhotoRec's file_check_drw finds "#END_OF_UGC" and keeps one extra byte.
        match footer_end_spanning(buf, recovery, DRW_FOOTER, 0) {
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
    registry.register(0, b"#UGC:2 DRAWING", Arc::new(DrwSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drw_header_match() {
        let sig = DrwSignature;
        // "#UGC:2 DRAWING" + 4 printable bytes.
        assert!(sig.header_check(b"#UGC:2 DRAWINGabcd", 0).is_some());
    }

    #[test]
    fn test_drw_no_match() {
        let sig = DrwSignature;
        // Non-printable trailing bytes.
        assert!(sig
            .header_check(b"#UGC:2 DRAWING\x00\x01\x02\x03", 0)
            .is_none());
        // Wrong magic.
        assert!(sig.header_check(b"#UGC:9 DRAWINGabcd", 0).is_none());
    }

    #[test]
    fn test_drw_footer_detection() {
        let sig = DrwSignature;
        let mut recovery = FileRecovery {
            extension: "drw".to_string(),
            file_size: 100,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 11,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = Vec::new();
        buf.extend_from_slice(b"xx");
        buf.extend_from_slice(DRW_FOOTER);
        buf.push(b'\n');
        // footer at pos 2, size = 100 + 2 + 11 + 1 = 114
        assert_eq!(
            sig.data_check(&buf, &mut recovery),
            DataCheckResult::Stop(114)
        );
    }
}
