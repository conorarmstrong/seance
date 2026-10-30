use crate::checks::footer_end_spanning;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// The Games Factory / Multimedia Fusion (MFA) carving signature.
/// Header: magic "MMF2" followed by {0x04,0x00,0x00,0x00} at offset 0.
/// Footer: "!DNE!" with 0x84 trailing bytes kept after the marker
/// (PhotoRec file_search_footer extra_length=0x84).
struct MfaSignature;

const MFA_MAGIC: &[u8] = &[b'M', b'M', b'F', b'2', 0x04, 0x00, 0x00, 0x00];
const MFA_FOOTER: &[u8] = b"!DNE!";
const MFA_EXTRA: u64 = 0x84;

impl FileSignature for MfaSignature {
    fn name(&self) -> &str {
        "MFA"
    }
    fn extensions(&self) -> &[&str] {
        &["mfa"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= MFA_MAGIC.len() && &buf[0..MFA_MAGIC.len()] == MFA_MAGIC {
            Some(RecoveryInit {
                min_filesize: MFA_MAGIC.len() as u64,
                extension: "mfa".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // Scan for the "!DNE!" end marker. PhotoRec keeps footer_length + 0x84
        // bytes past the marker start as part of the recovered file.
        match footer_end_spanning(buf, recovery, MFA_FOOTER, 0) {
            Some(end) => DataCheckResult::Stop(end + MFA_EXTRA),
            None => DataCheckResult::Continue,
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MFA_MAGIC, Arc::new(MfaSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mfa_header_match() {
        let sig = MfaSignature;
        assert!(sig.header_check(b"MMF2\x04\x00\x00\x00", 0).is_some());
    }

    #[test]
    fn test_mfa_no_match() {
        let sig = MfaSignature;
        assert!(sig.header_check(b"MMF2\x05\x00\x00\x00", 0).is_none());
        assert!(sig.header_check(b"NOTMFA", 0).is_none());
    }

    #[test]
    fn test_mfa_footer_detection() {
        let sig = MfaSignature;
        let mut recovery = FileRecovery {
            extension: "mfa".to_string(),
            file_size: 1000,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 8,
            extra: 0,
            extra_bytes: Vec::new(),
        };
        let mut buf = vec![0u8; 3];
        buf.extend_from_slice(MFA_FOOTER);
        let result = sig.data_check(&buf, &mut recovery);
        assert_eq!(
            result,
            DataCheckResult::Stop(1000 + 3 + MFA_FOOTER.len() as u64 + MFA_EXTRA)
        );
    }
}
