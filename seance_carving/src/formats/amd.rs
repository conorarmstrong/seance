use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// AlphaCAM carving signature. Two magics at offset 0: "Licom-APS File V" (amd/atd) and
/// "Licom-APS Tool File " (amt/att). Extension refined from an embedded
/// version string. No footer.
struct AmdSignature;

const AMD_MAGIC: &[u8] = b"Licom-APS File V";
const AMT_MAGIC: &[u8] = b"Licom-APS Tool File ";

impl FileSignature for AmdSignature {
    fn name(&self) -> &str {
        "AMD"
    }

    fn extensions(&self) -> &[&str] {
        &["amd", "atd", "amt", "att"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let ext = if buf.len() >= AMD_MAGIC.len() && &buf[0..AMD_MAGIC.len()] == AMD_MAGIC {
            // amd 1.36 / atd 1.19 -- version at bytes 16..20.
            if buf.len() >= 20 && &buf[16..20] == b"1.19" {
                "atd"
            } else {
                "amd"
            }
        } else if buf.len() >= AMT_MAGIC.len() && &buf[0..AMT_MAGIC.len()] == AMT_MAGIC {
            // amt 1.19 / att 1.08 -- version at bytes 21..25.
            if buf.len() >= 25 && &buf[21..25] == b"1.08" {
                "att"
            } else {
                "amt"
            }
        } else {
            return None;
        };
        Some(RecoveryInit {
            min_filesize: 20,
            extension: ext.to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, AMD_MAGIC, Arc::new(AmdSignature));
    registry.register(0, AMT_MAGIC, Arc::new(AmdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_amd_header_match() {
        let mut buf = Vec::new();
        buf.extend_from_slice(AMD_MAGIC);
        buf.extend_from_slice(b"1.19");
        let init = AmdSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "atd");

        let mut buf2 = Vec::new();
        buf2.extend_from_slice(AMT_MAGIC);
        buf2.extend_from_slice(b"?1.08");
        let init2 = AmdSignature.header_check(&buf2, 0).unwrap();
        assert_eq!(init2.extension, "att");
    }

    #[test]
    fn test_amd_no_match() {
        assert!(AmdSignature.header_check(b"Licom-XYZ", 0).is_none());
        assert!(AmdSignature.header_check(b"not a match", 0).is_none());
    }
}
