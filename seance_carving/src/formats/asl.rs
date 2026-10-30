use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Adobe Layer Style carving signature. Header: 00 02 "8BSL" 00 03 00 at offset 0 (9 bytes). No
/// footer; max-size cutoff.
///
/// # This is not the Apple System Log (`CARVE-012`)
///
/// On macOS, `.asl` is the Apple System Log store under `/var/log/asl/`, and
/// the two formats share nothing: `8BSL` is Photoshop's tag and can never
/// match one. While this signature answered to the name `ASL` the public
/// formats catalogue listed "ASL / .asl", which a macOS examiner reads as the
/// system log — so a carve that returned none read as "there were none"
/// rather than as "this tool never looked". The name is therefore the format's
/// own, `Adobe Layer Style`, and the extension is `.asl8bsl` so that neither
/// the catalogue nor a carved file's name can be mistaken for Apple's.
///
/// Apple System Log support is `ROADMAP` §1.6 and is a separate format; when
/// it lands it takes the name `Apple System Log` and the bare `.asl`.
struct AslSignature;

const ASL_MAGIC: &[u8] = &[0x00, 0x02, b'8', b'B', b'S', b'L', 0x00, 0x03, 0x00];

impl FileSignature for AslSignature {
    fn name(&self) -> &str {
        "Adobe Layer Style"
    }
    fn extensions(&self) -> &[&str] {
        &["asl8bsl"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= ASL_MAGIC.len() && &buf[0..ASL_MAGIC.len()] == ASL_MAGIC {
            Some(RecoveryInit {
                min_filesize: 9,
                extension: "asl8bsl".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, ASL_MAGIC, Arc::new(AslSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The name and the extension are the assertion, not a label: while they
    /// said `ASL` / `.asl` the formats catalogue told a macOS examiner this
    /// build recovers Apple System Log records, which it does not
    /// (`CARVE-012`).
    #[test]
    fn the_signature_names_the_format_it_matches_and_not_apples() {
        let sig = AslSignature;
        assert_eq!(sig.name(), "Adobe Layer Style");
        assert_eq!(sig.extensions(), &["asl8bsl"]);
        assert!(
            !sig.extensions().contains(&"asl"),
            "the bare .asl extension belongs to the Apple System Log, which nothing here \
             carves; claiming it makes an empty carve read as an empty log"
        );
        let mut buf = ASL_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            sig.header_check(&buf, 0).expect("matches").extension,
            "asl8bsl"
        );
    }

    #[test]
    fn test_asl_header_match() {
        let sig = AslSignature;
        let mut buf = ASL_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_asl_no_match() {
        let sig = AslSignature;
        // Corrupt the "8BSL" tag.
        assert!(sig
            .header_check(&[0x00, 0x02, b'8', b'B', b'X', b'L', 0x00, 0x03, 0x00], 0)
            .is_none());
        // Too short.
        assert!(sig.header_check(&[0x00, 0x02, b'8', b'B'], 0).is_none());
    }
}
