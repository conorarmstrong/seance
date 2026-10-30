use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Didson Data File (DDF) carving signature. Header: "DDF" followed by a version byte (0x03, 0x04
/// or 0x05) at offset 0.
/// The 512-byte master header carries m_nNumRawBeams (le32 @16) and
/// m_nSamplesPerChannel (le32 @24), validated per version. No footer.
struct DdfSignature;

impl FileSignature for DdfSignature {
    fn name(&self) -> &str {
        "DDF"
    }
    fn extensions(&self) -> &[&str] {
        &["ddf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 28 || &buf[0..3] != b"DDF" {
            return None;
        }
        let version = buf[3];
        let num_beams = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
        let samples = u32::from_le_bytes([buf[24], buf[25], buf[26], buf[27]]);
        match version {
            0x03 | 0x04 => {
                if num_beams != 96 && num_beams != 48 {
                    return None;
                }
                if samples != 512 {
                    return None;
                }
            }
            0x05 => {
                if !matches!(num_beams, 48 | 96 | 64 | 128) {
                    return None;
                }
                if !(512..=4096).contains(&samples) {
                    return None;
                }
            }
            _ => return None,
        }
        Some(RecoveryInit {
            min_filesize: 512,
            extension: "ddf".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[b'D', b'D', b'F', 0x03], Arc::new(DdfSignature));
    registry.register(0, &[b'D', b'D', b'F', 0x04], Arc::new(DdfSignature));
    registry.register(0, &[b'D', b'D', b'F', 0x05], Arc::new(DdfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(version: u8, beams: u32, samples: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 28];
        buf[0..3].copy_from_slice(b"DDF");
        buf[3] = version;
        buf[16..20].copy_from_slice(&beams.to_le_bytes());
        buf[24..28].copy_from_slice(&samples.to_le_bytes());
        buf
    }

    #[test]
    fn test_ddf_header_match() {
        assert!(DdfSignature
            .header_check(&header(0x03, 96, 512), 0)
            .is_some());
        assert!(DdfSignature
            .header_check(&header(0x05, 128, 2048), 0)
            .is_some());
    }

    #[test]
    fn test_ddf_no_match() {
        // Wrong magic.
        assert!(DdfSignature
            .header_check(&header(0x02, 96, 512), 0)
            .is_none());
        // v3 with invalid beam count.
        assert!(DdfSignature
            .header_check(&header(0x03, 100, 512), 0)
            .is_none());
        // v3 with wrong samples-per-channel.
        assert!(DdfSignature
            .header_check(&header(0x04, 48, 256), 0)
            .is_none());
    }
}
