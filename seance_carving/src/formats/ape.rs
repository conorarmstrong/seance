use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Monkey's Audio carving signature. Header: "MAC " at offset 0. Version-dependent validation of
/// the descriptor
/// (>=3.98) or the legacy header (channels/sample-rate/frames). No footer.
struct ApeSignature;

const APE_MAGIC: &[u8] = b"MAC ";

fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

impl FileSignature for ApeSignature {
    fn name(&self) -> &str {
        "APE"
    }

    fn extensions(&self) -> &[&str] {
        &["ape"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // sizeof(APE_HEADER_OLD) == 32
        if buf.len() < 32 || &buf[0..4] != APE_MAGIC {
            return None;
        }
        let n_version = le16(buf, 4);
        if n_version >= 3980 {
            // APE_DESCRIPTOR path (sizeof == 52, APE_HEADER == 24).
            let n_descriptor_bytes = le32(buf, 8) as usize;
            if n_descriptor_bytes < 52 {
                return None;
            }
            let n_header_data_bytes = le32(buf, 20);
            if n_header_data_bytes > 0 && n_header_data_bytes < 24 {
                return None;
            }
            if n_descriptor_bytes >= buf.len() {
                return None;
            }
            if n_descriptor_bytes + 24 >= buf.len() {
                return None;
            }
            // APE_HEADER.nChannels at descriptor+18.
            let n_channels = le16(buf, n_descriptor_bytes + 18);
            if !(1..=2).contains(&n_channels) {
                return None;
            }
        } else {
            // Legacy APE_HEADER_OLD path.
            let n_channels = le16(buf, 10);
            if !(1..=2).contains(&n_channels) {
                return None;
            }
            if le32(buf, 12) == 0 {
                return None;
            }
            if le32(buf, 24) == 0 {
                return None;
            }
        }
        Some(RecoveryInit {
            min_filesize: 32,
            extension: "ape".to_string(),
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
    registry.register(0, APE_MAGIC, Arc::new(ApeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ape_header_match() {
        // Legacy path: version 3810, channels=2, sample_rate!=0, total_frames!=0.
        let mut buf = vec![0u8; 32];
        buf[0..4].copy_from_slice(APE_MAGIC);
        buf[4..6].copy_from_slice(&3810u16.to_le_bytes()); // nVersion
        buf[10..12].copy_from_slice(&2u16.to_le_bytes()); // nChannels
        buf[12..16].copy_from_slice(&44100u32.to_le_bytes()); // nSampleRate
        buf[24..28].copy_from_slice(&100u32.to_le_bytes()); // nTotalFrames
        assert!(ApeSignature.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_ape_no_match() {
        // Wrong magic.
        let buf = vec![0u8; 32];
        assert!(ApeSignature.header_check(&buf, 0).is_none());
        // Correct magic, legacy path, but channels out of range.
        let mut bad = vec![0u8; 32];
        bad[0..4].copy_from_slice(APE_MAGIC);
        bad[4..6].copy_from_slice(&3810u16.to_le_bytes());
        bad[10..12].copy_from_slice(&5u16.to_le_bytes());
        assert!(ApeSignature.header_check(&bad, 0).is_none());
    }
}
