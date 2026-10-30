use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// MIDI carving signature. Header: "MThd" 00 00 00 06 (8 bytes) at offset 0, followed by a
/// big-endian
/// format word (must be <= 2) and track count (must be non-zero).
///
/// Note: PhotoRec walks the "MTrk" chunk chain (data_check_midi/file_check_midi)
/// to compute the exact end of file. That stateful, block-spanning walk is
/// degraded here to a header-magic + validation signature; the carved size is
/// bounded by the next header match or max_file_size instead of the last track.
struct MidSignature;

const MID_MAGIC: [u8; 8] = *b"MThd\x00\x00\x00\x06";

impl FileSignature for MidSignature {
    fn name(&self) -> &str {
        "MIDI"
    }
    fn extensions(&self) -> &[&str] {
        &["mid"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // struct midi_header: magic[4] + len(be32) + format(be16) + tracks(be16)
        // + time_division(be16). Need format@8 and tracks@10.
        if buf.len() < 12 || buf[0..MID_MAGIC.len()] != MID_MAGIC {
            return None;
        }
        let format = u16::from_be_bytes([buf[8], buf[9]]);
        let tracks = u16::from_be_bytes([buf[10], buf[11]]);
        if format > 2 || tracks == 0 {
            return None;
        }
        Some(RecoveryInit {
            min_filesize: 14,
            extension: "mid".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        50 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &MID_MAGIC, Arc::new(MidSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mid_header_match() {
        let sig = MidSignature;
        // MThd + len 6 + format 1 + tracks 2 + time_division
        let buf = [b'M', b'T', b'h', b'd', 0, 0, 0, 6, 0, 1, 0, 2, 0x01, 0xe0];
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_mid_no_match() {
        let sig = MidSignature;
        // format = 3 (>2) rejected.
        let bad_format = [b'M', b'T', b'h', b'd', 0, 0, 0, 6, 0, 3, 0, 2, 0, 0];
        assert!(sig.header_check(&bad_format, 0).is_none());
        // tracks = 0 rejected.
        let no_tracks = [b'M', b'T', b'h', b'd', 0, 0, 0, 6, 0, 1, 0, 0, 0, 0];
        assert!(sig.header_check(&no_tracks, 0).is_none());
        // Wrong magic.
        assert!(sig
            .header_check(b"RIFF\x00\x00\x00\x06\x00\x01\x00\x02", 0)
            .is_none());
    }
}
