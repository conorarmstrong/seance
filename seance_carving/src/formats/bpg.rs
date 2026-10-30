use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Better Portable Graphics (.bpg) carving signature. Header: 4-byte magic "BPG\xFB" at offset 0.
/// Width, height and picture size are
/// ue32-encoded (7-bit variable-length) starting at byte 6; the size drives the
/// calculated file size. A size of 0 means the picture data runs to the end of
/// the file: nothing in the header gives the extent then, so the signature
/// returns no size and the engine bounds the carve by the next header or the
/// cap and reports it as not validated. A declared size over MAX_BPG_SIZE (64 MiB) is
/// refused by the engine (the cap), and the file is not carved.
struct BpgSignature;

/// 4-byte header magic.
const BPG_HEADER: [u8; 4] = [b'B', b'P', b'G', 0xFB];

/// 64 MiB (CARVE-018; was 8 MiB). A declared length over it is refused, and it
/// also bounds a length-0 picture, carved to the next header or this far.
const MAX_BPG_SIZE: u64 = 0x400_0000;

/// Decode a ue32 (7 bits per byte, MSB = continuation) as in PhotoRec's getue32.
fn getue32(buffer: &[u8], buf_ptr: &mut usize) -> u32 {
    let mut value: u64 = 0;
    let mut bits_read = 0;
    while *buf_ptr < buffer.len() {
        let b = buffer[*buf_ptr] as u64;
        *buf_ptr += 1;
        value <<= 7;
        value |= b & 0x7F;
        if (b & 0x80) == 0 {
            break;
        }
        bits_read += 7;
        if bits_read >= 32 {
            break;
        }
    }
    (value & 0xffff_ffff) as u32
}

impl FileSignature for BpgSignature {
    fn name(&self) -> &str {
        "BPG image"
    }

    fn extensions(&self) -> &[&str] {
        &["bpg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // PhotoRec requires buffer_size >= 6 + 3*5 to decode width/height/size.
        if buf.len() < 21 || buf[..BPG_HEADER.len()] != BPG_HEADER {
            return None;
        }
        let mut buf_ptr = 6usize;
        let picture_width = getue32(buf, &mut buf_ptr);
        let picture_height = getue32(buf, &mut buf_ptr);
        let size = getue32(buf, &mut buf_ptr) as u64;
        if picture_width == 0 || picture_height == 0 {
            return None;
        }
        // Size 0: the picture data runs to the end of the file, so the header
        // does not say where that is. Leave it to active recovery, which bounds
        // the carve and reports it as not validated.
        let calculated_file_size = (size != 0).then(|| size + buf_ptr as u64);
        Some(RecoveryInit {
            min_filesize: 21,
            extension: "bpg".to_string(),
            calculated_file_size,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        MAX_BPG_SIZE
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &BPG_HEADER, Arc::new(BpgSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bpg_header_match() {
        let sig = BpgSignature;
        let mut buf = vec![0u8; 24];
        buf[..BPG_HEADER.len()].copy_from_slice(&BPG_HEADER);
        buf[6] = 0x10; // width = 16
        buf[7] = 0x10; // height = 16
        buf[8] = 0x40; // size = 64
        let init = sig.header_check(&buf, 0).unwrap();
        // size (64) + buf_ptr after reading 3 single-byte ue32s (9)
        assert_eq!(init.calculated_file_size, Some(64 + 9));
    }

    /// A picture-data length of 0 means "to the end of the file": the header
    /// gives no extent, so no size is claimed.
    #[test]
    fn test_bpg_zero_length_claims_no_size() {
        let sig = BpgSignature;
        let mut buf = vec![0u8; 24];
        buf[..BPG_HEADER.len()].copy_from_slice(&BPG_HEADER);
        buf[6] = 0x10; // width = 16
        buf[7] = 0x10; // height = 16
        buf[8] = 0x00; // size = 0
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, None);
    }

    #[test]
    fn test_bpg_no_match() {
        let sig = BpgSignature;
        // width == 0 rejects
        let mut buf = vec![0u8; 24];
        buf[..BPG_HEADER.len()].copy_from_slice(&BPG_HEADER);
        buf[6] = 0x00;
        assert!(sig.header_check(&buf, 0).is_none());
        // wrong magic rejects
        let mut buf2 = vec![0u8; 24];
        buf2[..BPG_HEADER.len()].copy_from_slice(&BPG_HEADER);
        buf2[3] = 0x00;
        assert!(sig.header_check(&buf2, 0).is_none());
    }
}
