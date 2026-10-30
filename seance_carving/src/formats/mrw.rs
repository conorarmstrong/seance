use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Minolta Raw picture (MRW) carving signature. Header: {0x00,'M','R','M'} at offset 0, with
/// {0x00,'P','R','D'} at offset 8.
/// Size is computed from the header (big-endian fields plus CCD dimensions).
struct MrwSignature;

const MRW_MAGIC: &[u8] = &[0x00, b'M', b'R', b'M'];
const PRD_MAGIC: &[u8] = &[0x00, b'P', b'R', b'D'];

impl FileSignature for MrwSignature {
    fn name(&self) -> &str {
        "MRW"
    }

    fn extensions(&self) -> &[&str] {
        &["mrw"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need 2*sizeof(hdr)=16 + sizeof(prd)=24 = 40 bytes.
        if buf.len() < 40 || &buf[0..4] != MRW_MAGIC || &buf[8..12] != PRD_MAGIC {
            return None;
        }
        // mrmhdr->size: big-endian u32 at offset 4.
        let mrm_size = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as u64;
        // prd starts at offset 16: ver[8], ccd{y:u16, x:u16}, img{...}, datasize:u8.
        let ccd_y = u16::from_be_bytes([buf[24], buf[25]]) as u64;
        let ccd_x = u16::from_be_bytes([buf[26], buf[27]]) as u64;
        let datasize = buf[32] as u64;
        let calc = mrm_size + 8 + (ccd_x * ccd_y * datasize).div_ceil(8);
        Some(RecoveryInit {
            min_filesize: 8,
            extension: "mrw".to_string(),
            calculated_file_size: Some(calc),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        64 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, MRW_MAGIC, Arc::new(MrwSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mrw_header_match() {
        let sig = MrwSignature;
        let mut buf = vec![0u8; 40];
        buf[0..4].copy_from_slice(MRW_MAGIC);
        buf[8..12].copy_from_slice(PRD_MAGIC);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    /// The size is the MRM block's length, 8, and the raw image data: the CCD's
    /// width times height times bits per sample, in bytes, rounded up.
    #[test]
    fn test_mrw_size_adds_the_raw_image_data() {
        let sig = MrwSignature;
        let mut buf = vec![0u8; 40];
        buf[0..4].copy_from_slice(MRW_MAGIC);
        buf[4..8].copy_from_slice(&0x1234u32.to_be_bytes()); // mrm_size
        buf[8..12].copy_from_slice(PRD_MAGIC);
        buf[24..26].copy_from_slice(&30u16.to_be_bytes()); // ccd_y
        buf[26..28].copy_from_slice(&41u16.to_be_bytes()); // ccd_x
        buf[32] = 12; // datasize: 12 bits
        let init = sig.header_check(&buf, 0).unwrap();
        // 30 * 41 * 12 = 14760 bits = 1845 bytes exactly.
        assert_eq!(init.calculated_file_size, Some(0x1234 + 8 + 1845));
        // 3 * 5 * 12 = 180 bits = 22.5 bytes: rounded up to 23.
        buf[24..26].copy_from_slice(&3u16.to_be_bytes());
        buf[26..28].copy_from_slice(&5u16.to_be_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x1234 + 8 + 23));
    }

    #[test]
    fn test_mrw_no_match() {
        let sig = MrwSignature;
        // Correct MRM magic but missing PRD block.
        let mut buf = vec![0u8; 40];
        buf[0..4].copy_from_slice(MRW_MAGIC);
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong leading magic.
        let bad = vec![0xFFu8; 40];
        assert!(sig.header_check(&bad, 0).is_none());
    }
}
