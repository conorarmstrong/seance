use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WIM (Windows Imaging) carving signature. Ported from file_wim.c.
/// Header: "MSWIM\0\0\0" (8 bytes) at offset 0. The exact size is derived from
/// cbSize plus the largest (offset + size) among the resource headers.
struct WimSignature;

const WIM_MAGIC: &[u8] = &[b'M', b'S', b'W', b'I', b'M', 0x00, 0x00, 0x00];
const PHOTOREC_MAX_FILE_SIZE: u64 = (1u64 << 41) - 1;
/// sizeof(struct _WIMHEADER_V1_PACKED).
const WIM_HEADER_SIZE: u64 = 208;

fn u32le(buf: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([buf[at], buf[at + 1], buf[at + 2], buf[at + 3]])
}

fn u64le(buf: &[u8], at: usize) -> u64 {
    u64::from_le_bytes([
        buf[at],
        buf[at + 1],
        buf[at + 2],
        buf[at + 3],
        buf[at + 4],
        buf[at + 5],
        buf[at + 6],
        buf[at + 7],
    ])
}

/// RESHDR_GET_SIZE: low 7 bytes hold the size, top byte is flags.
fn reshdr_size(buf: &[u8], at: usize) -> u64 {
    u64le(buf, at) & 0x00FF_FFFF_FFFF_FFFF
}

/// Mirrors wim_max() in the C source.
fn wim_max(offset: u64, size: u64, max_size: u64) -> u64 {
    if size == 0 {
        return max_size;
    }
    if offset > PHOTOREC_MAX_FILE_SIZE {
        return 0;
    }
    let tmp = offset + size;
    if tmp > max_size {
        tmp
    } else {
        max_size
    }
}

impl FileSignature for WimSignature {
    fn name(&self) -> &str {
        "WIM"
    }
    fn extensions(&self) -> &[&str] {
        &["wim"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < WIM_HEADER_SIZE as usize {
            return None;
        }
        if &buf[0..WIM_MAGIC.len()] != WIM_MAGIC {
            return None;
        }
        let mut size = u32le(buf, 8) as u64; // cbSize
        if size < WIM_HEADER_SIZE {
            return None;
        }
        // rhOffsetTable @48, rhXmlData @72, rhBootMetadata @96, rhIntegrity @124.
        // Each reshdr_disk_short: size @+0, offset @+8.
        for &base in &[48usize, 72, 96, 124] {
            let s = reshdr_size(buf, base);
            let o = u64le(buf, base + 8);
            size = wim_max(o, s, size);
            if size == 0 {
                return None;
            }
        }
        Some(RecoveryInit {
            min_filesize: WIM_HEADER_SIZE,
            extension: "wim".to_string(),
            calculated_file_size: Some(size),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8_000_000_000
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, WIM_MAGIC, Arc::new(WimSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wim_header_match() {
        let sig = WimSignature;
        let mut buf = vec![0u8; WIM_HEADER_SIZE as usize];
        buf[0..WIM_MAGIC.len()].copy_from_slice(WIM_MAGIC);
        buf[8..12].copy_from_slice(&(WIM_HEADER_SIZE as u32).to_le_bytes()); // cbSize
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(WIM_HEADER_SIZE));
    }

    #[test]
    fn test_wim_no_match() {
        let sig = WimSignature;
        let mut buf = vec![0u8; WIM_HEADER_SIZE as usize];
        buf[0..WIM_MAGIC.len()].copy_from_slice(WIM_MAGIC);
        // cbSize too small.
        buf[8..12].copy_from_slice(&8u32.to_le_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(b"MSWIM\0\0\0", 0).is_none()); // too short
    }
}
