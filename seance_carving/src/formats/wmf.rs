use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WMF (Microsoft Windows Metafile) carving signature. Header: standard WMF magic {01 00 09 00 00
/// 03} at offset 0, or Aldus Placeable
/// Metafile (APM) magic {D7 CD C6 9A 00 00} at offset 0 (WMF header follows at 0x16).
/// Size comes from the metafile header (calculated_file_size); no footer.
struct WmfSignature;

/// Validate the WMF metafile header at the start of `hdr` and return its byte size.
/// Mirrors wmf_check_meta_header in file_wmf.c.
fn wmf_check_meta_header(hdr: &[u8]) -> Option<u64> {
    if hdr.len() < 18 {
        return None;
    }
    let size = 2u64 * u32::from_le_bytes([hdr[6], hdr[7], hdr[8], hdr[9]]) as u64;
    let num_objects = u16::from_le_bytes([hdr[10], hdr[11]]) as u64;
    let max_record = u32::from_le_bytes([hdr[12], hdr[13], hdr[14], hdr[15]]) as u64;
    if size < 18 {
        return None;
    }
    if num_objects == 0 {
        return None;
    }
    if 2 * max_record + num_objects > size {
        return None;
    }
    Some(size)
}

impl FileSignature for WmfSignature {
    fn name(&self) -> &str {
        "WMF"
    }

    fn extensions(&self) -> &[&str] {
        &["wmf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Aldus Placeable Metafile (APM): key D7 CD C6 9A, WMF header at 0x16.
        if buf.len() >= 6 && buf[0..4] == [0xd7, 0xcd, 0xc6, 0x9a] {
            if buf.len() < 0x16 + 18 {
                return None;
            }
            // reserved (u32 LE at offset 0x10) must be 0
            let reserved = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);
            if reserved != 0 {
                return None;
            }
            let size = wmf_check_meta_header(&buf[0x16..])?;
            return Some(RecoveryInit {
                min_filesize: 0x16,
                extension: "wmf".to_string(),
                calculated_file_size: Some(0x16 + size),
            });
        }
        // Standard WMF (disk, header size 9, version 3.0).
        if buf.len() >= 18 && buf[0..6] == [0x01, 0x00, 0x09, 0x00, 0x00, 0x03] {
            let size = wmf_check_meta_header(buf)?;
            return Some(RecoveryInit {
                min_filesize: 18,
                extension: "wmf".to_string(),
                calculated_file_size: Some(size),
            });
        }
        None
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
    // Aldus Placeable Metafile (APM)
    registry.register(
        0,
        &[0xd7, 0xcd, 0xc6, 0x9a, 0x00, 0x00],
        Arc::new(WmfSignature),
    );
    // Standard WMF
    registry.register(
        0,
        &[0x01, 0x00, 0x09, 0x00, 0x00, 0x03],
        Arc::new(WmfSignature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wmf_header_match() {
        // Standard WMF: magic, size field=9 (=> byte size 18), num_objects=1.
        let buf = [
            0x01, 0x00, 0x09, 0x00, 0x00, 0x03, // magic
            0x09, 0x00, 0x00, 0x00, // size = 9 (words) -> 18 bytes
            0x01, 0x00, // num_objects = 1
            0x00, 0x00, 0x00, 0x00, // max_record = 0
            0x00, 0x00, // members
        ];
        let sig = WmfSignature;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.calculated_file_size, Some(18));
    }

    #[test]
    fn test_wmf_no_match() {
        let sig = WmfSignature;
        assert!(sig.header_check(b"NOTWMFDATA........", 0).is_none());
        assert!(sig.header_check(&[0u8; 4], 0).is_none());
    }
}
