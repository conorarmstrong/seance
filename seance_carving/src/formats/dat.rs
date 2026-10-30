use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// DAT carving signature (IE cache history, Glavna Knjiga, phone .dat).
/// Four registered magic variants: - 30 7E 00 00 00 00 00 00 at offset 0 (Sony Ericsson phone
/// data).
///   - "Client UrlCache MMF Ver 5.2\0" at offset 0 (IE cache; size @ 0x1C).
///   - "NFPKDDAT" at offset 4 with "BrowserVisit" at 0x30 (history v4).
///   - "NFPKDDAT" at offset 10 with "BrowserVisit" at 0x36 (history v10).
///
/// No footer.
struct DatSignature;

const DAT_HEADER: [u8; 8] = [0x30, 0x7e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
const IE_MAGIC: &[u8] = b"Client UrlCache MMF Ver 5.2\x00";
const NFPK: &[u8] = b"NFPKDDAT";

impl FileSignature for DatSignature {
    fn name(&self) -> &str {
        "DAT"
    }
    fn extensions(&self) -> &[&str] {
        &["dat"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Variant 1: Sony Ericsson phone data header.
        if buf.len() >= 8 && buf[0..8] == DAT_HEADER {
            return Some(RecoveryInit {
                min_filesize: 8,
                extension: "dat".to_string(),
                calculated_file_size: None,
            });
        }
        // Variant 2: IE UrlCache; file size stored as little-endian u32 at 0x1C.
        if buf.len() >= 0x20 && &buf[0..IE_MAGIC.len()] == IE_MAGIC {
            let size = u32::from_le_bytes([buf[0x1C], buf[0x1D], buf[0x1E], buf[0x1F]]);
            if size < 0x20 {
                return None;
            }
            return Some(RecoveryInit {
                min_filesize: 0x20,
                extension: "dat".to_string(),
                calculated_file_size: Some(size as u64),
            });
        }
        // Variant 3: NFPKDDAT @4 + "BrowserVisit" @0x30.
        if buf.len() >= 0x3C && &buf[4..12] == NFPK && &buf[0x30..0x3C] == b"BrowserVisit" {
            return Some(RecoveryInit {
                min_filesize: 60,
                extension: "dat".to_string(),
                calculated_file_size: None,
            });
        }
        // Variant 4: NFPKDDAT @10 + "BrowserVisit" @0x36.
        if buf.len() >= 0x42 && &buf[10..18] == NFPK && &buf[0x36..0x42] == b"BrowserVisit" {
            return Some(RecoveryInit {
                min_filesize: 66,
                extension: "dat".to_string(),
                calculated_file_size: None,
            });
        }
        None
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        2 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &DAT_HEADER, Arc::new(DatSignature));
    registry.register(0, IE_MAGIC, Arc::new(DatSignature));
    registry.register(4, NFPK, Arc::new(DatSignature));
    registry.register(10, NFPK, Arc::new(DatSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dat_header_match() {
        // Variant 1.
        assert!(DatSignature.header_check(&DAT_HEADER, 0).is_some());
        // Variant 2.
        let mut ie = IE_MAGIC.to_vec();
        ie.resize(0x20, 0);
        ie[0x1C..0x20].copy_from_slice(&0x100u32.to_le_bytes());
        let init = DatSignature.header_check(&ie, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x100));
    }

    #[test]
    fn test_dat_no_match() {
        assert!(DatSignature
            .header_check(b"not a dat file at all here", 0)
            .is_none());
        // IE magic present but size too small.
        let mut ie = IE_MAGIC.to_vec();
        ie.resize(0x20, 0);
        ie[0x1C..0x20].copy_from_slice(&0x10u32.to_le_bytes());
        assert!(DatSignature.header_check(&ie, 0).is_none());
    }
}
