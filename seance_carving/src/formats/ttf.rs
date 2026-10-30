use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// TrueType Font (.ttf) carving signature. Ported from file_ttf.c.
/// Header: {0x00,0x01,0x00,0x00,0x00} at offset 0 (sfnt_version 0x00010000, numTables high
/// byte 0). Validates the offset-table fields (numTables/searchRange/entrySelector/
/// rangeShift consistency), then derives the file size from the table directory as
/// max(offset+length). No footer.
struct TtfSignature;

const MAGIC: &[u8] = &[0x00, 0x01, 0x00, 0x00, 0x00];

/// floor(log2(v)) matching PhotoRec's td_ilog2 (`while(v >>= 1) l++;`).
fn td_ilog2(mut v: u32) -> u32 {
    let mut l = 0u32;
    loop {
        v >>= 1;
        if v == 0 {
            break;
        }
        l += 1;
    }
    l
}

impl FileSignature for TtfSignature {
    fn name(&self) -> &str {
        "TTF"
    }

    fn extensions(&self) -> &[&str] {
        &["ttf"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 12 || &buf[0..5] != MAGIC {
            return None;
        }
        let num_tables = u16::from_be_bytes([buf[4], buf[5]]) as u32;
        let search_range = u16::from_be_bytes([buf[6], buf[7]]) as u32;
        let entry_selector = u16::from_be_bytes([buf[8], buf[9]]) as u32;
        let range_shift = u16::from_be_bytes([buf[10], buf[11]]) as u32;
        if num_tables == 0 {
            return None;
        }
        if td_ilog2(num_tables) != entry_selector {
            return None;
        }
        if (16u32 << entry_selector) != search_range {
            return None;
        }
        if num_tables * 16 != range_shift + search_range {
            return None;
        }
        // If the whole table directory is present, derive the file size.
        let mut calculated_file_size = None;
        let need = 12 + num_tables as usize * 16;
        if need <= buf.len() {
            let mut max_offset: u64 = 0;
            for i in 0..num_tables as usize {
                let base = 12 + i * 16;
                let offset = u32::from_be_bytes([
                    buf[base + 8],
                    buf[base + 9],
                    buf[base + 10],
                    buf[base + 11],
                ]) as u64;
                let length = u32::from_be_bytes([
                    buf[base + 12],
                    buf[base + 13],
                    buf[base + 14],
                    buf[base + 15],
                ]) as u64;
                let new_offset = offset + length;
                if max_offset < new_offset {
                    max_offset = new_offset;
                }
            }
            calculated_file_size = Some(max_offset);
        }
        Some(RecoveryInit {
            min_filesize: 12,
            extension: "ttf".to_string(),
            calculated_file_size,
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
    registry.register(0, MAGIC, Arc::new(TtfSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ttf_header_match() {
        let sig = TtfSignature;
        // numTables = 1: entrySelector = 0, searchRange = 16, rangeShift = 0.
        let mut buf = vec![0x00, 0x01, 0x00, 0x00];
        buf.extend_from_slice(&1u16.to_be_bytes()); // numTables
        buf.extend_from_slice(&16u16.to_be_bytes()); // searchRange
        buf.extend_from_slice(&0u16.to_be_bytes()); // entrySelector
        buf.extend_from_slice(&0u16.to_be_bytes()); // rangeShift
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_ttf_no_match() {
        let sig = TtfSignature;
        // Correct magic but inconsistent offset-table fields.
        let mut buf = vec![0x00, 0x01, 0x00, 0x00];
        buf.extend_from_slice(&1u16.to_be_bytes());
        buf.extend_from_slice(&99u16.to_be_bytes()); // wrong searchRange
        buf.extend_from_slice(&0u16.to_be_bytes());
        buf.extend_from_slice(&0u16.to_be_bytes());
        assert!(sig.header_check(&buf, 0).is_none());
        // Wrong magic.
        assert!(sig.header_check(&[0xffu8; 12], 0).is_none());
    }

    #[test]
    fn test_ttf_ilog2() {
        assert_eq!(td_ilog2(1), 0);
        assert_eq!(td_ilog2(8), 3);
        assert_eq!(td_ilog2(255), 7);
    }
}
