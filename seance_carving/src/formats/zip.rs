use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// ZIP file signature detector.
/// Header: 50 4B 03 04
/// Footer: End of Central Directory (50 4B 05 06)
/// Also detects OOXML (docx/xlsx/pptx) by extension update.
/// Ref: reference/testdisk/src/file_zip.c
struct ZipSignature;

impl FileSignature for ZipSignature {
    fn name(&self) -> &str {
        "ZIP"
    }

    fn extensions(&self) -> &[&str] {
        &["zip", "docx", "xlsx", "pptx", "jar", "odt", "ods"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= 4 && &buf[0..4] == b"PK\x03\x04" {
            // Check for OOXML: the first local file entry's filename often reveals the type
            // Local file header: 4 sig + 2 ver + 2 flags + 2 method + 2 time + 2 date
            //   + 4 crc + 4 comp_size + 4 uncomp_size + 2 name_len + 2 extra_len = 30 bytes
            let mut ext = "zip".to_string();
            if buf.len() >= 34 {
                let name_len = u16::from_le_bytes([buf[26], buf[27]]) as usize;
                if buf.len() >= 30 + name_len {
                    let filename = &buf[30..30 + name_len];
                    if filename.starts_with(b"[Content_Types].xml")
                        || filename.starts_with(b"_rels/")
                        || filename.starts_with(b"word/")
                    {
                        ext = "docx".to_string();
                    } else if filename.starts_with(b"xl/") {
                        ext = "xlsx".to_string();
                    } else if filename.starts_with(b"ppt/") {
                        ext = "pptx".to_string();
                    }
                }
            }

            Some(RecoveryInit {
                min_filesize: 22, // Minimum ZIP: just EOCD
                extension: ext,
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        // Scan for End of Central Directory signature (50 4B 05 06)
        if buf.len() < 4 {
            return DataCheckResult::Continue;
        }
        for i in 0..buf.len().saturating_sub(3) {
            if &buf[i..i + 4] == b"PK\x05\x06" {
                // EOCD record is at least 22 bytes: sig(4) + fields(16) + comment_len(2)
                if i + 22 <= buf.len() {
                    let comment_len = u16::from_le_bytes([buf[i + 20], buf[i + 21]]) as u64;
                    let end_pos = recovery.file_size + i as u64 + 22 + comment_len;
                    return DataCheckResult::Stop(end_pos);
                } else {
                    // EOCD at end of buffer, estimate size
                    let end_pos = recovery.file_size + i as u64 + 22;
                    return DataCheckResult::Stop(end_pos);
                }
            }
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {
        // Could verify EOCD is present
    }

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024 // 4 GB
    }
}

/// A local file header (PKWARE APPNOTE 4.3.7) states the version needed to
/// extract (its low byte, the specification version, at most 6.3), a
/// compression method the specification assigns, and a file name of 1 to
/// 4,096 bytes that holds no control characters.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 30 {
        return true;
    }
    let method = u16::from_le_bytes([buf[8], buf[9]]);
    let name_len = u16::from_le_bytes([buf[26], buf[27]]) as usize;
    let known_method = matches!(method, 0..=20 | 93..=99);
    if buf[4] > 63 || !known_method || name_len == 0 || name_len > 4096 {
        return false;
    }
    let name = &buf[30..buf.len().min(30 + name_len)];
    name.iter().all(|&b| b >= 0x20 && b != 0x7F)
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x50, 0x4B, 0x03, 0x04], Arc::new(ZipSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zip_header_match() {
        let sig = ZipSignature;
        let buf = b"PK\x03\x04\x14\x00\x00\x00\x08\x00";
        assert!(sig.header_check(buf, 0).is_some());
    }

    #[test]
    fn test_zip_header_no_match() {
        let sig = ZipSignature;
        let buf = b"PK\x05\x06"; // EOCD, not local file header
        assert!(sig.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_zip_eocd_detection() {
        let sig = ZipSignature;
        let mut recovery = FileRecovery {
            extension: "zip".to_string(),
            file_size: 500,
            calculated_file_size: None,
            offset_start: 0,
            min_filesize: 22,
            extra: 0,
            extra_bytes: Vec::new(),
        };

        // Build buffer with EOCD at position 4
        let mut buf = vec![0u8; 30];
        buf[4..8].copy_from_slice(b"PK\x05\x06");
        // comment_len = 0 at offset 4+20=24
        buf[24] = 0;
        buf[25] = 0;

        let result = sig.data_check(&buf, &mut recovery);
        // end_pos = 500 + 4 + 22 + 0 = 526
        assert_eq!(result, DataCheckResult::Stop(526));
    }
}
