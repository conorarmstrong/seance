use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Matroska/WebM video container signature detector.
/// Header: 1A 45 DF A3 (EBML header magic, 4 bytes at offset 0).
/// Both MKV and WebM use the EBML/Matroska container format.
/// The DocType element inside the EBML header distinguishes them:
///   "matroska" → .mkv, "webm" → .webm
/// File size is encoded in the Segment element's size field (variable-length EBML integer),
/// but parsing EBML vints adds complexity. Use max-size recovery.
/// Ref: Matroska specification, reference/testdisk/src/file_mkv.c
struct MkvSignature;

impl FileSignature for MkvSignature {
    fn name(&self) -> &str {
        "MKV"
    }

    fn extensions(&self) -> &[&str] {
        &["mkv", "webm", "mka"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 8 {
            return None;
        }
        // EBML header element ID
        if buf[0..4] != [0x1A, 0x45, 0xDF, 0xA3] {
            return None;
        }

        // Determine extension by scanning for DocType string
        let ext = detect_doctype(buf);

        Some(RecoveryInit {
            min_filesize: 8,
            extension: ext.to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        8 * 1024 * 1024 * 1024 // 8 GB — video files can be large
    }
}

/// Scan the EBML header for the DocType string to determine file extension.
fn detect_doctype(buf: &[u8]) -> &'static str {
    // DocType element ID is 0x4282. Scan first 64 bytes for it.
    let search_len = buf.len().min(64);
    for i in 0..search_len.saturating_sub(10) {
        if buf[i] == 0x42 && buf[i + 1] == 0x82 {
            // Next byte is the string length (EBML vint, usually 1 byte for short strings)
            let len_byte = buf[i + 2];
            if len_byte & 0x80 != 0 {
                let str_len = (len_byte & 0x7F) as usize;
                let start = i + 3;
                if start + str_len <= buf.len() {
                    if let Ok(doctype) = std::str::from_utf8(&buf[start..start + str_len]) {
                        if doctype == "webm" {
                            return "webm";
                        }
                    }
                }
            }
        }
    }
    "mkv" // default
}

/// The EBML header (RFC 8794) is an element: after its ID comes a variable-
/// length size, whose first byte cannot be zero, and then its first child,
/// which is one of the EBML header's own elements (`EBMLVersion` 0x4286,
/// `EBMLReadVersion` 0x42F7, `EBMLMaxIDLength` 0x42F2, `EBMLMaxSizeLength`
/// 0x42F3, `DocType` 0x4282, `DocTypeVersion` 0x4287, `DocTypeReadVersion`
/// 0x4285, `DocTypeExtension` 0x4281) or a global `Void` (0xEC) or `CRC-32`
/// (0xBF).
fn header_block_plausible(buf: &[u8]) -> bool {
    let Some(&first) = buf.get(4) else {
        return true;
    };
    if first == 0 {
        return false;
    }
    let child = 4 + first.leading_zeros() as usize + 1;
    match buf.get(child) {
        None => true,
        Some(0xEC | 0xBF) => true,
        Some(0x42) => match buf.get(child + 1) {
            None => true,
            Some(b) => matches!(b, 0x86 | 0xF7 | 0xF2 | 0xF3 | 0x82 | 0x87 | 0x85 | 0x81),
        },
        Some(_) => false,
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x1A, 0x45, 0xDF, 0xA3], Arc::new(MkvSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mkv_header_match() {
        let sig = MkvSignature;
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
        let init = sig.header_check(&buf, 0);
        assert!(init.is_some());
        assert_eq!(init.unwrap().extension, "mkv");
    }

    #[test]
    fn test_webm_doctype_detection() {
        let sig = MkvSignature;
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
        // DocType element: ID=0x4282, length=0x84 (vint for 4), "webm"
        buf[10] = 0x42;
        buf[11] = 0x82;
        buf[12] = 0x84; // vint: 0x80 | 4
        buf[13..17].copy_from_slice(b"webm");
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "webm");
    }

    #[test]
    fn test_mkv_no_match() {
        let sig = MkvSignature;
        let buf = vec![0u8; 64];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_mkv_too_short() {
        let sig = MkvSignature;
        let buf = &[0x1A, 0x45, 0xDF, 0xA3];
        assert!(sig.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_doctype_matroska_default() {
        let mut buf = vec![0u8; 64];
        buf[0..4].copy_from_slice(&[0x1A, 0x45, 0xDF, 0xA3]);
        // DocType with "matroska" — 8 bytes
        buf[10] = 0x42;
        buf[11] = 0x82;
        buf[12] = 0x88; // vint: 0x80 | 8
        buf[13..21].copy_from_slice(b"matroska");
        // Should still return "mkv" (matroska != "webm")
        assert_eq!(detect_doctype(&buf), "mkv");
    }
}
