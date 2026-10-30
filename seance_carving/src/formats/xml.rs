use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Symantec encrypted XML carving signature. Header: a fixed 142-byte UTF-16LE literal beginning
/// `<?xml version="1.0" encoding="UTF-16"?><!--GETRSFileHeaderSize=0x000008`
/// at offset 0. No footer; size not encoded in header.
struct XmlSignature;

/// The full 142-byte UTF-16LE header magic, transcribed verbatim from
/// register_header_check_xml in file_xml.c.
const XML_MAGIC: [u8; 142] = [
    0x3c, 0x00, 0x3f, 0x00, b'x', 0x00, b'm', 0x00, b'l', 0x00, b' ', 0x00, b'v', 0x00, b'e', 0x00,
    b'r', 0x00, b's', 0x00, b'i', 0x00, b'o', 0x00, b'n', 0x00, 0x3d, 0x00, 0x22, 0x00, b'1', 0x00,
    b'.', 0x00, b'0', 0x00, 0x22, 0x00, b' ', 0x00, b'e', 0x00, b'n', 0x00, b'c', 0x00, b'o', 0x00,
    b'd', 0x00, b'i', 0x00, b'n', 0x00, b'g', 0x00, 0x3d, 0x00, 0x22, 0x00, b'U', 0x00, b'T', 0x00,
    b'F', 0x00, 0x2d, 0x00, b'1', 0x00, b'6', 0x00, 0x22, 0x00, 0x3f, 0x00, 0x3e, 0x00, 0x3c, 0x00,
    0x21, 0x00, 0x2d, 0x00, 0x2d, 0x00, b'G', 0x00, b'E', 0x00, b'T', 0x00, b'R', 0x00, b'S', 0x00,
    b'F', 0x00, b'i', 0x00, b'l', 0x00, b'e', 0x00, b'H', 0x00, b'e', 0x00, b'a', 0x00, b'd', 0x00,
    b'e', 0x00, b'r', 0x00, b'S', 0x00, b'i', 0x00, b'z', 0x00, b'e', 0x00, 0x3d, 0x00, b'0', 0x00,
    b'x', 0x00, b'0', 0x00, b'0', 0x00, b'0', 0x00, b'0', 0x00, b'0', 0x00, b'8', 0x00,
];

impl FileSignature for XmlSignature {
    fn name(&self) -> &str {
        "XML"
    }

    fn extensions(&self) -> &[&str] {
        &["xml"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() >= XML_MAGIC.len() && buf[0..XML_MAGIC.len()] == XML_MAGIC {
            Some(RecoveryInit {
                min_filesize: 512,
                extension: "xml".to_string(),
                calculated_file_size: None,
            })
        } else {
            None
        }
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024 // document, PHOTOREC_MAX_FILE_SIZE in C
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &XML_MAGIC, Arc::new(XmlSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_xml_header_match() {
        let sig = XmlSignature;
        let mut buf = XML_MAGIC.to_vec();
        buf.extend_from_slice(&[0u8; 8]);
        assert!(sig.header_check(&buf, 0).is_some());
    }

    #[test]
    fn test_xml_no_match() {
        let sig = XmlSignature;
        // First byte wrong.
        let mut bad = XML_MAGIC.to_vec();
        bad[0] = 0x00;
        assert!(sig.header_check(&bad, 0).is_none());
        // Too short.
        assert!(sig.header_check(b"<\x00?\x00x\x00", 0).is_none());
    }
}
