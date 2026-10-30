use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// HTML file signature detector (DOCTYPE variant).
/// Header: "<!DOCTYPE html" at offset 0 (case-insensitive).
/// Registered pattern is "<!DOC" (5 bytes); full validation in header_check.
/// HTML is a text format with no reliable size field. Uses max-size recovery.
struct HtmlDoctypeSignature;

impl FileSignature for HtmlDoctypeSignature {
    fn name(&self) -> &str {
        "HTML (DOCTYPE)"
    }

    fn extensions(&self) -> &[&str] {
        &["html", "htm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Need at least "<!DOCTYPE html" = 14 bytes
        if buf.len() < 14 {
            return None;
        }

        // Validate full "<!DOCTYPE html" case-insensitively
        let prefix = &buf[..14];
        if !prefix.eq_ignore_ascii_case(b"<!DOCTYPE html") {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 14,
            extension: "html".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        // Text format with no reliable end marker. Rely on max_file_size.
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        50 * 1024 * 1024 // 50 MB
    }
}

/// HTML file signature detector (<html> tag variant).
/// Header: "<html" at offset 0, followed by space, '>', newline, or end of buffer.
/// HTML is a text format with no reliable size field. Uses max-size recovery.
struct HtmlTagSignature;

impl FileSignature for HtmlTagSignature {
    fn name(&self) -> &str {
        "HTML (<html>)"
    }

    fn extensions(&self) -> &[&str] {
        &["html", "htm"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 5 {
            return None;
        }

        // Validate "<html"
        if &buf[..5] != b"<html" {
            return None;
        }

        // Next byte (if present) must be a delimiter: space, '>', '\n', '\r'
        if buf.len() > 5 {
            let next = buf[5];
            if next != b' ' && next != b'>' && next != b'\n' && next != b'\r' {
                return None;
            }
        }

        Some(RecoveryInit {
            min_filesize: 5,
            extension: "html".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        50 * 1024 * 1024 // 50 MB
    }
}

/// XML file signature detector.
/// Header: "<?xml" at offset 0, followed by a space (0x20).
/// XML is a text format with no reliable size field. Uses max-size recovery.
struct XmlSignature;

impl FileSignature for XmlSignature {
    fn name(&self) -> &str {
        "XML"
    }

    fn extensions(&self) -> &[&str] {
        &["xml", "svg", "xsl", "xslt"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 6 {
            return None;
        }

        // Validate "<?xml"
        if &buf[..5] != b"<?xml" {
            return None;
        }

        // Next byte must be space to avoid false positives
        if buf[5] != b' ' {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: 6,
            extension: "xml".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        100 * 1024 * 1024 // 100 MB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[0x3C, 0x21, 0x44, 0x4F, 0x43],
        Arc::new(HtmlDoctypeSignature),
    );
    registry.register(
        0,
        &[0x3C, 0x68, 0x74, 0x6D, 0x6C],
        Arc::new(HtmlTagSignature),
    );
    registry.register(0, &[0x3C, 0x3F, 0x78, 0x6D, 0x6C], Arc::new(XmlSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_doctype_html_match() {
        let sig = HtmlDoctypeSignature;
        let buf = b"<!DOCTYPE html>\n<html><head></head><body></body></html>";
        let init = sig.header_check(buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "html");
    }

    #[test]
    fn test_html_tag_match() {
        let sig = HtmlTagSignature;
        let buf = b"<html>\n<head></head><body></body></html>";
        let init = sig.header_check(buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "html");
    }

    #[test]
    fn test_html_tag_non_delimiter_rejected() {
        let sig = HtmlTagSignature;
        // "<htmlx" — 'x' is not a valid delimiter after "<html"
        let buf = b"<htmlxyz>";
        assert!(sig.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_xml_match() {
        let sig = XmlSignature;
        let buf = b"<?xml version=\"1.0\"?>\n<root></root>";
        let init = sig.header_check(buf, 0);
        assert!(init.is_some());
        let init = init.unwrap();
        assert_eq!(init.extension, "xml");
    }

    #[test]
    fn test_xml_without_space_rejected() {
        let sig = XmlSignature;
        // "<?xmlversion" — no space after "<?xml"
        let buf = b"<?xmlversion=\"1.0\"?>";
        assert!(sig.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_no_match() {
        let doctype = HtmlDoctypeSignature;
        let tag = HtmlTagSignature;
        let xml = XmlSignature;
        let buf = b"This is just plain text, not HTML or XML.";
        assert!(doctype.header_check(buf, 0).is_none());
        assert!(tag.header_check(buf, 0).is_none());
        assert!(xml.header_check(buf, 0).is_none());
    }

    #[test]
    fn test_short_buffer() {
        let doctype = HtmlDoctypeSignature;
        let tag = HtmlTagSignature;
        let xml = XmlSignature;
        let buf = b"<";
        assert!(doctype.header_check(buf, 0).is_none());
        assert!(tag.header_check(buf, 0).is_none());
        assert!(xml.header_check(buf, 0).is_none());
    }
}
