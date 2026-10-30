use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// WPD (Corel/WordPerfect Documents) carving signature. Header: {FF 'W' 'P' 'C'} at offset 0.
/// WP6.1+ encodes documentSize (calculated_file_size); older variants use min_filesize
/// = documentOffset with no footer.
struct WpdSignature;

impl FileSignature for WpdSignature {
    fn name(&self) -> &str {
        "WPD"
    }

    fn extensions(&self) -> &[&str] {
        &["wpd"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // sizeof(struct wpd_hdr) == 24
        if buf.len() < 24 || buf[0..4] != [0xff, b'W', b'P', b'C'] {
            return None;
        }
        let document_offset = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);
        let file_type = buf[9];
        let major_version = buf[10];
        let minor_version = buf[11];

        if file_type == 0x0a && major_version == 0x02 {
            let document_size = u32::from_le_bytes([buf[20], buf[21], buf[22], buf[23]]);
            // WP 6
            if minor_version == 0 {
                if document_offset < 20 {
                    return None;
                }
                return Some(RecoveryInit {
                    min_filesize: document_offset as u64,
                    extension: "wpd".to_string(),
                    calculated_file_size: None,
                });
            }
            // WP 6.1 or later encodes the document size.
            if document_offset < 24 || document_size < document_offset {
                return None;
            }
            return Some(RecoveryInit {
                min_filesize: 24,
                extension: "wpd".to_string(),
                calculated_file_size: Some(document_size as u64),
            });
        }
        // WP5, or WP MAC 2.x / 3.0-3.5 / 3.5e
        if (file_type == 0x0a && major_version == 0x00)
            || (file_type == 0x2c && (0x02..=0x04).contains(&major_version))
        {
            if document_offset < 20 {
                return None;
            }
            return Some(RecoveryInit {
                min_filesize: document_offset as u64,
                extension: "wpd".to_string(),
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
        256 * 1024 * 1024
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0xff, b'W', b'P', b'C'], Arc::new(WpdSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wpd_header_match() {
        // WP6 variant: fileType=0x0a, majorVersion=0x02, minorVersion=0, documentOffset=20.
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(&[0xff, b'W', b'P', b'C']);
        buf[4..8].copy_from_slice(&20u32.to_le_bytes());
        buf[9] = 0x0a; // fileType
        buf[10] = 0x02; // majorVersion
        buf[11] = 0x00; // minorVersion
        let sig = WpdSignature;
        let init = sig.header_check(&buf, 0).expect("should match");
        assert_eq!(init.min_filesize, 20);
    }

    #[test]
    fn test_wpd_no_match() {
        let sig = WpdSignature;
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(b"WPC1");
        assert!(sig.header_check(&buf, 0).is_none());
        assert!(sig.header_check(&[0xff, b'W', b'P', b'C'], 0).is_none());
    }
}
