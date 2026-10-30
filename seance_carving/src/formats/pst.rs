use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Outlook PST/OST file signature detector.
/// Header: "!BDN" (21 42 44 4E) at offset 0, followed by specific PST magic.
/// Full signature: 21 42 44 4E + content type (SM=ANSI, SO=Unicode) at various offsets.
/// File size can be read from the header for Unicode PST (offset 0xB8, 8 bytes LE).
/// For ANSI PST, file size at offset 0xA8 (4 bytes LE).
/// Ref: MS-PST specification, reference/testdisk/src/file_pst.c
struct PstSignature;

impl FileSignature for PstSignature {
    fn name(&self) -> &str {
        "PST"
    }

    fn extensions(&self) -> &[&str] {
        &["pst", "ost"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 4 || &buf[0..4] != b"!BDN" {
            return None;
        }

        // wVer at offset 10 (2 bytes LE) distinguishes ANSI (14-15) vs Unicode (23+)
        if buf.len() < 0xC0 {
            return Some(RecoveryInit {
                min_filesize: 512,
                extension: "pst".to_string(),
                calculated_file_size: None,
            });
        }

        let ver = u16::from_le_bytes([buf[10], buf[11]]);

        let file_size = if ver >= 23 {
            // Unicode PST: 8-byte file size at offset 0xB8
            let size = u64::from_le_bytes([
                buf[0xB8], buf[0xB9], buf[0xBA], buf[0xBB], buf[0xBC], buf[0xBD], buf[0xBE],
                buf[0xBF],
            ]);
            if size >= 512 && size <= self.max_file_size() {
                Some(size)
            } else {
                None
            }
        } else if ver >= 14 {
            // ANSI PST: 4-byte file size at offset 0xA8
            if buf.len() >= 0xAC {
                let size = u32::from_le_bytes([buf[0xA8], buf[0xA9], buf[0xAA], buf[0xAB]]) as u64;
                if size >= 512 && size <= self.max_file_size() {
                    Some(size)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        };

        Some(RecoveryInit {
            min_filesize: 512,
            extension: "pst".to_string(),
            calculated_file_size: file_size,
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
        50 * 1024 * 1024 * 1024 // 50 GB — PST files can be very large
    }
}

/// The PST header ([MS-PST] 2.2.2.6) fixes the fields after `!BDN`:
/// `wMagicClient` is `SM` (a PST) or `SO` (an OST), `wVer` is 14 or 15 (ANSI)
/// or 23 and above (Unicode), and `bPlatformCreate` and `bPlatformAccess`
/// (bytes 14 and 15) are both 0x01.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 16 {
        return true;
    }
    let ver = u16::from_le_bytes([buf[10], buf[11]]);
    (buf[8..10] == *b"SM" || buf[8..10] == *b"SO")
        && (ver == 14 || ver == 15 || (23..=63).contains(&ver))
        && buf[14] == 0x01
        && buf[15] == 0x01
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x21, 0x42, 0x44, 0x4E], Arc::new(PstSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pst_header(ver: u16, file_size_bytes: &[u8], size_offset: usize) -> Vec<u8> {
        let mut buf = vec![0u8; 0xC0];
        buf[0..4].copy_from_slice(b"!BDN");
        buf[10..12].copy_from_slice(&ver.to_le_bytes());
        if size_offset + file_size_bytes.len() <= buf.len() {
            buf[size_offset..size_offset + file_size_bytes.len()].copy_from_slice(file_size_bytes);
        }
        buf
    }

    #[test]
    fn test_pst_unicode() {
        let sig = PstSignature;
        let size: u64 = 1024 * 1024; // 1 MB
        let buf = make_pst_header(23, &size.to_le_bytes(), 0xB8);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(1024 * 1024));
    }

    #[test]
    fn test_pst_ansi() {
        let sig = PstSignature;
        let size: u32 = 65536;
        let buf = make_pst_header(14, &size.to_le_bytes(), 0xA8);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(65536));
    }

    #[test]
    fn test_pst_no_match() {
        let sig = PstSignature;
        let buf = vec![0u8; 0xC0];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_pst_short_buffer() {
        let sig = PstSignature;
        let mut buf = vec![0u8; 10];
        buf[0..4].copy_from_slice(b"!BDN");
        let init = sig.header_check(&buf, 0).unwrap();
        assert!(init.calculated_file_size.is_none()); // too short for size parsing
    }
}
