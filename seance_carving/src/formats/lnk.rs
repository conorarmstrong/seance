use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// Windows Shell Link (.lnk) file signature detector.
/// Header: 4C 00 00 00 at offset 0, followed by CLSID 01 14 02 00 00 00 00 00 C0 00 00 00 00 00 00 46.
/// LNK files are typically small. No embedded size field covers the whole file,
/// so we parse the shell link header and known sections to estimate total size.
/// Ref: MS-SHLLINK specification, reference/testdisk/src/file_lnk.c
struct LnkSignature;

impl LnkSignature {
    /// Parse the LNK structure to estimate file size.
    /// Returns None if we can't parse it (fall back to max-size), and also when
    /// the walk runs off the end of `buf` before reading the terminal block: a
    /// size is only claimed for a structure that was read to its end.
    fn estimate_size(buf: &[u8]) -> Option<u64> {
        if buf.len() < 0x4C {
            return None;
        }

        // ShellLinkHeader is always 0x4C (76) bytes
        let mut pos: usize = 0x4C;

        // LinkFlags at offset 0x14
        let link_flags = u32::from_le_bytes([buf[0x14], buf[0x15], buf[0x16], buf[0x17]]);

        // HasLinkTargetIDList (bit 0)
        if link_flags & 1 != 0 {
            if pos + 2 > buf.len() {
                return None;
            }
            let id_list_size = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
            pos += 2 + id_list_size;
        }

        // HasLinkInfo (bit 1)
        if link_flags & 2 != 0 {
            if pos + 4 > buf.len() {
                return None;
            }
            let link_info_size =
                u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
            if link_info_size < 4 {
                return None;
            }
            pos += link_info_size;
        }

        // String data sections (each preceded by character count as u16)
        // HasName(2), HasRelativePath(3), HasWorkingDir(4), HasArguments(5), HasIconLocation(6)
        for bit in [2, 3, 4, 5, 6] {
            if link_flags & (1 << bit) != 0 {
                if pos + 2 > buf.len() {
                    return None;
                }
                let char_count = u16::from_le_bytes([buf[pos], buf[pos + 1]]) as usize;
                // Unicode if IsUnicode flag (bit 7) is set, otherwise ANSI
                let byte_count = if link_flags & 0x80 != 0 {
                    char_count * 2
                } else {
                    char_count
                };
                pos += 2 + byte_count;
            }
        }

        // Extra data blocks follow; each starts with a 4-byte size (0 = terminal)
        loop {
            if pos + 4 > buf.len() {
                // The terminal block lies past what was read: the extent is
                // not known, and `pos` is only how far the walk got.
                return None;
            }
            let block_size =
                u32::from_le_bytes([buf[pos], buf[pos + 1], buf[pos + 2], buf[pos + 3]]) as usize;
            if block_size < 4 {
                pos += 4; // terminal block
                break;
            }
            pos += block_size;
        }

        Some(pos as u64)
    }
}

impl FileSignature for LnkSignature {
    fn name(&self) -> &str {
        "LNK"
    }

    fn extensions(&self) -> &[&str] {
        &["lnk"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        // Full magic: 4C 00 00 00 + CLSID (16 bytes) = 20 bytes
        if buf.len() < 20 {
            return None;
        }
        if buf[0..4] != [0x4C, 0x00, 0x00, 0x00] {
            return None;
        }
        // Verify shell link CLSID
        let clsid: [u8; 16] = [
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ];
        if buf[4..20] != clsid {
            return None;
        }

        let calculated_size = Self::estimate_size(buf);

        if let Some(size) = calculated_size {
            if size >= 76 && size <= self.max_file_size() {
                return Some(RecoveryInit {
                    min_filesize: 76,
                    extension: "lnk".to_string(),
                    calculated_file_size: Some(size),
                });
            }
        }

        Some(RecoveryInit {
            min_filesize: 76,
            extension: "lnk".to_string(),
            calculated_file_size: None,
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        10 * 1024 * 1024 // 10 MB — LNK files are typically under 100 KB
    }
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x4C, 0x00, 0x00, 0x00], Arc::new(LnkSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_lnk_header(link_flags: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 256];
        // Header size
        buf[0..4].copy_from_slice(&[0x4C, 0x00, 0x00, 0x00]);
        // CLSID
        buf[4..20].copy_from_slice(&[
            0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x46,
        ]);
        // LinkFlags
        buf[0x14..0x18].copy_from_slice(&link_flags.to_le_bytes());
        buf
    }

    #[test]
    fn test_lnk_basic_match() {
        let sig = LnkSignature;
        let buf = make_lnk_header(0); // no optional sections
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "lnk");
        // Minimal LNK: 0x4C header + 4-byte terminal extra data block
        assert_eq!(init.calculated_file_size, Some(0x4C + 4));
    }

    #[test]
    fn test_lnk_with_id_list() {
        let sig = LnkSignature;
        let mut buf = make_lnk_header(1); // HasLinkTargetIDList
                                          // IDListSize at 0x4C = 10
        buf[0x4C..0x4E].copy_from_slice(&10u16.to_le_bytes());
        let init = sig.header_check(&buf, 0).unwrap();
        // 0x4C + 2 (size field) + 10 (data) + 4 (terminal block) = 92
        assert_eq!(init.calculated_file_size, Some(92));
    }

    /// LinkInfo (bit 1) is skipped by its own size field.
    #[test]
    fn test_lnk_with_link_info() {
        let mut buf = make_lnk_header(0x2);
        buf[0x4C..0x50].copy_from_slice(&20u32.to_le_bytes());
        let init = LnkSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x4C + 20 + 4));
    }

    /// A string-data section is a u16 character count; with IsUnicode (0x80)
    /// each character is two bytes.
    #[test]
    fn test_lnk_unicode_string_data_counts_two_bytes_per_character() {
        // HasName (bit 2) + IsUnicode.
        let mut buf = make_lnk_header(0x80 | 0x4);
        buf[0x4C..0x4E].copy_from_slice(&5u16.to_le_bytes());
        let init = LnkSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x4C + 2 + 10 + 4));
        // The same count in ANSI is one byte per character.
        let mut ansi = make_lnk_header(0x4);
        ansi[0x4C..0x4E].copy_from_slice(&5u16.to_le_bytes());
        let init = LnkSignature.header_check(&ansi, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x4C + 2 + 5 + 4));
    }

    /// Extra-data blocks are walked by their sizes until the terminal block.
    #[test]
    fn test_lnk_chain_of_extra_data_blocks() {
        let mut buf = make_lnk_header(0);
        buf[0x4C..0x50].copy_from_slice(&32u32.to_le_bytes());
        buf[0x4C + 32..0x4C + 36].copy_from_slice(&16u32.to_le_bytes());
        // then a zero (terminal) block at 0x4C + 48
        let init = LnkSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x4C + 32 + 16 + 4));
    }

    /// A walk that runs off the end of the block without reading the terminal
    /// block has no known extent: it must not be reported as a short file.
    #[test]
    fn test_lnk_walk_past_the_block_claims_no_size() {
        // A 700-byte ID list on a 512-byte block.
        let mut buf = make_lnk_header(1);
        buf.resize(512, 0);
        buf[0x4C..0x4E].copy_from_slice(&700u16.to_le_bytes());
        let init = LnkSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, None);
        // Extra-data blocks whose walk stops within 4 bytes of the block end.
        let mut buf = make_lnk_header(0);
        buf.resize(512, 0);
        buf[0x4C..0x50].copy_from_slice(&(512u32 - 0x4C - 2).to_le_bytes());
        let init = LnkSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, None);
    }

    #[test]
    fn test_lnk_no_match_bad_clsid() {
        let sig = LnkSignature;
        let mut buf = vec![0u8; 256];
        buf[0..4].copy_from_slice(&[0x4C, 0x00, 0x00, 0x00]);
        // Wrong CLSID
        buf[4] = 0xFF;
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_lnk_no_match() {
        let sig = LnkSignature;
        let buf = vec![0u8; 256];
        assert!(sig.header_check(&buf, 0).is_none());
    }
}
