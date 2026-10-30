use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// PE (Portable Executable) file signature detector — EXE, DLL, SYS.
/// Header: "MZ" (4D 5A) at offset 0.
/// PE offset at 0x3C (LE u32), PE signature "PE\0\0" at that offset.
/// Size calculated from section table: max(section.PointerToRawData + section.SizeOfRawData),
/// extended to the end of the attribute certificate table (the Authenticode
/// signature, data directory entry 4, whose offset is a file offset) when that
/// lies past the last section. Other overlay (a self-extractor's payload, data
/// appended without a certificate table) is not described by the headers and is
/// not covered: such a file is carved to the end of its last section or of its
/// certificate table.
/// Ref: reference/testdisk/src/file_exe.c
struct PeSignature;

impl FileSignature for PeSignature {
    fn name(&self) -> &str {
        "PE"
    }

    fn extensions(&self) -> &[&str] {
        &["exe", "dll", "sys"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 64 || buf[0] != b'M' || buf[1] != b'Z' {
            return None;
        }

        // PE header offset at 0x3C
        let pe_offset = u32::from_le_bytes([buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F]]) as usize;

        // Validate PE offset is reasonable and within buffer
        if !(4..=0x10000).contains(&pe_offset) {
            // Still a valid MZ stub, use max-size recovery
            return Some(RecoveryInit {
                min_filesize: 64,
                extension: "exe".to_string(),
                calculated_file_size: None,
            });
        }

        // Need PE sig (4) + COFF header (20) + optional header size field
        if buf.len() < pe_offset + 24 {
            return Some(RecoveryInit {
                min_filesize: 64,
                extension: "exe".to_string(),
                calculated_file_size: None,
            });
        }

        // Verify PE signature
        if &buf[pe_offset..pe_offset + 4] != b"PE\x00\x00" {
            return Some(RecoveryInit {
                min_filesize: 64,
                extension: "exe".to_string(),
                calculated_file_size: None,
            });
        }

        // COFF header starts at pe_offset + 4
        let coff = pe_offset + 4;
        let num_sections = u16::from_le_bytes([buf[coff + 2], buf[coff + 3]]) as usize;
        let optional_header_size = u16::from_le_bytes([buf[coff + 16], buf[coff + 17]]) as usize;

        // Determine extension from characteristics
        let characteristics = u16::from_le_bytes([buf[coff + 18], buf[coff + 19]]);
        let ext = if characteristics & 0x2000 != 0 {
            "dll" // IMAGE_FILE_DLL
        } else if characteristics & 0x1000 != 0 {
            "sys" // IMAGE_FILE_SYSTEM (driver)
        } else {
            "exe"
        };

        // Sanity-check optional header size (typically 0xE0 for PE32 or 0xF0 for PE32+)
        if optional_header_size > 0x1000 {
            return Some(RecoveryInit {
                min_filesize: 64,
                extension: ext.to_string(),
                calculated_file_size: None,
            });
        }

        // Section table starts after optional header
        let section_table_offset = coff + 20 + optional_header_size;

        // Each section header is 40 bytes
        let needed = section_table_offset.saturating_add(num_sections.saturating_mul(40));
        if buf.len() < needed || num_sections == 0 || num_sections > 96 {
            return Some(RecoveryInit {
                min_filesize: 64,
                extension: ext.to_string(),
                calculated_file_size: None,
            });
        }

        // Calculate file size from sections: max(PointerToRawData + SizeOfRawData)
        let mut max_end: u64 = 0;
        for i in 0..num_sections {
            let sec = section_table_offset + i * 40;
            let raw_size =
                u32::from_le_bytes([buf[sec + 16], buf[sec + 17], buf[sec + 18], buf[sec + 19]])
                    as u64;
            let raw_ptr =
                u32::from_le_bytes([buf[sec + 20], buf[sec + 21], buf[sec + 22], buf[sec + 23]])
                    as u64;
            let section_end = raw_ptr + raw_size;
            if section_end > max_end {
                max_end = section_end;
            }
        }

        // The Authenticode signature is appended after the last section and is
        // outside the section table.
        if let Some(cert_end) = certificate_table_end(
            buf,
            coff + 20,
            optional_header_size,
            max_end,
            self.max_file_size(),
        ) {
            max_end = max_end.max(cert_end);
        }

        if max_end < 64 || max_end > self.max_file_size() {
            return Some(RecoveryInit {
                min_filesize: 64,
                extension: ext.to_string(),
                calculated_file_size: None,
            });
        }

        Some(RecoveryInit {
            min_filesize: 64,
            extension: ext.to_string(),
            calculated_file_size: Some(max_end),
        })
    }

    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        // A header match is a claim; the header block is where it is checked
        // (CARVE-015). Refusing it here keeps a stray magic from ending a
        // carve already running and from starting a carve of its own.
        if recovery.file_size == 0 && !header_block_plausible(buf) {
            return DataCheckResult::Error;
        }
        // No footer; rely on calculated_file_size or max_file_size
        DataCheckResult::Continue
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    fn max_file_size(&self) -> u64 {
        256 * 1024 * 1024 // 256 MB
    }
}

/// Where the attribute certificate table ends, from data directory entry 4
/// (IMAGE_DIRECTORY_ENTRY_SECURITY) of the optional header at `opt`: a file
/// offset and a size, both non-zero. The directories start 96 bytes into a PE32
/// optional header (magic 0x10b) and 112 into a PE32+ one (0x20b). `None` when
/// the optional header does not cover the entry, the entry is empty, it starts
/// inside the sections (`sections_end`), or it ends past `cap`: a damaged entry
/// must not move the size the section table gives.
fn certificate_table_end(
    buf: &[u8],
    opt: usize,
    opt_size: usize,
    sections_end: u64,
    cap: u64,
) -> Option<u64> {
    let directories = match buf.get(opt..opt + 2)? {
        [0x0b, 0x01] => 96,
        [0x0b, 0x02] => 112,
        _ => return None,
    };
    const SECURITY_ENTRY: usize = 4 * 8;
    let entry = directories + SECURITY_ENTRY;
    if opt_size < entry + 8 {
        return None;
    }
    let at = opt + entry;
    let raw = buf.get(at..at + 8)?;
    let offset = u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]) as u64;
    let size = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as u64;
    if offset == 0 || size == 0 || offset < sections_end {
        return None;
    }
    let end = offset + size;
    (end <= cap).then_some(end)
}

/// Reached only when the PE headers could not size the file, so the MZ header
/// is all there is to check. A DOS executable header (the MS-DOS EXE format)
/// counts the bytes used in its last 512-byte page (`e_cblp`, below 512), at
/// least one page (`e_cp`), and a header of at least two 16-byte paragraphs
/// (`e_cparhdr`) that holds the relocation table (`e_crlc` four-byte entries
/// from `e_lfarlc`, which starts after the 28-byte fixed header). A new-style
/// header (`PE\0\0`, `NE`, `LE`, `LX`) where `e_lfanew` points, inside this
/// block, is itself the proof, whatever the DOS stub says.
fn header_block_plausible(buf: &[u8]) -> bool {
    if buf.len() < 64 {
        return true;
    }
    let lfanew = u32::from_le_bytes([buf[0x3C], buf[0x3D], buf[0x3E], buf[0x3F]]) as usize;
    if let Some(sig) = buf.get(lfanew..lfanew.saturating_add(4)) {
        if lfanew >= 0x40 && (sig == b"PE\0\0" || matches!(&sig[..2], b"NE" | b"LE" | b"LX")) {
            return true;
        }
    }
    let w = |o: usize| u16::from_le_bytes([buf[o], buf[o + 1]]) as u32;
    let (cblp, cp, crlc, cparhdr, lfarlc) = (w(2), w(4), w(6), w(8), w(0x18));
    cblp < 512
        && cp >= 1
        && cparhdr >= 2
        && (crlc == 0 || (lfarlc >= 28 && lfarlc + 4 * crlc <= cparhdr * 16))
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(0, &[0x4D, 0x5A], Arc::new(PeSignature));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_pe_header(num_sections: u16, sections: &[(u32, u32)], characteristics: u16) -> Vec<u8> {
        let pe_offset: u32 = 0x80;
        let optional_header_size: u16 = 0; // minimal
        let coff_start = pe_offset as usize + 4;
        let section_table = coff_start + 20 + optional_header_size as usize;
        let total = section_table + sections.len() * 40;
        let mut buf = vec![0u8; total.max(256)];

        // MZ header
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C..0x40].copy_from_slice(&pe_offset.to_le_bytes());

        // PE signature
        let po = pe_offset as usize;
        buf[po..po + 4].copy_from_slice(b"PE\x00\x00");

        // COFF header
        buf[coff_start + 2..coff_start + 4].copy_from_slice(&num_sections.to_le_bytes());
        buf[coff_start + 16..coff_start + 18].copy_from_slice(&optional_header_size.to_le_bytes());
        buf[coff_start + 18..coff_start + 20].copy_from_slice(&characteristics.to_le_bytes());

        // Sections
        for (i, &(raw_size, raw_ptr)) in sections.iter().enumerate() {
            let sec = section_table + i * 40;
            buf[sec + 16..sec + 20].copy_from_slice(&raw_size.to_le_bytes());
            buf[sec + 20..sec + 24].copy_from_slice(&raw_ptr.to_le_bytes());
        }

        buf
    }

    #[test]
    fn test_pe_basic_exe() {
        let sig = PeSignature;
        let buf = make_pe_header(2, &[(0x200, 0x400), (0x1000, 0x600)], 0);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "exe");
        // max section end: 0x600 + 0x1000 = 0x1600 = 5632
        assert_eq!(init.calculated_file_size, Some(5632));
    }

    /// A PE whose optional header (`magic`, `opt_size` bytes) carries a security
    /// directory entry of (`cert_off`, `cert_size`), after one section ending
    /// at 0x800.
    fn make_pe_with_certificate(
        magic: u16,
        opt_size: u16,
        cert_off: u32,
        cert_size: u32,
    ) -> Vec<u8> {
        let mut buf = make_pe_header(1, &[(0x400, 0x400)], 0);
        buf.resize(512, 0);
        let coff = 0x80 + 4;
        let opt = coff + 20;
        // Rebuild the layout with the optional header in place: the section
        // table moves to after it.
        let section = buf[coff + 20..coff + 20 + 40].to_vec();
        buf[coff + 20..coff + 20 + 40].fill(0);
        buf[coff + 16..coff + 18].copy_from_slice(&opt_size.to_le_bytes());
        buf[opt..opt + 2].copy_from_slice(&magic.to_le_bytes());
        let dirs = if magic == 0x20b { 112 } else { 96 };
        let entry = opt + dirs + 32;
        if opt_size as usize >= dirs + 40 {
            buf[entry..entry + 4].copy_from_slice(&cert_off.to_le_bytes());
            buf[entry + 4..entry + 8].copy_from_slice(&cert_size.to_le_bytes());
        }
        let table = opt + opt_size as usize;
        buf[table..table + 40].copy_from_slice(&section);
        buf
    }

    /// A signed PE: the certificate table past the last section is part of the
    /// file, for both optional-header layouts.
    #[test]
    fn test_pe_certificate_table_extends_the_size() {
        for (magic, opt_size) in [(0x20bu16, 0xF0u16), (0x10b, 0xE0)] {
            let buf = make_pe_with_certificate(magic, opt_size, 0x800, 0x1A00);
            let init = PeSignature.header_check(&buf, 0).unwrap();
            assert_eq!(init.calculated_file_size, Some(0x2200), "magic {magic:#x}");
        }
    }

    /// CARVE-018, decided limitation. Nothing in the headers bounds an overlay
    /// (a self-extractor's payload), so a PE with no certificate table is sized
    /// at its last section and the payload after it is neither carved nor
    /// flagged. Synthetic header with a planted 4 KiB payload.
    #[test]
    fn a_pe_with_overlay_and_no_certificate_table_ends_at_its_last_section() {
        let mut buf = make_pe_with_certificate(0x20b, 0xF0, 0, 0);
        buf.resize(0x800, 0);
        buf.extend_from_slice(&[0xC3; 4096]);
        let init = PeSignature.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(0x800));
    }

    /// An entry that starts inside the sections, is empty, runs past the cap, or
    /// lies beyond a short optional header does not move the size.
    #[test]
    fn test_pe_bogus_certificate_entries_are_ignored() {
        let cases = [
            (0x20bu16, 0xF0u16, 0x100u32, 0x1A00u32), // inside the sections
            (0x20b, 0xF0, 0x800, 0),                  // no size
            (0x20b, 0xF0, 0, 0x1A00),                 // no offset
            (0x20b, 0xF0, 0x800, 0xFFFF_FFF0),        // past the 256 MiB cap
            (0x20b, 0x70, 0x800, 0x1A00),             // optional header too short
        ];
        for (magic, opt_size, off, size) in cases {
            let buf = make_pe_with_certificate(magic, opt_size, off, size);
            let init = PeSignature.header_check(&buf, 0).unwrap();
            assert_eq!(
                init.calculated_file_size,
                Some(0x800),
                "{magic:#x} {opt_size:#x} {off:#x} {size:#x}"
            );
        }
    }

    #[test]
    fn test_pe_dll() {
        let sig = PeSignature;
        let buf = make_pe_header(1, &[(0x200, 0x200)], 0x2000);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "dll");
        assert_eq!(init.calculated_file_size, Some(0x400));
    }

    #[test]
    fn test_pe_sys_driver() {
        let sig = PeSignature;
        let buf = make_pe_header(1, &[(0x200, 0x200)], 0x1000);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.extension, "sys");
    }

    #[test]
    fn test_pe_no_match() {
        let sig = PeSignature;
        let buf = vec![0u8; 256];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_pe_mz_only_no_pe_sig() {
        let sig = PeSignature;
        let mut buf = vec![0u8; 256];
        buf[0] = b'M';
        buf[1] = b'Z';
        buf[0x3C] = 0x80;
        // No PE\0\0 at offset 0x80
        let init = sig.header_check(&buf, 0).unwrap();
        assert!(init.calculated_file_size.is_none()); // fallback to max-size
    }

    #[test]
    fn test_pe_short_buffer() {
        let sig = PeSignature;
        let buf = b"MZ";
        assert!(sig.header_check(buf, 0).is_none()); // too short
    }
}
