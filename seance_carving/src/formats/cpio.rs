//! cpio archives — the `newc`, `crc` and `odc` formats.
//!
//! # Why it is worth carving
//!
//! cpio is not a format anyone chooses any more, but it is the format two
//! things a case cares about are *made* of: **initramfs images**, which every
//! Linux system boots from and which an attacker with persistence may have
//! modified, and **RPM payloads**, which carry the contents of an installed
//! package.
//!
//! # Recognition and extent
//!
//! The portable formats open with a six-character magic — `070701` for `newc`,
//! `070702` for the CRC variant, `070707` for the old character format —
//! followed by fixed-width hexadecimal or octal fields. Requiring those fields
//! to *be* hexadecimal turns six characters into a much stronger test, since
//! `070701` alone is a plausible run of digits.
//!
//! An archive ends with a `TRAILER!!!` entry. `data_check` walks the entries
//! structurally, block by block, until it reaches the entry *named*
//! `TRAILER!!!`, and stops at the end of that entry: the extent is the archive,
//! not the run to the next header. A forward string match would end the
//! archive at a file whose *contents* contain the text, so none is used. The
//! engine then asks `verify_footer` to confirm that the extent ends with the
//! trailer entry. An archive whose entries stop making sense (a damaged or
//! overwritten header) stops being walked and is carved the old way, to the
//! next header or the size cap, and is not reported as validated.
//!
//! The old binary format is deliberately not carved: its magic is the two bytes
//! `0xC7 0x71`, which is not enough to distinguish an archive from noise.

use crate::checks::join_carry;
use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// The magics of the portable formats.
const NEWC: &[u8] = b"070701";
const NEWC_CRC: &[u8] = b"070702";
const ODC: &[u8] = b"070707";

/// The entry that ends every archive.
const TRAILER: &[u8] = b"TRAILER!!!";

struct CpioSignature;

impl FileSignature for CpioSignature {
    fn name(&self) -> &str {
        "cpio"
    }

    fn extensions(&self) -> &[&str] {
        &["cpio"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        let magic = buf.get(..6)?;
        let (is_ascii_hex, header_len) = match magic {
            m if m == NEWC || m == NEWC_CRC => (true, 110),
            m if m == ODC => (false, 76),
            _ => return None,
        };
        let header = buf.get(..header_len)?;

        // The fields after the magic are fixed-width numbers. Requiring them to
        // be so is what makes six digits a signature rather than a coincidence:
        // `070701` on its own is an unremarkable run of characters.
        let fields = &header[6..];
        let well_formed = if is_ascii_hex {
            fields.iter().all(|b| b.is_ascii_hexdigit())
        } else {
            fields.iter().all(|b| (b'0'..=b'7').contains(b))
        };
        if !well_formed {
            return None;
        }

        Some(RecoveryInit {
            min_filesize: header_len as u64,
            extension: "cpio".to_string(),
            calculated_file_size: None,
        })
    }

    /// Walk the archive's entries; stop at the end of the one named `TRAILER!!!`.
    ///
    /// `recovery.extra` is the file offset of the next entry's header
    /// (`WALK_ABANDONED` once the structure stopped making sense), and
    /// `recovery.extra_bytes` the part of a header that the previous block ended
    /// in the middle of.
    fn data_check(&self, buf: &[u8], recovery: &mut FileRecovery) -> DataCheckResult {
        let block_start = recovery.file_size;
        let block_end = block_start + buf.len() as u64;
        let (data, carry_len) = join_carry(buf, recovery);
        // File offset of data[0]: the carry precedes the block.
        let data_start = block_start - carry_len as u64;
        loop {
            let at = recovery.extra;
            if at >= block_end {
                // WALK_ABANDONED, or the entry's body runs on past this block.
                return DataCheckResult::Continue;
            }
            if at < data_start {
                // The carry should begin where the walk stands; it does not.
                recovery.extra = WALK_ABANDONED;
                return DataCheckResult::Continue;
            }
            let rest = &data[(at - data_start) as usize..];
            match entry_at(rest) {
                Entry::Incomplete => {
                    recovery.extra_bytes = rest.to_vec();
                    return DataCheckResult::Continue;
                }
                Entry::Malformed => {
                    recovery.extra = WALK_ABANDONED;
                    return DataCheckResult::Continue;
                }
                Entry::Trailer(len) => return DataCheckResult::Stop(at + len),
                Entry::Member(len) => recovery.extra = at + len,
            }
        }
    }

    fn file_check(&self, _data: &[u8], _recovery: &mut FileRecovery) {}

    /// A real verdict: an archive is complete when its extent ends with the
    /// `TRAILER!!!` entry: the name, its NUL, and at most the three bytes that
    /// pad a `newc` entry to four.
    fn verify_footer(&self, data: &[u8]) -> Option<bool> {
        let tail = &data[data.len().saturating_sub(TRAILER.len() + 1 + 3)..];
        let name = [TRAILER, b"\0"].concat();
        Some(
            (0..tail.len())
                .filter(|&i| tail[i..].starts_with(&name))
                .any(|i| tail[i + name.len()..].iter().all(|&b| b == 0)),
        )
    }

    fn max_file_size(&self) -> u64 {
        4 * 1024 * 1024 * 1024
    }
}

/// `recovery.extra` once the entry walk found something it could not read.
const WALK_ABANDONED: u64 = u64::MAX;

/// What the bytes at the start of an entry say.
enum Entry {
    /// More bytes are needed to read the header or the trailer's name.
    Incomplete,
    /// Not a cpio entry header, or a field that is not a number.
    Malformed,
    /// An ordinary entry of this many bytes (header, name, data, padding).
    Member(u64),
    /// The `TRAILER!!!` entry, of this many bytes.
    Trailer(u64),
}

/// Parse the entry header at the start of `rest` (the formats are described in
/// cpio(5)): `newc` and `crc` have a 110-byte header of hexadecimal fields and
/// pad the name and the data each to four bytes; `odc` has a 76-byte header of
/// octal fields and no padding.
fn entry_at(rest: &[u8]) -> Entry {
    let Some(magic) = rest.get(..6) else {
        return Entry::Incomplete;
    };
    let (header_len, radix, name_field, size_field, padded) = if magic == NEWC || magic == NEWC_CRC
    {
        // Fields are 8 digits each after the magic: c_filesize is the 7th and
        // c_namesize the 12th.
        (
            110usize,
            16,
            6 + 11 * 8..6 + 12 * 8,
            6 + 6 * 8..6 + 7 * 8,
            true,
        )
    } else if magic == ODC {
        // c_namesize is 6 octal digits at 59, c_filesize 11 at 65.
        (76usize, 8, 59..65, 65..76, false)
    } else {
        return Entry::Malformed;
    };
    let Some(header) = rest.get(..header_len) else {
        return Entry::Incomplete;
    };
    let number = |range: std::ops::Range<usize>| {
        std::str::from_utf8(&header[range])
            .ok()
            .and_then(|digits| u64::from_str_radix(digits, radix).ok())
    };
    let (Some(name_len), Some(file_len)) = (number(name_field), number(size_field)) else {
        return Entry::Malformed;
    };
    let align = |n: u64| if padded { n.next_multiple_of(4) } else { n };
    let len = align(header_len as u64 + name_len) + align(file_len);
    // The trailer's name is `TRAILER!!!` and its NUL: only an entry with a name
    // that long can be it, and the name must be in view to say.
    if name_len == TRAILER.len() as u64 + 1 {
        let Some(name) = rest.get(header_len..header_len + TRAILER.len() + 1) else {
            return Entry::Incomplete;
        };
        if name[..TRAILER.len()] == *TRAILER && name[TRAILER.len()] == 0 {
            return Entry::Trailer(len);
        }
    }
    Entry::Member(len)
}

pub fn register(registry: &mut SignatureRegistry) {
    for magic in [NEWC, NEWC_CRC, ODC] {
        registry.register(0, magic, Arc::new(CpioSignature));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn newc_header(name: &str) -> Vec<u8> {
        let mut out = NEWC.to_vec();
        // Thirteen eight-character hexadecimal fields.
        for _ in 0..13 {
            out.extend_from_slice(b"00000001");
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        out
    }

    #[test]
    fn the_portable_formats_are_recognised() {
        let sig = CpioSignature;
        assert_eq!(
            sig.header_check(&newc_header("init"), 0).unwrap().extension,
            "cpio"
        );

        let mut crc = newc_header("init");
        crc[..6].copy_from_slice(NEWC_CRC);
        assert!(sig.header_check(&crc, 0).is_some());

        let mut odc = ODC.to_vec();
        odc.extend_from_slice(&[b'7'; 70]);
        assert!(sig.header_check(&odc, 0).is_some());
    }

    /// **What makes six digits a signature.** `070701` is an unremarkable run
    /// of characters; the fixed-width numeric fields behind it are not.
    #[test]
    fn a_magic_with_non_numeric_fields_behind_it_is_refused() {
        let sig = CpioSignature;
        let mut buf = newc_header("init");
        buf[20] = b'z';
        assert!(
            sig.header_check(&buf, 0).is_none(),
            "the header fields must be hexadecimal, or the magic is a coincidence"
        );

        // The old format's fields are octal: 8 and 9 do not occur.
        let mut odc = ODC.to_vec();
        odc.extend_from_slice(&[b'9'; 70]);
        assert!(sig.header_check(&odc, 0).is_none());

        // Truncated input is refused rather than read past.
        assert!(sig.header_check(NEWC, 0).is_none());
        assert!(sig.header_check(&[], 0).is_none());
        assert!(sig.header_check(b"070700", 0).is_none());
    }

    /// One `newc` entry with real size fields.
    fn newc_entry(name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = NEWC.to_vec();
        for field in 0..13 {
            let value = match field {
                6 => data.len(),
                11 => name.len() + 1,
                _ => 0,
            };
            out.extend_from_slice(format!("{value:08X}").as_bytes());
        }
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out.extend_from_slice(data);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        out
    }

    /// Feed `archive` to `data_check` a block at a time, as the engine does,
    /// and return what it answered at the end of the archive's own bytes.
    fn walk(archive: &[u8], block: usize) -> DataCheckResult {
        let sig = CpioSignature;
        let init = sig.header_check(archive, 0).expect("a cpio header");
        let mut recovery = FileRecovery::from_init(&init, 0);
        for (i, chunk) in archive.chunks(block).enumerate() {
            recovery.file_size = (i * block) as u64;
            match sig.data_check(chunk, &mut recovery) {
                DataCheckResult::Continue => {}
                other => return other,
            }
        }
        DataCheckResult::Continue
    }

    /// The trailer entry, not a string match, ends the archive, wherever the
    /// block boundaries fall in the headers, names and data. A member whose
    /// contents hold the text `TRAILER!!!` does not end it.
    #[test]
    fn the_walk_stops_at_the_trailer_entry_wherever_blocks_split_it() {
        for data_len in [0usize, 1, 3, 100, 401, 402, 403, 404, 515] {
            let mut archive = newc_entry("init", &vec![b'x'; data_len]);
            archive.extend(newc_entry("lure", b"TRAILER!!!\0 inside a file"));
            archive.extend(newc_entry("etc/passwd", b"root"));
            archive.extend(newc_entry("TRAILER!!!", b""));
            let end = archive.len() as u64;
            archive.extend_from_slice(&[0x55; 3000]); // unrelated data after it
            for block in [64usize, 100, 512] {
                assert_eq!(
                    walk(&archive, block),
                    DataCheckResult::Stop(end),
                    "data {data_len}, block {block}"
                );
            }
        }
    }

    /// Through the whole engine: an initramfs in front of unrelated data is
    /// carved to the end of its `TRAILER!!!` entry and validated, not run on to
    /// the next header.
    #[test]
    fn a_cpio_archive_is_carved_to_its_trailer_and_validated() {
        use crate::engine::{CarvingDataSource, CarvingEngine};
        let mut archive = newc_entry("init", &[b'i'; 700]);
        archive.extend(newc_entry("bin/sh", &[b's'; 1300]));
        archive.extend(newc_entry("TRAILER!!!", b""));
        let end = archive.len() as u64;
        archive.extend_from_slice(&[0x55; 4096]);
        let mut registry = SignatureRegistry::new();
        register(&mut registry);
        let src = crate::scan_tests::Mem(archive);
        let files = CarvingEngine::new(Arc::new(registry)).scan(&src, src.size());
        assert_eq!(files.len(), 1, "{files:?}");
        assert_eq!((files[0].offset, files[0].size), (0, end));
        assert_eq!(files[0].validated, Some(true));
    }

    /// An old-format (`odc`) archive has octal fields and no padding.
    #[test]
    fn the_walk_reads_the_old_character_format() {
        let entry = |name: &str, data: &[u8]| {
            let mut out = ODC.to_vec();
            out.extend_from_slice(&[b'0'; 53]); // dev .. mtime
            out.extend_from_slice(format!("{:06o}", name.len() + 1).as_bytes());
            out.extend_from_slice(format!("{:011o}", data.len()).as_bytes());
            out.extend_from_slice(name.as_bytes());
            out.push(0);
            out.extend_from_slice(data);
            out
        };
        let mut archive = entry("a", &[b'y'; 300]);
        archive.extend(entry("TRAILER!!!", b""));
        let end = archive.len() as u64;
        archive.extend_from_slice(&[0x55; 2000]);
        assert_eq!(walk(&archive, 128), DataCheckResult::Stop(end));
    }

    /// A header the walk cannot read stops the walk; it does not end the carve.
    #[test]
    fn a_damaged_entry_header_abandons_the_walk() {
        let mut archive = newc_entry("init", &[b'x'; 50]);
        archive.extend_from_slice(b"not a cpio header, not at all, and long enough to be one.....");
        archive.extend_from_slice(&newc_entry("TRAILER!!!", b""));
        assert_eq!(walk(&archive, 64), DataCheckResult::Continue);
    }

    /// The trailer is a real terminator: an extent that ends with the trailer
    /// entry is whole; one that merely mentions the name, or never reached it,
    /// is not.
    #[test]
    fn the_trailer_distinguishes_a_whole_archive_from_a_truncated_one() {
        let sig = CpioSignature;

        let mut whole = newc_entry("init", &[1u8; 64]);
        whole.extend(newc_entry("TRAILER!!!", b""));
        assert_eq!(sig.verify_footer(&whole), Some(true));

        let truncated = newc_entry("init", &[1u8; 64]);
        assert_eq!(
            sig.verify_footer(&truncated),
            Some(false),
            "an archive that never reached its trailer must not read as complete"
        );

        let mut mentions = newc_entry("init", &[1u8; 64]);
        mentions.extend_from_slice(b"TRAILER!!! and then more archive bytes follow it");
        assert_eq!(
            sig.verify_footer(&mentions),
            Some(false),
            "the name must be the last entry, not text somewhere near the end"
        );
    }
}
