use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::sync::Arc;

/// OLE2 Compound Binary File (legacy Office: .doc, .xls, .ppt, .msg) signature detector.
/// Header: D0 CF 11 E0 A1 B1 1A E1 (8 bytes at offset 0).
/// Sector size from header (offset 0x1E, power of 2). FAT sector count at 0x2C (LE u32).
/// File size = (1 + fat_sectors + data_sectors) * sector_size, but simpler to use
/// total_sectors from the FAT. We approximate with: sector_size * (1 + total_sectors).
/// Ref: reference/testdisk/src/file_doc.c
struct Ole2Signature;

impl FileSignature for Ole2Signature {
    fn name(&self) -> &str {
        "OLE2"
    }

    fn extensions(&self) -> &[&str] {
        &["doc", "xls", "ppt", "msg"]
    }

    fn header_check(&self, buf: &[u8], _offset: usize) -> Option<RecoveryInit> {
        if buf.len() < 0x40 {
            return None;
        }
        // Full 8-byte magic
        let magic: [u8; 8] = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        if buf[0..8] != magic {
            return None;
        }

        // Sector size power at offset 0x1E (LE u16)
        let sector_power = u16::from_le_bytes([buf[0x1E], buf[0x1F]]);
        if !(7..=16).contains(&sector_power) {
            return None; // invalid sector size
        }
        let sector_size = 1u64 << sector_power;

        // Total FAT sectors at offset 0x2C (LE u32)
        let fat_sectors = u32::from_le_bytes([buf[0x2C], buf[0x2D], buf[0x2E], buf[0x2F]]) as u64;

        // Total sectors in the file can be estimated:
        // Each FAT sector covers (sector_size / 4) sectors.
        // Total data sectors ≈ fat_sectors * (sector_size / 4)
        // File size ≈ (1 + total_data_sectors) * sector_size
        let entries_per_fat = sector_size / 4;
        let total_sectors = fat_sectors * entries_per_fat;
        let file_size = (1 + total_sectors) * sector_size;

        // Extension detection from CLSID would require reading the root directory entry
        // inside the FAT, which is beyond what we can do from the header alone.
        // Default to "doc"; the file_check or a downstream plugin can refine.
        let ext = "doc";

        if file_size < sector_size * 2 || file_size > self.max_file_size() {
            return Some(RecoveryInit {
                min_filesize: sector_size,
                extension: ext.to_string(),
                calculated_file_size: None,
            });
        }

        Some(RecoveryInit {
            min_filesize: sector_size,
            extension: ext.to_string(),
            calculated_file_size: Some(file_size),
        })
    }

    fn data_check(&self, _buf: &[u8], _recovery: &mut FileRecovery) -> DataCheckResult {
        DataCheckResult::Continue
    }

    fn refines_extension(&self) -> bool {
        true
    }

    fn file_check(&self, data: &[u8], recovery: &mut FileRecovery) {
        // The Office application is told by the stream names the root storage
        // holds: read from the directory, not found by searching the whole
        // file, since an embedded object's own names (an Excel sheet with a
        // Word document inside it) would otherwise be taken for the file's.
        match root_stream_extension(data) {
            Some(Some(ext)) => recovery.extension = ext.to_string(),
            // The directory was read and names no Office application (a .msg):
            // the default stands.
            Some(None) => {}
            // The directory could not be read from `data` (a damaged chain, or
            // it lies past what was read): fall back to a search of the bytes
            // for the stream names, UTF-16LE.
            None => {
                if contains_utf16le(data, "WordDocument") {
                    recovery.extension = "doc".to_string();
                } else if contains_utf16le(data, "PowerPoint Document") {
                    recovery.extension = "ppt".to_string();
                } else if contains_utf16le(data, "Workbook") || contains_utf16le(data, "Book") {
                    recovery.extension = "xls".to_string();
                }
            }
        }

        // Refine the size down from header_check's worst-case estimate to the
        // real compound-file length by reading the FAT and finding the highest
        // allocated sector. header_check only sees the 512-byte header (one scan
        // block) and can't reach the FAT, so it must over-estimate; without this
        // the over-carve swallows the next file on disk (overlap dedup then drops
        // that real file). Only shrink, never grow, and only when we could read
        // the whole FAT from `data`.
        if let Some(actual) = compute_ole2_size(data) {
            recovery.calculated_file_size = Some(actual);
        }
    }

    fn max_file_size(&self) -> u64 {
        2 * 1024 * 1024 * 1024 // 2 GB
    }
}

/// Compute the true byte length of an OLE2/CFBF compound file from its FAT.
///
/// The header's DIFAT (109 entries at 0x4C) locates the FAT sectors; the FAT is
/// a flat array where entry `i` describes sector `i`. The highest index whose
/// entry is not FREESECT (0xFFFFFFFF) is the last allocated sector, and sector
/// `s` occupies bytes `[(s+1)*ss, (s+2)*ss)`, so the file ends at `(last+2)*ss`.
///
/// Returns `None` (caller keeps the header estimate) when the format is out of
/// range, the DIFAT spills beyond the 109 inline entries, or the FAT sectors are
/// not fully present in `data` (a truncated read can't be sized safely).
fn compute_ole2_size(data: &[u8]) -> Option<u64> {
    const FREESECT: u32 = 0xFFFF_FFFF;
    if data.len() < 512 {
        return None;
    }
    let rd =
        |o: usize| -> u32 { u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]) };
    let sector_power = u16::from_le_bytes([data[0x1E], data[0x1F]]);
    if !(7..=16).contains(&sector_power) {
        return None;
    }
    let sector_size = 1usize << sector_power;
    let num_fat_sectors = rd(0x2C) as usize;
    // >109 FAT sectors needs the DIFAT chain (rare for carved office docs); the
    // header estimate is the safe fallback there.
    if num_fat_sectors == 0 || num_fat_sectors > 109 {
        return None;
    }
    let entries_per_sector = sector_size / 4;
    let mut highest: i64 = -1;
    for k in 0..num_fat_sectors {
        let fat_sector = rd(0x4C + k * 4);
        if fat_sector == FREESECT {
            continue;
        }
        let base = (fat_sector as usize)
            .checked_add(1)?
            .checked_mul(sector_size)?;
        // The FAT sector must be fully within the data we were given.
        if base.checked_add(sector_size)? > data.len() {
            return None;
        }
        for e in 0..entries_per_sector {
            if rd(base + e * 4) != FREESECT {
                let global_idx = (k * entries_per_sector + e) as i64;
                if global_idx > highest {
                    highest = global_idx;
                }
            }
        }
    }
    if highest < 0 {
        return None;
    }
    Some((highest as u64 + 2) * sector_size as u64)
}

/// The extension the streams directly under the root storage name: `doc` for
/// `WordDocument`, `ppt` for `PowerPoint Document`, `xls` for `Workbook` (or the
/// older `Book`). Read from the directory ([MS-CFB] 2.6): its first sector is at
/// header offset 0x30 and its chain is followed through the FAT, each 128-byte
/// entry carrying a UTF-16LE name, an object type, and the ids of its left and
/// right siblings and its child in a red-black tree. Only stream entries
/// (type 2) reached from the root's child through sibling links count; a storage
/// is not entered, so streams of an embedded object are not the file's.
///
/// `None` when the directory cannot be read from `data`; `Some(None)` when it was
/// read and names no application.
fn root_stream_extension(data: &[u8]) -> Option<Option<&'static str>> {
    const ENDOFCHAIN: u32 = 0xFFFF_FFFE;
    const FREESECT: u32 = 0xFFFF_FFFF;
    const MAX_DIRECTORY_SECTORS: usize = 1024;
    const STREAM: u8 = 2;
    const ROOT: u8 = 5;
    let rd = |o: usize| -> Option<u32> {
        let b = data.get(o..o.checked_add(4)?)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };
    let sector_power = u16::from_le_bytes([*data.get(0x1E)?, *data.get(0x1F)?]);
    if !(7..=16).contains(&sector_power) {
        return None;
    }
    let ss = 1usize << sector_power;
    let sector_at = |s: u32| -> Option<&[u8]> {
        let start = (s as usize).checked_add(1)?.checked_mul(ss)?;
        data.get(start..start.checked_add(ss)?)
    };
    // The FAT entry for sector `s`: the next sector in its chain.
    let next_sector = |s: u32| -> Option<u32> {
        let per_fat = ss / 4;
        let k = s as usize / per_fat;
        if k >= 109 {
            return None; // past the inline DIFAT
        }
        let fat_sector = rd(0x4C + k * 4)?;
        if fat_sector == FREESECT {
            return None;
        }
        let at = (s as usize % per_fat) * 4;
        let b = sector_at(fat_sector)?.get(at..at + 4)?;
        Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    };

    struct Entry {
        name: String,
        kind: u8,
        left: u32,
        right: u32,
        child: u32,
    }
    let mut entries: Vec<Entry> = Vec::new();
    let mut sector = rd(0x30)?;
    let mut hops = 0;
    while sector != ENDOFCHAIN {
        hops += 1;
        if hops > MAX_DIRECTORY_SECTORS {
            return None;
        }
        for e in sector_at(sector)?.as_chunks::<128>().0 {
            let name_bytes = (u16::from_le_bytes([e[0x40], e[0x41]]) as usize).clamp(2, 64) - 2;
            let name = char::decode_utf16(
                e[..name_bytes]
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c)),
            )
            .map(|c| c.unwrap_or(char::REPLACEMENT_CHARACTER))
            .collect();
            let id = |o: usize| u32::from_le_bytes([e[o], e[o + 1], e[o + 2], e[o + 3]]);
            entries.push(Entry {
                name,
                kind: e[0x42],
                left: id(0x44),
                right: id(0x48),
                child: id(0x4C),
            });
        }
        sector = next_sector(sector)?;
    }
    let root = entries.first().filter(|r| r.kind == ROOT)?;

    let mut seen = vec![false; entries.len()];
    let mut stack = vec![root.child];
    let mut found = None;
    while let Some(id) = stack.pop() {
        let Some(entry) = entries.get(id as usize) else {
            continue; // NOSTREAM, or an id outside the directory
        };
        if std::mem::replace(&mut seen[id as usize], true) {
            continue; // a cycle in a damaged tree
        }
        stack.extend([entry.left, entry.right]);
        if entry.kind == STREAM {
            let ext = match entry.name.as_str() {
                "WordDocument" => Some("doc"),
                "PowerPoint Document" => Some("ppt"),
                "Workbook" | "Book" => Some("xls"),
                _ => None,
            };
            // The first named in id order of discovery wins; a real file names
            // exactly one.
            found = found.or(ext);
        }
    }
    Some(found)
}

/// True if `needle` (ASCII) appears in `haystack` encoded as UTF-16LE.
fn contains_utf16le(haystack: &[u8], needle: &str) -> bool {
    let pat: Vec<u8> = needle.bytes().flat_map(|b| [b, 0]).collect();
    haystack.windows(pat.len()).any(|w| w == pat.as_slice())
}

pub fn register(registry: &mut SignatureRegistry) {
    registry.register(
        0,
        &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        Arc::new(Ole2Signature),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_ole2_header(sector_power: u16, fat_sectors: u32) -> Vec<u8> {
        let mut buf = vec![0u8; 0x40];
        buf[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        buf[0x1E..0x20].copy_from_slice(&sector_power.to_le_bytes());
        buf[0x2C..0x30].copy_from_slice(&fat_sectors.to_le_bytes());
        buf
    }

    #[test]
    fn test_ole2_header_match() {
        let sig = Ole2Signature;
        // sector_power=9 (512 bytes), 1 FAT sector → 128 data sectors → (1+128)*512 = 66048
        let buf = make_ole2_header(9, 1);
        let init = sig.header_check(&buf, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(66048));
        assert_eq!(init.extension, "doc");
    }

    #[test]
    fn test_ole2_4k_sectors() {
        let sig = Ole2Signature;
        // sector_power=12 (4096 bytes), 2 FAT sectors → 2048 data sectors → (1+2048)*4096
        let buf = make_ole2_header(12, 2);
        let init = sig.header_check(&buf, 0).unwrap();
        let expected = (1 + 2048) * 4096;
        assert_eq!(init.calculated_file_size, Some(expected));
    }

    #[test]
    fn test_ole2_no_match() {
        let sig = Ole2Signature;
        let buf = vec![0u8; 0x40];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    /// Build a full OLE2 image: 512-byte header + one FAT sector (sector 0)
    /// with `allocated` leading sectors marked used and the rest FREESECT.
    fn make_ole2_image(allocated: usize) -> Vec<u8> {
        const FREESECT: u32 = 0xFFFF_FFFF;
        let ss = 512usize;
        let mut buf = vec![0u8; ss * 2]; // header + FAT sector (sector 0 @ byte 512)
        buf[0..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        buf[0x1E..0x20].copy_from_slice(&9u16.to_le_bytes()); // 512-byte sectors
        buf[0x2C..0x30].copy_from_slice(&1u32.to_le_bytes()); // 1 FAT sector
        buf[0x4C..0x50].copy_from_slice(&0u32.to_le_bytes()); // DIFAT[0] = sector 0
                                                              // FAT sector at byte 512: mark 0..allocated used, rest free.
        for e in 0..(ss / 4) {
            let val = if e < allocated {
                0xFFFF_FFFEu32
            } else {
                FREESECT
            };
            let o = ss + e * 4;
            buf[o..o + 4].copy_from_slice(&val.to_le_bytes());
        }
        buf
    }

    #[test]
    fn test_ole2_size_from_fat_is_exact() {
        // 10 allocated sectors → highest index 9 → (9+2)*512 = 5632, NOT the
        // 66048 worst-case the header alone would imply.
        let img = make_ole2_image(10);
        assert_eq!(compute_ole2_size(&img), Some(5632));
        // file_check must refine calculated_file_size down to the real length.
        let sig = Ole2Signature;
        let init = sig.header_check(&img, 0).unwrap();
        assert_eq!(init.calculated_file_size, Some(66048)); // header over-estimates
        let mut rec = FileRecovery::from_init(&init, 0);
        sig.file_check(&img, &mut rec);
        assert_eq!(rec.calculated_file_size, Some(5632)); // refined to truth
    }

    #[test]
    fn test_ole2_size_truncated_read_falls_back() {
        // Only the header present (FAT sector not readable) → can't size safely.
        let img = make_ole2_image(10);
        assert_eq!(compute_ole2_size(&img[..512]), None);
    }

    #[test]
    fn test_ole2_invalid_sector_power() {
        let sig = Ole2Signature;
        let buf = make_ole2_header(3, 1); // sector_power=3 is too small
        assert!(sig.header_check(&buf, 0).is_none());
    }

    #[test]
    fn test_ole2_too_short() {
        let sig = Ole2Signature;
        let buf = [0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1];
        assert!(sig.header_check(&buf, 0).is_none());
    }

    /// A compound file with a directory in sector 1 (the FAT is sector 0):
    /// `entries` are (name, type, left, right, child); the first is the root.
    fn make_ole2_with_directory(entries: &[(&str, u8, u32, u32, u32)]) -> Vec<u8> {
        let mut img = make_ole2_image(0);
        img.resize(512 * 4, 0);
        img[0x30..0x34].copy_from_slice(&1u32.to_le_bytes()); // directory at sector 1
        let fat = |img: &mut Vec<u8>, entry: usize, value: u32| {
            img[512 + entry * 4..512 + entry * 4 + 4].copy_from_slice(&value.to_le_bytes());
        };
        fat(&mut img, 0, 0xFFFF_FFFD); // the FAT sector itself
        fat(&mut img, 1, 0xFFFF_FFFE); // the directory: one sector
        for (i, (name, kind, left, right, child)) in entries.iter().enumerate() {
            let at = 1024 + i * 128;
            let units: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
            img[at..at + units.len()].copy_from_slice(&units);
            let name_len = (units.len() + 2) as u16;
            img[at + 0x40..at + 0x42].copy_from_slice(&name_len.to_le_bytes());
            img[at + 0x42] = *kind;
            img[at + 0x44..at + 0x48].copy_from_slice(&left.to_le_bytes());
            img[at + 0x48..at + 0x4C].copy_from_slice(&right.to_le_bytes());
            img[at + 0x4C..at + 0x50].copy_from_slice(&child.to_le_bytes());
        }
        // Unused entries are not streams.
        for i in entries.len()..4 {
            let at = 1024 + i * 128;
            img[at + 0x44..at + 0x50].fill(0xFF);
        }
        img
    }

    fn extension_of(img: &[u8]) -> String {
        let sig = Ole2Signature;
        let init = sig.header_check(img, 0).unwrap();
        let mut rec = FileRecovery::from_init(&init, 0);
        sig.file_check(img, &mut rec);
        rec.extension
    }

    /// The application is told by the streams directly under the root. An Excel
    /// workbook with a Word document embedded in it holds the text
    /// `WordDocument` too, but as a stream of an embedded storage.
    #[test]
    fn an_embedded_word_document_does_not_make_a_workbook_a_doc() {
        const NONE: u32 = 0xFFFF_FFFF;
        let img = make_ole2_with_directory(&[
            ("Root Entry", 5, NONE, NONE, 1),
            ("Workbook", 2, NONE, 2, NONE),
            ("ObjectPool", 1, NONE, NONE, 3),
            ("WordDocument", 2, NONE, NONE, NONE),
        ]);
        assert_eq!(extension_of(&img), "xls");
    }

    /// A Word file that merely holds the text `Workbook` stays a doc.
    #[test]
    fn workbook_text_inside_a_word_file_does_not_make_it_an_xls() {
        const NONE: u32 = 0xFFFF_FFFF;
        let mut img = make_ole2_with_directory(&[
            ("Root Entry", 5, NONE, NONE, 1),
            ("WordDocument", 2, NONE, NONE, NONE),
        ]);
        let text: Vec<u8> = "Workbook"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        img[1536..1536 + text.len()].copy_from_slice(&text);
        assert_eq!(extension_of(&img), "doc");
        // And a PowerPoint stream is a ppt.
        let ppt = make_ole2_with_directory(&[
            ("Root Entry", 5, NONE, NONE, 1),
            ("PowerPoint Document", 2, NONE, NONE, NONE),
        ]);
        assert_eq!(extension_of(&ppt), "ppt");
    }

    /// With no readable directory the search of the bytes is the fallback, as it
    /// was before the directory was read.
    #[test]
    fn an_unreadable_directory_falls_back_to_the_text_search() {
        let mut img = make_ole2_image(10);
        img[0x30..0x34].copy_from_slice(&50u32.to_le_bytes()); // past the data
        let text: Vec<u8> = "PowerPoint Document"
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        img[600..600 + text.len()].copy_from_slice(&text);
        assert_eq!(extension_of(&img), "ppt");
    }

    /// A compound file whose FAT sizes it to end exactly where the source
    /// ends was sized by its own structure, not clamped at the source's end:
    /// it is not a heuristic truncation. (The header's worst-case estimate
    /// overruns the source; the FAT does not.)
    #[test]
    fn a_compound_file_the_fat_sizes_to_the_source_end_is_not_marked_truncated() {
        use crate::engine::{CarvingDataSource, CarvingEngine};
        struct Mem(Vec<u8>);
        impl CarvingDataSource for Mem {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                let off = (offset as usize).min(self.0.len());
                let n = buf.len().min(self.0.len() - off);
                buf[..n].copy_from_slice(&self.0[off..off + n]);
                Ok(n)
            }
            fn size(&self) -> u64 {
                self.0.len() as u64
            }
        }
        let mut img = make_ole2_image(10);
        img.resize(5632, 0x41);
        let mut registry = SignatureRegistry::new();
        register(&mut registry);
        let src = Mem(img);
        let files = CarvingEngine::new(Arc::new(registry)).scan(&src, src.size());
        let f = files.iter().find(|f| f.offset == 0).expect("carved");
        assert_eq!(f.size, 5632);
        assert_eq!(f.validated, None, "sized by its FAT, not clamped");
    }
}
