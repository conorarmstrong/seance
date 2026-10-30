use chrono::{DateTime, Utc};

/// Records a Win7/Vista AppCompatCache can hold. Windows itself never writes
/// more; a header declaring more is damaged or hostile, and the excess is
/// reported as a cap rather than walked.
const MAX_WIN7_ENTRIES: usize = 1024;

/// A parsed Shimcache entry
#[derive(Debug, Clone)]
pub struct ShimcacheEntry {
    pub path: String,
    pub last_modified: Option<DateTime<Utc>>,
    /// Whether the cache recorded that this binary was executed.
    ///
    /// Three states, not two. `Some(true)` and `Some(false)` are readings of
    /// the record's insertion-flags field, which only the Win7/Vista fixed
    /// record layout has. `None` means this cache format does not carry an
    /// execution flag this parser reads, so nothing is known either way.
    ///
    /// It used to be a plain `bool` and the Win8/8.1/10 reader hard-coded
    /// `false`, which put "this program was never executed" on every entry of
    /// every modern Windows hive as though it had been measured. An examiner
    /// cannot tell a fabricated negative from a real one, and "never executed"
    /// is exactly the kind of claim a defence relies on (B8-010). Absent is
    /// the only supportable answer for those formats.
    pub exec_flag: Option<bool>,
    /// The entry's length on disk, in bytes.
    pub data_size: u32,
}

/// Detect the AppCompatCache format version from the header.
///
/// Returns `None` when nothing in the value identifies a known layout. An
/// unrecognised value is never assumed to be Win10: walking arbitrary bytes with
/// the Win10 record reader yields entries no format guarantees, and a fabricated
/// execution record is worse than a stated gap. The caller reports the value as
/// present-but-unrecognised instead.
pub fn detect_version(data: &[u8]) -> Option<AppCompatCacheVersion> {
    if data.len() < 4 {
        return None;
    }
    let sig = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    match sig {
        0x30 | 0x34 => Some(AppCompatCacheVersion::Win10),
        0x80 => Some(AppCompatCacheVersion::Win81),
        0xBADC0FEE => Some(AppCompatCacheVersion::Win7),
        // Windows Vista / Server 2008 use the same fixed-record layout as Win7
        // but with an 8-byte header (magic + entry count) and this signature.
        0xBADC0FFE => Some(AppCompatCacheVersion::Vista),
        _ => {
            // Win10 Creator's Update and later: the first 4 bytes are normally a
            // header size (0x30 / 0x34), but some builds carry a different value
            // there. Only claim Win10 when an entry signature really sits at one
            // of the two header offsets.
            if has_ts_signature_at(data, 0x30) || has_ts_signature_at(data, 0x34) {
                Some(AppCompatCacheVersion::Win10)
            } else {
                None
            }
        }
    }
}

/// True when a Win8/Win10 cached-entry signature begins at `offset`.
fn has_ts_signature_at(data: &[u8], offset: usize) -> bool {
    matches!(data.get(offset..offset + 4), Some(b"10ts") | Some(b"00ts"))
}

/// The outcome of parsing one AppCompatCache value: the entries recovered, plus
/// what the walk could not reach.
///
/// Shimcache answers "what ran on this machine". A record stream that stops
/// early, or an entry count the parser refuses to follow, shortens that answer;
/// carrying the fact back to the caller is what keeps "no more entries" apart
/// from "no more entries were read".
#[derive(Debug, Default)]
pub struct CacheParse {
    /// Entries decoded, in cache order.
    pub entries: Vec<ShimcacheEntry>,
    /// The parser's per-value entry cap stopped the walk.
    pub cap_reached: bool,
    /// The record stream ended before the declared or expected last entry, on
    /// bytes that are not end-of-buffer padding.
    pub stopped_early: bool,
    /// Records that were reached but could not be decoded into a path.
    pub undecodable_records: u64,
    /// Entry count the header declares, where the format carries one.
    pub declared_entries: Option<u32>,
}

impl CacheParse {
    /// True when everything the value holds reached [`CacheParse::entries`].
    pub fn is_complete(&self) -> bool {
        !self.cap_reached && !self.stopped_early && self.undecodable_records == 0
    }

    /// Stable reason for the standard incompleteness pair, or `None`.
    pub fn incomplete_reason(&self) -> Option<&'static str> {
        if self.cap_reached {
            Some(seance_core::io::IncompleteReason::CapReached.as_str())
        } else if self.stopped_early || self.undecodable_records > 0 {
            Some(seance_core::io::IncompleteReason::UnresolvedStructure.as_str())
        } else {
            None
        }
    }
}

/// True when everything from `pos` to the end of the value is zero padding.
///
/// AppCompatCache is a fixed-size buffer: the record stream legitimately ends
/// with unused zero bytes. Treating that as a truncated walk would put a false
/// incompleteness marker on every healthy cache, which teaches examiners to
/// ignore the marker.
fn remainder_is_padding(data: &[u8], pos: usize) -> bool {
    data.get(pos..)
        .is_none_or(|rest| rest.iter().all(|b| *b == 0))
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppCompatCacheVersion {
    Win10,
    Win81,
    Win7,
    Vista,
}

/// Parse Win10 AppCompatCache entries
pub fn parse_win10_entries(data: &[u8]) -> CacheParse {
    if data.len() < 48 {
        return CacheParse {
            stopped_early: !remainder_is_padding(data, 0),
            ..CacheParse::default()
        };
    }

    // Win10 format: header_size(4) + entries starting at offset 0x30 or 0x34
    let header_size = u32::from_le_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let offset = if header_size == 0x30 || header_size == 0x34 {
        header_size
    } else if has_ts_signature_at(data, 0x34) {
        0x34
    } else {
        0x30 // Default
    };
    if offset >= data.len() {
        return CacheParse {
            stopped_early: true,
            ..CacheParse::default()
        };
    }
    parse_ts_entries(data, offset)
}

/// Parse the shared "signature-tagged" AppCompatCache entry stream used by
/// Win8.0, Win8.1 and Win10/11. Each entry begins with a 4-byte signature and
/// (per libyal winreg-kb / Velociraptor) carries:
///   0x00 u32  signature ("00ts" for Win8.0, "10ts" for Win8.1/Win10)
///   0x04 u32  unknown
///   0x08 u32  cached entry data size (bytes after this field; total = +12)
///   0x0C u16  path size (bytes)
///   0x0E ..   path (UTF-16LE, path_size bytes)
///   +path     u64 last modification time (FILETIME)
///   +8        u16 data size, then data / exec flag
/// `start` is the byte offset of the first entry (immediately after the fixed
/// header). Read through the path-size field, so pos+14 must be available.
fn parse_ts_entries(data: &[u8], start: usize) -> CacheParse {
    let mut out = CacheParse::default();
    let mut pos = start;
    while pos + 14 <= data.len() {
        // Accept both the Win8.0 ("00ts") and Win8.1/Win10 ("10ts") signatures.
        let sig = &data[pos..pos + 4];
        if sig != b"10ts" && sig != b"00ts" {
            // Unused tail of the fixed-size value is the normal end of the
            // stream; anything else means records were left unread.
            out.stopped_early = !remainder_is_padding(data, pos);
            break;
        }

        let entry_data_size =
            u32::from_le_bytes([data[pos + 8], data[pos + 9], data[pos + 10], data[pos + 11]])
                as usize;
        // Total on-disk entry length is the data size plus the 12-byte prefix.
        let entry_len = match entry_data_size.checked_add(12) {
            Some(l) => l,
            None => {
                out.stopped_early = true;
                break;
            }
        };
        if entry_data_size == 0 || pos + entry_len > data.len() {
            out.stopped_early = true;
            break;
        }

        let path_size = u16::from_le_bytes([data[pos + 12], data[pos + 13]]) as usize;
        let path_start = pos + 14;
        let path_end = match path_start.checked_add(path_size) {
            Some(e) if e <= data.len() => e,
            _ => {
                out.stopped_early = true;
                break;
            }
        };
        let path = seance_core::codepage::decode_utf16le(&data[path_start..path_end]);

        // Last modification FILETIME immediately follows the path.
        let ft_offset = path_end;
        let last_modified = if ft_offset + 8 <= data.len() {
            let ft = u64::from_le_bytes([
                data[ft_offset],
                data[ft_offset + 1],
                data[ft_offset + 2],
                data[ft_offset + 3],
                data[ft_offset + 4],
                data[ft_offset + 5],
                data[ft_offset + 6],
                data[ft_offset + 7],
            ]);
            seance_core::time::filetime_to_datetime(ft)
        } else {
            None
        };

        if path.is_empty() {
            // A record with no decodable path is a cache slot whose program name
            // was lost, not an empty slot.
            out.undecodable_records += 1;
        } else {
            out.entries.push(ShimcacheEntry {
                path,
                last_modified,
                // The signature-tagged layout does not put an insertion-flags
                // field where this parser can read it: on Win10 the trailer
                // after the FILETIME is a data size and an opaque blob, and on
                // Win8.0/8.1 the flags sit at an offset that "10ts" alone does
                // not disambiguate. Reporting `false` here would have said
                // "never executed" about every entry of every Win8+ hive
                // without having looked (B8-010).
                exec_flag: None,
                data_size: entry_len as u32,
            });
        }

        pos += entry_len;
    }

    out
}

/// Parse Win8.0 / Win8.1 AppCompatCache entries.
///
/// The header is 0x80 (128) bytes and the entries begin at offset 128 using the
/// same "00ts"/"10ts"-signature layout as Win10 (BUG-098). The previous parser
/// read a u32 `path_size` at each entry's offset 0, so the first entry's "00ts"
/// signature (0x73743030) was misread as a ~1.9 GB path length and the loop
/// exited immediately — real Win8/8.1 SYSTEM hives produced no output at all.
pub fn parse_win81_entries(data: &[u8]) -> CacheParse {
    if data.len() < 128 {
        return CacheParse {
            stopped_early: true,
            ..CacheParse::default()
        };
    }
    parse_ts_entries(data, 128)
}

/// Parse Win7 / Server 2008 R2 AppCompatCache entries (signature 0xBADC0FEE).
/// The 128-byte header is followed by fixed-size records; both 32- and 64-bit
/// layouts are handled (BUG-108).
pub fn parse_win7_entries(data: &[u8]) -> CacheParse {
    parse_win7_style_entries(data, 128)
}

/// Parse Vista / Server 2008 AppCompatCache entries (signature 0xBADC0FFE).
/// Vista shares Win7's fixed-record layout but uses only an 8-byte header
/// (magic + entry count), so records begin at offset 8. Not validated against a
/// real Vista hive; on a layout mismatch the path bounds checks fail and no
/// entries are emitted (fail-closed, never fabricated).
pub fn parse_vista_entries(data: &[u8]) -> CacheParse {
    parse_win7_style_entries(data, 8)
}

/// Shared Win7/Vista fixed-record parser. `header_len` is the byte offset of the
/// first record (128 for Win7, 8 for Vista). The path is NOT inline: each record
/// stores a `path_offset` into a strings area that follows all records.
///
/// 64-bit record (48 bytes):        32-bit record (32 bytes):
///   0  u16 path length               0  u16 path length
///   2  u16 max path length           2  u16 max path length
///   4  u32 padding (zero)            4  u32 path offset
///   8  u64 path offset               8  u64 FILETIME
///  16  u64 FILETIME                 16  u32 insertion flags (bit 0x2 = executed)
///  24  u32 insertion flags          20  u32 shim flags
///  28  u32 shim flags               24  u32 data size
///  32  u64 data size                28  u32 data offset
///  40  u64 data offset
///
/// The record width is auto-detected from the first record: in the 64-bit layout
/// bytes 4..8 are zero padding, whereas in the 32-bit layout they hold the
/// (non-zero) path offset. The earlier code assumed 64-bit only, so 32-bit Win7
/// hives were misaligned after the first record.
fn parse_win7_style_entries(data: &[u8], header_len: usize) -> CacheParse {
    let mut out = CacheParse::default();

    if data.len() < 8 {
        out.stopped_early = true;
        return out;
    }
    let declared = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    out.declared_entries = Some(declared);
    let entry_count = declared as usize;

    // Need at least one record's worth of bytes to detect the width.
    let detect = match data.get(header_len + 4..header_len + 8) {
        Some(b) => b,
        None => {
            // The header declares records the value is too short to hold.
            out.stopped_early = entry_count > 0;
            return out;
        }
    };
    let is_x64 = detect == [0, 0, 0, 0];

    // (record_size, path_offset field offset, path_offset is u64, filetime off, flags off)
    let (record_size, poff, poff_u64, ft_off, flags_off) = if is_x64 {
        (48usize, 8usize, true, 16usize, 24usize)
    } else {
        (32usize, 4usize, false, 8usize, 16usize)
    };

    // Win7/Vista caches hold at most 1024 records by design, so a header that
    // declares more is damaged or hostile. Stop, and say that the walk stopped:
    // the remaining declared records were never examined.
    let walk_count = entry_count.min(MAX_WIN7_ENTRIES);
    if entry_count > MAX_WIN7_ENTRIES {
        out.cap_reached = true;
    }

    let mut pos = header_len;
    for _ in 0..walk_count {
        if pos + record_size > data.len() {
            // The value ends before the declared record count is satisfied.
            out.stopped_early = true;
            break;
        }

        let path_length = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;

        let path_offset = if poff_u64 {
            u64::from_le_bytes([
                data[pos + poff],
                data[pos + poff + 1],
                data[pos + poff + 2],
                data[pos + poff + 3],
                data[pos + poff + 4],
                data[pos + poff + 5],
                data[pos + poff + 6],
                data[pos + poff + 7],
            ]) as usize
        } else {
            u32::from_le_bytes([
                data[pos + poff],
                data[pos + poff + 1],
                data[pos + poff + 2],
                data[pos + poff + 3],
            ]) as usize
        };

        let last_modified = {
            let ft = u64::from_le_bytes([
                data[pos + ft_off],
                data[pos + ft_off + 1],
                data[pos + ft_off + 2],
                data[pos + ft_off + 3],
                data[pos + ft_off + 4],
                data[pos + ft_off + 5],
                data[pos + ft_off + 6],
                data[pos + ft_off + 7],
            ]);
            seance_core::time::filetime_to_datetime(ft)
        };

        let flags = u32::from_le_bytes([
            data[pos + flags_off],
            data[pos + flags_off + 1],
            data[pos + flags_off + 2],
            data[pos + flags_off + 3],
        ]);
        let exec_flag = (flags & 0x02) != 0; // InsertFlag bit

        let path = if path_length > 0
            && path_offset < data.len()
            && path_offset + path_length <= data.len()
        {
            seance_core::codepage::decode_utf16le(&data[path_offset..path_offset + path_length])
        } else {
            String::new()
        };

        if path.is_empty() {
            // The record exists; its path could not be resolved out of the
            // strings area. That is a lost program name, not an empty slot.
            out.undecodable_records += 1;
        } else {
            out.entries.push(ShimcacheEntry {
                path,
                last_modified,
                exec_flag: Some(exec_flag),
                // The fixed-record layouts have no per-entry length field; the
                // record IS the fixed width. Reporting the width is a fact;
                // the zero this used to carry was not.
                data_size: record_size as u32,
            });
        }

        pos += record_size;
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filetime_to_datetime() {
        // Known FILETIME: 132539328000000000 = 2021-01-01T00:00:00Z
        let ft = 132539328000000000u64;
        let dt = seance_core::time::filetime_to_datetime(ft);
        assert!(dt.is_some());
        let dt = dt.unwrap();
        assert_eq!(dt.format("%Y-%m-%d").to_string(), "2021-01-01");
    }

    #[test]
    fn test_filetime_zero() {
        assert!(seance_core::time::filetime_to_datetime(0).is_none());
    }

    #[test]
    fn test_detect_win10() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0x30u32.to_le_bytes());
        assert_eq!(detect_version(&data), Some(AppCompatCacheVersion::Win10));
    }

    /// An unknown signature is not Win10 just because the value is long enough.
    /// Walking arbitrary bytes with the Win10 reader invents execution records.
    #[test]
    fn unknown_signature_is_not_forced_to_win10() {
        let mut data = vec![0xAAu8; 4096];
        data[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        assert_eq!(detect_version(&data), None);

        // A genuine Win10 value whose header field is not 0x30/0x34 is still
        // recognised, because a "10ts" record really sits at the header offset.
        let mut real = vec![0u8; 4096];
        real[0..4].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        real[0x30..0x34].copy_from_slice(b"10ts");
        assert_eq!(detect_version(&real), Some(AppCompatCacheVersion::Win10));
    }

    /// A Win7 header declaring more records than the format can hold stops at
    /// the cap. The truncation must reach the caller, not just the record list.
    #[test]
    fn win7_entry_cap_is_reported() {
        // 2000 declared records, 48-byte x64 stride, paths in a strings area.
        let declared = 2000u32;
        let records = MAX_WIN7_ENTRIES + 8;
        let strings_base = 128 + records * 48;
        let mut data = vec![0u8; strings_base + 32];
        data[0..4].copy_from_slice(&0xBADC0FEEu32.to_le_bytes());
        data[4..8].copy_from_slice(&declared.to_le_bytes());

        for (i, ch) in "C:\\a.exe".encode_utf16().enumerate() {
            let at = strings_base + i * 2;
            data[at..at + 2].copy_from_slice(&ch.to_le_bytes());
        }
        for r in 0..records {
            let pos = 128 + r * 48;
            data[pos..pos + 2].copy_from_slice(&16u16.to_le_bytes());
            data[pos + 8..pos + 16].copy_from_slice(&(strings_base as u64).to_le_bytes());
            data[pos + 16..pos + 24].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
        }

        let parse = parse_win7_entries(&data);
        assert_eq!(parse.entries.len(), MAX_WIN7_ENTRIES);
        assert!(parse.cap_reached, "the entry cap must be reported");
        assert!(!parse.is_complete());
        assert_eq!(parse.incomplete_reason(), Some("cap_reached"));
        assert_eq!(parse.declared_entries, Some(declared));
    }

    /// A record stream that stops on a malformed entry, with real bytes still
    /// ahead of it, is a truncated walk and not the end of the cache.
    #[test]
    fn ts_stream_stopping_on_garbage_is_reported() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&0x30u32.to_le_bytes());

        let eo = 0x30;
        data[eo..eo + 4].copy_from_slice(b"10ts");
        let path = "C:\\test.ex";
        let path_bytes = 20usize;
        data[eo + 8..eo + 12].copy_from_slice(&32u32.to_le_bytes());
        data[eo + 12..eo + 14].copy_from_slice(&(path_bytes as u16).to_le_bytes());
        for (i, ch) in path.encode_utf16().enumerate() {
            let off = eo + 14 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let ft_off = eo + 14 + path_bytes;
        data[ft_off..ft_off + 8].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());

        // Non-signature, non-zero bytes where the next entry belongs.
        let next = eo + 32 + 12;
        data[next..next + 8].copy_from_slice(&[0x5A; 8]);

        let parse = parse_win10_entries(&data);
        assert_eq!(parse.entries.len(), 1);
        assert!(parse.stopped_early, "a garbage tail must be reported");
        assert_eq!(parse.incomplete_reason(), Some("unresolved_structure"));

        // A cache whose records simply end in zero padding is complete.
        let mut clean = data.clone();
        for b in clean[next..].iter_mut() {
            *b = 0;
        }
        let clean_parse = parse_win10_entries(&clean);
        assert!(
            clean_parse.is_complete(),
            "zero padding is the normal end of a cache value"
        );
    }

    #[test]
    fn test_detect_win81() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        assert_eq!(detect_version(&data), Some(AppCompatCacheVersion::Win81));
    }

    #[test]
    fn test_detect_win7() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(&0xBADC0FEEu32.to_le_bytes());
        assert_eq!(detect_version(&data), Some(AppCompatCacheVersion::Win7));
    }

    #[test]
    fn test_parse_win10_entry() {
        // Minimal Win10 "10ts" entry with correct field offsets:
        //   sig(4) unknown(4) entry_data_size(4) path_size(2) path FILETIME(8) data_size(2)
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&0x30u32.to_le_bytes()); // header size

        let eo = 0x30;
        data[eo..eo + 4].copy_from_slice(b"10ts");
        // path "C:\\test.ex" = 10 code units = 20 bytes.
        let path = "C:\\test.ex";
        let path_bytes = 20usize;
        // entry_data_size = path_size_field(2) + path(20) + filetime(8) + data_size(2) = 32.
        data[eo + 8..eo + 12].copy_from_slice(&32u32.to_le_bytes());
        data[eo + 12..eo + 14].copy_from_slice(&(path_bytes as u16).to_le_bytes());
        for (i, ch) in path.encode_utf16().enumerate() {
            let off = eo + 14 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        // FILETIME (2021-01-01) immediately after the path.
        let ft_off = eo + 14 + path_bytes;
        data[ft_off..ft_off + 8].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());

        let entries = parse_win10_entries(&data).entries;
        assert_eq!(entries.len(), 1);
        assert!(entries[0].path.contains("test"));
        // The timestamp only decodes if path_size/path/FILETIME offsets are correct.
        assert_eq!(
            entries[0]
                .last_modified
                .unwrap()
                .format("%Y-%m-%d")
                .to_string(),
            "2021-01-01"
        );
    }

    #[test]
    fn test_parse_win7_x64_multiple_entries() {
        // Two 48-byte x64 records at offset 128, with paths in a trailing strings
        // area. Regression for the 552-byte stride, which read only the first
        // entry (or misaligned the rest).
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&0xBADC0FEEu32.to_le_bytes());
        data[4..8].copy_from_slice(&2u32.to_le_bytes()); // entry count

        let strings_base = 128 + 2 * 48; // 224
        let write_path = |data: &mut [u8], at: usize, s: &str| {
            for (i, ch) in s.encode_utf16().enumerate() {
                data[at + i * 2..at + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
            }
        };
        // "C:\\a.exe" and "C:\\b.exe": 8 code units = 16 bytes each.
        write_path(&mut data, strings_base, "C:\\a.exe");
        write_path(&mut data, strings_base + 16, "C:\\b.exe");

        // Entry 0 @128: executed, FILETIME 2021-01-01.
        data[128..130].copy_from_slice(&16u16.to_le_bytes()); // path length
        data[136..144].copy_from_slice(&(strings_base as u64).to_le_bytes()); // path offset
        data[144..152].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes()); // FILETIME
        data[152..156].copy_from_slice(&0x2u32.to_le_bytes()); // insertion flags: executed

        // Entry 1 @176: not executed.
        data[176..178].copy_from_slice(&16u16.to_le_bytes());
        data[184..192].copy_from_slice(&((strings_base + 16) as u64).to_le_bytes());
        data[200..204].copy_from_slice(&0u32.to_le_bytes());

        let entries = parse_win7_entries(&data).entries;
        assert_eq!(entries.len(), 2, "48-byte stride must yield both entries");
        assert!(entries[0].path.contains("a.exe"));
        assert_eq!(entries[0].exec_flag, Some(true));
        assert!(entries[0].last_modified.is_some());
        assert!(entries[1].path.contains("b.exe"));
        assert_eq!(
            entries[1].exec_flag,
            Some(false),
            "a Win7 record's cleared insertion flag is a real reading, not an absent one"
        );
    }

    #[test]
    fn test_parse_win81_00ts_entry() {
        // BUG-098: real Win8/8.1 hives store "00ts"/"10ts"-signature entries after
        // a 128-byte header. The old parser read the signature as a u32 path size
        // and produced nothing. Build one Win8.0 ("00ts") entry and assert it now
        // decodes path + FILETIME.
        let mut data = vec![0u8; 320];
        // Header size marker 0x80 (not required by the parser, but realistic).
        data[0..4].copy_from_slice(&0x80u32.to_le_bytes());

        let eo = 128;
        data[eo..eo + 4].copy_from_slice(b"00ts");
        let path = "C:\\win8.ex";
        let path_bytes = 20usize; // 10 code units * 2
                                  // entry_data_size = path_size_field(2) + path(20) + filetime(8) + data_size(2)
        data[eo + 8..eo + 12].copy_from_slice(&32u32.to_le_bytes());
        data[eo + 12..eo + 14].copy_from_slice(&(path_bytes as u16).to_le_bytes());
        for (i, ch) in path.encode_utf16().enumerate() {
            let off = eo + 14 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let ft_off = eo + 14 + path_bytes;
        data[ft_off..ft_off + 8].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());

        let entries = parse_win81_entries(&data).entries;
        assert_eq!(entries.len(), 1, "Win8 00ts entry must be parsed");
        assert!(entries[0].path.contains("win8"));
        assert_eq!(
            entries[0]
                .last_modified
                .unwrap()
                .format("%Y-%m-%d")
                .to_string(),
            "2021-01-01"
        );
    }

    #[test]
    fn test_parse_win7_x86_records() {
        // BUG-108: 32-bit Win7 records are 32 bytes (path len 2, max 2, path
        // offset u32 @4, FILETIME @8, insert flags @16). The old parser only
        // handled the 48-byte x64 record, misaligning x86 hives after entry 0.
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&0xBADC0FEEu32.to_le_bytes());
        data[4..8].copy_from_slice(&2u32.to_le_bytes()); // entry count

        let strings_base = 128 + 2 * 32; // 192
        let write_path = |data: &mut [u8], at: usize, s: &str| {
            for (i, ch) in s.encode_utf16().enumerate() {
                data[at + i * 2..at + i * 2 + 2].copy_from_slice(&ch.to_le_bytes());
            }
        };
        write_path(&mut data, strings_base, "C:\\a.exe"); // 8 units = 16 bytes
        write_path(&mut data, strings_base + 16, "C:\\b.exe");

        // Entry 0 @128 (x86, 32 bytes). Non-zero path offset @4 forces x86 detect.
        data[128..130].copy_from_slice(&16u16.to_le_bytes()); // path length
        data[132..136].copy_from_slice(&(strings_base as u32).to_le_bytes()); // path offset
        data[136..144].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes()); // FILETIME
        data[144..148].copy_from_slice(&0x2u32.to_le_bytes()); // executed

        // Entry 1 @160.
        data[160..162].copy_from_slice(&16u16.to_le_bytes());
        data[164..168].copy_from_slice(&((strings_base + 16) as u32).to_le_bytes());
        data[176..180].copy_from_slice(&0u32.to_le_bytes()); // not executed

        let entries = parse_win7_entries(&data).entries;
        assert_eq!(
            entries.len(),
            2,
            "32-byte x86 stride must yield both entries"
        );
        assert!(entries[0].path.contains("a.exe"));
        assert_eq!(entries[0].exec_flag, Some(true));
        assert!(entries[0].last_modified.is_some());
        assert!(entries[1].path.contains("b.exe"));
        assert_eq!(entries[1].exec_flag, Some(false));
    }

    /// B8-010: the Win8/8.1/10 record stream carries no insertion-flags field
    /// this parser reads. It used to store `exec_flag: false` on every entry,
    /// so on every modern Windows hive the cache asserted that nothing had ever
    /// been executed — a negative finding nobody had measured, and one an
    /// examiner could not tell from a measured one. The Win7 layout does carry
    /// the flag and must keep reporting it.
    #[test]
    fn a_win8_plus_entry_reports_execution_as_unknown_not_as_never() {
        let mut data = vec![0u8; 256];
        data[0..4].copy_from_slice(&0x30u32.to_le_bytes());

        let eo = 0x30;
        data[eo..eo + 4].copy_from_slice(b"10ts");
        let path = "C:\\test.ex";
        let path_bytes = 20usize;
        data[eo + 8..eo + 12].copy_from_slice(&32u32.to_le_bytes());
        data[eo + 12..eo + 14].copy_from_slice(&(path_bytes as u16).to_le_bytes());
        for (i, ch) in path.encode_utf16().enumerate() {
            let off = eo + 14 + i * 2;
            data[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let ft_off = eo + 14 + path_bytes;
        data[ft_off..ft_off + 8].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());

        let entries = parse_win10_entries(&data).entries;
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].exec_flag, None,
            "a format with no execution flag must report unknown, never 'not executed'"
        );

        // Win8.0's "00ts" stream is the same reader and gets the same answer.
        let mut win8 = vec![0u8; 320];
        win8[0..4].copy_from_slice(&0x80u32.to_le_bytes());
        let eo = 128;
        win8[eo..eo + 4].copy_from_slice(b"00ts");
        win8[eo + 8..eo + 12].copy_from_slice(&32u32.to_le_bytes());
        win8[eo + 12..eo + 14].copy_from_slice(&(path_bytes as u16).to_le_bytes());
        for (i, ch) in path.encode_utf16().enumerate() {
            let off = eo + 14 + i * 2;
            win8[off..off + 2].copy_from_slice(&ch.to_le_bytes());
        }
        let ft_off = eo + 14 + path_bytes;
        win8[ft_off..ft_off + 8].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
        let win8_entries = parse_win81_entries(&win8).entries;
        assert_eq!(win8_entries.len(), 1);
        assert_eq!(win8_entries[0].exec_flag, None);
    }

    #[test]
    fn test_parse_vista_signature_and_entry() {
        // BUG-108: Vista/2008 signature 0xBADC0FFE was unrecognized. Records use
        // Win7's layout with an 8-byte header (entries begin at offset 8).
        let mut data = vec![0u8; 128];
        data[0..4].copy_from_slice(&0xBADC0FFEu32.to_le_bytes());
        data[4..8].copy_from_slice(&1u32.to_le_bytes()); // entry count

        assert_eq!(detect_version(&data), Some(AppCompatCacheVersion::Vista));

        let strings_base = 8 + 32; // one x86 record then strings
        for (i, ch) in "C:\\v.exe".encode_utf16().enumerate() {
            let at = strings_base + i * 2;
            data[at..at + 2].copy_from_slice(&ch.to_le_bytes());
        }
        // x86 record @8: non-zero path offset @12 forces x86 detection.
        data[8..10].copy_from_slice(&16u16.to_le_bytes()); // path length
        data[12..16].copy_from_slice(&(strings_base as u32).to_le_bytes()); // path offset
        data[16..24].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes()); // FILETIME

        let entries = parse_vista_entries(&data).entries;
        assert_eq!(entries.len(), 1, "Vista entry must be parsed");
        assert!(entries[0].path.contains("v.exe"));
        assert!(entries[0].last_modified.is_some());
    }
}
