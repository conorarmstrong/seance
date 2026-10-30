//! The `DestList` stream of an `automaticDestinations-ms` jump list.
//!
//! The stream is the jump list's own record of its entries: a 32-byte header
//! and then one entry per destination, each naming the numbered stream that
//! holds the destination's shortcut. Two entry layouts are documented and
//! both are decoded here, chosen by the header's format version and never
//! guessed: version 1 (Windows 7 and 8) has a 114-byte fixed part; versions
//! 2, 3 and 4 (Windows 10 and later) a 130-byte fixed part and four trailing
//! bytes after the path. Any other version is refused with the number.
//!
//! The layout follows the libyal "Jump lists format" documentation as plaso
//! encodes it (`automatic_destinations.yaml`). Of the fields those sources
//! mark unknown, one is surfaced — the 32-bit value at offset 116 of a
//! version 2+ entry, which libyal lists as "Unknown (access count?)" and
//! plaso as `unknown5` — and it is surfaced under that uncertainty: the
//! field is named `offset_116_unknown_possibly_access_count` and carries
//! [`OFFSET_116_NOTE`] beside it, never `access_count`. Every other unknown
//! field (the header's float at 12; the entry's float at 96, the 32-bit value
//! at 112, the bytes at 120–127 and the four trailing bytes) is not surfaced.
//!
//! The MRU position is the entry's index in stream order. The libyal document
//! does not state the order of entries; that the stream is kept most recently
//! used first is what the real files show (last recorded times descending)
//! and how plaso and JLECmd read it, and the record says it rests on that.

/// Bytes in the stream header.
pub const HEADER_LEN: usize = 32;

/// Entries read from one stream before the parser stops.
pub const MAX_ENTRIES: usize = 100_000;

/// What is and is not known about the 32-bit field at offset 116 of a
/// version 2+ entry, written beside the value wherever it is reported.
pub const OFFSET_116_NOTE: &str = "the sources this module follows do not establish what this \
    field is: the libyal \"Jump lists format\" document lists offset 116 of a version 2+ entry as \
    \"Unknown (access count?)\" and plaso's automatic_destinations.yaml names it unknown5; the \
    value is reported as read and is not asserted to be an access count";

/// Why a version 1 entry reports no value at offset 116.
pub const OFFSET_116_UNAVAILABLE: &str = "a DestList format version 1 entry (Windows 7 and 8) \
    has a 114-byte fixed part and no field at offset 116; none is reported";

/// Which of the two documented entry layouts a stream uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// Format version 1: Windows 7 and 8.
    Windows7,
    /// Format versions 2, 3 and 4: Windows 10 and later.
    Windows10,
}

impl Layout {
    pub fn label(self) -> &'static str {
        match self {
            Layout::Windows7 => "windows_7",
            Layout::Windows10 => "windows_10",
        }
    }

    /// Bytes in an entry before its variable-length path.
    pub fn fixed_len(self) -> usize {
        match self {
            Layout::Windows7 => 114,
            Layout::Windows10 => 130,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestListHeader {
    pub format_version: u32,
    pub number_of_entries: u32,
    pub number_of_pinned_entries: u32,
    pub last_entry_number: u32,
    pub last_revision_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestListEntry {
    pub offset: usize,
    pub mru_position: usize,
    pub entry_number: u32,
    pub stream_name: String,
    pub droid_volume_identifier: String,
    pub droid_file_identifier: String,
    pub birth_droid_volume_identifier: String,
    pub birth_droid_file_identifier: String,
    pub hostname: Option<String>,
    pub last_recorded_time_raw: u64,
    pub last_recorded_time: Option<String>,
    pub pin_status: i32,
    /// The 32-bit value at offset 116 of a version 2+ entry, read as it is;
    /// `None` for version 1, which has no such field. See [`OFFSET_116_NOTE`]
    /// for why it is not called an access count.
    pub offset_116: Option<u32>,
    pub path: String,
    pub path_had_invalid_utf16: bool,
}

/// Why the entry walk stopped before the end of the stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    Truncated {
        offset: usize,
        needed: usize,
        available: usize,
    },
    EntryCap {
        cap: usize,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DestList {
    pub header: DestListHeader,
    pub layout: Layout,
    pub entries: Vec<DestListEntry>,
    pub stopped: Option<Stop>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DestListError {
    TooShort { len: usize },
    UnsupportedVersion { version: u32 },
}

impl std::fmt::Display for DestListError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DestListError::TooShort { len } => write!(
                f,
                "the DestList stream is {len} bytes, shorter than its {HEADER_LEN}-byte header"
            ),
            DestListError::UnsupportedVersion { version } => write!(
                f,
                "DestList format version {version} is not one this build decodes (1, 2, 3 or 4)"
            ),
        }
    }
}

pub fn parse(bytes: &[u8]) -> Result<DestList, DestListError> {
    if bytes.len() < HEADER_LEN {
        return Err(DestListError::TooShort { len: bytes.len() });
    }
    let u32_at = |off: usize| u32::from_le_bytes(bytes[off..off + 4].try_into().unwrap());
    let header = DestListHeader {
        format_version: u32_at(0),
        number_of_entries: u32_at(4),
        number_of_pinned_entries: u32_at(8),
        last_entry_number: u32_at(16),
        last_revision_number: u32_at(24),
    };
    let layout = match header.format_version {
        1 => Layout::Windows7,
        2..=4 => Layout::Windows10,
        version => return Err(DestListError::UnsupportedVersion { version }),
    };

    let mut entries = Vec::new();
    let mut stopped = None;
    let mut offset = HEADER_LEN;
    while offset < bytes.len() {
        if entries.len() >= MAX_ENTRIES {
            stopped = Some(Stop::EntryCap { cap: MAX_ENTRIES });
            break;
        }
        match parse_entry(bytes, offset, layout, entries.len()) {
            Ok((entry, len)) => {
                entries.push(entry);
                offset += len;
            }
            Err(needed) => {
                stopped = Some(Stop::Truncated {
                    offset,
                    needed,
                    available: bytes.len() - offset,
                });
                break;
            }
        }
    }
    Ok(DestList {
        header,
        layout,
        entries,
        stopped,
    })
}

/// One entry at `offset`, with its total length; `Err(needed)` when the
/// bytes run out, with how many the entry would have occupied.
fn parse_entry(
    bytes: &[u8],
    offset: usize,
    layout: Layout,
    mru_position: usize,
) -> Result<(DestListEntry, usize), usize> {
    let fixed = layout.fixed_len();
    let e = bytes.get(offset..offset + fixed).ok_or(fixed)?;
    let guid = |at: usize| {
        let raw: [u8; 16] = e[at..at + 16].try_into().unwrap();
        seance_core::guid::format_guid(&raw)
    };
    let u32_at = |at: usize| u32::from_le_bytes(e[at..at + 4].try_into().unwrap());

    let host_raw = &e[72..88];
    let host_end = host_raw.iter().position(|&b| b == 0).unwrap_or(16);
    let hostname = match &host_raw[..host_end] {
        [] => None,
        h => Some(String::from_utf8_lossy(h).into_owned()),
    };
    let entry_number = u32_at(88);
    let last_recorded_time_raw = u64::from_le_bytes(e[100..108].try_into().unwrap());
    let pin_status = u32_at(108) as i32;
    let (offset_116, path_size_at, trailer) = match layout {
        Layout::Windows7 => (None, 112, 0),
        Layout::Windows10 => (Some(u32_at(116)), 128, 4),
    };
    let path_units = u16::from_le_bytes([e[path_size_at], e[path_size_at + 1]]) as usize;
    let total = fixed + path_units * 2 + trailer;
    let path_bytes = bytes
        .get(offset + fixed..offset + fixed + path_units * 2)
        .ok_or(total)?;
    if offset + total > bytes.len() {
        return Err(total);
    }
    let units: Vec<u16> = path_bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    let mut path_had_invalid_utf16 = false;
    let path: String = char::decode_utf16(units.iter().copied())
        .map(|r| {
            r.unwrap_or_else(|_| {
                path_had_invalid_utf16 = true;
                char::REPLACEMENT_CHARACTER
            })
        })
        .collect();

    Ok((
        DestListEntry {
            offset,
            mru_position,
            entry_number,
            stream_name: format!("{entry_number:x}"),
            droid_volume_identifier: guid(8),
            droid_file_identifier: guid(24),
            birth_droid_volume_identifier: guid(40),
            birth_droid_file_identifier: guid(56),
            hostname,
            last_recorded_time_raw,
            last_recorded_time: seance_core::time::filetime_to_rfc3339(last_recorded_time_raw),
            pin_status,
            offset_116,
            path,
            path_had_invalid_utf16,
        },
        total,
    ))
}

/// Byte builders for a DestList stream, laid out per the format
/// documentation, shared with the crate's other tests.
#[cfg(test)]
pub(crate) mod fixtures {
    use super::Layout;

    pub fn header(version: u32, entries: u32, pinned: u32) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(&version.to_le_bytes());
        h.extend_from_slice(&entries.to_le_bytes());
        h.extend_from_slice(&pinned.to_le_bytes());
        h.extend_from_slice(&1.0f32.to_le_bytes());
        h.extend_from_slice(&entries.to_le_bytes()); // last entry number
        h.extend_from_slice(&0u32.to_le_bytes());
        h.extend_from_slice(&7u32.to_le_bytes()); // last revision number
        h.extend_from_slice(&0u32.to_le_bytes());
        h
    }

    /// One entry with the fields the tests care about set and the rest zero;
    /// `offset_116` is the Windows 10 layout's value at that offset.
    pub fn entry(
        layout: Layout,
        entry_number: u32,
        filetime: u64,
        pin: i32,
        offset_116: u32,
        path: &str,
    ) -> Vec<u8> {
        let mut e = vec![0u8; layout.fixed_len()];
        e[72..72 + 4].copy_from_slice(b"host");
        e[88..92].copy_from_slice(&entry_number.to_le_bytes());
        e[100..108].copy_from_slice(&filetime.to_le_bytes());
        e[108..112].copy_from_slice(&pin.to_le_bytes());
        let utf16: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let count = (utf16.len() / 2) as u16;
        match layout {
            Layout::Windows7 => {
                e[112..114].copy_from_slice(&count.to_le_bytes());
                e.extend_from_slice(&utf16);
            }
            Layout::Windows10 => {
                e[112..116].copy_from_slice(&(-1i32).to_le_bytes());
                e[116..120].copy_from_slice(&offset_116.to_le_bytes());
                e[128..130].copy_from_slice(&count.to_le_bytes());
                e.extend_from_slice(&utf16);
                e.extend_from_slice(&[0u8; 4]);
            }
        }
        e
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{entry, header};
    use super::*;

    // 2012-04-01T13:52:38.9975382Z
    const FT: u64 = 129_777_619_589_975_382;

    #[test]
    fn a_version_1_stream_is_read_with_the_windows_7_layout() {
        let mut s = header(1, 2, 0);
        s.extend(entry(Layout::Windows7, 11, FT, -1, 0, "C:\\one"));
        s.extend(entry(Layout::Windows7, 3, FT - 10_000_000, 0, 0, "C:\\two"));
        let d = parse(&s).expect("parses");
        assert_eq!(d.layout, Layout::Windows7);
        assert_eq!(d.header.format_version, 1);
        assert_eq!(d.header.number_of_entries, 2);
        assert_eq!(d.header.last_revision_number, 7);
        assert_eq!(d.entries.len(), 2);
        assert!(d.stopped.is_none());

        let e = &d.entries[0];
        assert_eq!(e.offset, 32);
        assert_eq!(e.mru_position, 0);
        assert_eq!(e.entry_number, 11);
        assert_eq!(e.stream_name, "b");
        assert_eq!(e.path, "C:\\one");
        assert_eq!(e.hostname.as_deref(), Some("host"));
        assert_eq!(e.pin_status, -1);
        assert_eq!(
            e.last_recorded_time.as_deref(),
            Some("2012-04-01T13:52:38.997538200+00:00")
        );
        assert_eq!(e.last_recorded_time_raw, FT);
        assert_eq!(
            e.offset_116, None,
            "a version 1 entry has no field at offset 116"
        );
        assert_eq!(
            e.droid_volume_identifier,
            "00000000-0000-0000-0000-000000000000"
        );

        let e = &d.entries[1];
        assert_eq!(e.mru_position, 1);
        assert_eq!(e.entry_number, 3);
        assert_eq!(e.stream_name, "3");
        assert_eq!(e.pin_status, 0);
        assert_eq!(e.offset, 32 + 114 + 12);
    }

    #[test]
    fn a_version_3_stream_is_read_with_the_windows_10_layout_and_yields_the_offset_116_value() {
        let mut s = header(3, 1, 1);
        s.extend(entry(Layout::Windows10, 2, FT, 0, 5, "http://a/b"));
        let d = parse(&s).expect("parses");
        assert_eq!(d.layout, Layout::Windows10);
        assert_eq!(d.header.format_version, 3);
        assert_eq!(d.header.number_of_pinned_entries, 1);
        let e = &d.entries[0];
        assert_eq!(e.offset_116, Some(5));
        assert_eq!(e.path, "http://a/b");
        assert_eq!(e.pin_status, 0);
        assert_eq!(e.entry_number, 2);
    }

    #[test]
    fn versions_2_and_4_use_the_windows_10_layout_and_5_is_refused_rather_than_guessed() {
        for v in [2u32, 4] {
            let mut s = header(v, 1, 0);
            s.extend(entry(Layout::Windows10, 1, FT, -1, 1, "x"));
            let d = parse(&s).expect("parses");
            assert_eq!(d.layout, Layout::Windows10, "version {v}");
            assert_eq!(d.entries.len(), 1);
        }
        let mut s = header(5, 1, 0);
        s.extend(entry(Layout::Windows10, 1, FT, -1, 1, "x"));
        assert_eq!(
            parse(&s),
            Err(DestListError::UnsupportedVersion { version: 5 })
        );
    }

    #[test]
    fn the_offset_116_note_names_both_sources_and_their_uncertainty() {
        // Neither source the module follows establishes the field: libyal
        // writes "Unknown (access count?)" and plaso names it unknown5. The
        // note is what lets a reader weigh the number, so it must say so.
        for needle in ["libyal", "Unknown (access count?)", "plaso", "unknown5"] {
            assert!(
                OFFSET_116_NOTE.contains(needle),
                "the note must name {needle:?}: {OFFSET_116_NOTE}"
            );
        }
        assert!(!OFFSET_116_NOTE.contains("is the access count"));
    }

    #[test]
    fn a_stream_shorter_than_its_header_is_refused_with_its_length() {
        assert_eq!(parse(&[0u8; 31]), Err(DestListError::TooShort { len: 31 }));
        assert_eq!(parse(&[]), Err(DestListError::TooShort { len: 0 }));
    }

    #[test]
    fn a_header_and_nothing_else_is_an_empty_list_not_an_error() {
        let d = parse(&header(1, 0, 0)).expect("parses");
        assert!(d.entries.is_empty());
        assert!(d.stopped.is_none());
    }

    #[test]
    fn an_entry_cut_short_stops_the_walk_and_says_how_much_was_missing() {
        let mut s = header(1, 2, 0);
        s.extend(entry(Layout::Windows7, 1, FT, -1, 0, "C:\\whole"));
        let second = entry(Layout::Windows7, 2, FT, -1, 0, "C:\\cut");
        let second_offset = s.len();
        s.extend_from_slice(&second[..second.len() - 3]);
        let d = parse(&s).expect("parses what is whole");
        assert_eq!(d.entries.len(), 1);
        assert_eq!(
            d.stopped,
            Some(Stop::Truncated {
                offset: second_offset,
                needed: second.len(),
                available: second.len() - 3,
            })
        );
        // Cut inside the fixed part as well.
        let mut s = header(1, 1, 0);
        s.extend_from_slice(&entry(Layout::Windows7, 1, FT, -1, 0, "C:\\x")[..50]);
        let d = parse(&s).unwrap();
        assert!(d.entries.is_empty());
        assert_eq!(
            d.stopped,
            Some(Stop::Truncated {
                offset: 32,
                needed: 114,
                available: 50
            })
        );
    }

    #[test]
    fn an_unset_time_is_absent_not_1601() {
        let mut s = header(1, 1, 0);
        s.extend(entry(Layout::Windows7, 1, 0, -1, 0, "x"));
        let d = parse(&s).unwrap();
        assert_eq!(d.entries[0].last_recorded_time, None);
        assert_eq!(d.entries[0].last_recorded_time_raw, 0);
    }

    #[test]
    fn an_empty_host_name_is_absent_and_a_lone_surrogate_in_the_path_is_flagged() {
        let mut s = header(1, 1, 0);
        let mut e = entry(Layout::Windows7, 1, FT, -1, 0, "ab");
        e[72..76].copy_from_slice(&[0, 0, 0, 0]);
        // Replace the first path unit with a lone high surrogate.
        e[114..116].copy_from_slice(&0xD800u16.to_le_bytes());
        s.extend(e);
        let d = parse(&s).unwrap();
        assert_eq!(d.entries[0].hostname, None);
        assert!(d.entries[0].path_had_invalid_utf16);
        assert_eq!(d.entries[0].path, "\u{FFFD}b");
    }

    #[test]
    fn droids_are_rendered_in_the_mixed_endian_guid_form() {
        let mut s = header(1, 1, 0);
        let mut e = entry(Layout::Windows7, 1, FT, -1, 0, "x");
        e[8..24].copy_from_slice(&[
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F,
        ]);
        s.extend(e);
        let d = parse(&s).unwrap();
        assert_eq!(
            d.entries[0].droid_volume_identifier,
            "03020100-0504-0706-0809-0a0b0c0d0e0f"
        );
    }

    #[test]
    fn the_entry_ceiling_stops_the_walk_and_is_named() {
        let mut s = header(1, (MAX_ENTRIES + 1) as u32, 0);
        for i in 0..=MAX_ENTRIES {
            s.extend(entry(Layout::Windows7, i as u32 + 1, FT, -1, 0, ""));
        }
        let d = parse(&s).unwrap();
        assert_eq!(d.entries.len(), MAX_ENTRIES);
        assert_eq!(d.stopped, Some(Stop::EntryCap { cap: MAX_ENTRIES }));
    }
}
