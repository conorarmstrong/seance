//! The OLE compound-file directory of an `automaticDestinations-ms` file:
//! the `DestList` stream and the numbered shortcut streams beside it.
//!
//! The container is read with the `cfb` crate — header, FAT, mini-FAT and
//! directory — in its permissive mode, so a file whose header fields are
//! slightly off is still followed. A file it cannot open at all is returned
//! as an error for the caller to fall back on; this module does not carve.
//! Shortcut streams are the ones the directory names by a hexadecimal
//! number without a leading zero, which is the entry number in `DestList`
//! written in hex; anything else beside `DestList` is listed by name and
//! left unread.

use std::io::{Cursor, Read};

/// Ceilings on what is read out of one jump list, stated on the record when
/// they are hit.
#[derive(Debug, Clone, Copy)]
pub struct Caps {
    pub lnk_stream_bytes: u64,
    pub dest_list_bytes: u64,
    pub lnk_streams: usize,
}

impl Default for Caps {
    fn default() -> Self {
        Caps {
            lnk_stream_bytes: 16 * 1024 * 1024,
            dest_list_bytes: 64 * 1024 * 1024,
            lnk_streams: 10_000,
        }
    }
}

/// One stream as the directory lists it and as it was read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamRead {
    pub name: String,
    pub declared_len: u64,
    pub bytes: Vec<u8>,
    /// Set when the bytes are not the whole stream, with the reason.
    pub unavailable: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct JumpListStreams {
    pub dest_list: Option<StreamRead>,
    /// The numbered streams, in ascending numeric order.
    pub lnk_streams: Vec<StreamRead>,
    /// Directory entries that are neither `DestList` nor numbered.
    pub other_entries: Vec<String>,
    /// Numbered streams the directory lists, whether or not they were read.
    pub lnk_streams_in_directory: usize,
}

/// The number a shortcut stream is named by, or `None` for any other name.
pub fn lnk_stream_number(name: &str) -> Option<u32> {
    if name.is_empty() || name.len() > 8 || name.starts_with('0') {
        return None;
    }
    if !name.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u32::from_str_radix(name, 16).ok()
}

/// Read the directory and the streams a jump list is made of.
pub fn read(bytes: &[u8], caps: Caps) -> Result<JumpListStreams, String> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(bytes)).map_err(|e| e.to_string())?;

    let mut dest_list_entry: Option<(String, u64)> = None;
    let mut numbered: Vec<(u32, String, u64)> = Vec::new();
    let mut out = JumpListStreams::default();
    for entry in comp.read_root_storage() {
        let name = entry.name().to_string();
        if entry.is_stream() && name == "DestList" {
            dest_list_entry = Some((name, entry.len()));
        } else if let Some(n) = lnk_stream_number(&name).filter(|_| entry.is_stream()) {
            numbered.push((n, name, entry.len()));
        } else {
            out.other_entries.push(name);
        }
    }
    out.lnk_streams_in_directory = numbered.len();
    numbered.sort_by_key(|(n, _, _)| *n);
    numbered.truncate(caps.lnk_streams);

    if let Some((name, len)) = dest_list_entry {
        out.dest_list = Some(read_stream(&mut comp, &name, len, caps.dest_list_bytes));
    }
    for (_, name, len) in numbered {
        out.lnk_streams
            .push(read_stream(&mut comp, &name, len, caps.lnk_stream_bytes));
    }
    Ok(out)
}

fn read_stream(
    comp: &mut cfb::CompoundFile<Cursor<&[u8]>>,
    name: &str,
    declared_len: u64,
    cap: u64,
) -> StreamRead {
    let mut s = StreamRead {
        name: name.to_string(),
        declared_len,
        bytes: Vec::new(),
        unavailable: None,
    };
    if declared_len > cap {
        s.unavailable = Some(format!(
            "stream `{name}` declares {declared_len} bytes, past this build's {cap}-byte ceiling \
             for one stream, and was not read"
        ));
        return s;
    }
    let mut stream = match comp.open_stream(format!("/{name}")) {
        Ok(st) => st,
        Err(e) => {
            s.unavailable = Some(format!("stream `{name}` could not be opened: {e}"));
            return s;
        }
    };
    let mut buf = Vec::with_capacity(declared_len as usize);
    match stream.read_to_end(&mut buf) {
        Ok(_) => {
            if buf.len() as u64 != declared_len {
                s.unavailable = Some(format!(
                    "stream `{name}` declares {declared_len} bytes and {} were readable",
                    buf.len()
                ));
            }
            s.bytes = buf;
        }
        Err(e) => {
            s.unavailable = Some(format!(
                "stream `{name}` could not be read past byte {}: {e}",
                buf.len()
            ));
            s.bytes = buf;
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Cursor, Write};

    fn compound(streams: &[(&str, &[u8])], storages: &[&str]) -> Vec<u8> {
        let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).unwrap();
        for s in storages {
            comp.create_storage(format!("/{s}")).unwrap();
        }
        for (name, bytes) in streams {
            let mut st = comp.create_stream(format!("/{name}")).unwrap();
            st.write_all(bytes).unwrap();
        }
        comp.flush().unwrap();
        comp.into_inner().into_inner()
    }

    #[test]
    fn shortcut_streams_are_the_ones_named_by_a_hex_number_without_a_leading_zero() {
        assert_eq!(lnk_stream_number("1"), Some(1));
        assert_eq!(lnk_stream_number("a"), Some(10));
        assert_eq!(lnk_stream_number("b"), Some(11));
        assert_eq!(lnk_stream_number("10"), Some(16));
        assert_eq!(lnk_stream_number("1f3"), Some(0x1f3));
        assert_eq!(lnk_stream_number("A"), Some(10));
        assert_eq!(lnk_stream_number("0"), None);
        assert_eq!(lnk_stream_number("01"), None);
        assert_eq!(lnk_stream_number(""), None);
        assert_eq!(lnk_stream_number("DestList"), None);
        assert_eq!(lnk_stream_number("1g"), None);
        assert_eq!(lnk_stream_number("123456789"), None, "past u32");
    }

    #[test]
    fn the_directory_yields_the_dest_list_the_numbered_streams_and_names_the_rest() {
        let file = compound(
            &[
                ("b", b"eleven"),
                ("1", b"one"),
                ("DestList", b"dl"),
                ("Extra", b"?"),
                ("0", b"zero"),
            ],
            &["Sub"],
        );
        let s = read(&file, Caps::default()).expect("a well-formed compound file");
        assert_eq!(s.dest_list.as_ref().unwrap().bytes, b"dl");
        assert_eq!(s.dest_list.as_ref().unwrap().declared_len, 2);
        let names: Vec<&str> = s.lnk_streams.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["1", "b"], "ascending by number");
        assert_eq!(s.lnk_streams[1].bytes, b"eleven");
        assert_eq!(s.lnk_streams[1].declared_len, 6);
        assert!(s.lnk_streams.iter().all(|l| l.unavailable.is_none()));
        assert_eq!(s.lnk_streams_in_directory, 2);
        let mut other = s.other_entries.clone();
        other.sort();
        assert_eq!(other, ["0", "Extra", "Sub"]);
    }

    #[test]
    fn a_file_without_a_dest_list_says_so_rather_than_erroring() {
        let file = compound(&[("1", b"one")], &[]);
        let s = read(&file, Caps::default()).unwrap();
        assert!(s.dest_list.is_none());
        assert_eq!(s.lnk_streams.len(), 1);
    }

    #[test]
    fn bytes_that_are_not_a_compound_file_are_an_error_the_caller_can_fall_back_on() {
        let mut junk = vec![0u8; 4096];
        junk[..8].copy_from_slice(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
        assert!(read(&junk, Caps::default()).is_err());
        assert!(read(b"", Caps::default()).is_err());
    }

    #[test]
    fn a_stream_past_the_byte_ceiling_is_listed_unread_with_the_ceiling_named() {
        let file = compound(
            &[
                ("1", b"0123456789"),
                ("2", b"ok"),
                ("DestList", b"0123456789"),
            ],
            &[],
        );
        let caps = Caps {
            lnk_stream_bytes: 4,
            dest_list_bytes: 4,
            lnk_streams: 100,
        };
        let s = read(&file, caps).unwrap();
        let one = &s.lnk_streams[0];
        assert!(one.bytes.is_empty());
        assert_eq!(one.declared_len, 10);
        assert!(one.unavailable.as_deref().unwrap().contains("4-byte"));
        assert!(s.lnk_streams[1].unavailable.is_none());
        let dl = s.dest_list.as_ref().unwrap();
        assert!(dl.bytes.is_empty());
        assert!(dl.unavailable.as_deref().unwrap().contains("4-byte"));
    }

    #[test]
    fn the_stream_ceiling_keeps_the_lowest_numbered_streams_and_counts_the_rest() {
        let file = compound(&[("3", b"c"), ("1", b"a"), ("2", b"b")], &[]);
        let caps = Caps {
            lnk_streams: 2,
            ..Caps::default()
        };
        let s = read(&file, caps).unwrap();
        let names: Vec<&str> = s.lnk_streams.iter().map(|l| l.name.as_str()).collect();
        assert_eq!(names, ["1", "2"]);
        assert_eq!(s.lnk_streams_in_directory, 3);
    }
}
