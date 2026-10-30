//! Statedump (`0x6003`) and simpledump (`0x6004`) entries inside a
//! decompressed `.tracev3` chunkset.
//!
//! Neither refers to a format string: each carries its own text, so each is a
//! log entry in its own right (Apple's `log` tool lists them among the
//! messages, and the per-archive totals count them).
//!
//! # Layout
//!
//! After the entry's 16-byte preamble, both open with `u64` first and `u32`
//! second process id (the catalog's process key), four bytes of ttl and
//! padding, and the `u64` continuous time.
//!
//! * **Simpledump**: `u64` thread id, `u32` unknown offset, `u16` unknown ttl,
//!   `u16` unknown type, the 16-byte sender UUID and 16-byte shared-cache
//!   UUID, `u32` string count, `u32` subsystem size, `u32` message size, then
//!   the subsystem and message strings (each NUL-terminated within its size).
//! * **Statedump**: `u64` activity id, a 16-byte UUID, `u32` data type
//!   (1 property list, 2 protocol buffer, 3 custom object), `u32` data size,
//!   three 64-byte fixed fields — decoder library, object type, title — each
//!   read to its first NUL (the bytes after it are uninitialised memory, not
//!   evidence), then the data.
//!
//! A property list is decoded; a protocol buffer or a custom object is kept as
//! bytes and **said to be undecoded**, never rendered as if it were text.
//!
//! The layout was read from the corpus fixtures' own bytes (sizes that tile
//! the entry exactly) and agrees with the community reading in Mandiant's
//! `macos-UnifiedLogs`.

/// A simpledump entry: one line of text with its own subsystem.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Simpledump {
    pub(crate) first_proc_id: u64,
    pub(crate) second_proc_id: u32,
    pub(crate) continuous_time: u64,
    pub(crate) thread_id: u64,
    pub(crate) sender_uuid: String,
    pub(crate) dsc_uuid: String,
    pub(crate) subsystem: String,
    pub(crate) message: String,
    /// Why the entry is less than whole, in words.
    pub(crate) flaw: Option<String>,
}

/// What a statedump's data decoded to.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum StatedumpData {
    /// A property list, as JSON.
    Plist(serde_json::Value),
    /// Bytes this reader does not decode, with what they are.
    Undecoded { kind: &'static str, bytes: Vec<u8> },
    /// The entry declares no data at all.
    Empty,
}

/// A statedump entry: a titled snapshot of some state.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Statedump {
    pub(crate) first_proc_id: u64,
    pub(crate) second_proc_id: u32,
    pub(crate) continuous_time: u64,
    pub(crate) activity_id: u64,
    pub(crate) uuid: String,
    pub(crate) data_type: u32,
    pub(crate) decoder_library: String,
    pub(crate) object_type: String,
    pub(crate) title: String,
    pub(crate) data: StatedumpData,
    /// Why the entry is less than whole, in words.
    pub(crate) flaw: Option<String>,
}

fn le_u32(d: &[u8], at: usize) -> Option<u32> {
    d.get(at..at + 4)
        .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}
fn le_u64(d: &[u8], at: usize) -> Option<u64> {
    let mut b = [0u8; 8];
    b.copy_from_slice(d.get(at..at + 8)?);
    Some(u64::from_le_bytes(b))
}
fn uuid_at(d: &[u8], at: usize) -> Option<String> {
    d.get(at..at + 16)
        .map(|b| b.iter().map(|x| format!("{x:02X}")).collect())
}
/// Bytes up to the first NUL, as text.
fn c_string(b: &[u8]) -> String {
    let end = b.iter().position(|x| *x == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// Bytes in a simpledump's fixed header, and a statedump's.
const SIMPLEDUMP_HEADER: usize = 84;
const STATEDUMP_HEADER: usize = 56 + 3 * 64;

/// Parse a simpledump entry's payload (after its 16-byte preamble). `None`
/// when not even the fixed header fits.
pub(crate) fn parse_simpledump(p: &[u8]) -> Option<Simpledump> {
    if p.len() < SIMPLEDUMP_HEADER {
        return None;
    }
    let sub_size = le_u32(p, 76)? as usize;
    let msg_size = le_u32(p, 80)? as usize;
    let mut s = Simpledump {
        first_proc_id: le_u64(p, 0)?,
        second_proc_id: le_u32(p, 8)?,
        continuous_time: le_u64(p, 16)?,
        thread_id: le_u64(p, 24)?,
        sender_uuid: uuid_at(p, 40)?,
        dsc_uuid: uuid_at(p, 56)?,
        ..Default::default()
    };
    let body = &p[SIMPLEDUMP_HEADER..];
    let sub_end = sub_size.min(body.len());
    s.subsystem = c_string(&body[..sub_end]);
    let msg_end = sub_size.saturating_add(msg_size).min(body.len());
    s.message = c_string(body.get(sub_end..msg_end).unwrap_or_default());
    let need = sub_size.saturating_add(msg_size);
    if need > body.len() {
        s.flaw = Some(format!(
            "the entry declares {need} bytes of subsystem and message and holds {}",
            body.len()
        ));
    }
    Some(s)
}

/// Parse a statedump entry's payload (after its 16-byte preamble). `None`
/// when not even the fixed header fits.
pub(crate) fn parse_statedump(p: &[u8]) -> Option<Statedump> {
    if p.len() < STATEDUMP_HEADER {
        return None;
    }
    let data_type = le_u32(p, 48)?;
    let data_size = le_u32(p, 52)? as usize;
    let field = |i: usize| c_string(&p[56 + i * 64..56 + (i + 1) * 64]);
    let held = &p[STATEDUMP_HEADER..];
    let mut flaw = None;
    let bytes = if data_size > held.len() {
        flaw = Some(format!(
            "the entry declares {data_size} bytes of data and holds {}",
            held.len()
        ));
        held
    } else {
        &held[..data_size]
    };
    let undecoded = |kind| StatedumpData::Undecoded {
        kind,
        bytes: bytes.to_vec(),
    };
    let data = match data_type {
        _ if data_size == 0 => StatedumpData::Empty,
        1 if flaw.is_none() => match plist::from_bytes::<plist::Value>(bytes)
            .ok()
            .and_then(|v| serde_json::to_value(v).ok())
        {
            Some(v) => StatedumpData::Plist(v),
            None => {
                flaw = Some("the property list does not parse".into());
                undecoded("property list")
            }
        },
        1 => undecoded("property list"),
        2 => undecoded("protocol buffer"),
        3 => undecoded("custom object"),
        _ => undecoded("unknown data type"),
    };
    Some(Statedump {
        first_proc_id: le_u64(p, 0)?,
        second_proc_id: le_u32(p, 8)?,
        continuous_time: le_u64(p, 16)?,
        activity_id: le_u64(p, 24)?,
        uuid: uuid_at(p, 32)?,
        data_type,
        decoder_library: field(0),
        object_type: field(1),
        title: field(2),
        data,
        flaw,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::unifiedlog_chunks::{walk_entries, TAG_SIMPLEDUMP, TAG_STATEDUMP};

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("forensic_corpora/mandiant_unifiedlogs/test_data")
    }

    fn entry(rel: &str, tag: u32) -> Option<Vec<u8>> {
        let p = corpus().join(rel);
        let Ok(raw) = std::fs::read(&p) else {
            eprintln!("skipping: {} is not present", p.display());
            return None;
        };
        walk_entries(&raw)
            .entries
            .into_iter()
            .find(|e| e.tag == tag)
            .map(|e| e.payload.to_vec())
    }

    #[test]
    fn the_monterey_simpledump_yields_its_subsystem_and_message() {
        let Some(p) = entry(
            "Chunkset Tests/monterey_chunkset_simpledump.raw",
            TAG_SIMPLEDUMP,
        ) else {
            return;
        };
        let s = parse_simpledump(&p).expect("a simpledump");
        assert_eq!((s.first_proc_id, s.second_proc_id), (1, 1));
        assert_eq!(s.continuous_time, 0x0485_47C4_B62D);
        assert_eq!(s.thread_id, 0xEA03);
        assert_eq!(s.sender_uuid, "0DCF3E8B4923323EB3E5547307CF0EAC");
        assert_eq!(s.dsc_uuid, "3D05845F3F65358F9EBF2236E772AC01");
        assert_eq!(
            s.subsystem,
            "user/501/com.apple.mdworker.shared.0B000000-0000-0000-0000-000000000000 [4229]"
        );
        assert_eq!(
            s.message,
            "service exited: dirty = 0, supported pressured-exit = 1"
        );
        assert!(s.flaw.is_none());
    }

    #[test]
    fn the_big_sur_statedump_names_its_object_and_keeps_undecoded_data_as_bytes() {
        let Some(p) = entry(
            "Chunkset Tests/big_sur_statedump_chunkset.raw",
            TAG_STATEDUMP,
        ) else {
            return;
        };
        let s = parse_statedump(&p).expect("a statedump");
        assert_eq!((s.first_proc_id, s.second_proc_id), (0x71, 0x1d0));
        assert_eq!(s.continuous_time, 0xE8D5_B30D);
        assert_eq!(s.activity_id, 0x8000_0000_0000_0476);
        assert_eq!(s.data_type, 3);
        assert_eq!(s.decoder_library, "location");
        assert_eq!(s.object_type, "_CLDaemonStatusStateTrackerState");
        assert_eq!(s.title, "CLDaemonStatusStateTracker");
        match &s.data {
            StatedumpData::Undecoded { kind, bytes } => {
                assert_eq!(*kind, "custom object");
                assert_eq!(bytes.len(), 40);
            }
            d => panic!("a custom object is not decoded, not {d:?}"),
        }
        assert!(s.flaw.is_none());
    }

    #[test]
    fn a_plist_statedump_is_decoded() {
        let plist = br#"<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>state</key><string>idle</string></dict></plist>"#;
        let mut p = vec![0u8; 56];
        p[48..52].copy_from_slice(&1u32.to_le_bytes());
        p[52..56].copy_from_slice(&(plist.len() as u32).to_le_bytes());
        let mut name = |s: &str| {
            let mut f = s.as_bytes().to_vec();
            f.resize(64, 0);
            p.extend_from_slice(&f);
        };
        name("lib");
        name("type");
        name("a title");
        p.extend_from_slice(plist);
        let s = parse_statedump(&p).expect("a statedump");
        assert_eq!(s.title, "a title");
        assert_eq!(
            s.data,
            StatedumpData::Plist(serde_json::json!({ "state": "idle" }))
        );
    }

    /// Six Big Sur statedumps declare a property list of zero bytes: that
    /// is an empty snapshot, not a damaged one.
    #[test]
    fn a_statedump_with_no_data_is_empty_not_flawed() {
        let mut p = vec![0u8; 56 + 3 * 64];
        p[48..52].copy_from_slice(&1u32.to_le_bytes());
        let s = parse_statedump(&p).expect("a statedump");
        assert_eq!(s.data, StatedumpData::Empty);
        assert!(s.flaw.is_none());
    }

    #[test]
    fn dumps_cut_short_are_marked_not_dropped() {
        let Some(p) = entry(
            "Chunkset Tests/monterey_chunkset_simpledump.raw",
            TAG_SIMPLEDUMP,
        ) else {
            return;
        };
        let s = parse_simpledump(&p[..p.len() - 20]).expect("the header fits");
        assert!(s.flaw.is_some());
        assert!(s.message.starts_with("service exited"));
        assert!(parse_simpledump(&p[..40]).is_none());
        let Some(p) = entry(
            "Chunkset Tests/big_sur_statedump_chunkset.raw",
            TAG_STATEDUMP,
        ) else {
            return;
        };
        let s = parse_statedump(&p[..p.len() - 8]).expect("the header fits");
        assert!(s.flaw.as_deref().is_some_and(|f| f.contains("40")));
        assert!(parse_statedump(&p[..100]).is_none());
    }
}
