//! `StickyNotes.snt` — an OLE2 compound file, one storage per note.
//!
//! # No stream-naming guess is load-bearing
//!
//! The documented layout is one storage per note, named for the note's
//! identifier, holding a `0` stream (the RTF) and sometimes a `1` or `3`
//! stream. This parser does **not** assert that — and the name is treated as
//! an opaque identifier rather than parsed, partly because the format caps an
//! object name at 31 UTF-16 code units, so a brace-delimited GUID (38
//! characters) and a bare one (36) are both too long to be one. It enumerates the root's storages, emits
//! one note per storage, and for each stream inside records the name, the
//! declared length, and — when the bytes open `{\rtf` — the extracted text
//! with the raw RTF beside it. A storage whose streams it does not recognise is
//! **listed** with `unresolved_structure`, never skipped.
//!
//! That way the record says what was read, rather than asserting a layout
//! nobody here can check. See `lib.rs` for why nobody here can check it.
//!
//! # The timestamps, and what cannot be said about them
//!
//! A CFB directory entry carries a creation and a modification FILETIME. The
//! `cfb` crate exposes them as `SystemTime` and offers **no accessor for the
//! raw value**, so an unset (zero) timestamp arrives as 1601-01-01 — and on a
//! platform that cannot represent that instant, as the Unix epoch instead.
//! Both are therefore reported as **absent, with the reason**, because a note
//! created at 1601-01-01 is not a thing and a "Created 1601-01-01" row on a
//! report is a fabricated date. The cost is stated on the record: a note
//! genuinely created at exactly the Unix epoch would also read as absent, and
//! this build cannot tell the two apart through the reader it uses.

use serde_json::{json, Map, Value};
use std::io::{Cursor, Read};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::rtf;
use crate::unvalidated::stamp_snt;

/// Notes read before the parser stops.
pub const MAX_NOTES: usize = 100_000;

/// Streams read per note before the parser stops.
pub const MAX_STREAMS_PER_NOTE: usize = 64;

/// Bytes read from one stream.
pub const MAX_STREAM_BYTES: u64 = 16 * 1024 * 1024;

/// Whether these bytes are an OLE2 compound file.
pub fn is_compound_file(bytes: &[u8]) -> bool {
    bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
}

/// One stream inside a note's storage.
#[derive(Clone, Debug)]
pub struct NoteStream {
    pub name: String,
    /// What the directory entry declares.
    pub declared_len: u64,
    /// How many bytes were actually readable.
    pub read_len: Option<usize>,
    /// Set when the stream opens `{\rtf`.
    pub rtf: Option<rtf::Extracted>,
    /// Why nothing was read, when nothing was.
    pub unavailable: Option<String>,
}

/// One note.
#[derive(Clone, Debug)]
pub struct Note {
    /// The storage's own name. Used as an identifier and **never parsed for
    /// meaning**: the format caps a name at 31 UTF-16 code units, so whatever
    /// a given build of the app puts here, it is not a full GUID.
    pub storage_name: String,
    pub storage_path: String,
    pub created: Option<String>,
    pub modified: Option<String>,
    pub streams: Vec<NoteStream>,
    /// Set when no stream in this storage was recognised.
    pub unrecognised: bool,
}

/// What the whole file yielded.
#[derive(Clone, Debug, Default)]
pub struct SntFile {
    pub notes: Vec<Note>,
    /// Streams directly under the root, which the documented layout does not
    /// put there. Listed rather than dropped.
    pub root_streams: Vec<NoteStream>,
    pub capped: Option<String>,
}

/// A CFB timestamp, or `None` when it is one of the two sentinels this reader
/// cannot tell from an unset value.
///
/// See the module comment: `cfb` gives a `SystemTime` and no raw FILETIME, so
/// the FILETIME zero arrives as 1601-01-01, and an overflow arrives as the Unix
/// epoch.
pub fn entry_time(t: SystemTime) -> Option<String> {
    // Back to a FILETIME, so the shared converter's guards apply: it already
    // rejects zero, anything before the Unix epoch, and the far-future
    // "never" sentinels.
    const FILETIME_EPOCH_DIFF_SECS: u64 = 11_644_473_600;
    let filetime = match t.duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() + FILETIME_EPOCH_DIFF_SECS)
            .checked_mul(10_000_000)?
            .checked_add(u64::from(d.subsec_nanos() / 100))?,
        Err(e) => {
            // Before 1970. FILETIME zero is 1601-01-01, which is exactly the
            // unset sentinel, and the subtraction below yields 0 for it.
            let d = e.duration();
            let secs = FILETIME_EPOCH_DIFF_SECS.checked_sub(d.as_secs())?;
            secs.checked_mul(10_000_000)?
                .checked_sub(u64::from(d.subsec_nanos() / 100))?
        }
    };
    // The Unix epoch exactly is the other sentinel: the reader returns it when
    // the stored FILETIME cannot be represented. See the module comment.
    if t == UNIX_EPOCH {
        return None;
    }
    seance_core::time::filetime_to_rfc3339(filetime)
}

/// The sentence a record carries when a timestamp was one of the sentinels.
pub const TIME_ABSENT_REASON: &str =
    "Not recorded: this directory entry's timestamp is the unset sentinel. The OLE2 reader this \
     build uses exposes the timestamp as a wall-clock instant and offers no access to the raw \
     value, so an unset (zero) FILETIME arrives as 1601-01-01 and an unrepresentable one arrives \
     as 1970-01-01. Both are reported as no date, because \"created 1601-01-01\" is a fabricated \
     date on a report. The cost is that a note genuinely created at exactly 1970-01-01T00:00:00Z \
     would also read as absent, and this build cannot tell the two apart.";

/// Read a `StickyNotes.snt`.
pub fn read(bytes: &[u8]) -> Result<SntFile, String> {
    let mut comp = cfb::CompoundFile::open(Cursor::new(bytes)).map_err(|e| e.to_string())?;

    // The storages directly under the root, each of which is one note in the
    // documented layout. Collected first, because `walk` borrows immutably and
    // `open_stream` needs a mutable borrow.
    struct Pending {
        name: String,
        path: String,
        created: SystemTime,
        modified: SystemTime,
        streams: Vec<(String, String, u64)>,
    }
    let mut pending: Vec<Pending> = Vec::new();
    let mut root_stream_entries: Vec<(String, String, u64)> = Vec::new();
    let mut capped = None;

    for entry in comp.walk() {
        let path = entry.path().to_string_lossy().to_string();
        let depth = path.split('/').filter(|s| !s.is_empty()).count();
        if entry.is_root() {
            continue;
        }
        if depth == 1 {
            if entry.is_storage() {
                if pending.len() >= MAX_NOTES {
                    capped = Some(format!(
                        "The note ceiling of {MAX_NOTES} was reached. This file holds MORE \
                         storages than are reported here."
                    ));
                    break;
                }
                pending.push(Pending {
                    name: entry.name().to_string(),
                    path,
                    created: entry.created(),
                    modified: entry.modified(),
                    streams: Vec::new(),
                });
            } else {
                // A stream directly under the root. The documented layout does
                // not put one there, so it is listed rather than dropped.
                root_stream_entries.push((entry.name().to_string(), path, entry.len()));
            }
            continue;
        }
        if depth == 2 && entry.is_stream() {
            let parent = path.rsplit_once('/').map(|(p, _)| p.to_string());
            if let Some(p) = pending
                .iter_mut()
                .find(|p| Some(&p.path) == parent.as_ref())
            {
                if p.streams.len() < MAX_STREAMS_PER_NOTE {
                    p.streams
                        .push((entry.name().to_string(), path, entry.len()));
                }
            }
        }
    }

    let mut out = SntFile {
        capped,
        ..Default::default()
    };
    for (name, path, len) in root_stream_entries {
        out.root_streams
            .push(read_stream(&mut comp, &name, &path, len));
    }
    for p in pending {
        let mut streams = Vec::new();
        for (name, path, len) in &p.streams {
            streams.push(read_stream(&mut comp, name, path, *len));
        }
        let unrecognised = !streams.iter().any(|s| s.rtf.is_some());
        out.notes.push(Note {
            storage_name: p.name,
            storage_path: p.path,
            created: entry_time(p.created),
            modified: entry_time(p.modified),
            streams,
            unrecognised,
        });
    }
    Ok(out)
}

fn read_stream<F: Read + std::io::Seek>(
    comp: &mut cfb::CompoundFile<F>,
    name: &str,
    path: &str,
    declared_len: u64,
) -> NoteStream {
    let mut s = NoteStream {
        name: name.to_string(),
        declared_len,
        read_len: None,
        rtf: None,
        unavailable: None,
    };
    if declared_len > MAX_STREAM_BYTES {
        s.unavailable = Some(format!(
            "This stream declares {declared_len} bytes, past this build's {MAX_STREAM_BYTES}-byte \
             ceiling, and was not read. Nothing about its contents is established either way."
        ));
        return s;
    }
    let mut stream = match comp.open_stream(path) {
        Ok(st) => st,
        Err(e) => {
            s.unavailable = Some(format!("This stream could not be opened: {e}"));
            return s;
        }
    };
    let mut buf = Vec::with_capacity(declared_len as usize);
    match stream.read_to_end(&mut buf) {
        Ok(_) => {
            s.read_len = Some(buf.len());
            if buf.len() as u64 != declared_len {
                s.unavailable = Some(format!(
                    "This stream declares {declared_len} bytes and {} were readable. What the \
                     unread bytes hold is not established.",
                    buf.len()
                ));
            }
            if rtf::is_rtf(&buf) {
                s.rtf = Some(rtf::extract(&buf));
            }
        }
        Err(e) => s.unavailable = Some(format!("This stream could not be read: {e}")),
    }
    s
}

impl NoteStream {
    pub fn to_json(&self) -> Value {
        json!({
            "stream_name": self.name,
            "declared_bytes": self.declared_len,
            "readable_bytes": self.read_len,
            "is_rtf": self.rtf.is_some(),
            "unavailable_reason": self.unavailable,
        })
    }
}

/// The `source_format` every `.snt` record carries — the coverage record and
/// each note alike — and the value the viewer's Format column shows.
pub const SOURCE_FORMAT: &str = "snt_compound_file";

impl Note {
    pub fn to_json(&self, source_file: &str) -> Value {
        let mut m = Map::new();
        m.insert("type".into(), json!("StickyNote"));
        // `HUNT-242`: named as a `plum.sqlite` note names its format.
        m.insert("source_format".into(), json!(SOURCE_FORMAT));
        // The first RTF stream in the storage is the note's text. Which stream
        // that is, is NOT asserted: whichever one opened `{\rtf` is reported,
        // and its name is on the record so the choice can be checked.
        let text_stream = self.streams.iter().find(|s| s.rtf.is_some());
        let text = text_stream.and_then(|s| s.rtf.as_ref()).map(|r| &r.text);
        m.insert(
            "name".into(),
            json!(match text.map(|t| t.trim()) {
                Some(t) if !t.is_empty() => t.lines().next().unwrap_or(t).to_string(),
                _ => format!("Sticky note {}", self.storage_name),
            }),
        );
        m.insert("source_file".into(), json!(source_file));
        m.insert("storage_name".into(), json!(self.storage_name));
        m.insert("storage_path".into(), json!(self.storage_path));
        m.insert("text".into(), json!(text));
        m.insert(
            "text_stream_name".into(),
            json!(text_stream.map(|s| s.name.clone())),
        );
        m.insert(
            "text_basis".into(),
            json!(
                "The text is extracted from whichever stream in this storage opens with the RTF \
                 magic, and that stream's name is on this record. This build does not assert \
                 which stream name holds a note's text: it reports the one it found."
            ),
        );
        if let Some(r) = text_stream.and_then(|s| s.rtf.as_ref()) {
            m.insert("rtf_embedded_objects".into(), json!(r.embedded));
            m.insert(
                "rtf_skipped_destinations".into(),
                json!(r.skipped_destinations),
            );
            if let Some(u) = &r.unbalanced {
                m.insert("rtf_unbalanced".into(), json!(u));
                m.insert("content_incomplete".into(), json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
                );
            }
            if r.capped {
                m.insert("text_capped".into(), json!(true));
                m.insert("content_incomplete".into(), json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    json!(seance_core::io::IncompleteReason::CapReached.as_str()),
                );
            }
            if !r.embedded.is_empty() {
                m.insert(
                    "rtf_embedded_note".into(),
                    json!(
                        "This note holds an embedded picture or object. It is reported as present \
                         and is NOT rendered as text: its payload is hex-encoded bytes, and \
                         printing them would turn the note into a page of gibberish."
                    ),
                );
            }
        }
        m.insert("created".into(), json!(self.created));
        m.insert("modified".into(), json!(self.modified));
        if self.created.is_none() || self.modified.is_none() {
            m.insert("time_absent_reason".into(), json!(TIME_ABSENT_REASON));
        }
        m.insert(
            "time_scope".into(),
            json!(
                "the compound file's directory entry for this note's storage, not the note's own \
                   record of when it was written"
            ),
        );
        m.insert(
            "streams".into(),
            json!(self
                .streams
                .iter()
                .map(NoteStream::to_json)
                .collect::<Vec<_>>()),
        );
        if self.unrecognised {
            // LISTED, never skipped: a storage this build did not recognise is
            // a note it could not read, which is not the same as no note.
            m.insert("unrecognised_structure".into(), json!(true));
            m.insert(
                "unrecognised_reason".into(),
                json!(
                    "No stream in this storage opens with the RTF magic, so no text was \
                     extracted from it. The storage and every stream in it are listed above with \
                     their names and declared lengths: this is a note this build could not read, \
                     which is not the same as an absence of a note."
                ),
            );
            m.insert("content_incomplete".into(), json!(true));
            m.insert(
                "content_incomplete_reason".into(),
                json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
            );
        }
        stamp_snt(&mut m);
        Value::Object(m)
    }
}
