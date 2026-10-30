//! `StickyNotes.snt` — stated before it was read.
//!
//! **There is no `.snt` on this machine**, so every fixture here is built with
//! `cfb::CompoundFile::create`, the same way `seance_plugin_email`'s MSG tests
//! build theirs. That is also why each test is about what the reader REPORTS
//! rather than about a layout: the design goal is that no stream-naming guess
//! is load-bearing, and these tests are how that is held to.

use super::snt::*;
use std::io::{Cursor, Write};

/// One storage's streams: a name and its bytes.
type Streams<'a> = &'a [(&'a str, &'a [u8])];
/// One storage: its name and its streams.
type Storage<'a> = (&'a str, Streams<'a>);

/// Build a `.snt`-shaped compound file: one storage per note, streams inside.
fn build_snt(notes: &[Storage<'_>]) -> Vec<u8> {
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).expect("create");
    for (storage, streams) in notes {
        comp.create_storage(format!("/{storage}")).expect("storage");
        for (name, bytes) in *streams {
            let mut s = comp
                .create_stream(format!("/{storage}/{name}"))
                .expect("stream");
            s.write_all(bytes).expect("write");
        }
    }
    comp.into_inner().into_inner()
}

// A storage name, at the format's own limit. CFB caps an object name at 31
// UTF-16 code units, so a brace-delimited GUID (38) and a bare one (36) are
// both too long to BE a storage name -- which is one reason this reader treats
// the name as an opaque identifier and never parses it for meaning.
const NOTE_A: &str = "note-0e1d9a4f-00000001";
const NOTE_B: &str = "note-0e1d9a4f-00000002";

#[test]
fn a_compound_file_is_recognised_by_its_magic() {
    assert!(is_compound_file(&[
        0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1, 0x00
    ]));
    for not_one in [
        &b"{\\rtf1"[..],
        &b"SQLite format 3\0"[..],
        &b""[..],
        &[0xD0, 0xCF, 0x11, 0xE0][..],
    ] {
        assert!(!is_compound_file(not_one));
    }
}

/// One storage per note, and the text out of whichever stream is RTF.
#[test]
fn each_storage_is_one_note_and_its_rtf_stream_gives_the_text() {
    let bytes = build_snt(&[
        (NOTE_A, &[("0", br"{\rtf1\ansi Buy milk\par Call Bob}")]),
        (NOTE_B, &[("0", br"{\rtf1\ansi Dentist 3pm}")]),
    ]);
    let file = read(&bytes).expect("a real compound file opens");
    assert_eq!(file.notes.len(), 2);
    let a = file
        .notes
        .iter()
        .find(|n| n.storage_name == NOTE_A)
        .expect("note A");
    assert_eq!(
        a.streams[0].rtf.as_ref().map(|r| r.text.as_str()),
        Some("Buy milk\nCall Bob")
    );
    let j = a.to_json("StickyNotes.snt");
    assert_eq!(j["text"], "Buy milk\nCall Bob");
    assert_eq!(j["storage_name"], NOTE_A);
    // The name is the note's first line, which is what a list of notes needs.
    assert_eq!(j["name"], "Buy milk");
    // And which stream answered, so the choice can be checked.
    assert_eq!(j["text_stream_name"], "0");
}

/// `HUNT-242`: a `.snt` note names its format as a `plum.sqlite` note does, so
/// the viewer's Format column is not blank for every Windows 7 note — and an
/// unreadable storage's record names it too.
#[test]
fn every_snt_note_record_names_its_source_format() {
    let bytes = build_snt(&[
        (NOTE_A, &[("0", br"{\rtf1\ansi Buy milk}")]),
        (NOTE_B, &[("0", b"not rtf")]),
    ]);
    let file = read(&bytes).expect("opens");
    assert_eq!(file.notes.len(), 2);
    for n in &file.notes {
        assert_eq!(
            n.to_json("StickyNotes.snt")["source_format"],
            "snt_compound_file",
            "the value the coverage record and the viewer use"
        );
    }
}

/// **No stream name is load-bearing.** A note whose text is in a stream this
/// build has never heard of still yields its text.
#[test]
fn a_note_whose_text_is_in_an_unfamiliar_stream_is_still_read() {
    let bytes = build_snt(&[(NOTE_A, &[("SomethingElse", br"{\rtf1\ansi Feed the cat}")])]);
    let file = read(&bytes).expect("opens");
    let j = file.notes[0].to_json("StickyNotes.snt");
    assert_eq!(j["text"], "Feed the cat");
    assert_eq!(j["text_stream_name"], "SomethingElse");
    assert!(
        j["unrecognised_structure"].is_null(),
        "a stream that IS RTF is recognised whatever it is called"
    );
}

/// **A storage this build could not read is LISTED, never skipped** — with
/// every stream in it named and measured, because that is what the next reader
/// needs and what an examiner is entitled to.
#[test]
fn a_storage_with_no_recognised_stream_is_listed_with_its_streams() {
    let bytes = build_snt(&[(
        NOTE_A,
        &[("0", b"\x01\x02\x03\x04not rtf"), ("3", b"\xff\xfe")],
    )]);
    let file = read(&bytes).expect("opens");
    assert_eq!(file.notes.len(), 1, "the storage is not dropped");
    let n = &file.notes[0];
    assert!(n.unrecognised);
    let j = n.to_json("StickyNotes.snt");
    assert_eq!(j["unrecognised_structure"], serde_json::json!(true));
    assert!(j["text"].is_null());
    assert_eq!(
        j["content_incomplete_reason"], "unresolved_structure",
        "this is a note that would not read, not an absence of a note"
    );
    let streams = j["streams"].as_array().expect("the stream census");
    assert_eq!(streams.len(), 2);
    assert_eq!(streams[0]["stream_name"], "0");
    assert_eq!(streams[0]["declared_bytes"], serde_json::json!(11));
    assert_eq!(streams[0]["readable_bytes"], serde_json::json!(11));
    assert_eq!(streams[0]["is_rtf"], serde_json::json!(false));
    let why = j["unrecognised_reason"].as_str().unwrap_or("");
    assert!(
        why.contains("not the same as an absence of a note"),
        "got {why}"
    );
}

/// A stream directly under the root is not where a note lives, and is listed
/// rather than dropped.
#[test]
fn a_stream_at_the_root_is_listed_rather_than_dropped() {
    let mut comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).expect("create");
    {
        let mut s = comp.create_stream("/Version").expect("stream");
        s.write_all(b"\x02\x00\x00\x00").expect("write");
    }
    comp.create_storage(format!("/{NOTE_A}")).expect("storage");
    {
        let mut s = comp.create_stream(format!("/{NOTE_A}/0")).expect("stream");
        s.write_all(br"{\rtf1\ansi A note}").expect("write");
    }
    let bytes = comp.into_inner().into_inner();
    let file = read(&bytes).expect("opens");
    assert_eq!(file.notes.len(), 1);
    assert_eq!(file.root_streams.len(), 1);
    assert_eq!(file.root_streams[0].name, "Version");
    assert_eq!(file.root_streams[0].declared_len, 4);
}

/// **An unset directory-entry time is not 1601.**
#[test]
fn an_unset_entry_timestamp_is_absent_and_not_sixteen_oh_one() {
    use std::time::{Duration, UNIX_EPOCH};
    // The FILETIME zero, which is what the reader hands back for an unset
    // entry: 1601-01-01T00:00:00Z.
    let filetime_zero = UNIX_EPOCH
        .checked_sub(Duration::from_secs(11_644_473_600))
        .expect("1601 is representable here");
    assert_eq!(entry_time(filetime_zero), None);
    // And the other sentinel: the reader returns the Unix epoch when the
    // stored value cannot be represented.
    assert_eq!(entry_time(UNIX_EPOCH), None);
    // A real time converts, to the second and below.
    let real = UNIX_EPOCH + Duration::new(1_522_146_692, 123_456_700);
    let rendered = entry_time(real).expect("a real time renders");
    assert!(rendered.starts_with("2018-03-27T"), "got {rendered}");
    assert!(
        rendered.contains(".1234567"),
        "sub-second precision is kept: {rendered}"
    );
    // Whatever the SystemTime, nothing renders as 1601 or as a far-future date.
    for t in [filetime_zero, UNIX_EPOCH, real] {
        let r = entry_time(t).unwrap_or_default();
        assert!(!r.starts_with("1601"), "got {r}");
        assert!(!r.starts_with('+'), "got {r}");
    }
}

/// A fresh compound file with no storages records no notes, and says which of
/// the two that is.
#[test]
fn a_compound_file_with_no_storages_records_no_notes() {
    let comp = cfb::CompoundFile::create(Cursor::new(Vec::new())).expect("create");
    let bytes = comp.into_inner().into_inner();
    let file = read(&bytes).expect("an empty compound file still opens");
    assert!(file.notes.is_empty());
    assert!(file.root_streams.is_empty());
    assert!(file.capped.is_none());
}

/// Bytes that are not a compound file are an error, not an empty file — the
/// caller turns that into a status record rather than silence.
#[test]
fn bytes_that_are_not_a_compound_file_are_refused() {
    assert!(read(b"not a compound file at all").is_err());
}

/// **Every record carries the `.snt` stamp**, asserted structurally so a new
/// field cannot slip out without it — and the stamp claims exactly what
/// `SNT-1` measured: one real Windows 7 file, one plain-text note.
#[test]
fn every_note_record_carries_the_snt_validation_stamp() {
    let bytes = build_snt(&[
        (NOTE_A, &[("0", br"{\rtf1\ansi A}")]),
        (NOTE_B, &[("0", b"not rtf")]),
    ]);
    let file = read(&bytes).expect("opens");
    assert_eq!(file.notes.len(), 2);
    for note in &file.notes {
        let j = note.to_json("StickyNotes.snt");
        assert_eq!(
            j["validation_state"], "snt_validated_against_one_real_file",
            "including the storage this build could not read"
        );
        assert_eq!(j["validated_against_real_notes"], serde_json::json!(true));
        let notice = j["validation_notice"].as_str().unwrap_or("");
        assert!(notice.contains("one real Windows 7 file"), "{notice}");
        assert!(notice.contains("have not been met"), "{notice}");
        assert!(j["validation_basis"]
            .as_str()
            .unwrap_or("")
            .contains("SNT-1"));
    }
}

/// An embedded picture is reported on the record and not rendered into the
/// note's text.
#[test]
fn a_note_with_an_embedded_picture_says_so_and_does_not_print_it() {
    let bytes = build_snt(&[(
        NOTE_A,
        &[(
            "0",
            br"{\rtf1\ansi See this{\pict\pngblip 89504e470d0a1a0a}!}",
        )],
    )]);
    let file = read(&bytes).expect("opens");
    let j = file.notes[0].to_json("StickyNotes.snt");
    assert_eq!(j["text"], "See this!");
    assert_eq!(j["rtf_embedded_objects"], serde_json::json!(["pict"]));
    assert!(j["rtf_embedded_note"]
        .as_str()
        .unwrap_or("")
        .contains("NOT rendered as text"));
}

/// A truncated note keeps what it read and says the RTF did not close.
#[test]
fn a_truncated_note_is_marked_incomplete_and_keeps_its_text() {
    let bytes = build_snt(&[(NOTE_A, &[("0", br"{\rtf1\ansi Half a note")])]);
    let file = read(&bytes).expect("opens");
    let j = file.notes[0].to_json("StickyNotes.snt");
    assert_eq!(j["text"], "Half a note");
    assert!(j["rtf_unbalanced"].is_string());
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
}
