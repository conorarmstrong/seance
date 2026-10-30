//! `StickyNotes.snt` against a real Windows 7 file — `SNT-1` in
//! `documentation/VALIDATION.md`, the known answer `HUNT-128` asked for.
//!
//! The file is the NIST CFReDS Data Leakage case's
//! `Users/informant/AppData/Roaming/Microsoft/Sticky Notes/StickyNotes.snt`
//! (inode 22108 of the PC image; 4,096 bytes; SHA-256
//! `6ccbffc4e978aafeb950ca5d87a413f96435514ca16d6be5508ed68df071b7b2`). It is
//! not in the repository. `SEANCE_STICKYNOTES_SNT` is its path: unset skips
//! loudly, set-but-missing fails (`seance_core::test_support::corpus`).
//!
//! Every expected value was read off the file without this crate: the storage
//! and stream names, lengths and the storage's two times from 7-Zip's
//! compound-file listing (`7z l -slt`), the text from the RTF stream read by
//! hand, and cross-checked against the note's own UTF-16LE plain-text stream
//! (`3`), which holds `Tomorrow...\r\n\r\nEverything will be OK...\r\n\r\n`.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use seance_core::test_support::corpus;
use std::sync::Arc;

#[test]
fn the_data_leakage_windows_7_note_is_read_as_windows_wrote_it() {
    let Some(path) = corpus::path("SEANCE_STICKYNOTES_SNT") else {
        return;
    };
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path).expect("open the corpus file read-only"));
    // Shaped as the NTFS pipeline hands a file over: a FileEntry named by its
    // file name, with its path.
    let art = Artifact::new(
        Default::default(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({
            "name": "StickyNotes.snt",
            "path": "Users/informant/AppData/Roaming/Microsoft/Sticky Notes/StickyNotes.snt",
        }),
    );
    let out: Vec<serde_json::Value> = crate::StickyNotesParser
        .process(&art)
        .expect("the parser runs")
        .into_iter()
        .map(|a| a.metadata)
        .collect();
    assert_eq!(out.len(), 2, "one coverage record and one note: {out:#?}");

    let cov = &out[0];
    assert_eq!(cov["type"], "StickyNotesCoverage");
    assert_eq!(cov["note_storages"], 1);
    assert_eq!(cov["notes_with_text"], 1);
    assert_eq!(cov["storages_not_recognised"], 0);
    let root: Vec<(String, u64)> = cov["root_streams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["stream_name"].as_str().unwrap().to_string(),
                s["declared_bytes"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        root,
        [("Version".to_string(), 4), ("Metafile".to_string(), 294)]
    );
    assert!(cov.get("content_incomplete").is_none(), "{cov}");

    let note = &out[1];
    assert_eq!(note["type"], "StickyNote");
    assert_eq!(note["storage_name"], "ccbb72fb-d253-11e4-b");
    assert_eq!(note["name"], "Tomorrow...");
    assert_eq!(
        note["text"], "Tomorrow...\n\nEverything will be OK...\n\n\n",
        "the RTF's five \\par marks, and no NUL from the terminator after the closing brace"
    );
    assert_eq!(note["text_stream_name"], "0");
    // HUNT-242: the viewer's Format column reads this.
    assert_eq!(note["source_format"], "snt_compound_file");
    assert_eq!(cov["source_format"], "snt_compound_file");
    assert_eq!(note["created"], "2015-03-24T18:31:17.026+00:00");
    assert_eq!(note["modified"], "2015-03-24T18:31:17.058+00:00");
    assert_eq!(
        note["rtf_skipped_destinations"],
        serde_json::json!(["fonttbl", "generator"])
    );
    assert_eq!(note["rtf_embedded_objects"], serde_json::json!([]));
    assert!(note.get("content_incomplete").is_none(), "{note}");
    let streams: Vec<(String, u64, bool)> = note["streams"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| {
            (
                s["stream_name"].as_str().unwrap().to_string(),
                s["readable_bytes"].as_u64().unwrap(),
                s["is_rtf"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        streams,
        [
            ("0".to_string(), 490, true),
            ("1".to_string(), 10, false),
            ("3".to_string(), 88, false),
        ]
    );

    for r in &out {
        assert_eq!(r["validation_state"], "snt_validated_against_one_real_file");
        assert_eq!(r["validated_against_real_notes"], true);
    }
}
