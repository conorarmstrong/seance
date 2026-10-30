//! `plum.sqlite` against a lab-made known answer — `PLUM-1` in
//! `documentation/VALIDATION.md`, the comparison `HUNT-128` asked for.
//!
//! **The database is lab-made, not a public image.** It was written on
//! 2026-09-27 by the real Microsoft Sticky Notes app, version 6.1.4.0, driven
//! through its own UI on the project's Windows 11 25H2 lab VM (build 26200).
//! Every note is fictional. `SOURCE.md` in the corpus directory records how
//! it was made and every file's SHA-256; `GROUND-TRUTH.txt` holds the known
//! answer every expected value below is copied from.
//!
//! The corpus is the directory named by `SEANCE_STICKYNOTES_PLUM`, or
//! `~/forensic_corpora/lab_win11_sticky_notes`. Absent, each test skips and
//! says so; `SEANCE_REQUIRE_CORPUS` makes that a failure. It holds three copies
//! of the app's `LocalState`:
//!
//! * `running-before-delete/` — four notes, the app running;
//! * `running-app-copy/` — after N4 was deleted, the app running;
//! * `after-clean-close/` — after every window closed and the process exited.
//!
//! In every copy `plum.sqlite` is 4,096 bytes, page 1 only: the app never
//! checkpointed, so the schema and every row live in `plum.sqlite-wal`.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::module::ForensicsModule;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn corpus_dir() -> Option<PathBuf> {
    let dir = match std::env::var("SEANCE_STICKYNOTES_PLUM") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => PathBuf::from(std::env::var("HOME").unwrap_or_default())
            .join("forensic_corpora")
            .join("lab_win11_sticky_notes"),
    };
    if dir.is_dir() {
        return Some(dir);
    }
    let required = std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty());
    assert!(
        !required,
        "{} is not a directory, but SEANCE_REQUIRE_CORPUS demands the lab-made Sticky Notes corpus",
        dir.display()
    );
    eprintln!(
        "SKIPPED (no corpus): {} is not a directory — this test compared nothing",
        dir.display()
    );
    None
}

/// Run the module on one copy's `plum.sqlite`, shaped as the NTFS pipeline
/// hands a file over. The `-wal` is reached through the source's sibling
/// lookup, exactly as it is on a mounted image.
fn run(copy: &Path) -> Vec<Value> {
    let path = copy.join("plum.sqlite");
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(path).expect("open the corpus file read-only"));
    let art = Artifact::new(
        Default::default(),
        ArtifactType::FileEntry,
        Some(src),
        serde_json::json!({
            "name": "plum.sqlite",
            "path": "Users/analyst/AppData/Local/Packages/Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe/LocalState/plum.sqlite",
        }),
    );
    crate::StickyNotesParser
        .process(&art)
        .expect("the parser runs")
        .into_iter()
        .map(|a| a.metadata)
        .collect()
}

fn live_notes(out: &[Value]) -> Vec<&Value> {
    out.iter().filter(|r| r["type"] == "StickyNote").collect()
}

fn recovered(out: &[Value]) -> Vec<&Value> {
    out.iter()
        .filter(|r| r["type"] == "StickyNoteRecovered")
        .collect()
}

/// One note of GROUND-TRUTH.txt.
struct Known {
    id: &'static str,
    rowid: i64,
    visible: &'static str,
    stored: &'static str,
    created_ticks: i64,
    created: &'static str,
    updated_ticks: i64,
    updated: &'static str,
}

const N1: Known = Known {
    id: "579b4e3b-0771-4dd4-8d7d-67033aa0f051",
    rowid: 1,
    visible: "Call Dr. Okafor re: case 2026-0419 before Friday",
    stored:
        "\\id=5f293e2c-74e9-416f-afbb-25bce1288d05 Call Dr. Okafor re: case 2026-0419 before Friday",
    created_ticks: 639_261_413_931_443_023,
    created: "2026-09-27T21:29:53.144302300+00:00",
    updated_ticks: 639_261_414_398_948_277,
    updated: "2026-09-27T21:30:39.894827700+00:00",
};

const N2: Known = Known {
    id: "8f480d64-d199-4a52-830d-f95a3df418e2",
    rowid: 2,
    visible: "Evidence checklist\n1. Seize laptop SN HX-5521\n2. Image drive with write blocker\n3. Log chain of custody",
    stored: "\\id=cb205a0c-c266-4683-add3-55a1d748b5d0 Evidence checklist\n\
             \\id=44a83ad6-6548-4e5d-baeb-06bd05c25f8f 1. Seize laptop SN HX-5521\n\
             \\id=f855698a-c2ea-4bb3-84e6-feebf931e1cc 2. Image drive with write blocker\n\
             \\id=a4083c7f-104b-4b90-a38f-c2c39a1694a1 3. Log chain of custody",
    created_ticks: 639_261_414_500_778_124,
    created: "2026-09-27T21:30:50.077812400+00:00",
    updated_ticks: 639_261_414_671_765_916,
    updated: "2026-09-27T21:31:07.176591600+00:00",
};

const N3: Known = Known {
    id: "22ff190a-f37e-4dce-b899-ec333324ac8d",
    rowid: 3,
    visible: "Réunion à 15h — Zoë Müller, café in Łódź\n東京オフィス 会議メモ\nΕλληνικά: Καλημέρα\nPin 📌 done ✓",
    stored: "\\id=2e85663c-a7bc-42fb-9cdf-8e1c862b4f49 Réunion à 15h — Zoë Müller, café in Łódź\n\
             \\id=3f4ac24c-9864-4487-a52a-814c6b4c7a54 東京オフィス 会議メモ\n\
             \\id=82d09081-1062-4248-ae4d-4759cb48b091 Ελληνικά: Καλημέρα\n\
             \\id=2250401d-e45a-4250-945f-b22e81a2ebdf Pin 📌 done ✓",
    created_ticks: 639_261_415_096_942_500,
    created: "2026-09-27T21:31:49.694250+00:00",
    updated_ticks: 639_261_415_173_643_688,
    updated: "2026-09-27T21:31:57.364368800+00:00",
};

const N4: Known = Known {
    id: "1ab471ae-5463-4782-942d-a3ccd77d2f1a",
    rowid: 4,
    visible: "DELETE-ME marker 7C3E91 temporary note to be removed",
    stored: "\\id=3931c612-a199-4c0e-962f-55552ed5305b DELETE-ME marker 7C3E91 temporary note to be removed",
    created_ticks: 639_261_415_366_713_590,
    created: "2026-09-27T21:32:16.671359+00:00",
    updated_ticks: 639_261_415_493_657_630,
    updated: "2026-09-27T21:32:29.365763+00:00",
};

fn assert_note(r: &Value, k: &Known) {
    assert_eq!(r["note_id"], k.id, "{r:#}");
    assert_eq!(r["text"], k.visible, "paragraph ids stripped: {r:#}");
    assert_eq!(r["text_raw"], k.stored, "the stored text kept: {r:#}");
    assert_eq!(r["created"], k.created, "{r:#}");
    assert_eq!(r["created_ticks"], k.created_ticks, "{r:#}");
    assert_eq!(r["modified"], k.updated, "{r:#}");
    assert_eq!(r["modified_ticks"], k.updated_ticks, "{r:#}");
    assert!(r["deleted"].is_null(), "DeletedAt is never set: {r:#}");
    assert_eq!(r["name"], k.visible.lines().next().unwrap(), "{r:#}");
}

fn by_id<'a>(notes: &[&'a Value], id: &str) -> &'a Value {
    notes
        .iter()
        .find(|n| n["note_id"] == id)
        .unwrap_or_else(|| panic!("note {id} not read: {notes:#?}"))
}

/// **Every live note comes out of a database that lives wholly in its WAL**,
/// with its exact text (paragraph ids stripped, the stored text kept), both
/// times converted from .NET ticks, and its row id — four before the delete,
/// three after, in all three copies.
#[test]
fn the_lab_made_6_1_4_0_notes_are_read_through_the_wal_in_every_copy() {
    let Some(dir) = corpus_dir() else { return };
    for (copy, expected) in [
        ("running-before-delete", vec![&N1, &N2, &N3, &N4]),
        ("running-app-copy", vec![&N1, &N2, &N3]),
        ("after-clean-close", vec![&N1, &N2, &N3]),
    ] {
        let out = run(&dir.join(copy));
        let notes = live_notes(&out);
        assert_eq!(notes.len(), expected.len(), "{copy}: {out:#?}");
        for k in expected {
            let r = by_id(&notes, k.id);
            assert_note(r, k);
            assert_eq!(r["rowid"], k.rowid, "{copy}: {r:#}");
            assert_eq!(r["user_version"], 13, "{copy}: {r:#}");
            assert_eq!(r["theme"], "Yellow", "{copy}: {r:#}");
            assert!(r.get("content_incomplete").is_none(), "{copy}: {r:#}");
        }
        assert!(
            !out.iter().any(|r| r["type"] == "StickyNotesParseStatus"),
            "{copy}: a status record means the WAL was not read: {out:#?}"
        );
    }
}

/// **N4 is surfaced from the superseded WAL frames**, as recovered and not as
/// live, with the frame it was read from, that frame's offset in the WAL, and
/// the basis for calling it deleted: the app sets no tombstone, so deletion is
/// inferred from the row's absence in the latest committed state. Before the
/// delete there is nothing to recover.
#[test]
fn the_deleted_note_is_recovered_from_a_superseded_wal_frame() {
    let Some(dir) = corpus_dir() else { return };

    let before = run(&dir.join("running-before-delete"));
    assert!(
        recovered(&before).is_empty(),
        "N4 is live before the delete, so nothing is recovered: {before:#?}"
    );

    for copy in ["running-app-copy", "after-clean-close"] {
        let out = run(&dir.join(copy));
        let rec = recovered(&out);
        assert_eq!(rec.len(), 1, "{copy}: exactly N4: {out:#?}");
        let r = rec[0];
        assert_note(r, &N4);
        assert_eq!(r["rowid"], N4.rowid, "{copy}: {r:#}");
        assert_eq!(
            r["recovery_source"], "wal_superseded_frame",
            "{copy}: {r:#}"
        );
        // GROUND-TRUTH.txt's frame map (0-based): page 2 is the Note leaf;
        // frame 58 is the newest image of it holding N4 as a cell, and frame
        // 59 is the delete transaction's page 2, which holds N4's bytes only
        // in free space. Frames 52-57 are the page as N4 was being typed.
        assert_eq!(r["wal_frame"], 58, "{copy}: {r:#}");
        assert_eq!(
            r["wal_frame_offset"],
            32 + 58 * (24 + 4096),
            "{copy}: {r:#}"
        );
        assert_eq!(r["wal_page_number"], 2, "{copy}: {r:#}");
        assert_eq!(
            r["wal_frames_holding_row"],
            serde_json::json!([52, 54, 55, 56, 57, 58]),
            "{copy}: {r:#}"
        );
        assert_eq!(r["first_wal_frame_without_row"], 59, "{copy}: {r:#}");
        assert_eq!(r["deleted_inferred"], true, "{copy}: {r:#}");
        let basis = r["deletion_basis"].as_str().unwrap_or("");
        assert!(
            basis.contains("absent from the latest committed state")
                && basis.contains("no tombstone"),
            "{copy}: {basis}"
        );
        assert_eq!(r["user_version"], 13, "{copy}: {r:#}");
    }
}

/// The stamp on this corpus's records states what was validated: 6.1.4.0,
/// `user_version` 13, lab-made — and that other versions are not.
#[test]
fn records_from_the_lab_made_database_carry_the_bounded_stamp() {
    let Some(dir) = corpus_dir() else { return };
    for copy in [
        "running-before-delete",
        "running-app-copy",
        "after-clean-close",
    ] {
        let out = run(&dir.join(copy));
        assert!(!out.is_empty());
        for r in &out {
            assert_eq!(
                r["validation_state"], "plum_validated_against_one_lab_made_database",
                "{copy}: {r:#}"
            );
            assert_eq!(r["validated_against_real_notes"], true, "{copy}: {r:#}");
            let notice = r["validation_notice"].as_str().unwrap_or("");
            assert!(
                notice.contains("6.1.4.0")
                    && notice.contains("user_version 13")
                    && notice.contains("lab-made")
                    && notice.contains("not been compared"),
                "{copy}: {notice}"
            );
        }
    }
}

/// Reading the evidence does not change it: SQLite opening a WAL database in
/// place can checkpoint it and rewrite `-shm`.
#[test]
fn reading_the_corpus_leaves_every_file_byte_identical() {
    let Some(dir) = corpus_dir() else { return };
    for copy in [
        "running-before-delete",
        "running-app-copy",
        "after-clean-close",
    ] {
        let files = ["plum.sqlite", "plum.sqlite-wal", "plum.sqlite-shm"];
        let before: Vec<Vec<u8>> = files
            .iter()
            .map(|f| std::fs::read(dir.join(copy).join(f)).unwrap())
            .collect();
        let _ = run(&dir.join(copy));
        for (f, b) in files.iter().zip(before) {
            assert_eq!(
                std::fs::read(dir.join(copy).join(f)).unwrap(),
                b,
                "{copy}/{f} changed"
            );
        }
    }
}
