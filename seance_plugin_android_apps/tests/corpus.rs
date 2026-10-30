//! The corpus-diff half of ROADMAP §1.4a for this crate: the real `calendar.db`
//! and `keep.db` the validated ranges were read from, parsed through the
//! product path, so a parser that falls behind their schema fails here rather
//! than going quiet.
//!
//! Gated on `SEANCE_ANDROID2022_TREE`, the `data/` directory extracted from the
//! Magnet 2022 Android CTF image; it skips loudly when unset and panics when it
//! names a missing path.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
    test_support::corpus,
};
use seance_plugin_android_apps::{AndroidCalendarParser, GoogleKeepParser};
use seance_sqlite_util::{check_corpus, CorpusExpectation};
use std::sync::Arc;

fn artifact_for(path: &std::path::Path) -> Artifact {
    let name = path.file_name().unwrap().to_string_lossy().to_string();
    let ds: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).unwrap());
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(ds),
        serde_json::json!({ "name": name, "path": path.display().to_string() }),
    )
}

fn stale_messages(out: &[Artifact]) -> Vec<String> {
    out.iter()
        .filter(|a| a.metadata["type"] == "ParserStaleWarning")
        .map(|a| a.metadata["message"].to_string())
        .collect()
}

/// `calendar.db`: `user_version` 600, 77 events across three named calendars,
/// every column this parser reads present.
#[test]
fn the_android2022_calendar_parses_inside_its_validated_range() {
    let Some(path) = corpus::file(
        "SEANCE_ANDROID2022_TREE",
        "data/com.android.providers.calendar/databases/calendar.db",
    ) else {
        return;
    };
    let out = AndroidCalendarParser::new()
        .process(&artifact_for(&path))
        .unwrap();
    assert!(
        stale_messages(&out).is_empty(),
        "{:?}",
        stale_messages(&out)
    );
    let events: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "CalendarEvent")
        .collect();
    check_corpus(
        &CorpusExpectation {
            label: "android2022 calendar.db v600".into(),
            min_records: 77,
        },
        events.len(),
    )
    .unwrap();
    assert!(events.iter().all(|e| e.metadata.get("dtstart").is_some()));
    assert!(events
        .iter()
        .any(|e| e.metadata["calendar"] == "Holidays in United States"));
    let summary = out
        .iter()
        .find(|a| a.metadata["type"] == "AndroidCalendarSummary")
        .unwrap();
    assert_eq!(summary.metadata["event_count"], 77);
    assert!(summary.metadata.get("content_incomplete").is_none());
}

/// `keep.db`: `user_version` 95, one untitled note whose 63-character body is a
/// single `list_item` row — `tree_entity` has no `text` column in this store.
#[test]
fn the_android2022_keep_store_parses_inside_its_validated_range() {
    let Some(path) = corpus::file(
        "SEANCE_ANDROID2022_TREE",
        "data/com.google.android.keep/databases/keep.db",
    ) else {
        return;
    };
    let out = GoogleKeepParser::new()
        .process(&artifact_for(&path))
        .unwrap();
    assert!(
        stale_messages(&out).is_empty(),
        "{:?}",
        stale_messages(&out)
    );
    let notes: Vec<_> = out
        .iter()
        .filter(|a| a.metadata["type"] == "AndroidNote")
        .collect();
    check_corpus(
        &CorpusExpectation {
            label: "android2022 keep.db v95".into(),
            min_records: 1,
        },
        notes.len(),
    )
    .unwrap();
    assert_eq!(
        notes[0].metadata["text"].as_str().unwrap().chars().count(),
        63
    );
    assert_eq!(notes[0].metadata["color"], "CERULEAN");
    assert!(notes[0].metadata.get("content_incomplete").is_none());
}
