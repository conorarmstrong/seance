//! Real-data validation for the browser parsers.
//!
//! Unit tests validate against schema-accurate synthetic databases; this runner
//! validates against **real** browser artifact files produced by actual app
//! versions, catching schema variants the fixtures don't.
//!
//! It is gated on the `SEANCE_BROWSER_SAMPLES` environment variable pointing at a
//! directory of real browser files, so it is a no-op in CI without a corpus:
//!
//! ```sh
//! SEANCE_BROWSER_SAMPLES=/path/to/samples \
//!   cargo test -p seance_plugin_browser_history --test real_samples -- --nocapture
//! ```
//!
//! Each file is content-detected (by its SQLite tables, or the mozLz4 magic for
//! session files) and fed to `BrowserHistoryParser` under the filename that
//! parser self-selects on; the run reports how many records each yielded.

use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    module::ForensicsModule,
};
use seance_plugin_browser_history::BrowserHistoryParser;
use std::sync::Arc;
use uuid::Uuid;

/// True if the SQLite DB at `path` has a table named `table`.
fn has_table(path: &std::path::Path, table: &str) -> bool {
    Connection::open_with_flags(path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
        .and_then(|c| {
            c.query_row(
                "SELECT COUNT(*) > 0 FROM sqlite_master WHERE type='table' AND name=?1",
                [table],
                |r| r.get::<_, bool>(0),
            )
        })
        .unwrap_or(false)
}

/// Decide which browser artifact `path` is and the filename the parser gates on.
/// Returns `None` for files that aren't a recognised browser artifact.
fn classify(path: &std::path::Path) -> Option<&'static str> {
    // Firefox session restore (not SQLite): mozLz4 magic.
    if let Ok(head) = std::fs::read(path) {
        if head.starts_with(b"mozLz40\0") {
            return Some("sessionstore.jsonlz4");
        }
        // Safari's own cookie jar (not SQLite either): `cook` magic.
        if head.starts_with(b"cook") {
            return Some("Cookies.binarycookies");
        }
    }
    // SQLite browser artifacts, by characteristic table.
    if has_table(path, "urls") {
        Some("History") // Chrome/Edge history
    } else if has_table(path, "moz_places") {
        Some("places.sqlite") // Firefox history
    } else if has_table(path, "cookies") {
        Some("Cookies") // Chrome/Edge cookies
    } else if has_table(path, "moz_cookies") {
        Some("cookies.sqlite") // Firefox cookies
    } else if has_table(path, "autofill") {
        Some("Web Data") // Chrome/Edge autofill
    } else if has_table(path, "moz_formhistory") {
        Some("formhistory.sqlite") // Firefox form history
    } else if has_table(path, "logins") {
        Some("Login Data") // Chrome/Edge saved logins
    } else {
        None
    }
}

#[test]
fn validate_browser_parsers_against_real_samples() {
    let Some(dir) = seance_core::test_support::corpus::dir("SEANCE_BROWSER_SAMPLES") else {
        return;
    };
    let dir = dir.display().to_string();
    let Ok(entries) = std::fs::read_dir(&dir) else {
        eprintln!("Cannot read sample directory {dir}; skipping.");
        return;
    };

    let parser = BrowserHistoryParser;
    let mut recognised = 0usize;
    let mut with_records = 0usize;

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(gate_name) = classify(&path) else {
            eprintln!(
                "  - {:?}: not a recognised browser artifact",
                path.file_name().unwrap()
            );
            continue;
        };
        recognised += 1;

        let Ok(fds) = FileDataSource::new(path.clone()) else {
            eprintln!("  ! {:?}: could not open", path.file_name().unwrap());
            continue;
        };
        let ds: Arc<dyn DataSource> = Arc::new(fds);
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            serde_json::json!({ "name": gate_name }),
        );

        match parser.process(&artifact) {
            Ok(records) => {
                if !records.is_empty() {
                    with_records += 1;
                }
                // Summarise the record types produced.
                let mut counts: std::collections::BTreeMap<String, usize> =
                    std::collections::BTreeMap::new();
                for r in &records {
                    let t = r
                        .metadata
                        .get("type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("?")
                        .to_string();
                    *counts.entry(t).or_default() += 1;
                }
                eprintln!(
                    "  ✓ {:?} (as {gate_name}) -> {} records {:?}",
                    path.file_name().unwrap(),
                    records.len(),
                    counts
                );
            }
            Err(e) => eprintln!(
                "  ! {:?} (as {gate_name}) -> parse error: {e}",
                path.file_name().unwrap()
            ),
        }
    }

    eprintln!(
        "Real-data validation: {recognised} recognised browser file(s), {with_records} produced records."
    );
    // If a corpus was supplied, at least one file must have been recognised —
    // otherwise the corpus or classification is wrong and worth failing on.
    assert!(
        recognised > 0,
        "no files in {dir} were recognised as browser artifacts"
    );
}
