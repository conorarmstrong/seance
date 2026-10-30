//! The shared corpus, run against the Rust expression of the one timestamp
//! decision procedure.
//!
//! The corpus file lives under the frontend because the browser reader
//! (`frontend/src/lib/epoch.ts`) is the implementation every viewer already
//! ships; a retyped copy of the rule would pin a copy rather than the shipping
//! code. Both languages read the same bytes, so a divergence between them is a
//! failing test here rather than a silent disagreement about when something
//! happened.

use seance_core::timestamp::{place_from_metadata, Corpus, Placement, Reason};

/// Compiled in rather than read at runtime so a moved or deleted corpus is a
/// build failure, not a test that quietly stops covering anything.
const CORPUS_JSON: &str = include_str!("../../frontend/src/test/fixtures/epoch-corpus.json");

fn corpus() -> Corpus {
    serde_json::from_str(CORPUS_JSON).expect("the shared corpus must parse")
}

#[test]
fn every_corpus_row_places_exactly_as_the_browser_reader_does() {
    let corpus = corpus();
    assert!(
        corpus.rows.len() >= 40,
        "the corpus is the whole coverage argument; {} rows is too few to be it",
        corpus.rows.len()
    );

    let mut failures = Vec::new();
    for row in &corpus.rows {
        let got = place_from_metadata(&row.input, &row.keys);
        if got != row.expect {
            failures.push(format!(
                // forensic-lint: allow RAGGED-STRING — column alignment in failure output.
                "  {}\n    expected {:?}\n    got      {:?}",
                row.name, row.expect, got
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} corpus rows disagree with the Rust reference:\n{}",
        failures.len(),
        corpus.rows.len(),
        failures.join("\n")
    );
}

#[test]
fn the_corpus_exercises_all_four_census_classes() {
    // A corpus that never produced one of the four answers would let a whole
    // branch of the procedure rot untested, so the coverage is asserted rather
    // than assumed.
    let corpus = corpus();
    let mut seen: Vec<&'static str> = corpus
        .rows
        .iter()
        .map(|row| place_from_metadata(&row.input, &row.keys).census_class())
        .collect();
    seen.sort_unstable();
    seen.dedup();
    assert_eq!(
        seen,
        vec![
            "placed_as_written",
            "placed_by_rescue",
            "unplaceable_absent",
            "unplaceable_value",
        ]
    );
}

#[test]
fn the_expectation_shape_round_trips_so_wave_three_can_reuse_it() {
    // The SQL wave compares its own answers against `expect` read from this
    // same file, so the three-valued shape must deserialise and re-serialise
    // unchanged.
    for row in &corpus().rows {
        let json = serde_json::to_string(&row.expect).expect("expectation serialises");
        let back: Placement = serde_json::from_str(&json).expect("expectation round-trips");
        assert_eq!(back, row.expect, "row: {}", row.name);
    }
}

#[test]
fn a_zone_less_date_time_is_refused_rather_than_guessed() {
    // `Date.parse("2024-03-05T12:00:00")` reads a zone-less date-time in the
    // VIEWER's local zone, so the same evidence is a different instant on two
    // examiners' machines. A server cannot know that zone and must not invent
    // one, so the Rust reference refuses the shape outright. This is a stated
    // divergence from the browser, not an oversight, and it is why no such row
    // appears in the shared corpus.
    let meta = serde_json::json!({ "date": "2024-03-05T12:00:00" });
    assert_eq!(
        place_from_metadata(meta.as_object().unwrap(), &["date"]),
        Placement::Unplaceable {
            unplaceable: Reason::Value
        }
    );
}

#[test]
fn every_expectation_uses_the_documented_shape_and_nothing_else() {
    // `expect` is read by an untagged enum, which ignores a field it does not
    // know. A misspelled `confidence` would therefore be dropped in silence and
    // the row would pin less than it claims to, so the raw key sets are checked
    // against the documented shape here.
    let raw: serde_json::Value = serde_json::from_str(CORPUS_JSON).expect("corpus parses");
    for row in raw["rows"].as_array().expect("rows is an array") {
        let name = row["name"].as_str().expect("every row is named");
        let expect = row["expect"]
            .as_object()
            .expect("every row has an expect object");
        let mut keys: Vec<&str> = expect.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert!(
            keys == ["confidence", "placed_secs"] || keys == ["unplaceable"],
            "row {name} has expectation keys {keys:?}, which is not one of the three documented shapes"
        );
        assert!(
            row["keys"].as_array().is_some_and(|keys| !keys.is_empty()),
            "row {name} must state the ordered key list it is given"
        );
    }
}
