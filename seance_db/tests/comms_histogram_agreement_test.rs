//! The histogram's SQL epoch expression and `seance_core::timestamp` must place
//! every row of the shared corpus at the same instant, or say the same reason
//! they could not.
//!
//! A histogram is a claim about WHEN things happened. If the server buckets a
//! record in 2020 while the browser shows it in 1970, one examiner reads two
//! different instants for one message off two parts of the same screen, and one
//! of them ends up in a statement. So the agreement is not asserted by retyping
//! the rule in SQL and hoping: this file loads
//! `frontend/src/test/fixtures/epoch-corpus.json` — the SAME bytes the browser
//! suite reads — inserts each row's `input` as an artifact's `metadata_json`,
//! and runs THE SHIPPING STATEMENT that `comms_volume_census` builds.
//!
//! Where the two genuinely cannot agree, the row is named in
//! [`KNOWN_DIVERGENCES`] with the reason, and the test asserts the divergent set
//! is EXACTLY that — no larger. A test that silently skipped what SQL cannot do
//! would prove nothing at all.

use anyhow::Result;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::db::DatabaseConnection;
use seance_core::timestamp::{place_from_metadata, Corpus, Placement, CORPUS_PATH};
use seance_db::{CommsVolumeCensus, SqliteConnection};
use serde_json::{json, Map, Value};
use std::path::PathBuf;
use uuid::Uuid;

/// Corpus rows the SQL expression cannot match, each with the reason it cannot.
///
/// Keyed on the row's `name`, which is a sentence, so a failure here names the
/// finding rather than an index. Adding a row to this list is a decision to
/// SHOW ONE INSTANT IN THE BROWSER AND ANOTHER (or none) ON THE CHART for that
/// shape, so it needs the same scrutiny as a change to the rule itself.
const KNOWN_DIVERGENCES: &[(&str, &str)] = &[(
    "RFC-2822, the shape an email or MMS header arrives in",
    "SQLite's date functions parse ISO-8601 only; there is no RFC-2822 reader \
     and no way to write one as an expression, so an email `Date:` header \
     placed by the browser is `unplaceable_value` on the chart. The chart \
     therefore UNDERSTATES email volume wherever a parser passed the header \
     through as written instead of normalising it, and the census says so by \
     counting the record under unplaceable_value rather than dropping it.",
)];

/// Shapes outside the shared corpus that the SQL expression cannot match.
///
/// Same standard as [`KNOWN_DIVERGENCES`]: each entry is a decision to place a
/// record in the browser and not on the chart, so each carries its reason.
const KNOWN_TRAP_DIVERGENCES: &[(&str, &str)] = &[
    (
        "hex in the FILETIME band",
        "JavaScript's `Number()` reads `0x…`, `0o…` and `0b…` as numbers, and \
         `seance_core::timestamp` mirrors that. SQLite has no radix-prefixed \
         literal in an expression — `CAST('0x1DA…' AS REAL)` is 0, which is \
         WORSE than refusing because it looks like a value — so the shape check \
         refuses it and the record is counted under unplaceable_value. Only a \
         radix literal INSIDE a band diverges; `0x1000` is below the seconds \
         floor and both sides refuse it, which is why the shared corpus does \
         not show this.",
    ),
    (
        "hex in the seconds band",
        "The same limitation, at the magnitude a Unix seconds value would have.",
    ),
    (
        "octal in the seconds band",
        "The same limitation, for the `0o…` form.",
    ),
];

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("seance_db sits one level below the repo root")
        .to_path_buf()
}

fn load_corpus() -> Result<Corpus> {
    let path = repo_root().join(CORPUS_PATH);
    let text = std::fs::read_to_string(&path)
        .map_err(|e| anyhow::anyhow!("cannot read the shared corpus at {}: {e}", path.display()))?;
    Ok(serde_json::from_str(&text)?)
}

/// One corpus row as a comms record: the row's own metadata, filed under a
/// message type with a contact unique to the row so the shipping statement's
/// `contact` filter can single it out.
fn artifact_for(case_id: Uuid, index: usize, input: &Map<String, Value>) -> Artifact {
    let mut meta = input.clone();
    meta.insert("type".into(), json!("WhatsApp"));
    meta.insert("subtype".into(), json!("chat_message"));
    meta.insert("contact".into(), json!(format!("row-{index}")));
    Artifact {
        id: Uuid::new_v4(),
        case_id,
        parent_id: None,
        artifact_type: ArtifactType::ParsedRecord,
        metadata: Value::Object(meta),
        data: None,
    }
}

/// What the census says about one record: its class, and the instant it was
/// placed at when it was placed at all. The extent over a single matched record
/// IS that record's instant, which is how the aggregate statement is made to
/// answer a per-record question without a second statement that could drift.
fn observed(census: &CommsVolumeCensus) -> (String, Option<i64>) {
    let classes: Vec<(&str, i64)> = vec![
        ("unreadable_metadata", census.unreadable_metadata),
        ("not_a_message", census.not_a_message),
        ("unplaceable_absent", census.unplaceable_absent),
        ("unplaceable_value", census.unplaceable_value),
        ("placed_by_rescue", census.placed_by_rescue),
        ("placed_as_written", census.placed_as_written),
    ];
    let hit: Vec<&str> = classes
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(c, _)| *c)
        .collect();
    assert_eq!(
        hit.len(),
        1,
        "one matched record must land in exactly one census class, got {hit:?}"
    );
    assert_eq!(census.matched_records, 1);
    assert_eq!(census.min_ts_secs, census.max_ts_secs);
    (hit[0].to_string(), census.min_ts_secs)
}

/// The reference answer, as the shared procedure gives it.
fn reference(placement: &Placement) -> (String, Option<i64>) {
    (placement.census_class().to_string(), placement.epoch_secs())
}

#[tokio::test]
async fn the_shipping_sql_places_every_corpus_row_where_the_shared_procedure_does() -> Result<()> {
    let corpus = load_corpus()?;
    assert!(
        corpus.rows.len() >= 40,
        "the corpus shrank to {} rows; agreement over a corpus that lost its \
         hard cases is not agreement",
        corpus.rows.len()
    );

    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Agreement", "Examiner").await?;

    for (i, row) in corpus.rows.iter().enumerate() {
        db.record_artifact(&artifact_for(case_id, i, &row.input))
            .await?;
    }

    let mut diverged: Vec<(String, String, String)> = Vec::new();

    for (i, row) in corpus.rows.iter().enumerate() {
        let keys: Vec<&str> = row.keys.iter().map(String::as_str).collect();

        // The corpus row's own expectation must still be what the shared
        // procedure produces, or the two sides of this comparison are pinned to
        // different rules and the agreement below means nothing.
        let placement = place_from_metadata(&row.input, &keys);
        assert_eq!(
            placement, row.expect,
            "seance_core::timestamp disagrees with the corpus on: {}",
            row.name
        );

        let census = db
            .comms_volume_census(
                case_id,
                &keys,
                Some("WhatsApp"),
                None,
                Some(&format!("row-{i}")),
            )
            .await?;

        let got = observed(&census);
        let want = reference(&placement);
        if got != want {
            diverged.push((row.name.clone(), format!("{want:?}"), format!("{got:?}")));
        }
    }

    let allowed: Vec<&str> = KNOWN_DIVERGENCES.iter().map(|(n, _)| *n).collect();
    let names: Vec<&str> = diverged.iter().map(|(n, _, _)| n.as_str()).collect();

    assert_eq!(
        names, allowed,
        "the set of corpus rows where the histogram SQL cannot match the shared \
         procedure must be EXACTLY the allow-list. Observed divergences \
         (row, procedure, sql): {diverged:#?}"
    );

    // Reported, not merely asserted: the size of the disagreement is a fact
    // about the product and belongs in the test's output.
    println!(
        "corpus rows: {}; known divergences: {} ({:.1}%)",
        corpus.rows.len(),
        diverged.len(),
        100.0 * diverged.len() as f64 / corpus.rows.len() as f64
    );
    for (name, reason) in KNOWN_DIVERGENCES {
        // forensic-lint: allow RAGGED-STRING — indented continuation line in test output.
        println!("  DIVERGES: {name}\n    because {reason}");
    }

    Ok(())
}

/// The same corpus, counted in ONE pass rather than row by row: the census over
/// the whole set must tally to the classes the shared procedure assigns, with
/// the one known divergence moved from its own class into `unplaceable_value`.
///
/// The per-row test above could pass while the aggregate double-counted or lost
/// rows; this one cannot.
#[tokio::test]
async fn the_census_over_the_whole_corpus_tallies_to_the_shared_procedure() -> Result<()> {
    let corpus = load_corpus()?;
    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Agreement", "Examiner").await?;

    // Only the rows keyed on the comms key list; the corpus carries one row on
    // a different key list to prove the procedure is not hard-wired to `date`,
    // and it would be read under the wrong keys by the shipping statement.
    let comms_rows: Vec<_> = corpus
        .rows
        .iter()
        .filter(|r| r.keys == vec!["date".to_string(), "timestamp".to_string()])
        .collect();

    for (i, row) in comms_rows.iter().enumerate() {
        db.record_artifact(&artifact_for(case_id, i, &row.input))
            .await?;
    }

    let mut want_as_written = 0i64;
    let mut want_rescue = 0i64;
    let mut want_value = 0i64;
    let mut want_absent = 0i64;
    for row in &comms_rows {
        let keys: Vec<&str> = row.keys.iter().map(String::as_str).collect();
        let mut class = place_from_metadata(&row.input, &keys)
            .census_class()
            .to_string();
        if KNOWN_DIVERGENCES.iter().any(|(n, _)| *n == row.name) {
            class = "unplaceable_value".into();
        }
        match class.as_str() {
            "placed_as_written" => want_as_written += 1,
            "placed_by_rescue" => want_rescue += 1,
            "unplaceable_value" => want_value += 1,
            "unplaceable_absent" => want_absent += 1,
            other => panic!("unexpected class {other}"),
        }
    }

    let census = db
        .comms_volume_census(
            case_id,
            seance_db::COMMS_TIME_KEYS,
            Some("WhatsApp"),
            None,
            None,
        )
        .await?;

    assert_eq!(census.placed_as_written, want_as_written);
    assert_eq!(census.placed_by_rescue, want_rescue);
    assert_eq!(census.unplaceable_value, want_value);
    assert_eq!(census.unplaceable_absent, want_absent);
    assert_eq!(census.not_a_message, 0);
    assert_eq!(census.unreadable_metadata, 0);

    // The invariant, as an equation over the matched population.
    assert_eq!(census.matched_records, comms_rows.len() as i64);
    assert_eq!(census.class_sum(), census.matched_records);
    assert_eq!(census.total_records, comms_rows.len() as i64);

    Ok(())
}

/// Shapes the SHARED corpus does not carry, held to the same standard.
///
/// The shared corpus pins the rule the browser and the server both implement;
/// it does not, and should not, enumerate every trap SQLite's date functions
/// set for an expression that has to reproduce that rule. These are those
/// traps — SQLite magic that no evidence supports, boundaries of the magnitude
/// bands, and literals past the exact range of the arithmetic used to read
/// them. Each is compared against `seance_core::timestamp` exactly as the
/// corpus rows are, with its own allow-list, which is EMPTY: none of these is a
/// shape the two sides are permitted to disagree about.
///
/// Written because a mutation test found the hole: deleting the offset check
/// from the SQL — so a zone-less `"2024-03-05T12:00:00"` was silently read as
/// UTC where the browser reads it in the VIEWER's zone — left every corpus row
/// passing.
#[tokio::test]
async fn the_sqlite_traps_the_shared_corpus_does_not_carry_also_agree() -> Result<()> {
    let cases: Vec<(&str, Value)> = vec![
        // ---- SQLite date magic the shape check exists to refuse ----------
        // Read as UTC by SQLite; read in the VIEWER's local zone by the
        // browser. Placing it would invent an agreement between two examiners'
        // machines that does not exist.
        ("zone-less date-time", json!("2024-03-05T12:00:00")),
        // SQLite accepts a space where RFC 3339 requires `T`, and again with no
        // zone in sight.
        ("space separator", json!("2024-03-05 12:00:00Z")),
        ("space separator, no zone", json!("2024-03-05 12:00:00")),
        // SQLite accepts HH:MM with no seconds; chrono's RFC 3339 does not.
        ("no seconds", json!("2024-03-05T12:00Z")),
        // unixepoch() rolls this silently forward to 2024-03-01 — a message
        // moved a day, on a chart read as evidence.
        ("a day that does not exist", json!("2024-02-30T12:00:00Z")),
        ("a month that does not exist", json!("2024-13-01")),
        ("a day that does not exist, bare", json!("2024-02-30")),
        // A bare numeric string is read as a JULIAN DAY by SQLite's date
        // functions. 2451545 is J2000, i.e. 2000-01-01.
        ("the Julian-day trap", json!("2451545")),
        ("time of day only", json!("10:00:00")),
        ("the query's own clock", json!("now")),
        ("a modifier, not an instant", json!("+1 day")),
        // ---- JavaScript's Number() coercion, at its edges ----------------
        ("two leading signs", json!("++1709640000")),
        ("two exponents", json!("1e9e9")),
        ("a trailing dot", json!("1709640000.")),
        ("leading zeros", json!("0001709640000")),
        // ---- band boundaries --------------------------------------------
        ("the seconds floor, exactly", json!(100_000_000i64)),
        ("one past the seconds floor", json!(100_000_001i64)),
        (
            "the millisecond floor, exactly",
            json!(1_000_000_000_000i64),
        ),
        (
            "one past the millisecond floor",
            json!(1_000_000_000_001i64),
        ),
        (
            "the FILETIME floor, exactly",
            json!(1_000_000_000_000_000i64),
        ),
        (
            "one past the FILETIME floor",
            json!(1_000_000_000_000_001i64),
        ),
        ("i64::MAX as an integer", json!(i64::MAX)),
        ("i64::MAX as a literal string", json!("9223372036854775807")),
        // Past i64, so `CAST(... AS INTEGER)` would CLAMP rather than fail.
        ("one past i64::MAX", json!("9223372036854775808")),
        ("nineteen nines", json!("9999999999999999999")),
        ("twenty nines", json!("99999999999999999999")),
        // ---- reals -------------------------------------------------------
        (
            "microseconds written as a real",
            json!(1_709_640_000_000_000.0f64),
        ),
        (
            "milliseconds written as a real",
            json!(1_709_640_000_000.5f64),
        ),
        ("a real below the band", json!(-1.5f64)),
        ("a real in the seconds band", json!(1_709_640_000.999f64)),
        // ---- written date-times at the edges ------------------------------
        (
            "the last instant SQLite can name",
            json!("9999-12-31T23:59:59Z"),
        ),
        ("one year past it", json!("10000-01-01T00:00:00Z")),
        ("a negative year", json!("-0001-01-01T00:00:00Z")),
        ("an impossible hour", json!("2024-03-05T25:00:00Z")),
        (
            "an offset that does not exist",
            json!("2024-03-05T12:00:00+99:00"),
        ),
        (
            "a sub-second value with an offset",
            json!("2024-03-05T12:00:00.123+05:30"),
        ),
        ("lower-case zone marker", json!("2024-03-05T12:00:00z")),
        ("lower-case separator", json!("2024-03-05t12:00:00Z")),
        ("a decimal and an exponent together", json!("1.5e9")),
        ("a signed exponent", json!("1e+9")),
        ("a decimal string", json!("1709640000.5")),
        ("a leading point", json!(".5")),
        ("two points", json!("1709640000.5.5")),
        ("a trailing exponent marker", json!("1709640000e")),
        ("a leading exponent marker", json!("e9")),
        (
            "a decimal in the millisecond band",
            json!("1709640000000.5"),
        ),
        (
            "a decimal in the FILETIME band",
            json!("1335000000000000000.5"),
        ),
        (
            "an offset without a colon",
            json!("2024-03-05T12:00:00+0530"),
        ),
        ("a bare year", json!("2024")),
        ("a year and month", json!("2024-03")),
        ("a date with trailing text", json!("2024-03-05 (approx)")),
        ("a padded date-time", json!(" 2024-03-05T12:00:00Z ")),
        ("hex in the FILETIME band", json!("0x1DA6F4F00000000")),
        ("hex in the seconds band", json!("0x65E71A80")),
        ("octal in the seconds band", json!("0o14571615200")),
        ("binary, far below the band", json!("0b1010")),
        ("an exponent past the range of a double", json!("1e400")),
        ("a boolean", json!(true)),
        ("an empty array", json!([])),
    ];

    let db = SqliteConnection::new("sqlite::memory:").await?;
    db.initialize().await?;
    let case_id = db.create_case("Traps", "Examiner").await?;

    for (i, (_, value)) in cases.iter().enumerate() {
        let mut meta = Map::new();
        meta.insert("date".into(), value.clone());
        db.record_artifact(&artifact_for(case_id, i, &meta)).await?;
    }

    let mut diverged: Vec<String> = Vec::new();
    for (i, (name, value)) in cases.iter().enumerate() {
        let mut meta = Map::new();
        meta.insert("date".into(), value.clone());
        let placement = place_from_metadata(&meta, seance_db::COMMS_TIME_KEYS);

        let census = db
            .comms_volume_census(
                case_id,
                seance_db::COMMS_TIME_KEYS,
                Some("WhatsApp"),
                None,
                Some(&format!("row-{i}")),
            )
            .await?;

        let got = observed(&census);
        let want = reference(&placement);
        if got != want {
            diverged.push(format!("{name} ({value}): procedure {want:?}, sql {got:?}"));
        }
    }

    let allowed: Vec<&str> = KNOWN_TRAP_DIVERGENCES.iter().map(|(n, _)| *n).collect();
    let names: Vec<&str> = diverged
        .iter()
        .map(|d| d.split(" (").next().unwrap_or(d))
        .collect();
    assert_eq!(
        names,
        allowed,
        "the shapes the two sides disagree about must be EXACTLY the allow-list \
         below; observed:\n{}",
        diverged.join("\n")
    );
    for (name, reason) in KNOWN_TRAP_DIVERGENCES {
        // forensic-lint: allow RAGGED-STRING — indented continuation line in test output.
        println!("  DIVERGES: {name}\n    because {reason}");
    }
    Ok(())
}
