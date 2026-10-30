//! The scaffolding every capped browser-database walk shares.
//!
//! Thirteen walks in this crate read a browser table the same way: prepare a
//! newest-first SELECT with a bound `LIMIT`, take rows until the row budget is
//! spent, skip the ones that will not decode, and then declare both losses. The
//! SQL and the row map are schema-specific and stay at the call site; the four
//! obligations around them are not, and every copy of them was a chance to get
//! one wrong.
//!
//! It already happened twice. The deterministic `ORDER BY` that decides *which*
//! rows survive a cap was added to the cookie / login / autofill walks in one
//! wave and to the eight history / download / bookmark walks only in a later
//! one, because the first sweep missed them. And the drop marker was built here
//! by a private `RowDrops` that stamped a bare `detail` key, while the shared
//! [`seance_sqlite_util::RowDrops`] it was copied from had learned to stamp
//! `content_incomplete_detail` / `inventory_incomplete_detail` as well — the
//! keys `frontend/src/lib/incompleteness.ts` actually reads. Every browser drop
//! marker therefore reached the examiner as the bare token "unresolved
//! structure", with the sentence naming the table, the count and the decoder's
//! reason attached to a key nothing on that path displays.
//!
//! So the obligations live in one function that cannot be half-satisfied:
//! [`walk_capped_rows`] owns the cap probe, the cap marker, the drop tally and
//! the drop marker, and there is no way to run a walk through it and forget one.

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_sqlite_util::{cap_marker, CapCounter, RowDrops};
use tracing::debug;
use uuid::Uuid;

/// One capped walk over one browser table.
pub(crate) struct CappedWalk<'a> {
    /// The schema-specific SELECT. It must bind its row budget as `LIMIT ?1`
    /// and must order on something beyond its timestamp, so that which rows
    /// survive the cap is the same on every run over the same evidence.
    pub sql: &'a str,
    /// The table named on both markers, so the examiner knows which listing is
    /// short.
    pub source_table: &'a str,
    /// The `type` both markers carry. It must NOT be the `type` the walk's own
    /// records carry: `seance_db` groups ParsedRecords by `metadata.$.type`, so
    /// reusing it files the marker as a browsing record.
    pub marker_type: &'a str,
    /// What this walk reads, for the error context and the skip log
    /// ("Chrome visits", "Firefox bookmarks").
    pub what: &'a str,
    /// The row budget. One row past it is fetched as the cap probe.
    pub max_entries: usize,
}

/// Run one capped walk and return its records followed by whatever
/// incompleteness it has to declare.
///
/// `map_row` is the whole schema-specific part: it decodes one row and builds
/// the artifacts for it. Returning `Err` from it (which any `row.get::<_, T>()?`
/// does on a column of an unexpected type, or on a corrupt page) is not a
/// silent skip — the row is counted and reported.
///
/// Both ways the listing can come up short are declared here, and an examiner
/// has to be able to tell them apart:
///
/// * the walk stopped at its budget, so the rows past it (oldest first, where
///   the query is newest-first) were never fetched — [`cap_marker`];
/// * rows were fetched and would not decode, so the record count is a floor —
///   [`RowDrops::marker`].
///
/// `records_recovered` on the drop marker counts the `ParsedRecord`s the walk
/// produced, not the artifacts: several of these walks emit a `TimelineEvent`
/// for the same visit, and the count an examiner compares against the listing
/// in front of them is the record count. Counting artifacts made a two-record
/// walk claim four, and counting them after the cap marker was pushed made the
/// marker count itself.
pub(crate) fn walk_capped_rows(
    conn: &Connection,
    walk: &CappedWalk<'_>,
    case_id: Uuid,
    parent_id: Uuid,
    map_row: impl FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<Vec<Artifact>>,
) -> Result<Vec<Artifact>> {
    let mut stmt = conn
        .prepare(walk.sql)
        .with_context(|| format!("Failed to prepare {} query", walk.what))?;
    let mut cap = CapCounter::new(walk.max_entries);
    let mut drops = RowDrops::new();
    let rows = stmt
        .query_map([cap.limit()], map_row)
        .with_context(|| format!("Failed to query {}", walk.what))?;

    let mut artifacts: Vec<Artifact> = Vec::new();
    let mut recovered = 0usize;
    for row in rows {
        // The budget is spent on rows FETCHED, not on rows that decoded: a
        // malformed row is admitted and then counted as a drop, exactly as the
        // hand-written walks did.
        if !cap.admit() {
            break;
        }
        match row {
            Ok(built) => {
                recovered += built
                    .iter()
                    .filter(|a| a.artifact_type == ArtifactType::ParsedRecord)
                    .count();
                artifacts.extend(built);
            }
            Err(e) => {
                debug!("Skipping malformed {} row: {}", walk.what, e);
                drops.record(&e);
            }
        }
    }

    if cap.truncated() {
        artifacts.push(cap_marker(
            case_id,
            parent_id,
            walk.marker_type,
            walk.source_table,
            &cap,
        ));
    }
    if let Some(marker) = drops.marker(
        case_id,
        parent_id,
        walk.marker_type,
        walk.source_table,
        recovered,
    ) {
        artifacts.push(marker);
    }
    Ok(artifacts)
}
