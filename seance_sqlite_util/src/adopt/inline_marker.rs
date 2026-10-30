//! The schema records a parser files as a shared `ParserStaleWarning` when it
//! keeps its field maps inline rather than behind a `SchemaSupport` bound:
//! Android SMS, call history, iMessage, Twitter and Facebook Messenger. Lifted
//! here by ROADMAP §5.11 from five copies (2026-09-26); the output is pinned
//! byte-for-byte by `golden/inline_marker.json`, captured from the
//! android_sms copy before the lift.
//!
//! Four records, one vocabulary (owner decision (b), 2026-09-26):
//!
//! * [`field_drift_marker`] — `SchemaFieldsUnresolved`: a column the parser
//!   was validated against is gone. A claim (`content_incomplete`).
//! * [`stale_marker`] — `SchemaOutsideValidated`: the version is outside the
//!   window. A disclosure only; a version by itself says nothing moved.
//! * [`version_undetermined_marker`] — `SchemaVersionUndetermined`: the
//!   version could not be read. A claim: the store cannot be vouched for.
//! * [`version_not_recorded_marker`] — `SchemaVersionNotRecorded`: the store
//!   carries no version. Unranked, never "older than supported".

use super::{SCHEMA_SUBTYPE, WARNING_CLASS};
use crate::{probe_columns, FieldMap, StaleWarning, SupportedRange};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
};
use serde_json::json;
use uuid::Uuid;

/// The column list of a table would not read, so which columns exist is unknown
/// (not the same as the columns being gone).
#[derive(Debug)]
pub struct ColumnsUnreadable {
    pub table: &'static str,
    pub why: String,
}

impl std::fmt::Display for ColumnsUnreadable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the `{}` columns could not be read: {}",
            self.table, self.why
        )
    }
}

impl std::error::Error for ColumnsUnreadable {}

/// One table's logical-to-physical column map, resolved against the store.
///
/// Kept in one place after three parsers (Android SMS, call history, Twitter)
/// each carried a copy (ROADMAP §5.11).
pub struct TableFields {
    pub app: &'static str,
    pub table: &'static str,
    pub map: FieldMap,
}

impl TableFields {
    /// Resolve `specs` against the columns actually present. `Err` when the
    /// column list itself would not read: that is "could not look", and the
    /// caller must not spend it as "the columns are gone".
    pub fn resolve(
        conn: &Connection,
        app: &'static str,
        table: &'static str,
        specs: &[(&str, &[&str])],
    ) -> Result<Self, ColumnsUnreadable> {
        let present = probe_columns(conn, table).map_err(|why| ColumnsUnreadable {
            table,
            why: why.to_string(),
        })?;
        Ok(Self {
            app,
            table,
            map: FieldMap::resolve(&present, specs),
        })
    }

    /// The physical column for `logical`, or the SQL literal `NULL`: usable in
    /// an ORDER BY as well as a SELECT.
    pub fn col(&self, logical: &str) -> String {
        self.col_or(logical, "NULL")
    }

    /// The physical column for `logical`, or `fallback` — for the row id, where
    /// SQLite's own `rowid` still identifies the row when the column has gone.
    pub fn col_or(&self, logical: &str, fallback: &str) -> String {
        self.map
            .column(logical)
            .map(str::to_string)
            .unwrap_or_else(|| fallback.to_string())
    }

    /// The marker naming every logical field no candidate column matched, or
    /// `None` when all resolved. `recovered` is how many records the walk still
    /// produced without those fields.
    pub fn drift_marker(
        &self,
        case_id: Uuid,
        parent_id: Uuid,
        recovered: usize,
    ) -> Option<Artifact> {
        field_drift_marker(
            case_id, parent_id, self.app, self.table, &self.map, recovered,
        )
    }
}

/// The record that says a table this parser reads no longer carries a column
/// it was validated against, or `None` when every field resolved. The rows are
/// still walked with that field absent; what this marker stops is the absence
/// reading as "the store held no such value".
pub fn field_drift_marker(
    case_id: Uuid,
    parent_id: Uuid,
    app: &str,
    table: &str,
    map: &FieldMap,
    recovered: usize,
) -> Option<Artifact> {
    if map.all_resolved() {
        return None;
    }
    let unresolved = map.unresolved();
    let detail = format!(
        "{app}: the `{table}` table has no column this parser recognises for {} — the schema \
         has moved since the parser was validated, and the {recovered} record(s) recovered \
         omit those fields rather than substituting a guess",
        unresolved
            .iter()
            .map(|f| format!("`{f}`"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    let reason = IncompleteReason::UnresolvedStructure.as_str();
    Some(
        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": WARNING_CLASS,
                "subtype": SCHEMA_SUBTYPE,
                "warning_class": WARNING_CLASS,
                "status": "SchemaFieldsUnresolved",
                "app": app,
                "source_table": table,
                "unresolved_fields": unresolved,
                "records_recovered": recovered,
                "content_incomplete": true,
                "content_incomplete_reason": reason,
                "content_incomplete_detail": detail,
                "detail": detail,
                "name": format!("ParserStaleWarning: {detail}"),
            }),
        )
        .with_parent(parent_id)
        .with_subtype(SCHEMA_SUBTYPE),
    )
}

/// The shared stale-schema marker under the unified status. A disclosure, not
/// an incompleteness claim (ROADMAP §1.4a, decided 2026-09-26): the version is
/// newer or older than the evidence held, which by itself says nothing about a
/// column having moved. A required column that did not resolve is what claims,
/// and it has its own record.
pub fn stale_marker(warning: &StaleWarning, case_id: Uuid, parent_id: Uuid) -> Artifact {
    let mut marker = warning
        .marker(case_id, parent_id)
        .with_subtype(SCHEMA_SUBTYPE);
    if let Some(meta) = marker.metadata.as_object_mut() {
        let message = warning.message();
        meta.insert("status".into(), json!("SchemaOutsideValidated"));
        meta.insert("detail".into(), json!(message));
        meta.insert(
            "name".into(),
            json!(format!("ParserStaleWarning: {message}")),
        );
    }
    marker
}

/// The record for a store whose schema version could not be read at all. Not
/// "in range": a version that could not be looked at is a store this parser
/// cannot vouch for.
pub fn version_undetermined_marker(
    case_id: Uuid,
    parent_id: Uuid,
    app: &str,
    supported: &SupportedRange,
    why: &str,
) -> Artifact {
    let detail = format!(
        "{app}: the schema version could not be read ({why}), so whether this store is one \
         the parser was validated against is undetermined rather than answered"
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": WARNING_CLASS,
            "subtype": SCHEMA_SUBTYPE,
            "warning_class": WARNING_CLASS,
            "status": "SchemaVersionUndetermined",
            "app": app,
            "supported_range": supported.describe(),
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "content_incomplete_detail": detail,
            "detail": detail,
            "name": format!("ParserStaleWarning: {detail}"),
        }),
    )
    .with_parent(parent_id)
    .with_subtype(SCHEMA_SUBTYPE)
}

/// The record for a store that carries no schema version where the parser
/// looks. That is the absence of a version, not "version 0": comparing it to
/// the window would manufacture an "older than supported" finding out of an
/// unset field. The parse is unranked, and says so, without claiming anything
/// is incomplete.
pub fn version_not_recorded_marker(
    case_id: Uuid,
    parent_id: Uuid,
    app: &str,
    supported: &SupportedRange,
    where_looked: &str,
) -> Artifact {
    let detail = format!(
        "{app}: no schema version is recorded ({where_looked}), so nothing compares this \
         store to the validated range {} — the parse is unranked, not stale",
        supported.describe()
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": WARNING_CLASS,
            "subtype": SCHEMA_SUBTYPE,
            "warning_class": WARNING_CLASS,
            "status": "SchemaVersionNotRecorded",
            "app": app,
            "supported_range": supported.describe(),
            "message": detail,
            "detail": detail,
            "name": format!("ParserStaleWarning: {detail}"),
        }),
    )
    .with_parent(parent_id)
    .with_subtype(SCHEMA_SUBTYPE)
}

/// Compare a version reading with the validated window: `None` inside it,
/// otherwise the record to file, carrying `evidence` as `validated_against`.
/// `reading` is `Ok(Some(v))` for a version, `Ok(None)` for a store that
/// records none (described by `where_looked`), and `Err(why)` when the read
/// failed — neither of the last two is ever spent as "in range".
pub fn version_marker(
    reading: Result<Option<i64>, String>,
    where_looked: &str,
    case_id: Uuid,
    parent_id: Uuid,
    app: &str,
    supported: &SupportedRange,
    evidence: &str,
) -> Option<Artifact> {
    let marker = match reading {
        Ok(Some(v)) if supported.contains(v) => return None,
        Ok(Some(v)) => stale_marker(
            &StaleWarning {
                app: app.to_string(),
                seen_version: v,
                supported: supported.clone(),
            },
            case_id,
            parent_id,
        ),
        Ok(None) => version_not_recorded_marker(case_id, parent_id, app, supported, where_looked),
        Err(why) => version_undetermined_marker(case_id, parent_id, app, supported, &why),
    };
    Some(with_evidence(marker, evidence))
}

/// [`version_marker`] over `PRAGMA user_version`. Zero is SQLite's default for
/// a store that never set one, so it is "not recorded", never "older".
pub fn user_version_marker(
    conn: &Connection,
    case_id: Uuid,
    parent_id: Uuid,
    app: &str,
    supported: &SupportedRange,
    evidence: &str,
) -> Option<Artifact> {
    let reading = match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(0) => Ok(None),
        Ok(v) => Ok(Some(v)),
        Err(e) => Err(format!("PRAGMA user_version would not read: {e}")),
    };
    version_marker(
        reading,
        "PRAGMA user_version is 0, SQLite's default for a store that never set one",
        case_id,
        parent_id,
        app,
        supported,
        evidence,
    )
}

/// Name the real store(s) a schema record's range was read out of
/// (`validated_against`), so a reader can go from the warning to the file
/// that set each endpoint (HUNT-204).
pub fn with_evidence(mut marker: Artifact, evidence: &str) -> Artifact {
    if let Some(meta) = marker.metadata.as_object_mut() {
        meta.insert("validated_against".into(), json!(evidence));
    }
    marker
}

#[cfg(test)]
mod table_fields_tests {
    use super::*;

    const SPECS: &[(&str, &[&str])] = &[
        ("id", &["_id"]),
        ("text", &["body", "message"]),
        ("when", &["date"]),
    ];

    fn conn(sql: &str) -> Connection {
        let c = Connection::open_in_memory().unwrap();
        c.execute_batch(sql).unwrap();
        c
    }

    #[test]
    fn a_column_resolves_to_the_candidate_the_table_has() {
        let c = conn("CREATE TABLE sms (_id INTEGER, message TEXT, date INTEGER);");
        let f = TableFields::resolve(&c, "TestApp", "sms", SPECS).unwrap();
        assert_eq!(f.col("text"), "message");
        assert_eq!(f.col_or("id", "rowid"), "_id");
        assert!(f.drift_marker(Uuid::new_v4(), Uuid::new_v4(), 3).is_none());
    }

    #[test]
    fn a_missing_column_is_null_in_a_select_and_a_named_drift_record() {
        let c = conn("CREATE TABLE sms (_id INTEGER, body TEXT);");
        let f = TableFields::resolve(&c, "TestApp", "sms", SPECS).unwrap();
        assert_eq!(f.col("when"), "NULL", "usable in a SELECT and an ORDER BY");
        let marker = f
            .drift_marker(Uuid::new_v4(), Uuid::new_v4(), 5)
            .expect("a field is unresolved");
        assert!(
            marker.metadata.to_string().contains("when"),
            "{}",
            marker.metadata
        );
    }

    #[test]
    fn the_row_id_falls_back_when_its_column_has_gone() {
        let c = conn("CREATE TABLE sms (body TEXT);");
        let f = TableFields::resolve(&c, "TestApp", "sms", SPECS).unwrap();
        assert_eq!(f.col_or("id", "rowid"), "rowid");
    }

    #[test]
    fn a_table_with_no_columns_leaves_every_field_unresolved_rather_than_failing() {
        // probe_columns on a missing table yields no columns, not an error, so
        // every field is unresolved rather than "could not look".
        let c = conn("CREATE TABLE other (x INTEGER);");
        let f = TableFields::resolve(&c, "TestApp", "sms", SPECS).unwrap();
        assert!(!f.map.all_resolved());
    }
}
