//! The schema record filed as a shared `ParserStaleWarning` (ROADMAP §1.4a,
//! lifted here by §5.11 from byte-identical copies in the contacts, browser
//! history, installed apps, Android apps and mobile device crates): where each
//! store keeps its schema version, the range a parser was validated against,
//! and the markers a parse owes when the evidence is outside that range or a
//! column it reads is gone.
//!
//! Every range endpoint an adopter declares was read out of a real database;
//! the `evidence` string on each [`SchemaSupport`] names the file. A
//! single-point range (`3..=3`) means one real store was seen and is the
//! honest form — widening it downward would fabricate the lower bound.
//!
//! `PRAGMA user_version` is 0 — SQLite's unset default — on most genuine Apple
//! and Chromium stores, so 0 is never a version here: it is
//! [`SchemaVersion::NotRecorded`], stated but never ranked against a range.

use std::collections::HashSet;

use crate::{probe_columns, probe_table, FieldMap, Presence, StaleWarning, SupportedRange};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
};
use serde_json::json;
use uuid::Uuid;

/// A store's schema version, as it could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaVersion {
    /// The store carries a version and this is it.
    Found(i64),
    /// The store carries no version where this parser knows to look.
    NotRecorded(String),
    /// The read itself failed, so nothing is known either way.
    Undetermined(String),
}

/// `PRAGMA user_version`, with 0 read as "not recorded" rather than as version
/// zero.
pub fn user_version(conn: &Connection) -> SchemaVersion {
    match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(0) => SchemaVersion::NotRecorded(
            "PRAGMA user_version is 0, SQLite's unset default, so this store does not carry \
             the version the validated stores carried"
                .to_string(),
        ),
        Ok(v) => SchemaVersion::Found(v),
        Err(e) => SchemaVersion::Undetermined(format!("PRAGMA user_version would not read: {e}")),
    }
}

/// A version kept as a row of a key/value table — Chromium's `meta` table
/// (`key`/`value`, key `version`) and Apple's `_SqliteDatabaseProperties`
/// (`_ClientVersion`) — read through the catalogue probes so a table that
/// would not read is [`SchemaVersion::Undetermined`], never "not recorded".
///
/// `table` and the column names are compile-time constants at every call site.
pub fn keyed_version(
    conn: &Connection,
    table: &str,
    key_column: &str,
    value_column: &str,
    key: &str,
) -> SchemaVersion {
    match probe_table(conn, table) {
        Presence::Present => {}
        Presence::Absent => {
            return SchemaVersion::NotRecorded(format!(
                "there is no `{table}` table, which is where the validated stores carried it"
            ))
        }
        Presence::Undetermined(why) => return SchemaVersion::Undetermined(why),
    }
    let sql = format!("SELECT {value_column} FROM {table} WHERE {key_column} = ?1");
    match conn.query_row(&sql, [key], |r| r.get::<_, rusqlite::types::Value>(0)) {
        Ok(rusqlite::types::Value::Integer(v)) => SchemaVersion::Found(v),
        Ok(rusqlite::types::Value::Text(t)) => match t.trim().parse::<i64>() {
            Ok(v) => SchemaVersion::Found(v),
            Err(_) => SchemaVersion::Undetermined(format!(
                "`{table}`.`{key}` is {t:?}, which is not a whole number"
            )),
        },
        Ok(other) => SchemaVersion::Undetermined(format!(
            "`{table}`.`{key}` is a {} rather than a number",
            other.data_type()
        )),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            SchemaVersion::NotRecorded(format!("`{table}` has no `{key}` row"))
        }
        Err(e) => SchemaVersion::Undetermined(format!("`{table}`.`{key}` would not read: {e}")),
    }
}

/// A version kept as the single row of a one-column table — FrontBoard's
/// `applicationState.db` writes `schema(version INT NOT NULL)` — read through
/// the catalogue probe so a table that would not read is
/// [`SchemaVersion::Undetermined`], never "not recorded".
///
/// `table` and `column` are compile-time constants at every call site.
pub fn single_row_version(conn: &Connection, table: &str, column: &str) -> SchemaVersion {
    match probe_table(conn, table) {
        Presence::Present => {}
        Presence::Absent => {
            return SchemaVersion::NotRecorded(format!(
                "there is no `{table}` table, which is where the validated stores carried it"
            ))
        }
        Presence::Undetermined(why) => return SchemaVersion::Undetermined(why),
    }
    let sql = format!("SELECT {column} FROM {table} LIMIT 1");
    match conn.query_row(&sql, [], |r| r.get::<_, i64>(0)) {
        Ok(v) => SchemaVersion::Found(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => {
            SchemaVersion::NotRecorded(format!("`{table}` has no rows"))
        }
        Err(e) => SchemaVersion::Undetermined(format!("`{table}`.`{column}` would not read: {e}")),
    }
}

/// What one parser was validated against for one store.
pub struct SchemaSupport {
    /// The parser identity on the marker, e.g. `"android-accounts"`.
    pub app: &'static str,
    /// The file the range applies to, e.g. `"accounts_de.db"`.
    pub store: &'static str,
    /// The `type` of the records this parser emits, so the marker can say which
    /// records it qualifies.
    pub record_type: &'static str,
    /// Inclusive, every endpoint observed in a real file.
    pub range: SupportedRange,
    /// The real file(s) the endpoints were read from.
    pub evidence: &'static str,
}

/// The marker's shared shape: what the shipped [`StaleWarning::marker`] carries,
/// plus the `detail` sentence, the store and the evidence an examiner asks for.
/// The incompleteness reason and sentence are added only to a marker that
/// makes the claim (an undetermined version); an out-of-range version is a
/// disclosure and carries neither (ROADMAP §1.4a, decided 2026-09-26).
fn stamp(mut marker: Artifact, support: &SchemaSupport, status: &str, detail: &str) -> Artifact {
    let m = marker
        .metadata
        .as_object_mut()
        .expect("marker metadata is an object");
    m.insert("subtype".into(), json!(super::SCHEMA_SUBTYPE));
    m.insert("warning_class".into(), json!(super::WARNING_CLASS));
    m.insert("status".into(), json!(status));
    m.insert("store".into(), json!(support.store));
    m.insert("parser_record_type".into(), json!(support.record_type));
    m.insert("validated_against".into(), json!(support.evidence));
    m.insert("detail".into(), json!(detail));
    m.insert(
        "name".into(),
        json!(format!(
            "{}: schema outside what was validated",
            support.app
        )),
    );
    if m.get("content_incomplete") == Some(&json!(true)) {
        m.insert("content_incomplete_detail".into(), json!(detail));
        m.entry("content_incomplete_reason")
            .or_insert_with(|| json!(IncompleteReason::Unvalidated.as_str()));
    }
    marker.with_subtype(super::SCHEMA_SUBTYPE)
}

/// The marker a version answer entitles the report to, or `None` when the
/// version is inside the validated range.
///
/// Out of range is the shipped [`StaleWarning`] marker: a disclosure, not an
/// incompleteness claim — a version newer than the evidence held says nothing
/// about whether a column moved, and a required column that did not resolve is
/// what claims. Not recorded is stated
/// without an incompleteness claim: nothing was compared, and the absence of a
/// version is not evidence the columns moved. Undetermined is stated AS an
/// incompleteness: the question was asked and the store would not answer.
pub fn assess_version(
    support: &SchemaSupport,
    version: &SchemaVersion,
    case_id: Uuid,
    parent_id: Uuid,
) -> Option<Artifact> {
    match version {
        SchemaVersion::Found(v) if support.range.contains(*v) => None,
        SchemaVersion::Found(v) => {
            let warning = StaleWarning {
                app: support.app.to_string(),
                seen_version: *v,
                supported: support.range.clone(),
            };
            let detail = warning.message();
            Some(stamp(
                warning.marker(case_id, parent_id),
                support,
                "SchemaOutsideValidated",
                &detail,
            ))
        }
        SchemaVersion::NotRecorded(where_looked) => {
            let message = format!(
                "{}: no schema version is recorded in `{}` ({where_looked}); nothing compares \
                 this store to the validated range {} and the parse is unranked, not stale",
                support.app,
                support.store,
                support.range.describe()
            );
            let marker = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "ParserStaleWarning",
                    "app": support.app,
                    "supported_range": support.range.describe(),
                    "message": message,
                }),
            )
            .with_parent(parent_id);
            Some(stamp(marker, support, "SchemaVersionNotRecorded", &message))
        }
        SchemaVersion::Undetermined(why) => {
            let message = format!(
                "{}: the schema version of `{}` could not be read ({why}), so whether this \
                 store is inside the validated range {} is unknown",
                support.app,
                support.store,
                support.range.describe()
            );
            let marker = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "ParserStaleWarning",
                    "app": support.app,
                    "supported_range": support.range.describe(),
                    "message": message,
                    "content_incomplete": true,
                    "content_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
                }),
            )
            .with_parent(parent_id);
            Some(stamp(
                marker,
                support,
                "SchemaVersionUndetermined",
                &message,
            ))
        }
    }
}

/// The logical→physical column plan for one table: which fields resolved,
/// which required ones did not, and the columns that were there.
pub struct ColumnPlan {
    pub required: FieldMap,
    pub optional: FieldMap,
    pub present: HashSet<String>,
}

impl ColumnPlan {
    /// The physical column for `logical`, from either tier.
    pub fn column(&self, logical: &str) -> Option<&str> {
        self.required
            .column(logical)
            .or_else(|| self.optional.column(logical))
    }

    /// The required fields no candidate matched.
    pub fn missing_required(&self) -> &[String] {
        self.required.unresolved()
    }
}

/// Resolve a table's columns against two candidate lists: `required` fields the
/// record is meaningless without (unresolved → declared on the marker) and
/// `optional` ones that older real schemas genuinely lack.
pub fn plan_columns(
    conn: &Connection,
    table: &str,
    required: &[(&str, &[&str])],
    optional: &[(&str, &[&str])],
) -> Result<ColumnPlan, String> {
    let present = probe_columns(conn, table)?;
    Ok(ColumnPlan {
        required: FieldMap::resolve(&present, required),
        optional: FieldMap::resolve(&present, optional),
        present,
    })
}

/// The marker for required logical fields no column carried: the parser's
/// column map is stale for this schema, and the records it did produce lack
/// them. `recovered` is how many records the parse still produced.
pub fn unresolved_fields_marker(
    support: &SchemaSupport,
    table: &str,
    plan: &ColumnPlan,
    recovered: usize,
    case_id: Uuid,
    parent_id: Uuid,
) -> Artifact {
    let unresolved = plan.missing_required();
    let mut present: Vec<&String> = plan.present.iter().collect();
    present.sort();
    let message = format!(
        "{}: no column in `{table}` of `{}` carries {} — the schema has moved past this \
         parser's column map, so the {recovered} record(s) recovered lack {} and anything \
         keyed on {} was not read",
        support.app,
        support.store,
        list(unresolved),
        if unresolved.len() == 1 { "it" } else { "them" },
        if unresolved.len() == 1 { "it" } else { "them" },
    );
    let marker = Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "ParserStaleWarning",
            "app": support.app,
            "supported_range": support.range.describe(),
            "source_table": table,
            "unresolved_fields": unresolved,
            "present_columns": present,
            "records_recovered": recovered,
            "message": message,
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::Unvalidated.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::Unvalidated.as_str(),
            "inventory_incomplete_detail": message,
        }),
    )
    .with_parent(parent_id);
    stamp(marker, support, "SchemaFieldsUnresolved", &message)
}

fn list(fields: &[String]) -> String {
    fields
        .iter()
        .map(|f| format!("`{f}`"))
        .collect::<Vec<_>>()
        .join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn support() -> SchemaSupport {
        SchemaSupport {
            app: "test-app",
            store: "test.db",
            record_type: "TestRecord",
            range: SupportedRange::new(3, Some(3)),
            evidence: "a test",
        }
    }

    #[test]
    fn a_zero_user_version_is_not_recorded_rather_than_version_zero() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(matches!(user_version(&conn), SchemaVersion::NotRecorded(_)));
        conn.execute_batch("PRAGMA user_version = 3").unwrap();
        assert_eq!(user_version(&conn), SchemaVersion::Found(3));
    }

    #[test]
    fn a_single_row_version_is_read_or_stated_absent() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(matches!(
            single_row_version(&conn, "schema", "version"),
            SchemaVersion::NotRecorded(_)
        ));
        conn.execute_batch("CREATE TABLE schema (version INT NOT NULL);")
            .unwrap();
        assert!(matches!(
            single_row_version(&conn, "schema", "version"),
            SchemaVersion::NotRecorded(_)
        ));
        conn.execute_batch("INSERT INTO schema VALUES (1);")
            .unwrap();
        assert_eq!(
            single_row_version(&conn, "schema", "version"),
            SchemaVersion::Found(1)
        );
    }

    #[test]
    fn a_keyed_version_is_read_from_its_row_or_stated_absent() {
        let conn = Connection::open_in_memory().unwrap();
        assert!(matches!(
            keyed_version(&conn, "meta", "key", "value", "version"),
            SchemaVersion::NotRecorded(_)
        ));
        conn.execute_batch(
            "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
             INSERT INTO meta VALUES ('other', '1');",
        )
        .unwrap();
        assert!(matches!(
            keyed_version(&conn, "meta", "key", "value", "version"),
            SchemaVersion::NotRecorded(_)
        ));
        conn.execute_batch("INSERT INTO meta VALUES ('version', '41');")
            .unwrap();
        assert_eq!(
            keyed_version(&conn, "meta", "key", "value", "version"),
            SchemaVersion::Found(41)
        );
        conn.execute_batch("UPDATE meta SET value = 'x' WHERE key = 'version';")
            .unwrap();
        assert!(matches!(
            keyed_version(&conn, "meta", "key", "value", "version"),
            SchemaVersion::Undetermined(_)
        ));
    }

    #[test]
    fn an_in_range_version_owes_no_marker() {
        let (c, p) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(assess_version(&support(), &SchemaVersion::Found(3), c, p).is_none());
    }

    #[test]
    fn an_out_of_range_version_is_a_disclosure_not_an_incompleteness_claim() {
        let (c, p) = (Uuid::new_v4(), Uuid::new_v4());
        let m = assess_version(&support(), &SchemaVersion::Found(4), c, p).unwrap();
        assert_eq!(m.metadata["type"], "ParserStaleWarning");
        assert_eq!(m.metadata["status"], "SchemaOutsideValidated");
        assert_eq!(m.metadata["supported_range"], support().range.describe());
        assert!(m.metadata["validated_against"].is_string());
        assert!(m.metadata["message"].as_str().unwrap().contains("NEWER"));
        assert_eq!(m.metadata["detail"], m.metadata["message"]);
        // §1.4a (decided 2026-09-26): outside the range is a disclosure. A
        // missing column or table is what claims incompleteness.
        assert!(m.metadata.get("content_incomplete").is_none());
        assert!(m.metadata.get("content_incomplete_reason").is_none());
        assert!(m.metadata.get("content_incomplete_detail").is_none());
        assert_eq!(m.metadata["store"], "test.db");
        assert_eq!(m.parent_id, Some(p));
    }

    #[test]
    fn a_missing_version_is_stated_without_an_incompleteness_claim() {
        let (c, p) = (Uuid::new_v4(), Uuid::new_v4());
        let m = assess_version(
            &support(),
            &SchemaVersion::NotRecorded("nowhere".into()),
            c,
            p,
        )
        .unwrap();
        assert_eq!(m.metadata["status"], "SchemaVersionNotRecorded");
        assert!(m.metadata.get("content_incomplete").is_none());
    }

    #[test]
    fn an_unreadable_version_is_an_incompleteness_not_a_pass() {
        let (c, p) = (Uuid::new_v4(), Uuid::new_v4());
        let m =
            assess_version(&support(), &SchemaVersion::Undetermined("io".into()), c, p).unwrap();
        assert_eq!(m.metadata["status"], "SchemaVersionUndetermined");
        assert_eq!(m.metadata["content_incomplete"], true);
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
    }

    #[test]
    fn a_column_plan_separates_required_from_optional_losses() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE t (a TEXT, b_new TEXT)")
            .unwrap();
        let plan = plan_columns(
            &conn,
            "t",
            &[
                ("a", &["a"][..]),
                ("b", &["b", "b_new"][..]),
                ("c", &["c"][..]),
            ],
            &[("d", &["d"][..])],
        )
        .unwrap();
        assert_eq!(plan.column("b"), Some("b_new"));
        assert_eq!(plan.missing_required(), &["c".to_string()]);
        assert_eq!(plan.column("d"), None);
        let (c, p) = (Uuid::new_v4(), Uuid::new_v4());
        let m = unresolved_fields_marker(&support(), "t", &plan, 2, c, p);
        assert_eq!(m.metadata["status"], "SchemaFieldsUnresolved");
        assert_eq!(m.metadata["unresolved_fields"], json!(["c"]));
        assert_eq!(m.metadata["records_recovered"], 2);
        assert_eq!(m.metadata["present_columns"], json!(["a", "b_new"]));
        assert_eq!(m.metadata["inventory_incomplete_reason"], "unvalidated");
    }
}
