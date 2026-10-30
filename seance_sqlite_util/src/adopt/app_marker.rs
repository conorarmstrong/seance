//! The schema record an app parser files under its **own** `<App>Incomplete`
//! type (ROADMAP §1.4a, lifted here by §5.11 from five byte-identical copies in
//! the WhatsApp, Telegram, Viber, Kik and Signal crates).
//!
//! Two rules the record is built to:
//!
//! * **No range is declared that was not read out of a real database.** A
//!   [`SchemaBound::Validated`] range names the file each endpoint came from; a
//!   parser this project holds no real store for declares
//!   [`SchemaBound::Unranged`] with the reason, and its record carries no
//!   range at all.
//! * **`PRAGMA user_version` of 0 is the absence of a version.** It is SQLite's
//!   default, so a store that never set it reads 0, and "version 0 is OLDER
//!   than the supported range" would be a fabricated finding.
//!
//! The record keeps the marker contract every other honesty marker of the
//! adopting parser follows: the parser's own `*Incomplete` type (never the
//! message type — `seance_db` groups conversations by `metadata.$.type`), and
//! the incompleteness pair only where the parse is in fact incomplete — a
//! required logical field no column resolved. A version merely outside the
//! validated range is disclosed, not spent as a finding.
//!
//! The `status`, `subtype` and `warning_class` are the vocabulary every schema
//! record shares (ROADMAP §5.11, decided 2026-09-26): `SchemaOutsideValidated`,
//! `SchemaVersionNotRecorded`, `SchemaVersionUndetermined` and
//! `SchemaFieldsUnresolved`, subtype `parser_stale`, `warning_class`
//! `ParserStaleWarning`. Two statuses only this shape can reach keep their own
//! names: `SchemaNotRanged` (the parser declares no range; `SchemaUnvalidated`
//! until 2026-09-26) and
//! `SchemaOptionalFieldsUnresolved` (an optional field no column carried).

use super::{SCHEMA_SUBTYPE, WARNING_CLASS};
use crate::{
    open_readonly, probe_catalogue, probe_columns, probe_table, unreadable_store_marker, FieldMap,
    Presence, StaleWarning, SupportedRange,
};
use rusqlite::Connection;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use serde_json::json;
use uuid::Uuid;

/// The bound on what this parser knows about the app's schema versions.
#[derive(Debug, Clone)]
pub enum SchemaBound {
    /// Every endpoint of `range` was read out of a real database that
    /// `evidence` names. Never widened to reduce noise: a single observed
    /// version is the single-point range `n..=n`.
    Validated {
        range: SupportedRange,
        evidence: &'static str,
    },
    /// No real database of this app has been opened by this project, so no
    /// range is declared and no version is compared to anything.
    Unranged { why: &'static str },
}

/// A parser's declaration.
#[derive(Debug, Clone)]
pub struct SchemaSupport {
    /// The app and platform, e.g. `"whatsapp-android"`.
    pub app: &'static str,
    pub bound: SchemaBound,
}

/// What the store said about its schema version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaVersion {
    /// `PRAGMA user_version` holds a non-zero value.
    Found(i64),
    /// `PRAGMA user_version` is 0: SQLite's default, so unset — not "version 0".
    NotRecorded,
    /// The store keeps its version somewhere this build does not read — a Core
    /// Data store's model identity in `Z_METADATA`, say — and `PRAGMA
    /// user_version` is not it, so it is neither read nor reported. Only the
    /// parsers with a Core Data store construct it.
    NotRead {
        locator: &'static str,
        why: &'static str,
    },
    /// The pragma would not answer. Never spent as "in range".
    Undetermined(String),
}

/// Read the store's `PRAGMA user_version` through the open connection — never
/// from raw header bytes, which on a store with a live `-wal` predate the
/// migration that last wrote the version, and on a SQLCipher store with a
/// plaintext header are ciphertext.
pub fn user_version(conn: &Connection) -> SchemaVersion {
    match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(0) => SchemaVersion::NotRecorded,
        Ok(v) => SchemaVersion::Found(v),
        Err(e) => SchemaVersion::Undetermined(format!("PRAGMA user_version would not read: {e}")),
    }
}

/// SQL expression for a logical field: the resolved physical column (under
/// `alias.` when one is given), else the literal `NULL` — which the [`FieldMap`]
/// has already recorded as unresolved, so the substitution can never reach the
/// query unrecorded.
///
/// A parser that reads its rows by name rather than by expression does not
/// call this.
pub fn field_expr(fields: &FieldMap, alias: &str, logical: &str) -> String {
    match (fields.column(logical), alias) {
        (Some(c), "") => c.to_string(),
        (Some(c), a) => format!("{a}.{c}"),
        (None, _) => "NULL".to_string(),
    }
}

/// Everything the schema record is built from, for one parsed store.
pub struct SchemaCheck<'a> {
    pub support: &'a SchemaSupport,
    pub version: SchemaVersion,
    pub fields: &'a FieldMap,
    /// Logical fields whose absence makes the parse incomplete.
    pub required: &'a [&'a str],
    /// The parser's `*Incomplete` record type.
    pub record_type: &'a str,
    /// The table the fields were resolved against.
    pub store: &'a str,
}

impl SchemaCheck<'_> {
    /// The record this parse owes the examiner, or `None` when a Validated
    /// parser saw an in-range version and every field resolved.
    ///
    /// `recovered` is the number of records the parse produced and must be
    /// counted BEFORE the record joins the list, or it counts itself.
    pub fn marker(&self, case_id: Uuid, parent_id: Uuid, recovered: usize) -> Option<Artifact> {
        let missing_required: Vec<&str> = self
            .fields
            .unresolved()
            .iter()
            .map(String::as_str)
            .filter(|f| self.required.contains(f))
            .collect();
        let missing_optional: Vec<&str> = self
            .fields
            .unresolved()
            .iter()
            .map(String::as_str)
            .filter(|f| !self.required.contains(f))
            .collect();

        let stale = match (&self.support.bound, &self.version) {
            (SchemaBound::Validated { range, .. }, SchemaVersion::Found(v))
                if !range.contains(*v) =>
            {
                Some(StaleWarning {
                    app: self.support.app.to_string(),
                    seen_version: *v,
                    supported: range.clone(),
                })
            }
            _ => None,
        };

        let status = if !missing_required.is_empty() {
            "SchemaFieldsUnresolved"
        } else if stale.is_some() {
            // Newer or older is stated in `message`; the status is the one
            // name every schema record uses for a version outside the range.
            "SchemaOutsideValidated"
        } else {
            match (&self.support.bound, &self.version) {
                (_, SchemaVersion::Undetermined(_)) => "SchemaVersionUndetermined",
                (SchemaBound::Unranged { .. }, _) => "SchemaNotRanged",
                (
                    SchemaBound::Validated { .. },
                    SchemaVersion::NotRecorded | SchemaVersion::NotRead { .. },
                ) => "SchemaVersionNotRecorded",
                (SchemaBound::Validated { .. }, SchemaVersion::Found(_)) => {
                    if missing_optional.is_empty() {
                        return None;
                    }
                    "SchemaOptionalFieldsUnresolved"
                }
            }
        };

        let app = self.support.app;
        let store = self.store;
        let mut meta = serde_json::Map::new();
        meta.insert("type".into(), json!(self.record_type));
        meta.insert("subtype".into(), json!(SCHEMA_SUBTYPE));
        meta.insert("warning_class".into(), json!(WARNING_CLASS));
        meta.insert("status".into(), json!(status));
        meta.insert("app".into(), json!(app));
        meta.insert("source_table".into(), json!(store));
        meta.insert("records_recovered".into(), json!(recovered));
        let locator = match &self.version {
            SchemaVersion::NotRead { locator, .. } => locator,
            _ => "user_version",
        };
        meta.insert("schema_version_locator".into(), json!(locator));

        // The version, as the store answered it.
        let version_sentence = match &self.version {
            SchemaVersion::Found(v) => {
                meta.insert("schema_version_seen".into(), json!(v));
                meta.insert("schema_version_recorded".into(), json!(true));
                format!("the store records schema version {v} (PRAGMA user_version)")
            }
            SchemaVersion::NotRecorded => {
                meta.insert("schema_version_recorded".into(), json!(false));
                "the store records no schema version (PRAGMA user_version is 0, SQLite's unset \
                 default)"
                    .to_string()
            }
            SchemaVersion::NotRead { why, .. } => {
                meta.insert("schema_version_detail".into(), json!(why));
                format!("the store's schema version was not read: {why}")
            }
            SchemaVersion::Undetermined(why) => {
                meta.insert("schema_version_detail".into(), json!(why));
                format!(
                    "the store's schema version could not be read ({why}), so it was not \
                     compared to anything"
                )
            }
        };

        // The bound, as declared — and only a Validated one carries a range.
        let bound_sentence = match &self.support.bound {
            SchemaBound::Validated { range, evidence } => {
                meta.insert("schema_version_supported".into(), json!(range.describe()));
                meta.insert("schema_version_evidence".into(), json!(evidence));
                match &stale {
                    Some(w) => {
                        meta.insert("message".into(), json!(w.message()));
                        w.message()
                    }
                    None => format!(
                        "this parser was validated against schema version(s) {} ({evidence})",
                        range.describe()
                    ),
                }
            }
            SchemaBound::Unranged { why } => {
                format!("this parser has not been validated against a real {app} database: {why}")
            }
        };

        if !missing_optional.is_empty() {
            meta.insert(
                "schema_unresolved_optional_fields".into(),
                json!(missing_optional),
            );
        }

        let sentence = if missing_required.is_empty() {
            format!("{app}: {bound_sentence}; {version_sentence}")
        } else {
            let fields = missing_required.join(", ");
            meta.insert("schema_unresolved_fields".into(), json!(missing_required));
            let unvalidated = IncompleteReason::Unvalidated.as_str();
            let detail = format!(
                "{app}: `{store}` has no column this parser recognises for {fields}, so the \
                 {recovered} record(s) recovered from it are missing that field and the schema \
                 has moved beyond what this parser was written to; {bound_sentence}; \
                 {version_sentence}"
            );
            meta.insert("content_incomplete".into(), json!(true));
            meta.insert("content_incomplete_reason".into(), json!(unvalidated));
            meta.insert("content_incomplete_detail".into(), json!(detail));
            meta.insert("inventory_incomplete".into(), json!(true));
            meta.insert("inventory_incomplete_reason".into(), json!(unvalidated));
            meta.insert("inventory_incomplete_detail".into(), json!(detail));
            detail
        };
        meta.insert("schema_support".into(), json!(sentence));
        meta.insert("detail".into(), json!(sentence));
        meta.insert(
            "name".into(),
            json!(format!("{}: schema support — {status}", self.record_type)),
        );

        Some(
            Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::Value::Object(meta),
            )
            .with_parent(parent_id)
            .with_subtype(SCHEMA_SUBTYPE),
        )
    }
}

/// What a parser needs to open the one table it reads (kik: `messagesTable`).
pub struct StoreSpec<'a> {
    /// The app, as it is named in a sentence (`Kik`).
    pub app: &'a str,
    /// The parser's `<App>Incomplete` record type.
    pub record_type: &'a str,
    /// The table whose columns the fields resolve against.
    pub table: &'a str,
    /// Logical fields and the physical columns that have carried each.
    pub fields: &'a [(&'a str, &'a [&'a str])],
    /// The fields without which a row is not an evidentiary message.
    pub required: &'a [&'a str],
}

/// A store that opened, answered, and holds the table.
pub struct OpenStore {
    pub conn: Connection,
    pub fields: FieldMap,
    pub version: SchemaVersion,
}

impl OpenStore {
    /// The schema check this parse owes, built from what was resolved.
    pub fn check<'a>(
        &'a self,
        support: &'a SchemaSupport,
        spec: &'a StoreSpec<'a>,
    ) -> SchemaCheck<'a> {
        SchemaCheck {
            support,
            version: self.version.clone(),
            fields: &self.fields,
            required: spec.required,
            record_type: spec.record_type,
            store: spec.table,
        }
    }
}

/// Open a store its caller has already identified by name and take it as far as
/// its table's columns.
///
/// `Err(artifacts)` is the final answer: empty when the catalogue ANSWERED that
/// there is no such table (not this app's schema, and silence is the correct
/// finding), otherwise the record saying this tool could not read a store it
/// was told is evidence. That distinction is the whole function: a store that
/// would not open, or would not answer, must never render as a phone that never
/// had the app (`B8-039`: an empty column set from a failed PRAGMA used to fail
/// the later checks and look exactly like a clean absence).
pub fn open_store(
    path: &std::path::Path,
    case_id: Uuid,
    parent_id: Uuid,
    spec: &StoreSpec<'_>,
) -> Result<OpenStore, Vec<Artifact>> {
    let unreadable = |detail: String| {
        vec![unreadable_store_marker(
            case_id,
            parent_id,
            spec.record_type,
            detail,
        )]
    };
    let app = spec.app;
    let table = spec.table;
    let conn = open_readonly(path).map_err(|e| {
        unreadable(format!(
            "the {app} database is named as evidence and would not open: {e}"
        ))
    })?;
    probe_catalogue(&conn).map_err(|why| {
        unreadable(format!(
            "the {app} database opened and its schema catalogue would not read, so whether it \
             holds messages is undetermined rather than answered: {why}"
        ))
    })?;
    match probe_table(&conn, table) {
        Presence::Absent => return Err(Vec::new()),
        Presence::Undetermined(why) => {
            return Err(unreadable(format!(
                "the `{table}` table could not be looked for: {why}"
            )))
        }
        Presence::Present => {}
    }
    let cols = probe_columns(&conn, table).map_err(|why| {
        unreadable(format!(
            "`{table}` is present and its column list would not read: {why}"
        ))
    })?;
    let fields = FieldMap::resolve(&cols, spec.fields);
    let version = user_version(&conn);
    Ok(OpenStore {
        conn,
        fields,
        version,
    })
}

#[cfg(test)]
mod open_store_tests {
    use super::*;

    const SPEC: StoreSpec<'static> = StoreSpec {
        app: "Testapp",
        record_type: "TestappIncomplete",
        table: "messages",
        fields: &[("text", &["body"]), ("sent_at", &["date", "timestamp"])],
        required: &["text", "sent_at"],
    };

    fn db(sql: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(format!("seance_open_store_{}.db", Uuid::new_v4()));
        rusqlite::Connection::open(&path)
            .unwrap()
            .execute_batch(sql)
            .unwrap();
        path
    }

    #[test]
    fn a_store_with_the_table_opens_and_resolves_the_columns_it_has() {
        let path = db("CREATE TABLE messages (body TEXT, timestamp INTEGER);");
        let Ok(store) = open_store(&path, Uuid::new_v4(), Uuid::new_v4(), &SPEC) else {
            panic!("a store holding the table opens");
        };
        assert_eq!(store.fields.column("text"), Some("body"));
        assert_eq!(store.fields.column("sent_at"), Some("timestamp"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_missing_table_is_silence_because_the_catalogue_answered() {
        let path = db("CREATE TABLE other (id INTEGER);");
        let err = open_store(&path, Uuid::new_v4(), Uuid::new_v4(), &SPEC)
            .err()
            .expect("no table");
        assert!(err.is_empty(), "an answered absence files nothing");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn a_store_that_will_not_open_is_a_record_never_silence() {
        let path = std::env::temp_dir().join(format!("seance_no_such_{}.db", Uuid::new_v4()));
        let err = open_store(&path, Uuid::new_v4(), Uuid::new_v4(), &SPEC)
            .err()
            .expect("cannot open");
        assert_eq!(err.len(), 1);
        assert_eq!(err[0].metadata["type"], "TestappIncomplete");
        assert!(err[0].metadata.to_string().contains("named as evidence"));
    }
}
