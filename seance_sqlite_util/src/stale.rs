//! Schema-version staleness and data-driven field mapping for app parsers.
//!
//! Séance's ~20 messaging/app parsers are correct for the schemas they were
//! written against, and apps change those schemas every few weeks. Cellebrite,
//! AXIOM and Belkasoft each pay a team to chase that churn; Séance cannot match
//! that headcount, so the design goal here is different: **make falling behind
//! loud instead of silent, and cheap to fix.**
//!
//! This module provides three things, matching `ROADMAP.md` §1.4a
//! (mobile app-parser schema-drift defence):
//!
//! 1. [`StaleWarning`] + [`check_schema_version`] — a *typed* warning emitted
//!    when a database's schema version is outside the range a parser supports, so
//!    an examiner reads "WhatsApp schema newer than supported" rather than an
//!    empty result that looks like "no messages". The version is read as three
//!    answers ([`StoreSchemaVersion`]): a `PRAGMA user_version` of 0 is SQLite's
//!    unset default and is stated as "not recorded", never ranked as OLDER, and
//!    a pragma that will not read is stated as undetermined, never as in range.
//! 2. [`FieldMap`] — resolve logical field names to whatever physical columns a
//!    given schema uses, tolerating renames, so a schema bump is a data edit
//!    (add a candidate name) rather than a code change.
//! 3. [`CorpusExpectation`]/[`check_corpus`] — a regression-harness contract that
//!    asserts extraction counts against reference databases, so a change that
//!    breaks a parser fails CI immediately.

use rusqlite::Connection;
use serde_json::json;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use uuid::Uuid;

/// A parser's declared support window for an app's schema version.
///
/// `min`/`max` are inclusive. A `max` of `None` means "no known upper bound yet"
/// — the honest state for a parser that has only ever seen up to some version and
/// makes no claim about newer ones, which still lets it *warn* when a newer one
/// appears rather than pretend it is fine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedRange {
    pub min: i64,
    pub max: Option<i64>,
}

impl SupportedRange {
    pub fn new(min: i64, max: Option<i64>) -> Self {
        Self { min, max }
    }

    /// Whether `version` is within the supported window.
    pub fn contains(&self, version: i64) -> bool {
        version >= self.min && self.max.map(|m| version <= m).unwrap_or(true)
    }

    /// Human-readable form for a warning, e.g. `"1..=14"` or `"1..="`.
    pub fn describe(&self) -> String {
        match self.max {
            Some(m) => format!("{}..={}", self.min, m),
            None => format!("{}..=(open)", self.min),
        }
    }
}

/// A typed warning that a database's schema is outside what the parser supports.
///
/// It is a *finding*, not an error: the parser still extracts what it can and
/// emits this alongside, so the result is "partial, and here is why", never a
/// silent empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StaleWarning {
    /// The app/parser identity, e.g. `"whatsapp-android"`.
    pub app: String,
    /// The schema version actually found in the evidence.
    pub seen_version: i64,
    /// The range the parser was written and tested against.
    pub supported: SupportedRange,
}

impl StaleWarning {
    /// A one-line explanation suitable for a report cell.
    pub fn message(&self) -> String {
        if self.seen_version > self.supported.max.unwrap_or(i64::MAX) {
            format!(
                "{}: schema version {} is NEWER than the supported range {} — records may be \
                 incompletely parsed; this parser predates this app version",
                self.app,
                self.seen_version,
                self.supported.describe(),
            )
        } else {
            format!(
                "{}: schema version {} is OLDER than the supported range {} — this parser targets \
                 newer layouts and may miss records",
                self.app,
                self.seen_version,
                self.supported.describe(),
            )
        }
    }

    /// Emit the warning as a marker artifact, mirroring the other honesty markers
    /// in this crate ([`crate::cap_marker`] and friends).
    ///
    /// The marker contract the per-crate adopters converged on (HUNT-186):
    /// subtype `parser_stale`, a `status`, the `supported_range`, the
    /// `message` sentence repeated as `detail`, and a `name`.
    ///
    /// It is a **disclosure, not an incompleteness claim** (ROADMAP §1.4a,
    /// decided 2026-09-26): neither `content_incomplete` nor
    /// `inventory_incomplete` is stamped. Most validated ranges are a single
    /// point because one to four real stores are held per app, so claiming on
    /// every newer version would mark stores whose every column still resolves
    /// as incomplete. What does claim is the signal that rows or fields were
    /// actually lost — a required column or table that did not resolve — and a
    /// version that would not read at all
    /// ([`crate::adopt::app_marker::SchemaCheck::marker`]). Until 2026-09-26
    /// this marker stamped `content_incomplete` with reason `unvalidated`,
    /// which only the shared crate and five adopters did.
    pub fn marker(&self, case_id: Uuid, parent: Uuid) -> Artifact {
        self.marker_with_evidence(case_id, parent, None)
    }

    /// [`StaleWarning::marker`], naming the real file(s) the range's endpoints
    /// were read from as `validated_against`, so a reader can go from the
    /// warning to the store that set the range.
    pub fn marker_with_evidence(
        &self,
        case_id: Uuid,
        parent: Uuid,
        evidence: Option<&str>,
    ) -> Artifact {
        let mut meta = base_meta(&self.app, &self.supported, evidence);
        meta.insert("status".into(), json!("SchemaOutsideValidated"));
        meta.insert("seen_schema_version".into(), json!(self.seen_version));
        meta.insert("message".into(), json!(self.message()));
        finish_marker(
            meta,
            case_id,
            parent,
            &self.app,
            "schema outside what was validated",
        )
    }
}

/// The keys every shared schema marker carries.
fn base_meta(
    app: &str,
    supported: &SupportedRange,
    evidence: Option<&str>,
) -> serde_json::Map<String, serde_json::Value> {
    let mut meta = serde_json::Map::new();
    meta.insert("type".into(), json!("ParserStaleWarning"));
    meta.insert("subtype".into(), json!(STALE_SUBTYPE));
    // The class every schema record carries, whatever its `type` (ROADMAP
    // §5.11, decided 2026-09-26) — `crate::adopt::app_marker` files under the
    // parser's own `<App>Incomplete` type and is found by this key.
    meta.insert("warning_class".into(), json!("ParserStaleWarning"));
    meta.insert("app".into(), json!(app));
    meta.insert("supported_range".into(), json!(supported.describe()));
    if let Some(evidence) = evidence {
        meta.insert("validated_against".into(), json!(evidence));
    }
    meta
}

/// `detail` and `name`, then the artifact.
fn finish_marker(
    mut meta: serde_json::Map<String, serde_json::Value>,
    case_id: Uuid,
    parent: Uuid,
    app: &str,
    what: &str,
) -> Artifact {
    let detail = meta
        .get("message")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    meta.insert("detail".into(), detail);
    meta.insert("name".into(), json!(format!("{app}: {what}")));
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::Value::Object(meta),
    )
    .with_parent(parent)
    .with_subtype(STALE_SUBTYPE)
}

/// The subtype every shared schema marker carries.
const STALE_SUBTYPE: &str = "parser_stale";

/// What a store said about its schema version, read through `PRAGMA
/// user_version`. **Three** answers, not two (HUNT-186).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StoreSchemaVersion {
    /// `PRAGMA user_version` holds a non-zero value.
    Found(i64),
    /// `PRAGMA user_version` is 0: SQLite's default, so the store never set
    /// one. It is the absence of a version, not "version 0", and is never
    /// ranked against a range — true of every real Chromium store, the iOS
    /// `AddressBook.sqlitedb` and `applicationState.db`, plaso's
    /// `kik_ios.sqlite` and Skype's `main.db`.
    NotRecorded,
    /// The pragma would not answer. Never spent as "in range".
    Undetermined(String),
}

/// Read `PRAGMA user_version` through the open connection, as three answers.
pub fn read_user_version(conn: &Connection) -> StoreSchemaVersion {
    match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(0) => StoreSchemaVersion::NotRecorded,
        Ok(v) => StoreSchemaVersion::Found(v),
        Err(e) => {
            StoreSchemaVersion::Undetermined(format!("PRAGMA user_version would not read: {e}"))
        }
    }
}

/// One store's version against one parser's range: the answer
/// [`check_schema_version`] returns, and the record it owes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchemaVersionCheck {
    /// The app/parser identity, e.g. `"safari-bookmarks"`.
    pub app: String,
    /// The range the parser was validated against.
    pub supported: SupportedRange,
    /// What the store answered.
    pub version: StoreSchemaVersion,
}

impl SchemaVersionCheck {
    /// The stale warning, when — and only when — a recorded version lies
    /// outside the range. An unrecorded (0) or unreadable version is never one.
    pub fn warning(&self) -> Option<StaleWarning> {
        match self.version {
            StoreSchemaVersion::Found(v) if !self.supported.contains(v) => Some(StaleWarning {
                app: self.app.clone(),
                seen_version: v,
                supported: self.supported.clone(),
            }),
            _ => None,
        }
    }

    /// The record this answer owes the examiner, or `None` only when a
    /// recorded version lies inside the range.
    ///
    /// * outside the range — [`StaleWarning::marker`], `SchemaOutsideValidated`,
    ///   a disclosure with no incompleteness claim (§1.4a);
    /// * not recorded — `SchemaVersionNotRecorded`, stated without an
    ///   incompleteness claim: nothing was compared, and an unset version is
    ///   not evidence the columns moved;
    /// * undetermined — `SchemaVersionUndetermined`, stated AS an
    ///   incompleteness (`unresolved_structure`): the question was asked and
    ///   the store would not answer, so the parser cannot vouch for it.
    ///
    /// `evidence` names the real file(s) the range was read from and is
    /// written as `validated_against` on every record that carries the range.
    pub fn marker(&self, case_id: Uuid, parent: Uuid, evidence: Option<&str>) -> Option<Artifact> {
        let app = self.app.as_str();
        let range = self.supported.describe();
        let mut marker = match &self.version {
            StoreSchemaVersion::Found(v) if self.supported.contains(*v) => return None,
            StoreSchemaVersion::Found(_) => self
                .warning()
                .map(|w| w.marker_with_evidence(case_id, parent, evidence))?,
            StoreSchemaVersion::NotRecorded => {
                let message = format!(
                    "{app}: no schema version is recorded (PRAGMA user_version is 0, SQLite's \
                     unset default), so nothing compares this store to the validated range \
                     {range} — the parse is unranked, not stale"
                );
                let mut meta = base_meta(app, &self.supported, evidence);
                meta.insert("status".into(), json!("SchemaVersionNotRecorded"));
                meta.insert("schema_version_recorded".into(), json!(false));
                meta.insert("message".into(), json!(message));
                finish_marker(meta, case_id, parent, app, "no schema version recorded")
            }
            StoreSchemaVersion::Undetermined(why) => {
                let message = format!(
                    "{app}: the schema version could not be read ({why}), so whether this store \
                     is inside the validated range {range} is undetermined rather than answered"
                );
                let unresolved = IncompleteReason::UnresolvedStructure.as_str();
                let mut meta = base_meta(app, &self.supported, evidence);
                meta.insert("status".into(), json!("SchemaVersionUndetermined"));
                meta.insert("schema_version_detail".into(), json!(why));
                meta.insert("message".into(), json!(message));
                meta.insert("content_incomplete".into(), json!(true));
                meta.insert("content_incomplete_reason".into(), json!(unresolved));
                meta.insert("content_incomplete_detail".into(), json!(message));
                finish_marker(meta, case_id, parent, app, "schema version undetermined")
            }
        };
        // Where the version was looked for — only this check knows it was
        // `PRAGMA user_version`; a bare `StaleWarning` may carry a version
        // read from elsewhere (`_ClientVersion`, Chromium's `meta` row).
        if let Some(m) = marker.metadata.as_object_mut() {
            m.insert("schema_version_locator".into(), json!("user_version"));
        }
        Some(marker)
    }
}

/// Read a database's schema version from `PRAGMA user_version` and compare it to
/// the parser's [`SupportedRange`], as three answers: a recorded version (in or
/// out of range), no version recorded (0, SQLite's unset default — never ranked
/// as OLDER), or a pragma that would not read (never spent as "in range").
/// [`SchemaVersionCheck::marker`] is the record each answer owes.
pub fn check_schema_version(
    conn: &Connection,
    app: &str,
    supported: &SupportedRange,
) -> SchemaVersionCheck {
    SchemaVersionCheck {
        app: app.to_string(),
        supported: supported.clone(),
        version: read_user_version(conn),
    }
}

/// A data-driven mapping from a logical field to the candidate physical column
/// names that have carried it across schema versions.
///
/// Instead of hard-coding `row.get("timestamp")`, a parser declares
/// `("sent_at", &["timestamp", "ts", "date_sent"])` and resolves against the
/// actual column set. When a new app version renames the column, the fix is one
/// string in a list, not a code path — which is what keeps the parser cheap to
/// maintain against churn.
#[derive(Debug, Clone)]
pub struct FieldMap {
    /// (logical name, resolved physical column) for fields that were found.
    resolved: Vec<(String, String)>,
    /// Logical names that no candidate matched — a signal the schema moved.
    unresolved: Vec<String>,
}

impl FieldMap {
    /// Resolve a set of `(logical, &[candidate columns])` specs against the
    /// lower-cased physical columns present (as from [`crate::probe_columns`]).
    /// Candidate order is preference order: the first present candidate wins.
    pub fn resolve<'a>(
        present_columns: &std::collections::HashSet<String>,
        specs: &[(&'a str, &'a [&'a str])],
    ) -> Self {
        let mut resolved = Vec::new();
        let mut unresolved = Vec::new();
        for (logical, candidates) in specs {
            match candidates
                .iter()
                .find(|c| present_columns.contains(&c.to_ascii_lowercase()))
            {
                Some(col) => resolved.push((logical.to_string(), col.to_string())),
                None => unresolved.push(logical.to_string()),
            }
        }
        Self {
            resolved,
            unresolved,
        }
    }

    /// The physical column backing `logical`, if it resolved.
    pub fn column(&self, logical: &str) -> Option<&str> {
        self.resolved
            .iter()
            .find(|(l, _)| l == logical)
            .map(|(_, c)| c.as_str())
    }

    /// Logical fields no candidate matched — worth a stale warning if a
    /// *required* field is among them.
    pub fn unresolved(&self) -> &[String] {
        &self.unresolved
    }

    /// Whether every listed logical field resolved.
    pub fn all_resolved(&self) -> bool {
        self.unresolved.is_empty()
    }
}

/// One parser's expected extraction against a named reference database — the unit
/// of the corpus-diff regression harness.
#[derive(Debug, Clone)]
pub struct CorpusExpectation {
    /// Reference database identity (app + version), for the failure message.
    pub label: String,
    /// The minimum record count a correct parse must extract. A parser that
    /// silently breaks drops below this and fails the assertion.
    pub min_records: usize,
}

/// Check an actual extraction count against an expectation. Returns `Ok(())` or a
/// descriptive error naming the shortfall — the message a CI failure should show.
pub fn check_corpus(expect: &CorpusExpectation, actual_records: usize) -> Result<(), String> {
    if actual_records >= expect.min_records {
        Ok(())
    } else {
        Err(format!(
            "{}: extracted {} records, expected at least {} — the parser may have broken against \
             this schema",
            expect.label, actual_records, expect.min_records
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::Connection;
    use std::collections::HashSet;

    fn cols(names: &[&str]) -> HashSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn supported_range_contains_and_describes() {
        let r = SupportedRange::new(1, Some(14));
        assert!(r.contains(1) && r.contains(14) && r.contains(7));
        assert!(!r.contains(0) && !r.contains(15));
        assert_eq!(r.describe(), "1..=14");

        let open = SupportedRange::new(5, None);
        assert!(open.contains(9999));
        assert!(!open.contains(4));
        assert_eq!(open.describe(), "5..=(open)");
    }

    #[test]
    fn in_range_version_produces_no_warning() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 10;").unwrap();
        let r = SupportedRange::new(1, Some(14));
        let check = check_schema_version(&conn, "whatsapp", &r);
        assert_eq!(check.warning(), None);
        assert!(check.marker(Uuid::new_v4(), Uuid::new_v4(), None).is_none());
    }

    #[test]
    fn newer_schema_warns_clearly_not_silently() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 20;").unwrap();
        let r = SupportedRange::new(1, Some(14));
        let w = check_schema_version(&conn, "whatsapp-android", &r)
            .warning()
            .expect("a newer schema must warn");
        assert_eq!(w.seen_version, 20);
        assert!(w.message().contains("NEWER"));
        assert!(w.message().contains("1..=14"));
    }

    #[test]
    fn older_schema_also_warns() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 3;").unwrap();
        let r = SupportedRange::new(5, Some(14));
        let w = check_schema_version(&conn, "telegram", &r)
            .warning()
            .unwrap();
        assert!(w.message().contains("OLDER"));
    }

    /// HUNT-186: `PRAGMA user_version` is 0 on every store that never set one
    /// — every real Chromium store, the iOS `AddressBook.sqlitedb`, plaso's
    /// `kik_ios.sqlite`. Ranking that 0 as "OLDER than the supported range" is
    /// a finding manufactured out of an unset field.
    #[test]
    fn version_zero_is_not_recorded_never_older() {
        let conn = Connection::open_in_memory().unwrap();
        let r = SupportedRange::new(43, Some(43));
        let check = check_schema_version(&conn, "safari-bookmarks", &r);
        assert_eq!(check.version, StoreSchemaVersion::NotRecorded);
        assert!(
            check.warning().is_none(),
            "0 must never become a stale warning"
        );
        let m = check
            .marker(Uuid::new_v4(), Uuid::new_v4(), None)
            .expect("an unrecorded version is stated, not skipped");
        assert_eq!(m.metadata["status"], "SchemaVersionNotRecorded");
        assert_eq!(m.metadata["schema_version_recorded"], false);
        assert!(m.metadata.get("content_incomplete").is_none());
        let msg = m.metadata["message"].as_str().unwrap();
        assert!(!msg.contains("OLDER"), "{msg}");
    }

    /// HUNT-186: a pragma that would not read yielded no marker at all at the
    /// Safari and HealthKit call sites, which the function's own contract
    /// forbids ("the caller must not spend as in range").
    #[test]
    fn a_version_that_will_not_read_is_undetermined_and_says_so() {
        let dir = std::env::temp_dir().join(format!("stale_undet_{}", Uuid::new_v4()));
        std::fs::write(&dir, vec![0x5Au8; 4096]).unwrap();
        let conn = Connection::open(&dir).unwrap();
        let r = SupportedRange::new(5, Some(5));
        let check = check_schema_version(&conn, "safari-browserstate", &r);
        let _ = std::fs::remove_file(&dir);
        assert!(
            matches!(check.version, StoreSchemaVersion::Undetermined(_)),
            "{:?}",
            check.version
        );
        let m = check
            .marker(Uuid::new_v4(), Uuid::new_v4(), None)
            .expect("an unreadable version is never in range");
        assert_eq!(m.metadata["status"], "SchemaVersionUndetermined");
        assert_eq!(m.metadata["content_incomplete"], true);
        assert_eq!(
            m.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert!(m.metadata["content_incomplete_detail"]
            .as_str()
            .unwrap()
            .contains("could not be read"));
    }

    /// HUNT-186: the shared marker carried `content_incomplete: true` and no
    /// reason, no subtype, no status, no detail and no name, so the census
    /// filed it under "no reason was recorded" and the screen showed a flag
    /// with no sentence.
    #[test]
    fn the_out_of_range_marker_carries_the_whole_marker_contract() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("PRAGMA user_version = 44;").unwrap();
        let r = SupportedRange::new(43, Some(43));
        let check = check_schema_version(&conn, "safari-bookmarks", &r);
        assert!(check.warning().is_some());
        let m = check
            .marker(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Some("iOS 15.0 Bookmarks.db"),
            )
            .unwrap();
        assert_eq!(m.subtype(), Some("parser_stale"));
        assert_eq!(m.metadata["subtype"], "parser_stale");
        assert_eq!(m.metadata["status"], "SchemaOutsideValidated");
        assert_eq!(m.metadata["supported_range"], r.describe());
        // §1.4a (decided 2026-09-26): a version outside the validated range is
        // a disclosure, not an incompleteness claim. A missing column or table
        // is what claims; a newer version whose columns all resolve does not.
        assert!(m.metadata.get("content_incomplete").is_none());
        assert!(m.metadata.get("content_incomplete_reason").is_none());
        assert!(m.metadata.get("content_incomplete_detail").is_none());
        assert!(m.metadata.get("inventory_incomplete").is_none());
        assert_eq!(m.metadata["detail"], m.metadata["message"]);
        assert_eq!(m.metadata["validated_against"], "iOS 15.0 Bookmarks.db");
        assert!(m.metadata["message"].as_str().unwrap().contains("NEWER"));
        assert!(m.metadata["name"]
            .as_str()
            .unwrap()
            .contains("safari-bookmarks"));
        // In range: no record at all.
        conn.execute_batch("PRAGMA user_version = 43;").unwrap();
        let check = check_schema_version(&conn, "safari-bookmarks", &r);
        assert_eq!(check.version, StoreSchemaVersion::Found(43));
        assert!(check.marker(Uuid::new_v4(), Uuid::new_v4(), None).is_none());
    }

    #[test]
    fn an_out_of_range_version_is_a_disclosure_not_an_incompleteness_claim() {
        let w = StaleWarning {
            app: "signal".into(),
            seen_version: 99,
            supported: SupportedRange::new(1, Some(50)),
        };
        let case = Uuid::new_v4();
        let parent = Uuid::new_v4();
        let art = w.marker(case, parent);
        assert_eq!(art.metadata["type"], "ParserStaleWarning");
        assert!(art.metadata.get("content_incomplete").is_none());
        assert_eq!(art.metadata["seen_schema_version"], 99);
        assert!(art.metadata.get("content_incomplete_reason").is_none());
        assert_eq!(art.metadata["status"], "SchemaOutsideValidated");
        assert_eq!(art.metadata["supported_range"], "1..=50");
        assert!(art.metadata.get("validated_against").is_none());
        assert_eq!(art.parent_id, Some(parent));
    }

    #[test]
    fn field_map_resolves_renamed_columns() {
        // The schema renamed `timestamp` to `date_sent`; the parser's candidate
        // list absorbs the change with no code path touched.
        let present = cols(&["_id", "date_sent", "body", "address"]);
        let map = FieldMap::resolve(
            &present,
            &[
                ("sent_at", &["timestamp", "ts", "date_sent"][..]),
                ("text", &["body", "message_text"][..]),
                ("peer", &["address", "jid"][..]),
            ],
        );
        assert_eq!(map.column("sent_at"), Some("date_sent"));
        assert_eq!(map.column("text"), Some("body"));
        assert_eq!(map.column("peer"), Some("address"));
        assert!(map.all_resolved());
    }

    #[test]
    fn field_map_reports_a_field_no_candidate_matched() {
        let present = cols(&["_id", "body"]);
        let map = FieldMap::resolve(
            &present,
            &[
                ("text", &["body"][..]),
                ("sent_at", &["timestamp", "date_sent"][..]),
            ],
        );
        assert_eq!(map.column("text"), Some("body"));
        assert_eq!(map.column("sent_at"), None);
        assert!(!map.all_resolved());
        assert_eq!(map.unresolved(), &["sent_at".to_string()]);
    }

    #[test]
    fn candidate_preference_order_is_honoured() {
        // When two candidates are both present, the first listed wins.
        let present = cols(&["timestamp", "date_sent"]);
        let map = FieldMap::resolve(&present, &[("sent_at", &["timestamp", "date_sent"][..])]);
        assert_eq!(map.column("sent_at"), Some("timestamp"));
    }

    #[test]
    fn corpus_check_passes_at_or_above_minimum_and_fails_below() {
        let e = CorpusExpectation {
            label: "whatsapp v2.24".into(),
            min_records: 100,
        };
        assert!(check_corpus(&e, 100).is_ok());
        assert!(check_corpus(&e, 250).is_ok());
        let err = check_corpus(&e, 3).unwrap_err();
        assert!(err.contains("extracted 3"));
        assert!(err.contains("at least 100"));
    }
}
