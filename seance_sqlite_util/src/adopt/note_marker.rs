//! The schema note a parser files per store under its own `<App>Incomplete`
//! type, at most one about the version and one about the fields (ROADMAP §1.4a,
//! lifted here by §5.11 from five byte-identical copies in the Snapchat, Skype,
//! LINE, WeChat and Instagram crates).
//!
//! Three things: a three-valued read of a store's schema version, the bound a
//! parser may honestly declare for that store, and the record it emits when the
//! store is outside the bound or carries columns the parser does not know.
//!
//! The rule the record follows: a version beyond the validated range is a
//! DISCLOSURE — the version seen and the range are stated, and nothing is
//! claimed incomplete while every field the parser reads still resolves. Only a
//! required logical field that no column carries, or the table itself being
//! absent from a catalogue that read, claims incompleteness: those are the two
//! shapes in which a stale parser produces a silent wrong answer.

use crate::{FieldMap, StaleWarning, SupportedRange};
use rusqlite::Connection;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// What a store said its schema version is. Three answers, because "could not
/// look" and "looked and found nothing recorded" are not the same fact and
/// neither is "in range".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SchemaVersion {
    /// The locator answered a number.
    Found(i64),
    /// `PRAGMA user_version` read 0 — SQLite's default for a store that never
    /// set one — or the app's own version table was not there. A store that
    /// never set a version and one that deliberately set 0 cannot be told
    /// apart by any reader, so 0 is never compared against a range.
    NotRecorded,
    /// The locator could not be asked. Never spent as "in range".
    Undetermined(String),
}

/// The locator name recorded on every schema note this parser emits.
pub const USER_VERSION_LOCATOR: &str = "PRAGMA user_version";

/// `PRAGMA user_version`, three-valued.
pub fn read_user_version(conn: &Connection) -> SchemaVersion {
    match conn.query_row("PRAGMA user_version", [], |r| r.get::<_, i64>(0)) {
        Ok(0) => SchemaVersion::NotRecorded,
        Ok(v) => SchemaVersion::Found(v),
        Err(e) => SchemaVersion::Undetermined(format!("`PRAGMA user_version` would not read: {e}")),
    }
}

/// The bound a parser may declare for one store.
pub enum SupportBound {
    /// Every endpoint was read out of a named real database. `evidence` names
    /// the file(s); a reviewer checks that each is one someone opened.
    Validated {
        range: SupportedRange,
        evidence: &'static str,
    },
    /// No real database of the app is held, so there is no range to compare
    /// against. The version seen is still recorded, and compared to nothing.
    Unranged { why: &'static str },
}

/// One store's declaration.
pub struct SchemaSupport {
    pub app: &'static str,
    pub store: &'static str,
    pub table: &'static str,
    /// The `<App>Incomplete` record type the parser's other markers use —
    /// never the message type, which `seance_db` groups conversations on.
    pub record_type: &'static str,
    pub locator: &'static str,
    pub bound: SupportBound,
}

pub use super::WARNING_CLASS;

/// Subtype of a note that discloses and claims nothing incomplete — the shared
/// [`super::SCHEMA_SUBTYPE`] (`schema_support` until 2026-09-26).
pub const DISCLOSURE_SUBTYPE: &str = super::SCHEMA_SUBTYPE;

/// Subtype of a note that does claim incompleteness — also the shared
/// [`super::SCHEMA_SUBTYPE`] (`parse_incomplete` until 2026-09-26). The claim
/// is the note's `content_incomplete` flag, not its subtype.
pub const INCOMPLETE_SUBTYPE: &str = super::SCHEMA_SUBTYPE;

/// What the parser observed of one store.
pub struct Observation<'a> {
    pub version: SchemaVersion,
    /// `None` when the table itself was absent from a catalogue that read.
    pub fields: Option<&'a FieldMap>,
    /// Logical fields whose absence makes the emitted records incomplete.
    pub required: &'a [&'a str],
    /// Records the parse produced before this assessment.
    pub recovered: usize,
}

/// The notes an observation entitles the parser to file: at most one about
/// the version and one about the fields, or a single one when the table was
/// absent. An in-range store whose every field resolved yields nothing — a
/// note present on every store would tell an examiner nothing.
pub fn assess(
    support: &SchemaSupport,
    obs: &Observation,
    case_id: Uuid,
    parent_id: Uuid,
) -> Vec<Artifact> {
    let mut out = Vec::new();
    let Some(fields) = obs.fields else {
        let detail = format!(
            "{}: the `{}` table this parser reads is not in `{}`, although the catalogue read; \
             either the app's schema has moved past this parser or this is not its message \
             store, and its content was not examined",
            support.app, support.table, support.store
        );
        out.push(note(
            support,
            obs,
            "SchemaTableAbsent",
            detail,
            None,
            true,
            case_id,
            parent_id,
        ));
        return out;
    };

    match (&support.bound, &obs.version) {
        (SupportBound::Validated { range, .. }, SchemaVersion::Found(v)) => {
            if !range.contains(*v) {
                let warning = StaleWarning {
                    app: support.app.to_string(),
                    seen_version: *v,
                    supported: range.clone(),
                };
                // Newer or older is stated in the detail; the status is the
                // one name every schema record uses (ROADMAP §5.11).
                let status = "SchemaOutsideValidated";
                out.push(note(
                    support,
                    obs,
                    status,
                    warning.message(),
                    None,
                    false,
                    case_id,
                    parent_id,
                ));
            }
        }
        (SupportBound::Validated { range, .. }, SchemaVersion::NotRecorded) => {
            let detail = format!(
                "{}: no schema version is recorded where this parser looks ({}), so the store \
                 was not compared against the validated range {}",
                support.app,
                support.locator,
                range.describe()
            );
            out.push(note(
                support,
                obs,
                "SchemaVersionNotRecorded",
                detail,
                None,
                false,
                case_id,
                parent_id,
            ));
        }
        (_, SchemaVersion::Undetermined(why)) => {
            let detail = format!(
                "{}: the schema version could not be read ({why}), so the store was compared \
                 against nothing; this is not a statement that it is in range",
                support.app
            );
            out.push(note(
                support,
                obs,
                "SchemaVersionUndetermined",
                detail,
                None,
                false,
                case_id,
                parent_id,
            ));
        }
        (SupportBound::Unranged { why }, version) => {
            let seen = match version {
                SchemaVersion::Found(v) => format!("schema version seen: {v}"),
                _ => format!("no schema version is recorded at {}", support.locator),
            };
            let detail = format!(
                "{}: this parser declares no validated schema range — {why}; {seen}, compared \
                 against nothing",
                support.app
            );
            out.push(note(
                support,
                obs,
                "SchemaNotRanged",
                detail,
                None,
                false,
                case_id,
                parent_id,
            ));
        }
    }

    let unresolved = fields.unresolved();
    if !unresolved.is_empty() {
        let missing_required: Vec<&str> = unresolved
            .iter()
            .map(String::as_str)
            .filter(|f| obs.required.contains(f))
            .collect();
        if missing_required.is_empty() {
            let detail = format!(
                "{}: no column in `{}` carries the field(s) {}; the records emitted omit them \
                 rather than guess, and the parser may predate this schema",
                support.app,
                support.table,
                unresolved.join(", ")
            );
            out.push(note(
                support,
                obs,
                "SchemaOptionalFieldsUnresolved",
                detail,
                Some(unresolved),
                false,
                case_id,
                parent_id,
            ));
        } else {
            let detail = format!(
                "{}: no column in `{}` carries the required field(s) {}; the records emitted \
                 lack them, and the parser is running on a schema it was not validated against",
                support.app,
                support.table,
                missing_required.join(", ")
            );
            out.push(note(
                support,
                obs,
                "SchemaFieldsUnresolved",
                detail,
                Some(unresolved),
                true,
                case_id,
                parent_id,
            ));
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn note(
    support: &SchemaSupport,
    obs: &Observation,
    status: &str,
    detail: String,
    unresolved: Option<&[String]>,
    incomplete: bool,
    case_id: Uuid,
    parent_id: Uuid,
) -> Artifact {
    let subtype = super::SCHEMA_SUBTYPE;
    let mut meta = Map::new();
    meta.insert("type".into(), json!(support.record_type));
    meta.insert("subtype".into(), json!(subtype));
    meta.insert("warning_class".into(), json!(WARNING_CLASS));
    meta.insert("status".into(), json!(status));
    meta.insert("app".into(), json!(support.app));
    meta.insert("store".into(), json!(support.store));
    meta.insert("table".into(), json!(support.table));
    meta.insert("schema_version_locator".into(), json!(support.locator));
    match &obs.version {
        SchemaVersion::Found(v) => {
            meta.insert("schema_version_seen".into(), json!(v));
        }
        SchemaVersion::NotRecorded => {
            meta.insert("schema_version_not_recorded".into(), json!(true));
        }
        SchemaVersion::Undetermined(why) => {
            meta.insert("schema_version_undetermined".into(), json!(why));
        }
    }
    match &support.bound {
        SupportBound::Validated { range, evidence } => {
            meta.insert("schema_version_supported".into(), json!(range.describe()));
            meta.insert("schema_version_evidence".into(), json!(evidence));
        }
        SupportBound::Unranged { why } => {
            meta.insert("schema_unranged_reason".into(), json!(why));
        }
    }
    if let Some(fields) = unresolved {
        meta.insert("schema_unresolved_fields".into(), json!(fields));
    }
    meta.insert("records_recovered".into(), json!(obs.recovered));
    meta.insert("detail".into(), json!(detail));
    meta.insert(
        "name".into(),
        json!(format!("{}: {status} — {detail}", support.record_type)),
    );
    if incomplete {
        let reason = IncompleteReason::Unvalidated.as_str();
        meta.insert("content_incomplete".into(), json!(true));
        meta.insert("content_incomplete_reason".into(), json!(reason));
        meta.insert("content_incomplete_detail".into(), json!(detail));
        meta.insert("inventory_incomplete".into(), json!(true));
        meta.insert("inventory_incomplete_reason".into(), json!(reason));
        meta.insert("inventory_incomplete_detail".into(), json!(detail));
    }
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent_id)
    .with_subtype(subtype)
}
