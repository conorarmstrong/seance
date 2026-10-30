//! Golden records of every marker and version-locator answer the two shapes
//! produce. The JSON under `golden/` was captured from the per-crate copies
//! before they were lifted here (WhatsApp for [`super::app_marker`], browser
//! history and installed apps for [`super::stale_marker`]), so the lift cannot
//! change a byte an examiner reads without this test saying so. The adopting
//! crates keep their own golden tests over their re-exports.

use super::app_marker::{SchemaBound, SchemaCheck, SchemaSupport as AppSupport};
use super::note_marker::{assess, Observation, SchemaSupport as NoteSupport, SupportBound};
use super::stale_marker::{
    assess_version, keyed_version, plan_columns, single_row_version, unresolved_fields_marker,
    user_version, SchemaSupport, SchemaVersion,
};
use crate::{FieldMap, SupportedRange};
use rusqlite::Connection;
use seance_core::artifact::Artifact;
use serde_json::{json, Value};
use std::collections::HashSet;
use uuid::Uuid;

type AppVersion = super::app_marker::SchemaVersion;
type NoteVersion = super::note_marker::SchemaVersion;

const FIELDS: &[(&str, &[&str])] = &[
    ("id", &["_id"]),
    ("text", &["data", "text_data"]),
    ("when", &["timestamp"]),
    ("extra", &["extra"]),
];

fn fields(present: &[&str]) -> FieldMap {
    let present: HashSet<String> = present.iter().map(|s| s.to_string()).collect();
    FieldMap::resolve(&present, FIELDS)
}

fn shown(a: Option<Artifact>) -> Value {
    a.map(|a| json!({ "subtype": a.subtype(), "metadata": a.metadata }))
        .unwrap_or(Value::Null)
}

fn app(support: &AppSupport, version: AppVersion, fm: &FieldMap) -> Value {
    shown(
        SchemaCheck {
            support,
            version,
            fields: fm,
            required: &["id", "text"],
            record_type: "GoldenIncomplete",
            store: "message",
        }
        .marker(Uuid::nil(), Uuid::nil(), 7),
    )
}

fn every_app_marker() -> Value {
    let validated = AppSupport {
        app: "golden-app",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(3, Some(3)),
            evidence: "golden.db",
        },
    };
    let unranged = AppSupport {
        app: "golden-app",
        bound: SchemaBound::Unranged {
            why: "no store held",
        },
    };
    let all = fields(&["_id", "data", "timestamp", "extra"]);
    let no_optional = fields(&["_id", "data", "timestamp"]);
    let no_required = fields(&["_id", "timestamp"]);
    let not_read = AppVersion::NotRead {
        locator: "coredata_model",
        why: "not read here",
    };
    json!([
        app(&validated, AppVersion::Found(3), &all),
        app(&validated, AppVersion::Found(4), &all),
        app(&validated, AppVersion::Found(2), &all),
        app(&validated, AppVersion::NotRecorded, &all),
        app(&validated, not_read, &all),
        app(&validated, AppVersion::Undetermined("io".into()), &all),
        app(&validated, AppVersion::Found(3), &no_optional),
        app(&validated, AppVersion::Found(4), &no_required),
        app(&unranged, AppVersion::Found(9), &all),
        app(&unranged, AppVersion::NotRecorded, &no_required),
    ])
}

fn keyed_locators() -> Value {
    let conn = Connection::open_in_memory().unwrap();
    let keyed = |conn: &Connection| {
        format!(
            "{:?}",
            keyed_version(conn, "meta", "key", "value", "version")
        )
    };
    let mut out = vec![format!("{:?}", user_version(&conn)), keyed(&conn)];
    conn.execute_batch(
        "PRAGMA user_version = 5;
         CREATE TABLE meta (key TEXT PRIMARY KEY, value);
         INSERT INTO meta VALUES ('other', '1');",
    )
    .unwrap();
    out.push(format!("{:?}", user_version(&conn)));
    out.push(keyed(&conn));
    for value in ["'41'", "42", "'x'", "X'00'"] {
        conn.execute_batch(&format!(
            "INSERT OR REPLACE INTO meta VALUES ('version', {value});"
        ))
        .unwrap();
        out.push(keyed(&conn));
    }
    json!(out)
}

fn single_row_locators() -> Value {
    let conn = Connection::open_in_memory().unwrap();
    let read = |conn: &Connection| format!("{:?}", single_row_version(conn, "schema", "version"));
    let mut out = vec![read(&conn)];
    conn.execute_batch("CREATE TABLE schema (version);")
        .unwrap();
    out.push(read(&conn));
    for value in ["7", "'x'"] {
        conn.execute_batch(&format!(
            "DELETE FROM schema; INSERT INTO schema VALUES ({value});"
        ))
        .unwrap();
        out.push(read(&conn));
    }
    json!(out)
}

fn every_stale_marker() -> Value {
    let support = SchemaSupport {
        app: "golden-app",
        store: "golden.db",
        record_type: "GoldenRecord",
        range: SupportedRange::new(3, Some(3)),
        evidence: "golden.db (a test)",
    };
    let (c, p) = (Uuid::nil(), Uuid::nil());
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
    let not_recorded = SchemaVersion::NotRecorded("nowhere".into());
    json!({
        "locators": keyed_locators(),
        "markers": [
            shown(assess_version(&support, &SchemaVersion::Found(3), c, p)),
            shown(assess_version(&support, &SchemaVersion::Found(4), c, p)),
            shown(assess_version(&support, &SchemaVersion::Found(2), c, p)),
            shown(assess_version(&support, &not_recorded, c, p)),
            shown(assess_version(&support, &SchemaVersion::Undetermined("io".into()), c, p)),
            shown(Some(unresolved_fields_marker(&support, "t", &plan, 2, c, p))),
        ],
    })
}

fn golden(json: &str) -> Value {
    serde_json::from_str(json).unwrap()
}

#[test]
fn the_app_marker_matches_the_record_the_whatsapp_copy_emitted() {
    assert_eq!(
        every_app_marker(),
        golden(include_str!("golden/app_marker.json"))
    );
}

#[test]
fn the_stale_marker_matches_the_record_the_browser_history_copy_emitted() {
    assert_eq!(
        every_stale_marker(),
        golden(include_str!("golden/stale_marker.json"))
    );
}

#[test]
fn the_single_row_locator_matches_the_installed_apps_copy() {
    assert_eq!(
        single_row_locators(),
        golden(include_str!("golden/single_row_locators.json"))
    );
}

/// ROADMAP §5.11, owner decision (b) of 2026-09-26: every schema record speaks
/// one vocabulary — the same `status` names, subtype `parser_stale` and
/// `warning_class: "ParserStaleWarning"` — while the app-marker shape keeps
/// filing under the parser's own `<App>Incomplete` type.
#[test]
fn every_shape_names_the_same_finding_the_same_way() {
    let range = SupportedRange::new(3, Some(3));
    let app_support = AppSupport {
        app: "a",
        bound: SchemaBound::Validated {
            range: range.clone(),
            evidence: "a.db",
        },
    };
    let stale_support = SchemaSupport {
        app: "a",
        store: "a.db",
        record_type: "ARecord",
        range: range.clone(),
        evidence: "a.db",
    };
    let all = fields(&["_id", "data", "timestamp", "extra"]);
    let (c, p) = (Uuid::nil(), Uuid::nil());
    let app_of = |v: AppVersion| {
        SchemaCheck {
            support: &app_support,
            version: v,
            fields: &all,
            required: &["id", "text"],
            record_type: "AIncomplete",
            store: "message",
        }
        .marker(c, p, 0)
        .unwrap()
    };
    let shared = |v: i64| {
        crate::StaleWarning {
            app: "a".into(),
            seen_version: v,
            supported: range.clone(),
        }
        .marker(c, p)
    };
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("PRAGMA user_version = 9").unwrap();
    let checked = crate::check_schema_version(&conn, "a", &range)
        .marker(c, p, None)
        .unwrap();

    let pairs = [
        (app_of(AppVersion::Found(4)), "SchemaOutsideValidated"),
        (app_of(AppVersion::Found(2)), "SchemaOutsideValidated"),
        (
            assess_version(&stale_support, &SchemaVersion::Found(4), c, p).unwrap(),
            "SchemaOutsideValidated",
        ),
        (shared(2), "SchemaOutsideValidated"),
        (checked, "SchemaOutsideValidated"),
        (
            app_of(AppVersion::Undetermined("io".into())),
            "SchemaVersionUndetermined",
        ),
        (
            assess_version(
                &stale_support,
                &SchemaVersion::Undetermined("io".into()),
                c,
                p,
            )
            .unwrap(),
            "SchemaVersionUndetermined",
        ),
        (app_of(AppVersion::NotRecorded), "SchemaVersionNotRecorded"),
        (
            assess_version(
                &stale_support,
                &SchemaVersion::NotRecorded("x".into()),
                c,
                p,
            )
            .unwrap(),
            "SchemaVersionNotRecorded",
        ),
    ];
    let note_of = |bound: SupportBound, v: NoteVersion, fm: Option<&FieldMap>| {
        let obs = Observation {
            version: v,
            fields: fm,
            required: &["id", "text"],
            recovered: 0,
        };
        let support = note_support(bound);
        let mut notes = assess(&support, &obs, c, p);
        assert_eq!(notes.len(), 1, "{notes:?}");
        notes.remove(0)
    };
    let validated = || SupportBound::Validated {
        range: range.clone(),
        evidence: "a.db",
    };
    let unranged = || SupportBound::Unranged { why: "none held" };
    let no_required = fields(&["_id", "timestamp", "extra"]);
    let app_unranged = AppSupport {
        app: "a",
        bound: SchemaBound::Unranged { why: "none held" },
    };
    let app_unranged_marker = SchemaCheck {
        support: &app_unranged,
        version: AppVersion::Found(9),
        fields: &all,
        required: &["id", "text"],
        record_type: "AIncomplete",
        store: "message",
    }
    .marker(c, p, 0)
    .unwrap();
    let pairs = pairs.into_iter().chain([
        (
            note_of(validated(), NoteVersion::Found(4), Some(&all)),
            "SchemaOutsideValidated",
        ),
        (
            note_of(validated(), NoteVersion::Found(2), Some(&all)),
            "SchemaOutsideValidated",
        ),
        (
            note_of(
                validated(),
                NoteVersion::Undetermined("io".into()),
                Some(&all),
            ),
            "SchemaVersionUndetermined",
        ),
        (
            note_of(validated(), NoteVersion::NotRecorded, Some(&all)),
            "SchemaVersionNotRecorded",
        ),
        (
            note_of(validated(), NoteVersion::Found(3), None),
            "SchemaTableAbsent",
        ),
        (
            note_of(validated(), NoteVersion::Found(3), Some(&no_required)),
            "SchemaFieldsUnresolved",
        ),
        (
            note_of(unranged(), NoteVersion::Found(9), Some(&all)),
            "SchemaNotRanged",
        ),
        (app_unranged_marker, "SchemaNotRanged"),
    ]);
    for (m, status) in pairs {
        assert_eq!(m.metadata["status"], status, "{}", m.metadata);
        assert_eq!(m.subtype(), Some("parser_stale"), "{}", m.metadata);
        assert_eq!(m.metadata["subtype"], "parser_stale", "{}", m.metadata);
        assert_eq!(
            m.metadata["warning_class"], "ParserStaleWarning",
            "{}",
            m.metadata
        );
    }
    // The app shape still files under the parser's own type.
    assert_eq!(app_of(AppVersion::Found(4)).metadata["type"], "AIncomplete");
}

fn note_support(bound: SupportBound) -> NoteSupport {
    NoteSupport {
        app: "golden-app",
        store: "golden.db",
        table: "message",
        record_type: "GoldenIncomplete",
        locator: "PRAGMA user_version",
        bound,
    }
}

fn notes(support: &NoteSupport, version: NoteVersion, fm: Option<&FieldMap>) -> Value {
    let obs = Observation {
        version,
        fields: fm,
        required: &["id", "text"],
        recovered: 7,
    };
    Value::Array(
        assess(support, &obs, Uuid::nil(), Uuid::nil())
            .into_iter()
            .map(|a| json!({ "subtype": a.subtype(), "metadata": a.metadata }))
            .collect(),
    )
}

fn every_note() -> Value {
    let validated = note_support(SupportBound::Validated {
        range: SupportedRange::new(3, Some(3)),
        evidence: "golden.db",
    });
    let unranged = note_support(SupportBound::Unranged {
        why: "no store held",
    });
    let all = fields(&["_id", "data", "timestamp", "extra"]);
    let no_optional = fields(&["_id", "data", "timestamp"]);
    let no_required = fields(&["_id", "timestamp"]);
    json!([
        notes(&validated, NoteVersion::Found(3), Some(&all)),
        notes(&validated, NoteVersion::Found(4), Some(&all)),
        notes(&validated, NoteVersion::Found(2), Some(&all)),
        notes(&validated, NoteVersion::NotRecorded, Some(&all)),
        notes(
            &validated,
            NoteVersion::Undetermined("io".into()),
            Some(&all)
        ),
        notes(&validated, NoteVersion::Found(3), Some(&no_optional)),
        notes(&validated, NoteVersion::Found(4), Some(&no_required)),
        notes(&validated, NoteVersion::Found(3), None),
        notes(&unranged, NoteVersion::Found(9), Some(&all)),
        notes(&unranged, NoteVersion::NotRecorded, Some(&no_required)),
    ])
}

#[test]
fn the_note_marker_matches_the_record_the_line_copy_emitted() {
    assert_eq!(
        every_note(),
        golden(include_str!("golden/note_marker.json"))
    );
}

/// The inline shape (android_sms, call_history, imessage, twitter,
/// fbmessenger), driven through the same inputs as the android_sms copy's own
/// golden (`seance_plugin_android_sms/src/schema_golden_tests.rs`), whose JSON
/// this is.
fn every_inline_marker() -> Value {
    use super::inline_marker::{
        field_drift_marker, stale_marker, user_version_marker, version_not_recorded_marker,
        version_undetermined_marker,
    };
    use crate::StaleWarning;
    const INLINE_FIELDS: &[(&str, &[&str])] = &[("id", &["_id"]), ("body", &["body", "text"])];
    let (case, parent) = (Uuid::nil(), Uuid::nil());
    let range = SupportedRange::new(57, Some(67));
    let present =
        |names: &[&str]| -> HashSet<String> { names.iter().map(|s| s.to_string()).collect() };
    let all = FieldMap::resolve(&present(&["_id", "body"]), INLINE_FIELDS);
    let drifted = FieldMap::resolve(&present(&["_id"]), INLINE_FIELDS);
    let version = |v: i64| {
        let conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "user_version", v).unwrap();
        shown(user_version_marker(
            &conn,
            case,
            parent,
            "golden-app",
            &range,
            "golden.db",
        ))
    };
    json!([
        shown(field_drift_marker(
            case,
            parent,
            "golden-app",
            "sms",
            &all,
            4
        )),
        shown(field_drift_marker(
            case,
            parent,
            "golden-app",
            "sms",
            &drifted,
            4
        )),
        shown(Some(stale_marker(
            &StaleWarning {
                app: "golden-app".into(),
                seen_version: 70,
                supported: range.clone(),
            },
            case,
            parent,
        ))),
        shown(Some(version_undetermined_marker(
            case,
            parent,
            "golden-app",
            &range,
            "io"
        ))),
        shown(Some(version_not_recorded_marker(
            case,
            parent,
            "golden-app",
            &range,
            "nowhere"
        ))),
        version(0),
        version(60),
        version(70),
        version(40),
    ])
}

#[test]
fn the_inline_marker_matches_the_record_the_android_sms_copy_emitted() {
    assert_eq!(
        every_inline_marker(),
        golden(include_str!("golden/inline_marker.json"))
    );
}
