//! Golden record of every inline schema marker this crate can emit (ROADMAP
//! §5.11). It pins the marker metadata while the inline copy — repeated in
//! android_sms, call_history, imessage, twitter and fbmessenger — is lifted
//! into `seance_sqlite_util::adopt::inline_marker`, so the lift cannot change
//! a byte an examiner reads without this test saying so. The same JSON is the
//! shared module's golden (`seance_sqlite_util/src/adopt/golden/inline_marker.json`).

use super::*;
use seance_sqlite_util::adopt::inline_marker::{
    stale_marker, version_not_recorded_marker, version_undetermined_marker,
};
use seance_sqlite_util::StaleWarning;
use serde_json::Value;

const FIELDS: &[(&str, &[&str])] = &[("id", &["_id"]), ("body", &["body", "text"])];

fn record(a: Option<Artifact>) -> Value {
    a.map(|a| json!({ "subtype": a.subtype(), "metadata": a.metadata }))
        .unwrap_or(Value::Null)
}

fn store(user_version: i64) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.pragma_update(None, "user_version", user_version)
        .unwrap();
    conn
}

pub(crate) fn every_inline_marker() -> Value {
    let (case, parent) = (Uuid::nil(), Uuid::nil());
    let range = SupportedRange::new(57, Some(67));
    let present =
        |names: &[&str]| -> HashSet<String> { names.iter().map(|s| s.to_string()).collect() };
    let all = FieldMap::resolve(&present(&["_id", "body"]), FIELDS);
    let drifted = FieldMap::resolve(&present(&["_id"]), FIELDS);
    let version = |v: i64| {
        record(user_version_marker(
            &store(v),
            case,
            parent,
            "golden-app",
            &range,
            "golden.db",
        ))
    };
    json!([
        record(field_drift_marker(
            case,
            parent,
            "golden-app",
            "sms",
            &all,
            4
        )),
        record(field_drift_marker(
            case,
            parent,
            "golden-app",
            "sms",
            &drifted,
            4
        )),
        record(Some(stale_marker(
            &StaleWarning {
                app: "golden-app".into(),
                seen_version: 70,
                supported: range.clone()
            },
            case,
            parent,
        ))),
        record(Some(version_undetermined_marker(
            case,
            parent,
            "golden-app",
            &range,
            "io"
        ))),
        record(Some(version_not_recorded_marker(
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
fn inline_schema_markers_are_unchanged_by_the_lift() {
    let actual = every_inline_marker();
    if std::env::var_os("SEANCE_PRINT_GOLDEN").is_some() {
        println!("{}", serde_json::to_string_pretty(&actual).unwrap());
    }
    let expected: Value = serde_json::from_str(include_str!("schema_golden.json")).unwrap();
    assert_eq!(actual, expected);
}
