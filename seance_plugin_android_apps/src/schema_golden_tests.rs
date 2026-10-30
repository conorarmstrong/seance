//! Golden record of every schema marker, and every version-locator answer,
//! this crate's schema-support code can produce (ROADMAP §5.11). It pins them
//! while the per-crate copy is lifted into `seance_sqlite_util`, so the lift
//! cannot change a byte an examiner reads without this test saying so.

use crate::schema_support::{
    assess_version, plan_columns, unresolved_fields_marker, user_version, SchemaSupport,
    SchemaVersion,
};
use rusqlite::Connection;
use seance_core::artifact::Artifact;
use seance_sqlite_util::SupportedRange;
use serde_json::{json, Value};
use uuid::Uuid;

fn shown(a: Option<Artifact>) -> Value {
    a.map(|a| json!({ "subtype": a.subtype(), "metadata": a.metadata }))
        .unwrap_or(Value::Null)
}

fn locators() -> Value {
    let conn = Connection::open_in_memory().unwrap();
    let mut out = vec![format!("{:?}", user_version(&conn))];
    conn.execute_batch("PRAGMA user_version = 5;").unwrap();
    out.push(format!("{:?}", user_version(&conn)));
    json!(out)
}

pub(crate) fn every_schema_marker() -> Value {
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
    json!({
        "locators": locators(),
        "markers": [
            shown(assess_version(&support, &SchemaVersion::Found(3), c, p)),
            shown(assess_version(&support, &SchemaVersion::Found(4), c, p)),
            shown(assess_version(&support, &SchemaVersion::Found(2), c, p)),
            shown(assess_version(&support, &SchemaVersion::NotRecorded("nowhere".into()), c, p)),
            shown(assess_version(&support, &SchemaVersion::Undetermined("io".into()), c, p)),
            shown(Some(unresolved_fields_marker(&support, "t", &plan, 2, c, p))),
        ],
    })
}

#[test]
fn schema_markers_are_unchanged_by_the_lift() {
    let actual = every_schema_marker();
    if std::env::var_os("SEANCE_PRINT_GOLDEN").is_some() {
        println!("{}", serde_json::to_string_pretty(&actual).unwrap());
    }
    let expected: Value = serde_json::from_str(include_str!("schema_golden.json")).unwrap();
    assert_eq!(actual, expected);
}
