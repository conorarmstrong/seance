//! Golden record of every schema marker this crate can emit off
//! `_ClientVersion` (ROADMAP §5.11). It pins the metadata while the inline
//! copy is lifted into `seance_sqlite_util::adopt::inline_marker`: iMessage
//! reads its version from Apple's own row rather than `PRAGMA user_version`,
//! so it is the one caller of the shared `version_marker` with a reading of
//! its own.

use super::*;
use serde_json::Value;

fn record(a: Option<Artifact>) -> Value {
    a.map(|a| json!({ "subtype": a.subtype(), "metadata": a.metadata }))
        .unwrap_or(Value::Null)
}

/// A store with `_SqliteDatabaseProperties`, carrying `_ClientVersion` =
/// `value` when one is given.
fn store(value: Option<&str>) -> Connection {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch("CREATE TABLE _SqliteDatabaseProperties (key TEXT, value TEXT);")
        .unwrap();
    if let Some(v) = value {
        conn.execute(
            "INSERT INTO _SqliteDatabaseProperties VALUES ('_ClientVersion', ?1)",
            [v],
        )
        .unwrap();
    }
    conn
}

pub(crate) fn every_client_version_marker() -> Value {
    let (case, parent) = (Uuid::nil(), Uuid::nil());
    let marker = |c: &Connection| record(schema_version_marker(c, case, parent));
    json!([
        marker(&Connection::open_in_memory().unwrap()),
        marker(&store(None)),
        marker(&store(Some("14005"))),
        marker(&store(Some("16000"))),
        marker(&store(Some("8000"))),
        marker(&store(Some("nine"))),
    ])
}

#[test]
fn client_version_markers_are_unchanged_by_the_lift() {
    let actual = every_client_version_marker();
    if std::env::var_os("SEANCE_PRINT_GOLDEN").is_some() {
        println!("{}", serde_json::to_string_pretty(&actual).unwrap());
    }
    let expected: Value = serde_json::from_str(include_str!("schema_golden.json")).unwrap();
    assert_eq!(actual, expected);
}
