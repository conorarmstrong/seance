//! Golden record of every schema note this crate's schema module can emit
//! (ROADMAP §5.11). It pins the note metadata while the per-crate copy is
//! lifted into `seance_sqlite_util`, so the lift cannot change a byte an
//! examiner reads without this test saying so.

use crate::schema::{assess, Observation, SchemaSupport, SchemaVersion, SupportBound};
use seance_sqlite_util::{FieldMap, SupportedRange};
use serde_json::{json, Value};
use std::collections::HashSet;
use uuid::Uuid;

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

fn support(bound: SupportBound) -> SchemaSupport {
    SchemaSupport {
        app: "golden-app",
        store: "golden.db",
        table: "message",
        record_type: "GoldenIncomplete",
        locator: "PRAGMA user_version",
        bound,
    }
}

fn notes(support: &SchemaSupport, version: SchemaVersion, fm: Option<&FieldMap>) -> Value {
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

pub(crate) fn every_schema_note() -> Value {
    let validated = support(SupportBound::Validated {
        range: SupportedRange::new(3, Some(3)),
        evidence: "golden.db",
    });
    let unranged = support(SupportBound::Unranged {
        why: "no store held",
    });
    let all = fields(&["_id", "data", "timestamp", "extra"]);
    let no_optional = fields(&["_id", "data", "timestamp"]);
    let no_required = fields(&["_id", "timestamp"]);
    json!([
        notes(&validated, SchemaVersion::Found(3), Some(&all)),
        notes(&validated, SchemaVersion::Found(4), Some(&all)),
        notes(&validated, SchemaVersion::Found(2), Some(&all)),
        notes(&validated, SchemaVersion::NotRecorded, Some(&all)),
        notes(
            &validated,
            SchemaVersion::Undetermined("io".into()),
            Some(&all)
        ),
        notes(&validated, SchemaVersion::Found(3), Some(&no_optional)),
        notes(&validated, SchemaVersion::Found(4), Some(&no_required)),
        notes(&validated, SchemaVersion::Found(3), None),
        notes(&unranged, SchemaVersion::Found(9), Some(&all)),
        notes(&unranged, SchemaVersion::NotRecorded, Some(&no_required)),
    ])
}

#[test]
fn schema_notes_are_unchanged_by_the_lift() {
    let actual = every_schema_note();
    if std::env::var_os("SEANCE_PRINT_GOLDEN").is_some() {
        println!("{}", serde_json::to_string_pretty(&actual).unwrap());
    }
    let expected: Value = serde_json::from_str(include_str!("schema_golden.json")).unwrap();
    assert_eq!(actual, expected);
}
