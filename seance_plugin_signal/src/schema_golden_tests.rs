//! Golden record of every schema marker this crate's schema-support code can
//! emit (ROADMAP §5.11). It pins the marker metadata while the per-crate copy
//! is lifted into `seance_sqlite_util`, so the lift cannot change a byte an
//! examiner reads without this test saying so.

use crate::schema_support::{SchemaBound, SchemaCheck, SchemaSupport, SchemaVersion};
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

fn marker(support: &SchemaSupport, version: SchemaVersion, fm: &FieldMap) -> Value {
    SchemaCheck {
        support,
        version,
        fields: fm,
        required: &["id", "text"],
        record_type: "GoldenIncomplete",
        store: "message",
    }
    .marker(Uuid::nil(), Uuid::nil(), 7)
    .map(|a| json!({ "subtype": a.subtype(), "metadata": a.metadata }))
    .unwrap_or(Value::Null)
}

pub(crate) fn every_schema_marker() -> Value {
    let validated = SchemaSupport {
        app: "golden-app",
        bound: SchemaBound::Validated {
            range: SupportedRange::new(3, Some(3)),
            evidence: "golden.db",
        },
    };
    let unranged = SchemaSupport {
        app: "golden-app",
        bound: SchemaBound::Unranged {
            why: "no store held",
        },
    };
    let all = fields(&["_id", "data", "timestamp", "extra"]);
    let no_optional = fields(&["_id", "data", "timestamp"]);
    let no_required = fields(&["_id", "timestamp"]);
    json!([
        marker(&validated, SchemaVersion::Found(3), &all),
        marker(&validated, SchemaVersion::Found(4), &all),
        marker(&validated, SchemaVersion::Found(2), &all),
        marker(&validated, SchemaVersion::NotRecorded, &all),
        marker(
            &validated,
            SchemaVersion::NotRead {
                locator: "coredata_model",
                why: "not read here",
            },
            &all
        ),
        marker(&validated, SchemaVersion::Undetermined("io".into()), &all),
        marker(&validated, SchemaVersion::Found(3), &no_optional),
        marker(&validated, SchemaVersion::Found(4), &no_required),
        marker(&unranged, SchemaVersion::Found(9), &all),
        marker(&unranged, SchemaVersion::NotRecorded, &no_required),
    ])
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
