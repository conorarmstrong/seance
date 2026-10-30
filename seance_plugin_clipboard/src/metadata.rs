//! Reading the clipboard store's own inventory, without assuming its schema.
//!
//! # Why this is written tolerantly rather than to a schema
//!
//! Every other structured parser in this workspace verifies a schema before it
//! parses — SRUM's tables, `ActivitiesCache.db`'s columns, UAL's shape. That is
//! the right approach when the schema is documented or can be read off a real
//! artifact.
//!
//! `metadata.json` is neither. Published research establishes **that** it holds
//! an entry per item and a timestamp for each, and that a `source` field
//! distinguishes a locally-copied item from a synced one. No source available
//! to this project sets out its field names, and this project holds no Windows
//! 11 image to read them from.
//!
//! Writing a fixed schema against unverified field names would produce a parser
//! that silently yields nothing on the real artifact — the worst outcome, since
//! an empty result reads as "this user pinned nothing". So the document is
//! **walked** instead: entries are found by shape, and every field is reported
//! with the name it carried. What was not understood is preserved verbatim.
//!
//! The whole document is retained on the record for the same reason. An
//! examiner who meets a field this parser did not interpret can read it, and a
//! later version can interpret it without re-examining the evidence.

use serde_json::{Map, Value};

/// Ceiling on the inventory document. It lists at most a few dozen items.
pub const MAX_METADATA_BYTES: u64 = 8 * 1024 * 1024;

/// Ceiling on entries taken from one document.
const MAX_ITEMS: usize = 4_096;

/// One item as the inventory describes it.
#[derive(Debug, Clone, PartialEq)]
pub struct Item {
    /// The item's identifier, matching its folder name on disk when both exist.
    pub id: Option<String>,
    /// A timestamp, and how it was read.
    pub timestamp: Option<Timestamp>,
    /// Whether the item came from this machine or arrived by clipboard sync.
    pub source: Option<String>,
    /// The entry as it was written, so nothing this parser did not understand
    /// is lost between the evidence and the report.
    pub raw: Value,
}

/// A timestamp, with the interpretation that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Timestamp {
    /// RFC 3339, UTC.
    pub utc: String,
    /// The field it came from.
    pub field: String,
    /// How the stored value was read — the reading is a claim, and a report
    /// that cannot say which one it made cannot be checked.
    pub interpretation: &'static str,
}

/// What one inventory document yielded.
#[derive(Debug, Clone, PartialEq)]
pub struct Inventory {
    pub items: Vec<Item>,
    /// True when [`MAX_ITEMS`] stopped the walk. A cap that fires must be
    /// stated: a truncated list read as a complete one understates what the
    /// evidence held.
    pub truncated: bool,
    /// The document as written.
    pub raw: Value,
}

/// Field names that have carried an item's identity. Tried in order; the first
/// present wins.
const ID_FIELDS: &[&str] = &["itemId", "id", "ItemId", "Id", "guid", "Guid", "identifier"];

/// Field names that have carried a timestamp.
const TIME_FIELDS: &[&str] = &[
    "timestamp",
    "Timestamp",
    "time",
    "Time",
    "pinnedTime",
    "PinnedTime",
    "lastModified",
    "LastModifiedTime",
    "createdTime",
    "CreatedTime",
    "dateTime",
];

/// Field names that have carried the local/synced distinction.
const SOURCE_FIELDS: &[&str] = &["source", "Source", "origin", "Origin", "deviceId"];

/// Parse an inventory document.
///
/// Returns `None` only when the bytes are not JSON at all. An empty document
/// yields an empty inventory, which is a finding — the user pinned nothing —
/// and is reported as one rather than as a failure.
pub fn parse(bytes: &[u8]) -> Option<Inventory> {
    let raw: Value = serde_json::from_slice(bytes).ok()?;
    let mut items = Vec::new();
    let mut truncated = false;
    collect(&raw, &mut items, &mut truncated, 0);
    Some(Inventory {
        items,
        truncated,
        raw,
    })
}

/// Depth ceiling for the walk. JSON nests arbitrarily and this input is not
/// trusted; the document's real shape is two or three deep.
const MAX_DEPTH: usize = 32;

/// Walk the document collecting anything item-shaped.
///
/// Recurses because the entries have been observed both as a bare array and
/// under a named key, and no source settles which. Walking finds them either
/// way; keying on a name would find them in one layout and silently not in the
/// other.
fn collect(value: &Value, out: &mut Vec<Item>, truncated: &mut bool, depth: usize) {
    if depth > MAX_DEPTH || out.len() >= MAX_ITEMS {
        if out.len() >= MAX_ITEMS {
            *truncated = true;
        }
        return;
    }
    match value {
        Value::Array(entries) => {
            for entry in entries {
                collect(entry, out, truncated, depth + 1);
            }
        }
        Value::Object(map) => {
            if let Some(item) = as_item(map) {
                out.push(item);
                return;
            }
            for nested in map.values() {
                collect(nested, out, truncated, depth + 1);
            }
        }
        _ => {}
    }
}

/// An object is an item when it carries an identity or a timestamp.
///
/// Requiring both would drop an entry whose timestamp this parser could not
/// read, which is exactly the entry worth keeping: it still evidences that
/// something was pinned.
fn as_item(map: &Map<String, Value>) -> Option<Item> {
    let id = first_string(map, ID_FIELDS);
    let timestamp = first_timestamp(map);
    if id.is_none() && timestamp.is_none() {
        return None;
    }
    Some(Item {
        id,
        timestamp,
        source: first_string(map, SOURCE_FIELDS),
        raw: Value::Object(map.clone()),
    })
}

fn first_string(map: &Map<String, Value>, names: &[&str]) -> Option<String> {
    for name in names {
        if let Some(text) = map.get(*name).and_then(|v| v.as_str()) {
            if !text.is_empty() {
                return Some(text.to_string());
            }
        }
    }
    None
}

fn first_timestamp(map: &Map<String, Value>) -> Option<Timestamp> {
    for name in TIME_FIELDS {
        let Some(value) = map.get(*name) else {
            continue;
        };
        if let Some(stamp) = interpret(value, name) {
            return Some(stamp);
        }
    }
    None
}

/// Windows FILETIME epoch (1601-01-01) as seconds before the Unix epoch.
const FILETIME_EPOCH_DELTA: i64 = 11_644_473_600;

/// Below this, a number is more plausibly seconds than milliseconds: it is
/// 2001-09-09 read as seconds, and 1970-01-12 read as milliseconds.
const SECONDS_CEILING: i64 = 1_000_000_000_000;

/// Read a stored value as a time.
///
/// Windows writes times three ways and this document's convention is not
/// documented, so each is tried and the answer records which was used. A value
/// that is not plausibly a time yields `None` rather than an epoch date — the
/// same fail-closed rule the Timeline parser uses, and for the same reason: a
/// record dated 1601 or 1970 is a claim about the evidence that nothing
/// supports.
fn interpret(value: &Value, field: &str) -> Option<Timestamp> {
    let field = field.to_string();

    if let Some(text) = value.as_str() {
        let parsed = chrono::DateTime::parse_from_rfc3339(text).ok()?;
        // The same plausible range as a number (HUNT-198): a string dated
        // before clipboard history existed is no more a finding than a number
        // that decodes there.
        if !in_plausible_range(parsed.timestamp()) {
            return None;
        }
        return Some(Timestamp {
            utc: parsed.to_utc().to_rfc3339(),
            field,
            interpretation: "rfc3339",
        });
    }

    let number = value.as_i64()?;
    if number <= 0 {
        return None;
    }

    // FILETIME: 100-nanosecond ticks since 1601. Recognised by magnitude, which
    // is unambiguous — the smallest plausible FILETIME is orders larger than
    // the largest plausible millisecond epoch.
    if number > 100_000_000_000_000_000 {
        let seconds = number / 10_000_000 - FILETIME_EPOCH_DELTA;
        return build(seconds, field, "windows_filetime");
    }
    if number > SECONDS_CEILING {
        return build(number / 1000, field, "unix_milliseconds");
    }
    build(number, field, "unix_seconds")
}

/// Whether `seconds` (Unix) falls in 2018-01-01 ..= 2100-01-01, the range in
/// which this artifact can exist. Applied to every reading — numeric or
/// RFC 3339 string — so no interpretation escapes it.
fn in_plausible_range(seconds: i64) -> bool {
    /// 2018-01-01, comfortably before the feature shipped.
    const EARLIEST: i64 = 1_514_764_800;
    /// 2100-01-01.
    const LATEST: i64 = 4_102_444_800;
    (EARLIEST..=LATEST).contains(&seconds)
}

/// Reject a time outside the range in which this artifact can exist.
///
/// Clipboard history shipped with Windows 10 1809, in October 2018. A pinned
/// item dated before that, or in the future, is a misread value rather than a
/// finding, and emitting it would put a date in a report that the artifact
/// could not have produced.
fn build(seconds: i64, field: String, interpretation: &'static str) -> Option<Timestamp> {
    if !in_plausible_range(seconds) {
        return None;
    }
    let when = chrono::DateTime::from_timestamp(seconds, 0)?;
    Some(Timestamp {
        utc: when.to_rfc3339(),
        field,
        interpretation,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_bare_array_of_entries_is_read() {
        let doc = json!([
            {"itemId": "{aaaa}", "timestamp": "2026-03-04T05:06:07Z", "source": "Local"},
            {"itemId": "{bbbb}", "timestamp": "2026-03-05T05:06:07Z"}
        ]);
        let inv = parse(doc.to_string().as_bytes()).expect("parses");
        assert_eq!(inv.items.len(), 2);
        assert_eq!(inv.items[0].id.as_deref(), Some("{aaaa}"));
        assert_eq!(inv.items[0].source.as_deref(), Some("Local"));
        assert_eq!(
            inv.items[0].timestamp.as_ref().unwrap().interpretation,
            "rfc3339"
        );
        assert!(!inv.truncated);
    }

    /// **The reason this parser walks rather than keys on a name.** The same
    /// entries under a container key must produce the same result.
    #[test]
    fn entries_under_a_container_key_are_found_too() {
        let doc = json!({
            "version": 1,
            "items": [{"itemId": "{aaaa}", "timestamp": "2026-03-04T05:06:07Z"}]
        });
        let inv = parse(doc.to_string().as_bytes()).expect("parses");
        assert_eq!(inv.items.len(), 1);
        assert_eq!(inv.items[0].id.as_deref(), Some("{aaaa}"));
    }

    /// Field names are not documented anywhere this project could verify, so
    /// several spellings are accepted. If the real artifact uses another, the
    /// entry is still recovered through its timestamp, and `raw` carries the
    /// rest.
    #[test]
    fn alternative_field_spellings_are_accepted() {
        for id_field in ["itemId", "id", "Id", "guid"] {
            let doc = json!([{ id_field: "{aaaa}" }]);
            let inv = parse(doc.to_string().as_bytes()).expect("parses");
            assert_eq!(inv.items.len(), 1, "id field {id_field}");
            assert_eq!(inv.items[0].id.as_deref(), Some("{aaaa}"));
        }
        for time_field in ["timestamp", "pinnedTime", "LastModifiedTime"] {
            let doc = json!([{ time_field: "2026-03-04T05:06:07Z" }]);
            let inv = parse(doc.to_string().as_bytes()).expect("parses");
            assert_eq!(inv.items.len(), 1, "time field {time_field}");
            assert_eq!(inv.items[0].timestamp.as_ref().unwrap().field, time_field);
        }
    }

    #[test]
    fn the_three_windows_time_encodings_are_each_read_and_named() {
        // 2026-03-04T05:06:07Z in each encoding.
        let seconds = 1_772_600_767i64;
        let cases = [
            (json!(seconds), "unix_seconds"),
            (json!(seconds * 1000), "unix_milliseconds"),
            (
                json!((seconds + FILETIME_EPOCH_DELTA) * 10_000_000),
                "windows_filetime",
            ),
        ];
        for (value, expected) in cases {
            let doc = json!([{"itemId": "x", "timestamp": value}]);
            let inv = parse(doc.to_string().as_bytes()).expect("parses");
            let stamp = inv.items[0].timestamp.as_ref().expect("a timestamp");
            assert_eq!(stamp.interpretation, expected);
            assert!(
                stamp.utc.starts_with("2026-03-04T05:06:07"),
                "{expected} gave {}",
                stamp.utc
            );
        }
    }

    /// **Fail closed.** A value that cannot be a time must yield nothing, never
    /// an epoch date. A record dated 1601 or 1970 is a claim about the evidence
    /// that nothing supports.
    #[test]
    fn an_implausible_time_is_omitted_rather_than_rendered_as_an_epoch() {
        for bad in [
            json!(0),
            json!(-1),
            json!(1),
            json!("not a date"),
            json!(null),
        ] {
            let doc = json!([{"itemId": "x", "timestamp": bad}]);
            let inv = parse(doc.to_string().as_bytes()).expect("parses");
            assert_eq!(inv.items.len(), 1, "the entry itself must survive: {bad}");
            assert!(
                inv.items[0].timestamp.is_none(),
                "{bad} must not produce a timestamp, got {:?}",
                inv.items[0].timestamp
            );
        }
    }

    /// An entry whose timestamp could not be read is still an entry: it
    /// evidences that something was pinned.
    #[test]
    fn an_entry_with_no_readable_time_is_still_recorded() {
        let doc = json!([{"itemId": "{aaaa}"}]);
        let inv = parse(doc.to_string().as_bytes()).expect("parses");
        assert_eq!(inv.items.len(), 1);
        assert!(inv.items[0].timestamp.is_none());
    }

    /// Whatever this parser did not understand must survive to the record.
    #[test]
    fn unrecognised_fields_are_preserved_verbatim() {
        let doc = json!([{"itemId": "{aaaa}", "someFutureField": {"nested": [1, 2, 3]}}]);
        let inv = parse(doc.to_string().as_bytes()).expect("parses");
        assert_eq!(
            inv.items[0].raw["someFutureField"]["nested"],
            json!([1, 2, 3])
        );
        assert!(inv.raw.is_array(), "the whole document is kept too");
    }

    /// An empty inventory is a finding, not a failure.
    #[test]
    fn an_empty_document_yields_an_empty_inventory_rather_than_an_error() {
        for doc in ["[]", "{}", r#"{"items":[]}"#] {
            let inv = parse(doc.as_bytes()).expect("parses");
            assert!(inv.items.is_empty());
            assert!(!inv.truncated);
        }
    }

    #[test]
    fn bytes_that_are_not_json_yield_nothing() {
        assert!(parse(b"").is_none());
        assert!(parse(b"\x00\x01\x02\xff").is_none());
        assert!(parse(b"{not json").is_none());
    }

    /// Hostile input must not recurse without bound or allocate without bound.
    #[test]
    fn deep_nesting_and_many_entries_are_bounded() {
        // serde_json refuses beyond its own recursion limit, and this walk
        // stops at MAX_DEPTH below that. Either is a correct answer; what must
        // not happen is a stack overflow, so both are accepted and neither is
        // asserted as the one true outcome.
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        if let Some(inv) = parse(deep.as_bytes()) {
            assert!(inv.items.is_empty());
        }
        let shallow = format!("{}{}", "[".repeat(20), "]".repeat(20));
        let inv = parse(shallow.as_bytes()).expect("20 deep is ordinary JSON");
        assert!(inv.items.is_empty());

        let many: Vec<Value> = (0..MAX_ITEMS + 100)
            .map(|i| json!({"itemId": format!("{i}")}))
            .collect();
        let inv = parse(Value::Array(many).to_string().as_bytes()).expect("parses");
        assert_eq!(inv.items.len(), MAX_ITEMS);
        assert!(
            inv.truncated,
            "a cap that fires must be stated, or a truncated list reads as a complete one"
        );
    }
}
