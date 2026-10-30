//! Recording *why* a record is incomplete, without losing what an earlier
//! stage already found.

/// Add an incompleteness reason without erasing one an earlier stage stamped.
///
/// A hive can be both dirty and capped, and a cache inside it can additionally
/// have stopped on an undecodable record. Each of those calls for different
/// follow-up work, so whichever stage stamps second must not hide what the
/// first found. Reasons accumulate into a `+`-joined list in the order they
/// were discovered, and re-stamping a reason already present is a no-op — the
/// stampers run on shared metadata and are not all reached exactly once.
///
/// `content_incomplete` is set alongside the reason: the pair is the contract
/// the API, export and frontend read, and a reason without the flag would not
/// be surfaced to an examiner at all.
///
/// Long-term home is `seance_core::io`, beside `IncompleteReason`, where the
/// remaining copies across the plugin tree can use it too.
pub fn add_incomplete_reason(map: &mut serde_json::Map<String, serde_json::Value>, reason: &str) {
    map.insert("content_incomplete".into(), serde_json::json!(true));
    let merged = match map
        .get("content_incomplete_reason")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
    {
        Some(existing) if existing.split('+').any(|r| r == reason) => existing.to_string(),
        Some(existing) => format!("{}+{}", existing, reason),
        None => reason.to_string(),
    };
    map.insert(
        "content_incomplete_reason".into(),
        serde_json::json!(merged),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Two stages can each find the record incomplete; the second must not
    /// erase what the first said.
    #[test]
    fn incomplete_reasons_accumulate() {
        let mut meta = json!({});
        let map = meta.as_object_mut().unwrap();
        add_incomplete_reason(map, "short_read");
        add_incomplete_reason(map, "cap_reached");
        add_incomplete_reason(map, "short_read");
        assert_eq!(map["content_incomplete"], json!(true));
        assert_eq!(
            map["content_incomplete_reason"],
            json!("short_read+cap_reached"),
        );
    }

    /// An empty reason left behind by some other writer must not produce a
    /// leading separator, which would make the list unparseable.
    #[test]
    fn an_empty_existing_reason_is_replaced_rather_than_joined() {
        let mut meta = json!({ "content_incomplete_reason": "" });
        let map = meta.as_object_mut().unwrap();
        add_incomplete_reason(map, "cap_reached");
        assert_eq!(map["content_incomplete_reason"], json!("cap_reached"));
    }

    /// A prefix of an existing reason is a different reason and must be kept
    /// separate, not swallowed by a substring match.
    #[test]
    fn a_reason_that_is_a_prefix_of_another_is_not_treated_as_present() {
        let mut meta = json!({ "content_incomplete_reason": "short_read_partial" });
        let map = meta.as_object_mut().unwrap();
        add_incomplete_reason(map, "short_read");
        assert_eq!(
            map["content_incomplete_reason"],
            json!("short_read_partial+short_read"),
        );
    }
}
