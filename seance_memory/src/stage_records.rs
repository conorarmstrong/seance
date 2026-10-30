//! The records every memory stage emits, built once.
//!
//! The Linux and Windows analysis crates each carried a byte-for-byte copy of
//! these builders (ROADMAP §5.11, measured by `scripts/clone-scan.py`); they
//! differed only in the stamp naming the OS profile and in a name prefix, both
//! of which are parameters here. One more differs: the inventory whose own
//! reasons are folded into a short stage's (`task_inventory` on Linux,
//! `process_inventory` on Windows) — also a parameter. A fix to how a short stage is reported now
//! lands in one place instead of two that could drift.

use crate::binding::StageId;
use seance_core::artifact::{Artifact, ArtifactType};
use serde_json::{json, Map, Value};
use tracing::warn;

/// `type` / `record_type` of a record saying a stage did not run.
pub const MEMORY_STAGE_FAILURE_RECORD: &str = "MemoryStageFailure";

/// Adds the fields every memory record carries (the OS profile and the
/// evidence grade it rests on) to a record's object.
pub type Stamp<'a> = &'a dyn Fn(&mut Map<String, Value>);

/// The reasons a record itself gives for being short, as one sentence.
///
/// Every analysis type carries an `incomplete` array of `{reason, detail}`.
/// Promoting the details to the standard `content_incomplete_reason` key means
/// a consumer that reads only the two standard keys still learns *why* a count
/// is a floor.
///
/// The inventory's own reasons (`inventory_key`: `process_inventory` on
/// Windows, `task_inventory` on Linux) are folded in, because for a
/// per-process stage they are usually the ONLY reasons: a VAD tree that walked
/// perfectly over a list that stopped ten processes early has nothing in its
/// own `incomplete` array, and a record that said "incomplete, no reason
/// recorded" would send an examiner looking for a fault in the stage instead
/// of at the truncated list that caused it.
pub fn incomplete_reason(value: &Value, inventory_key: &str) -> Option<String> {
    let mut details: Vec<&str> = details_of(value.get("incomplete"));
    details.extend(details_of(
        value.get(inventory_key).and_then(|i| i.get("incomplete")),
    ));
    if details.is_empty() {
        return None;
    }
    Some(details.join("; "))
}

/// The `detail` strings of an `incomplete` array, or none when there is no
/// such array.
fn details_of(value: Option<&Value>) -> Vec<&str> {
    value
        .and_then(Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("detail").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

/// A record carrying one stage's results.
pub fn stage_record(
    parent: &Artifact,
    stage: &StageId,
    mut value: Value,
    complete: bool,
    inventory_key: &str,
    stamp: Stamp<'_>,
) -> Artifact {
    let reason = incomplete_reason(&value, inventory_key);
    if let Some(object) = value.as_object_mut() {
        object.insert("type".into(), json!(stage.record_type));
        object.insert("record_type".into(), json!(stage.record_type));
        object.insert("stage".into(), json!(stage.key));
        object.insert("stage_ran".into(), json!(true));
        // A stage that stopped early has produced a floor, not a total, and a
        // report that quotes its counts has to say so.
        object.insert("content_complete".into(), json!(complete));
        if !complete {
            object.insert("content_incomplete".into(), json!(true));
            object.insert(
                "content_incomplete_reason".into(),
                json!(reason.unwrap_or_else(|| format!(
                    "the {} stage did not establish this result in full and recorded no reason",
                    stage.key
                ))),
            );
        }
        stamp(object);
    }
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

/// A record saying a stage could not run, and why.
///
/// Emitted rather than logged because the absence of a stage's findings is not
/// evidence that there was nothing to find. `name_prefix` is the analysis's
/// label ("Memory analysis", "Linux memory analysis").
pub fn stage_failure(
    parent: &Artifact,
    module_id: &str,
    name_prefix: &str,
    stage: &StageId,
    err: &dyn std::fmt::Display,
    stamp: Stamp<'_>,
) -> Artifact {
    let key = stage.key;
    warn!("{}: stage '{}' did not run: {}", module_id, key, err);
    let mut value = json!({
        "type": MEMORY_STAGE_FAILURE_RECORD,
        "record_type": MEMORY_STAGE_FAILURE_RECORD,
        "name": format!("{name_prefix}: {key} did not run"),
        "stage": key,
        "stage_ran": false,
        "content_complete": false,
        "content_incomplete": true,
        "content_incomplete_reason": err.to_string(),
        "failure": err.to_string(),
    });
    stamp(value.as_object_mut().expect("object literal"));
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

/// A record saying several stages were skipped because a prerequisite failed.
pub fn skipped_record(
    parent: &Artifact,
    name: &str,
    stages: &[&StageId],
    reason: &str,
    stamp: Stamp<'_>,
) -> Artifact {
    let keys: Vec<&str> = stages.iter().map(|stage| stage.key).collect();
    let mut value = json!({
        "type": MEMORY_STAGE_FAILURE_RECORD,
        "record_type": MEMORY_STAGE_FAILURE_RECORD,
        "name": name,
        "stages": keys,
        "stage_ran": false,
        "content_complete": false,
        "content_incomplete": true,
        "content_incomplete_reason": reason,
        "failure": reason,
    });
    stamp(value.as_object_mut().expect("object literal"));
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    const STAGE: StageId = StageId {
        key: "vad",
        record_type: "MemoryVad",
        per_process: false,
        describes: "x",
    };

    fn parent() -> Artifact {
        Artifact::new(Uuid::new_v4(), ArtifactType::RawEvidence, None, json!({}))
    }

    fn stamp(o: &mut Map<String, Value>) {
        o.insert("os".into(), json!("test-os"));
    }

    #[test]
    fn a_complete_stage_record_is_typed_stamped_and_parented() {
        let p = parent();
        let a = stage_record(
            &p,
            &STAGE,
            json!({"count": 3}),
            true,
            "process_inventory",
            &stamp,
        );
        assert_eq!(a.parent_id, Some(p.id));
        assert_eq!(a.metadata["type"], "MemoryVad");
        assert_eq!(a.metadata["stage"], "vad");
        assert_eq!(a.metadata["stage_ran"], true);
        assert_eq!(a.metadata["content_complete"], true);
        assert_eq!(a.metadata["os"], "test-os");
        assert!(a.metadata.get("content_incomplete").is_none());
        assert_eq!(a.metadata["count"], 3, "the stage's own fields are kept");
    }

    #[test]
    fn a_short_stage_says_why_from_its_own_and_the_inventorys_reasons() {
        let value = json!({
            "incomplete": [{"reason": "cap", "detail": "stopped at 100 VADs"}],
            "process_inventory": {"incomplete": [{"detail": "list ended early"}]},
        });
        let a = stage_record(&parent(), &STAGE, value, false, "process_inventory", &stamp);
        assert_eq!(a.metadata["content_incomplete"], true);
        assert_eq!(
            a.metadata["content_incomplete_reason"],
            "stopped at 100 VADs; list ended early"
        );
    }

    #[test]
    fn a_short_stage_with_no_recorded_reason_says_so_instead_of_staying_silent() {
        let a = stage_record(
            &parent(),
            &STAGE,
            json!({}),
            false,
            "process_inventory",
            &stamp,
        );
        assert!(a.metadata["content_incomplete_reason"]
            .as_str()
            .unwrap()
            .contains("vad stage did not establish this result in full"));
    }

    #[test]
    fn a_failure_names_the_analysis_the_stage_and_the_error() {
        let a = stage_failure(
            &parent(),
            "plugin.test",
            "Linux memory analysis",
            &STAGE,
            &"no kernel symbols",
            &stamp,
        );
        assert_eq!(a.metadata["type"], MEMORY_STAGE_FAILURE_RECORD);
        assert_eq!(a.metadata["name"], "Linux memory analysis: vad did not run");
        assert_eq!(a.metadata["stage_ran"], false);
        assert_eq!(a.metadata["failure"], "no kernel symbols");
        assert_eq!(a.metadata["os"], "test-os");
    }

    #[test]
    fn a_skip_lists_every_stage_it_covers() {
        let a = skipped_record(
            &parent(),
            "Memory analysis: stages did not run",
            &[&STAGE],
            "no process list",
            &stamp,
        );
        assert_eq!(a.metadata["stages"], json!(["vad"]));
        assert_eq!(a.metadata["content_incomplete_reason"], "no process list");
        assert_eq!(a.metadata["name"], "Memory analysis: stages did not run");
    }

    #[test]
    fn the_folded_inventory_is_the_one_the_caller_names() {
        // Linux folds `task_inventory`; the same body under `process_inventory`
        // is not its inventory and contributes nothing.
        let body = json!({
            "count": 12,
            "task_inventory": {"incomplete": [{"detail": "the task walk stopped at its cap"}]}
        });
        assert!(incomplete_reason(&body, "task_inventory")
            .expect("an inventory that says it is short")
            .contains("task walk"));
        assert_eq!(incomplete_reason(&body, "process_inventory"), None);
        assert_eq!(
            incomplete_reason(&json!({"count": 12}), "task_inventory"),
            None
        );
        let own = json!({"incomplete": [{"detail": "the walk stopped at its cap of 64 entries"}]});
        assert!(incomplete_reason(&own, "task_inventory")
            .unwrap()
            .contains("cap of 64"));
    }
}
