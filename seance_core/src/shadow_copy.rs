//! Reading the content of a shadow-copy prior version without ever presenting
//! it as the live volume (HUNT-274, HUNT-277).
//!
//! A `VssPriorVersion` record (`seance_plugin_vss`) describes a file as it
//! stood in a Volume Shadow Copy and carries that snapshot's content. A content
//! parser that subscribes to `ParsedRecord` opens it with [`provenance_of`],
//! parses as usual, and stamps everything it produced with
//! [`ShadowCopyProvenance::stamp`], so a row, a hive key or a timeline event
//! from a shadow copy says so on its face.

use crate::artifact::{Artifact, ArtifactType};
use serde_json::{json, Map, Value};

/// The record type a prior version carries in its metadata.
pub const PRIOR_VERSION_TYPE: &str = "VssPriorVersion";

/// Keys copied from the prior version onto everything parsed out of it.
const COPIED_KEYS: [&str; 5] = [
    "is_snapshot_version",
    "snapshot_label",
    "vss_snapshot_id",
    "vss_creation_time",
    "vss_stack_position",
];

/// The shadow-copy identity of a prior version.
#[derive(Debug, Clone)]
pub struct ShadowCopyProvenance {
    fields: Map<String, Value>,
    creation_time: Option<String>,
}

/// The provenance of `artifact` when it is a shadow-copy prior version.
pub fn provenance_of(artifact: &Artifact) -> Option<ShadowCopyProvenance> {
    if artifact.metadata.get("type").and_then(Value::as_str) != Some(PRIOR_VERSION_TYPE) {
        return None;
    }
    let mut fields = Map::new();
    for key in COPIED_KEYS {
        if let Some(v) = artifact.metadata.get(key) {
            fields.insert(key.to_string(), v.clone());
        }
    }
    fields.insert("shadow_copy_sidecars_not_searched".to_string(), json!(true));
    let creation_time = artifact
        .metadata
        .get("vss_creation_time")
        .and_then(Value::as_str)
        .map(str::to_string);
    Some(ShadowCopyProvenance {
        fields,
        creation_time,
    })
}

impl ShadowCopyProvenance {
    /// Stamp one produced artifact. A timeline event also has its short
    /// description prefixed, because the timeline shows that and little else.
    pub fn stamp(&self, out: &mut Artifact) {
        let is_event = out.artifact_type == ArtifactType::TimelineEvent;
        let Some(map) = out.metadata.as_object_mut() else {
            return;
        };
        for (k, v) in &self.fields {
            map.insert(k.clone(), v.clone());
        }
        if is_event {
            let label = match &self.creation_time {
                Some(t) => format!("[shadow copy {t}] "),
                None => "[shadow copy] ".to_string(),
            };
            if let Some(Value::String(desc)) = map.get_mut("short_desc") {
                if !desc.starts_with(&label) {
                    desc.insert_str(0, &label);
                }
            }
        }
    }

    /// Stamp every produced artifact.
    pub fn stamp_all(&self, outputs: &mut [Artifact]) {
        for out in outputs {
            self.stamp(out);
        }
    }
}

/// The file's own name, for a parser that decides by name. A prior version is
/// named `<file> [shadow copy <time>]`, which no extension test accepts; its
/// original name is `file_name`.
pub fn original_name(artifact: &Artifact) -> Option<&str> {
    let key = if provenance_of(artifact).is_some() {
        "file_name"
    } else {
        "name"
    };
    artifact.metadata.get(key).and_then(Value::as_str)
}

/// The whole of a content parser's `process` for a parser that also reads
/// shadow-copy prior versions: a `ParsedRecord` that is not a prior version is
/// not this parser's and returns empty before its data is touched; a prior
/// version is parsed and everything produced is stamped; anything else is
/// parsed as it always was.
pub fn parse_with_shadow_copy<E>(
    artifact: &Artifact,
    parse: impl FnOnce(&Artifact) -> Result<Vec<Artifact>, E>,
) -> Result<Vec<Artifact>, E> {
    let provenance = provenance_of(artifact);
    if artifact.artifact_type == ArtifactType::ParsedRecord && provenance.is_none() {
        return Ok(Vec::new());
    }
    let mut produced = parse(artifact)?;
    if let Some(provenance) = &provenance {
        provenance.stamp_all(&mut produced);
    }
    Ok(produced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn prior() -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": PRIOR_VERSION_TYPE,
                "is_snapshot_version": true,
                "snapshot_label": "SHADOW COPY VERSION, not the live volume",
                "vss_snapshot_id": "snap-1",
                "vss_creation_time": "2015-03-23T00:00:00Z",
                "vss_stack_position": 2,
                "name": "SYSTEM",
            }),
        )
    }

    #[test]
    fn only_a_prior_version_has_a_provenance() {
        assert!(provenance_of(&prior()).is_some());
        let other = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "RegistryKey" }),
        );
        assert!(provenance_of(&other).is_none());
    }

    #[test]
    fn stamping_copies_the_identity_and_states_the_sidecar_gap() {
        let p = provenance_of(&prior()).unwrap();
        let mut out = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "RegistryKey", "path": "ROOT\\Run" }),
        );
        p.stamp(&mut out);
        assert_eq!(out.metadata["vss_snapshot_id"], json!("snap-1"));
        assert_eq!(out.metadata["is_snapshot_version"], json!(true));
        assert_eq!(
            out.metadata["shadow_copy_sidecars_not_searched"],
            json!(true)
        );
        assert_eq!(out.metadata["path"], json!("ROOT\\Run"), "own fields kept");
    }

    #[test]
    fn a_timeline_event_says_on_its_face_that_it_is_from_a_shadow_copy_once() {
        let p = provenance_of(&prior()).unwrap();
        let mut ev = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::TimelineEvent,
            None,
            json!({ "short_desc": "Key written: Run", "timestamp": 1 }),
        );
        p.stamp(&mut ev);
        p.stamp(&mut ev);
        assert_eq!(
            ev.metadata["short_desc"],
            json!("[shadow copy 2015-03-23T00:00:00Z] Key written: Run")
        );
    }

    #[test]
    fn the_wrapper_skips_other_parsed_records_and_stamps_prior_versions() {
        let calls = std::cell::Cell::new(0);
        let parse = |_: &Artifact| -> Result<Vec<Artifact>, ()> {
            calls.set(calls.get() + 1);
            Ok(vec![Artifact::new(
                Uuid::new_v4(),
                ArtifactType::ParsedRecord,
                None,
                json!({ "type": "Row" }),
            )])
        };

        // A ParsedRecord that is not a prior version: parser never runs.
        let other = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({ "type": "Row" }),
        );
        assert!(parse_with_shadow_copy(&other, parse).unwrap().is_empty());
        assert_eq!(calls.get(), 0);

        // A prior version: parsed and every output stamped.
        let out = parse_with_shadow_copy(&prior(), parse).unwrap();
        assert_eq!(calls.get(), 1);
        assert_eq!(out[0].metadata["vss_snapshot_id"], json!("snap-1"));

        // A FileEntry: parsed, and never stamped.
        let file = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "x" }),
        );
        let out = parse_with_shadow_copy(&file, parse).unwrap();
        assert!(out[0].metadata.get("is_snapshot_version").is_none());
    }

    #[test]
    fn a_name_gated_parser_sees_the_original_name_of_a_prior_version() {
        let mut a = prior();
        a.metadata["name"] = json!("a.lnk [shadow copy 2015-03-23T00:00:00Z]");
        a.metadata["file_name"] = json!("a.lnk");
        assert_eq!(original_name(&a), Some("a.lnk"));
        let live = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "b.lnk", "file_name": "ignored" }),
        );
        assert_eq!(original_name(&live), Some("b.lnk"));
    }
}
