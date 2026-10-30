#![forbid(unsafe_code)]
mod badclus_structs;

use badclus_structs::*;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::info;

#[cfg(test)]
mod tests;

pub struct BadClusParser;

impl ForensicsModule for BadClusParser {
    fn id(&self) -> &str {
        "plugin.ntfs.badclus_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // Subscribe to FileEntry artifacts - $BadClus is typically named "$BadClus" or "$Bad"
        vec![
            ArtifactType::FileEntry,
            ArtifactType::RawEvidence,
            ArtifactType::SystemArtifact,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Identify the $BadClus / $Bad stream. The MFT parser emits $BadClus:$Bad
        // as a FileEntry ADS keyed by "name" (and "stream_name"); RawEvidence /
        // SystemArtifact inputs carry a source path or name.
        let name = artifact
            .metadata
            .get("name")
            .or_else(|| artifact.metadata.get("file_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("source_path")
            .or_else(|| artifact.metadata.get("path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");

        // The map is exactly the `$Bad` stream of `$BadClus` (HUNT-220): a
        // substring test read any file whose name or path merely contained
        // `$Bad` as the volume's bad-cluster map.
        let is_target = is_bad_stream(name) || is_bad_stream(path);
        if !is_target {
            return Ok(vec![]);
        }
        let stream_name = if !name.is_empty() { name } else { path };

        info!("Processing $BadClus stream: {}", stream_name);

        // Bad-cluster LCNs live in the MFT $Bad attribute's non-resident runlist,
        // exposed here as `data_runs` ([offset_bytes|null, length_bytes] pairs).
        // The stream *content* is just the (sparse) on-disk image of those
        // clusters, NOT a runlist, so it must never be parsed as run bytes.
        // Without the runlist we cannot recover bad clusters and must not invent
        // any from content.
        //
        // The MFT parser publishes `$Bad`'s allocated runs as
        // `bad_cluster_runs`. Its `data_runs` is the stream's LOGICAL extent,
        // and `$Bad` has `initialized_size` 0 on every real volume, so that
        // list is one sparse run with every bad cluster discarded (HUNT-155).
        // `data_runs` is read only from a producer that published nothing
        // better — a hand-built record or an older ingest.
        let (runs_key, runs_value) = match artifact.metadata.get("bad_cluster_runs") {
            Some(v) => ("bad_cluster_runs", Some(v)),
            None => ("data_runs", artifact.metadata.get("data_runs")),
        };
        let runs_complete = runs_key != "bad_cluster_runs"
            || artifact.metadata.get("bad_cluster_runs_complete") != Some(&json!(false));
        let data_runs = match runs_value {
            Some(v) => parse_data_runs_meta(v)?,
            None => {
                // Bad clusters live in the MFT run list and cannot be recovered
                // from stream content. Without it this module could not look,
                // which is not the same answer as "no bad clusters" (HUNT-220).
                info!(
                    "$BadClus stream {} has no run list; publishing it as unread",
                    stream_name
                );
                return Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "record_type": "badclus_status",
                        "stream": stream_name,
                        "ranges_reported": 0,
                        "run_list_absent": true,
                        "inventory_incomplete": true,
                        "inventory_incomplete_reason": "unresolved_structure",
                        "inventory_incomplete_detail":
                            "The $BadClus:$Bad stream arrived without its run list, and bad \
                             clusters are recorded only there, so none could be looked for: \
                             this is not a finding that the volume has no bad clusters",
                    }),
                )
                .with_parent(artifact.id)]);
            }
        };

        // Volume cluster size, if the pipeline surfaced it. Byte offsets are
        // already exact without it; it only enables deriving LCN / cluster
        // counts, which stay null when it is unknown.
        let cluster_size = artifact
            .metadata
            .get("cluster_size")
            .or_else(|| artifact.metadata.get("allocation_cluster_size"))
            .or_else(|| artifact.metadata.get("bytes_per_cluster"))
            .and_then(|v| v.as_u64())
            .filter(|&cs| cs > 0);

        // Only non-sparse runs (offset present) are bad clusters. Sparse runs
        // (offset == null) are *good* clusters -- the bulk of $Bad on a healthy
        // volume -- and must not be flagged bad.
        let mut ranges = Vec::new();
        let mut vcn_bytes: u64 = 0;
        for (offset, length) in data_runs {
            if let Some(off) = offset {
                ranges.push(BadClusterRange {
                    stream: stream_name.to_string(),
                    offset_bytes: off,
                    length_bytes: length,
                    vcn_bytes,
                });
            }
            vcn_bytes = vcn_bytes.saturating_add(length);
        }

        info!(
            "Recovered {} bad-cluster range(s) from {}",
            ranges.len(),
            stream_name
        );

        let mut artifacts: Vec<Artifact> = ranges
            .iter()
            .map(|range| {
                create_artifact_from_range(artifact.case_id, range, cluster_size, artifact.id)
            })
            .collect();

        // The producer could not assemble the whole run list (an unresolved
        // `$ATTRIBUTE_LIST` extent, or more runs than it publishes): the ranges
        // above are some of the bad clusters, and a cluster missing from them
        // is not evidence that it is good.
        if !runs_complete {
            artifacts.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "record_type": "badclus_status",
                        "stream": stream_name,
                        "ranges_reported": ranges.len(),
                        "inventory_incomplete": true,
                        "inventory_incomplete_reason": "unresolved_structure",
                        "inventory_incomplete_detail":
                            "The MFT parser could not assemble all of $Bad's run list, so \
                             these are not all of the volume's bad clusters: a cluster absent \
                             from them is not shown to be good",
                    }),
                )
                .with_parent(artifact.id),
            );
        }

        Ok(artifacts)
    }
}

/// True when `s` names the `$BadClus:$Bad` stream itself: the whole name, or
/// the last component of a path (either separator).
fn is_bad_stream(s: &str) -> bool {
    s.rsplit(['/', '\\'])
        .next()
        .is_some_and(|last| last.eq_ignore_ascii_case("$BadClus:$Bad"))
}

/// Parse the `data_runs` metadata array of `[offset|null, length]` byte pairs
/// (the shape every filesystem parser emits and the content resolver consumes).
fn parse_data_runs_meta(value: &serde_json::Value) -> Result<Vec<(Option<u64>, u64)>, ModuleError> {
    let arr = value
        .as_array()
        .ok_or_else(|| ModuleError::ParsingError("data_runs is not an array".to_string()))?;
    let mut runs = Vec::with_capacity(arr.len());
    for run in arr {
        let pair = run.as_array().filter(|p| p.len() == 2).ok_or_else(|| {
            ModuleError::ParsingError("data_runs entry is not an [offset, length] pair".to_string())
        })?;
        let offset = if pair[0].is_null() {
            None
        } else {
            Some(pair[0].as_u64().ok_or_else(|| {
                ModuleError::ParsingError("data_runs offset is not an unsigned integer".to_string())
            })?)
        };
        let length = pair[1].as_u64().ok_or_else(|| {
            ModuleError::ParsingError("data_runs length is not an unsigned integer".to_string())
        })?;
        runs.push((offset, length));
    }
    Ok(runs)
}

/// Build a ParsedRecord artifact from a recovered bad-cluster range.
///
/// The byte offset/length come straight from the runlist, so the physical
/// location is authoritative. LCN / cluster-count fields are derived only when
/// `cluster_size` is known; otherwise they are null (never guessed from an
/// assumed 4 KiB cluster).
fn create_artifact_from_range(
    case_id: uuid::Uuid,
    range: &BadClusterRange,
    cluster_size: Option<u64>,
    parent_id: uuid::Uuid,
) -> Artifact {
    let (lcn_start, lcn_end, cluster_count, vcn_start, vcn_end) = match cluster_size {
        Some(cs) => {
            let start = range.offset_bytes / cs;
            let count = range.length_bytes / cs;
            let last = count.saturating_sub(1);
            let vcn_s = range.vcn_bytes / cs;
            (
                Some(start),
                Some(start + last),
                Some(count),
                Some(vcn_s),
                Some(vcn_s + last),
            )
        }
        None => (None, None, None, None, None),
    };

    let description = match cluster_count {
        Some(count) => format!(
            "Bad cluster region at byte offset {} ({} bytes, {} clusters)",
            range.offset_bytes, range.length_bytes, count
        ),
        None => format!(
            "Bad cluster region at byte offset {} ({} bytes)",
            range.offset_bytes, range.length_bytes
        ),
    };

    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        serde_json::json!({
            "record_type": "badclus_range",
            "stream": range.stream,
            "volume_offset_bytes": range.offset_bytes,
            "length_bytes": range.length_bytes,
            "cluster_size_bytes": cluster_size,
            "cluster_start_lcn": lcn_start,
            "cluster_end_lcn": lcn_end,
            "cluster_count": cluster_count,
            "vcn_start": vcn_start,
            "vcn_end": vcn_end,
            "description": description,
        }),
    )
    .with_parent(parent_id)
}
