//! Status records for archives that could not be expanded.
//!
//! A container that fails to expand produces no children. Nothing else about
//! the ingest distinguishes that from "this file was not one of ours" or "this
//! archive was empty", so without an explicit record the examiner is left to
//! infer — wrongly — that a corrupt or bomb-capped `.gz`/`.bz2`/`.xz` held
//! nothing. The ZIP and TAR extractors already emit such a record when an
//! archive is unreadable (B2-158 / B2-159); the single-stream compressors emit
//! this one (B3-031).

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
};
use serde_json::json;

/// A record saying this compressed stream could not be expanded.
///
/// Carries the standard incompleteness pair (`content_incomplete` /
/// `content_incomplete_reason`) plus `inventory_incomplete`, because both are
/// true: no bytes were recovered and nothing inside the archive was listed.
/// `reason` names the container and failure (e.g. `gzip_decompress_failed`),
/// `detail` carries the decoder's own message — a decompression-bomb cap and a
/// mid-stream corruption must not read alike.
pub(crate) fn expansion_failed_status(
    artifact: &Artifact,
    container: &'static str,
    name: &str,
    reason: &'static str,
    detail: &str,
) -> Artifact {
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "ArchiveScanStatus",
            "record_type": "archive_scan_status",
            "name": format!("{} (not expanded)", name),
            "container": container,
            "container_path": name,
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::UnresolvedStructure.as_str(),
            "entries_recovered": 0,
            "content_incomplete_detail": detail,
            "inventory_incomplete_detail": detail,
            "detail": detail,
            "message": "This compressed stream could not be expanded: its contents are \
                        unknown, not absent, and nothing inside it was examined",
        }),
    )
    .with_parent(artifact.id)
}
