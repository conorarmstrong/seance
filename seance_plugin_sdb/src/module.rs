//! The module: a shim database on disk becomes records.
//!
//! # How a database is recognised
//!
//! **By content, never by name.** The magic at byte 8 is `sdbf` or `zdbf`, and
//! a file that carries neither produces nothing at all — not a refusal, not an
//! empty record. A file merely named `.sdb` is not a shim database, and
//! inventing a parse failure for it would put a statement in the case about
//! something that is not evidence.
//!
//! The extension is used only to decide whether to *read* the first bytes, so
//! that a full disk's worth of files is not opened to check.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use tracing::debug;

use crate::{container, entities, format, strings};

/// Bytes read to decide whether a file is a shim database at all.
const SNIFF_BYTES: usize = 12;

/// The largest database this build will read whole.
///
/// The largest real one is 9.7 MiB inflated. 64 MiB of compressed input is two
/// orders of magnitude of headroom and finite.
const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;

pub struct SdbParser;

impl ForensicsModule for SdbParser {
    fn id(&self) -> &str {
        "plugin.windows.sdb_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::SystemArtifact]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(source) = artifact.data.as_ref() else {
            return Ok(vec![]);
        };
        let name = artifact
            .metadata
            .get("name")
            .or_else(|| artifact.metadata.get("file_name"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .or_else(|| artifact.metadata.get("source_path"))
            .and_then(|v| v.as_str())
            .unwrap_or("");
        // The extension decides only whether to look at the bytes. What decides
        // whether this IS a shim database is the magic below.
        let worth_sniffing = [name, path]
            .iter()
            .any(|s| s.to_ascii_lowercase().ends_with(".sdb"));
        if !worth_sniffing {
            return Ok(vec![]);
        }

        let mut magic = [0u8; SNIFF_BYTES];
        if source.read_at(0, &mut magic).unwrap_or(0) < SNIFF_BYTES {
            return Ok(vec![]);
        }
        if &magic[8..12] != container_magic_sdbf() && &magic[8..12] != container_magic_zdbf() {
            // Named `.sdb`, and not one. Nothing is said about it.
            return Ok(vec![]);
        }

        let size = source.size();
        if size > MAX_FILE_BYTES {
            // Said rather than skipped: a database too large to read is not a
            // database that holds nothing.
            return Ok(vec![Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::json!({
                    "type": "ShimDatabaseCoverage",
                    "name": "Shim database not read",
                    "content_incomplete": true,
                    "content_incomplete_reason":
                        seance_core::io::IncompleteReason::CapReached.as_str(),
                    "content_incomplete_detail": format!(
                        "This shim database is {size} bytes, past this build's \
                         {MAX_FILE_BYTES}-byte ceiling, and was not read. Nothing about its \
                         contents is established either way."
                    ),
                }),
            )
            .with_parent(artifact.id)]);
        }

        let mut bytes = vec![0u8; size as usize];
        let read = source.read_at(0, &mut bytes).unwrap_or(0);
        bytes.truncate(read);
        let short = (read as u64) < size;

        let opened = match container::open(&bytes) {
            Ok(o) => o,
            Err(e) => {
                debug!("sdb: {name} would not open: {e:?}");
                return Ok(vec![]);
            }
        };
        let walk = format::walk(&opened.body);
        let table = strings::build(&opened.body, &walk.tags).unwrap_or_default();
        let (db, exes) = entities::read(&opened.body, &walk.tags, &table);

        let mut out = Vec::new();
        let mut coverage = entities::coverage(&opened.body, &opened, &walk, &table).to_json();
        if short {
            if let Some(m) = coverage.as_object_mut() {
                m.insert("content_incomplete".into(), serde_json::json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    serde_json::json!(seance_core::io::IncompleteReason::ShortRead.as_str()),
                );
                m.insert(
                    "short_read_detail".into(),
                    serde_json::json!(format!(
                        "{read} of {size} bytes were readable. The records below are what \
                         those bytes held; what the unread bytes hold is not established."
                    )),
                );
            }
        }
        out.push(
            Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, coverage)
                .with_parent(artifact.id),
        );
        if let Some(db) = db {
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    db.to_json(),
                )
                .with_parent(artifact.id),
            );
        }
        for exe in exes {
            out.push(
                Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    exe.to_json(),
                )
                .with_parent(artifact.id),
            );
        }
        Ok(out)
    }
}

fn container_magic_sdbf() -> &'static [u8] {
    format::MAGIC_SDBF
}

fn container_magic_zdbf() -> &'static [u8] {
    format::MAGIC_ZDBF
}
