#![forbid(unsafe_code)]
//! The Windows Search index, `Windows.edb`.
//!
//! `%ProgramData%\Microsoft\Search\Data\Applications\Windows\Windows.edb` is
//! the indexer's ESE database: one row per item it has seen — files, folders,
//! Outlook mail, Internet Explorer history and favourites — with the
//! properties it recorded. Because the index is only rebuilt, not pruned, when
//! a file goes, a row can name a file that is no longer on the disk.
//!
//! [`index`] walks the property table in the two layouts measured on real
//! files (Windows 7 `SystemIndex_0A`, Windows 10 `SystemIndex_PropertyStore`)
//! and reads a fixed set of properties; [`compression`] decodes the encoded
//! text forms Windows 7 uses for some of them, and names the forms it does not
//! decode. A database is chosen by content (ESE) and kept only when it carries
//! one of those tables with a path property, so SRUM, WebCache and the rest
//! yield nothing.
//!
//! Windows 11 22H2 and later keep the index as SQLite (`Windows.db`); that is
//! **refused** with that reason, not read.

pub mod compression;
pub mod index;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::DataSource,
    file_detection::{try_detect_file_type, DetectedFileType},
    io::read_exact_or_fail,
    module::{ForensicsModule, InputCapability, ModuleError},
    temp_spill::TempSpill,
};
use serde_json::{json, Value};
use uuid::Uuid;

/// Cap on a staged database (4 GiB); a larger one is refused by name.
const MAX_INDEX_BYTES: u64 = 4 * 1024 * 1024 * 1024;

pub struct WinSearchParser;

/// How much is copied per step when staging a database.
const STAGE_CHUNK: u64 = 8 * 1024 * 1024;
/// The ESE file header, of which only the state field (offset 52) is read here.
const HEADER_BYTES: u64 = 4096;

/// Copy `ds` to a temporary file (libesedb opens paths) a chunk at a time,
/// returning the file and the first [`HEADER_BYTES`] of it.
fn stage(ds: &dyn DataSource) -> Result<(TempSpill, Vec<u8>), String> {
    use std::io::Write;
    let spill = TempSpill::write(&[], "winsearch", "edb").map_err(|e| {
        format!("the database could not be staged to a temporary file for libesedb ({e})")
    })?;
    let mut out = std::fs::OpenOptions::new()
        .append(true)
        .open(spill.path())
        .map_err(|e| format!("the temporary file could not be opened ({e})"))?;
    let size = ds.size();
    let mut header = Vec::new();
    let mut buf = vec![0u8; STAGE_CHUNK.min(size) as usize];
    let mut at = 0u64;
    while at < size {
        let n = STAGE_CHUNK.min(size - at) as usize;
        read_exact_or_fail(ds, at, &mut buf[..n], "Search index")
            .map_err(|e| format!("the file could not be read at byte {at} ({e})"))?;
        if at == 0 {
            header.extend_from_slice(&buf[..n.min(HEADER_BYTES as usize)]);
        }
        out.write_all(&buf[..n])
            .map_err(|e| format!("the temporary file could not be written ({e})"))?;
        at += n as u64;
    }
    Ok((spill, header))
}

fn state_name(s: Option<u32>) -> &'static str {
    match s {
        Some(1) => "just_created",
        Some(2) => "dirty_shutdown",
        Some(3) => "clean_shutdown",
        Some(4) => "being_converted",
        Some(5) => "force_detach",
        Some(_) => "unknown",
        None => "unread",
    }
}

impl WinSearchParser {
    pub fn new() -> Self {
        Self
    }

    fn marker(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        status: &str,
        detail: &str,
    ) -> Artifact {
        Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "WindowsSearchIndexIncomplete",
                "status": status,
                "source_file": source,
                "content_incomplete": true,
                "content_incomplete_reason": detail,
                "content_incomplete_detail": detail,
                "name": format!("Windows Search index {source}: {detail}"),
            }),
        )
        .with_parent(parent_id)
        .with_subtype("parse_incomplete")
    }

    fn item_record(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        layout: index::Layout,
        item: &index::Item,
    ) -> Artifact {
        let p = &item.properties;
        let path = p
            .get("System_ItemPathDisplay")
            .or_else(|| p.get("System_ItemUrl"))
            .and_then(|v| v.as_str())
            .unwrap_or("(no path)")
            .to_string();
        let not_decoded: Vec<Value> = item
            .not_decoded
            .iter()
            .map(|(prop, why)| json!({"property": prop, "reason": why}))
            .collect();
        let mut m = json!({
            "type": "WindowsSearchItem",
            "source_file": source,
            "schema_variant": layout.name(),
            "item_id": item.id,
            "path": path,
            "properties": Value::Object(p.clone()),
            "properties_not_decoded": not_decoded,
            "index_note": "a row of the Search index records that the indexer saw this item with \
                these properties; it is not evidence the item still exists",
            "name": format!("Search index: {path}"),
        });
        // The item's own modification time, when it has one, dates the record.
        if let Some(t) = p
            .get("System_DateModified")
            .or_else(|| p.get("System_Message_DateReceived"))
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
        {
            m["timestamp"] = json!(t.timestamp());
        }
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, m)
            .with_parent(parent_id)
            .with_subtype("windows_search_item")
    }

    /// Every record one database yields; nothing for an ESE database that is
    /// not a Search index.
    pub fn records_for_db(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        path: &std::path::Path,
        bytes: &[u8],
    ) -> Vec<Artifact> {
        let idx = match index::read_index(path, bytes) {
            Ok(Some(i)) => i,
            Ok(None) => {
                // Named like the index but not one: could not look, not "no items".
                if source.eq_ignore_ascii_case("windows.edb") {
                    return vec![Self::marker(
                        case_id,
                        parent_id,
                        source,
                        "NotDecoded",
                        "not decoded: the ESE database opened but carries neither Search property \
                         table this build reads (SystemIndex_PropertyStore, SystemIndex_0A) with a \
                         path property, so no item in it was read",
                    )];
                }
                return Vec::new();
            }
            Err(why) => {
                if source.eq_ignore_ascii_case("windows.edb") {
                    return vec![Self::marker(
                        case_id,
                        parent_id,
                        source,
                        "NotDecoded",
                        &format!("not decoded: {why}; no item in it was read"),
                    )];
                }
                return Vec::new();
            }
        };
        let mut out: Vec<Artifact> = idx
            .items
            .iter()
            .map(|i| Self::item_record(case_id, parent_id, source, idx.layout, i))
            .collect();
        let undecoded: usize = idx.items.iter().map(|i| i.not_decoded.len()).sum();

        let mut problems = Vec::new();
        if idx.db_state == Some(2) {
            problems.push(
                "the database header says dirty shutdown: it was copied from a running system \
                 or never closed, and changes held in its transaction logs are not replayed, so \
                 items the indexer added last may be absent"
                    .to_string(),
            );
        }
        if let Some(r) = idx.walk.reason() {
            problems.push(format!(
                "the table walk fell short ({r}; {} row(s) skipped)",
                idx.walk.rows_skipped
            ));
        }
        if let Some(e) = &idx.tree_error {
            let first = e
                .lines()
                .find(|l| l.contains("unsupported page"))
                .unwrap_or(e.lines().next().unwrap_or(""));
            problems.push(format!(
                "libesedb could not walk every page of the table's tree ({}); the {} item(s) read \
                 are those it could reach, a floor rather than the index's size",
                first.trim(),
                idx.items.len()
            ));
        }
        if idx.cut_at_cap {
            problems.push(format!(
                "the walk stopped at the {}-row cap",
                index::MAX_ROWS
            ));
        }
        let status = format!(
            "{} item(s); {undecoded} property value(s) not decoded",
            idx.items.len()
        );
        let mut m = json!({
            "type": "WindowsSearchIndex",
            "source_file": source,
            "schema_variant": idx.layout.name(),
            "items": idx.items.len(),
            "property_values_not_decoded": undecoded,
            "database_state": state_name(idx.db_state),
            "status": status,
            "name": format!("Windows Search index {source}: {status}"),
        });
        if !problems.is_empty() {
            let why = problems.join("; ");
            m["content_incomplete"] = json!(true);
            m["content_incomplete_reason"] = json!(why);
            m["content_incomplete_detail"] = json!(why);
            out.push(Self::marker(
                case_id,
                parent_id,
                source,
                if idx.db_state == Some(2) {
                    "DirtyDatabase"
                } else {
                    "TableWalkIncomplete"
                },
                &why,
            ));
        }
        out.push(
            Artifact::new(case_id, ArtifactType::ParsedRecord, None, m)
                .with_parent(parent_id)
                .with_subtype("windows_search_index"),
        );
        out
    }

    /// A `Windows.db` (Windows 11 22H2+, SQLite) is named and refused.
    fn windows_db_refusal(case_id: Uuid, parent_id: Uuid, source: &str) -> Artifact {
        Self::marker(
            case_id,
            parent_id,
            source,
            "NotDecoded",
            "not decoded: this is the SQLite form of the Search index that Windows 11 22H2 and \
             later keep, which this build does not read; no item in it was read",
        )
    }
}

impl Default for WinSearchParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for WinSearchParser {
    fn id(&self) -> &str {
        "plugin.windows.search_index"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl WinSearchParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let name = seance_core::shadow_copy::original_name(artifact)
            .unwrap_or_default()
            .to_string();
        // An unreadable header is "could not look": no marker may say "not ESE"
        // for a file whose header was never read (CR-047).
        let kind = try_detect_file_type(ds.as_ref()).map_err(ModuleError::IoError)?;
        if name.eq_ignore_ascii_case("windows.db") && kind == DetectedFileType::SqliteDatabase {
            return Ok(vec![Self::windows_db_refusal(
                artifact.case_id,
                artifact.id,
                &name,
            )]);
        }
        let named = name.eq_ignore_ascii_case("windows.edb");
        if kind != DetectedFileType::EseDatabase {
            if named {
                return Ok(vec![Self::marker(
                    artifact.case_id,
                    artifact.id,
                    &name,
                    "NotDecoded",
                    "not decoded: the file is named like the Search index but is not an ESE \
                     database (its header lacks the ESE signature), so no item in it was read \
                     (this is not a finding that the index was empty)",
                )]);
            }
            return Ok(Vec::new());
        }
        let source = if name.is_empty() {
            "Windows.edb"
        } else {
            name.as_str()
        };
        let size = ds.size();
        if size > MAX_INDEX_BYTES {
            if source.eq_ignore_ascii_case("windows.edb") {
                return Ok(vec![Self::marker(
                    artifact.case_id,
                    artifact.id,
                    source,
                    "NotDecoded",
                    &format!("not decoded: {size} bytes exceeds the {MAX_INDEX_BYTES}-byte cap"),
                )]);
            }
            return Ok(Vec::new());
        }
        // Staged in chunks rather than buffered whole: every ESE database in
        // a case reaches here, and only the header's state field is needed in
        // memory. A failure is a "could not look" for a file named like the
        // index; any other database is simply not this module's.
        let (spill, header) = match stage(ds.as_ref()) {
            Ok(v) => v,
            Err(why) => {
                if named {
                    return Ok(vec![Self::marker(
                        artifact.case_id,
                        artifact.id,
                        source,
                        "NotDecoded",
                        &format!("not decoded: {why}; no item in it was read"),
                    )]);
                }
                return Ok(Vec::new());
            }
        };
        Ok(Self::records_for_db(
            artifact.case_id,
            artifact.id,
            source,
            spill.path(),
            &header,
        ))
    }
}

#[cfg(test)]
mod tests;
