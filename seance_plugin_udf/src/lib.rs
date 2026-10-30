#![forbid(unsafe_code)]
//! UDF (ECMA-167 / OSTA Universal Disk Format) reader.
//!
//! Reads a UDF volume presented as a whole-volume `DataSource` and emits one
//! `FileEntry` per file and directory, with content served from the file's
//! extents (never materialised in memory).
//!
//! What it reads: the anchor at sector 256 / N-1 / N-257 with 2048-, 512-,
//! 1024- or 4096-byte sectors, and every partition-map kind UDF defines up to
//! 2.50: physical (Type 1), virtual (`*UDF Virtual Partition`, write-once
//! media, through the Virtual Allocation Table in the last recorded block),
//! sparable (`*UDF Sparable Partition`, rewritable media, through the
//! verified sparing table with the highest sequence number) and metadata
//! (`*UDF Metadata Partition`, UDF 2.50+, through the metadata file, or its
//! mirror when the main copy is unreadable). See `partition` and `resolve`.
//! Graded on the Windows 11 UDF 1.02 bridge ISO (real) and on self-made
//! makefs/mkudffs volumes of UDF 1.50, 2.01 and 2.50 (not real discs): see
//! `tests/`. No 1024-byte-sector volume has been read.
//!
//! What it refuses, by name: a Type 2 map of any other kind, a known kind
//! whose structures cannot be read (no VAT found, no sparing table verified,
//! neither metadata file readable), ICB strategies other than 4, and
//! extended allocation descriptors.
//!
//! Multisession: on a VAT volume the newest VAT describes the last session,
//! so an image holding every session in order is read as last written;
//! earlier VATs named through the previous-VAT field are located and
//! counted (`vat_earlier_icb_lbns`), not walked. If the image ends early, an
//! earlier VAT is the last one in it and that earlier state is what is read.
//! A multisession disc not joined by a VAT is read only as the session the
//! anchor names; other sessions are neither read nor detected.
//!
//! References: ECMA-167 3rd edition; OSTA UDF 1.02, 1.50, 2.01 and 2.50.

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::info;

pub mod cs0;
pub mod descriptors;
pub mod partition;
mod resolve;
pub mod tag;
pub mod timestamp;
mod walk;

#[cfg(test)]
mod test_builder;

pub struct UdfParser;

impl UdfParser {
    fn applies(artifact: &Artifact) -> bool {
        artifact.subtype() == Some("udf")
            || artifact
                .metadata
                .get("filesystem_type")
                .and_then(|v| v.as_str())
                .is_some_and(|s| s.eq_ignore_ascii_case("UDF"))
    }
}

impl ForensicsModule for UdfParser {
    fn id(&self) -> &str {
        "plugin.filesystem.udf"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileSystem]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if !Self::applies(artifact) {
            return Ok(Vec::new());
        }
        info!("UDF parser processing filesystem artifact {}", artifact.id);
        let ds = artifact.data.as_ref().ok_or_else(|| {
            ModuleError::InvalidInputFormat("UDF parser requires a data source".to_string())
        })?;

        // The volume-level record: what the volume structure said, and, when
        // the volume could not be read, why. A refusal is a record, never
        // silence, because an empty inventory reads as an empty disc.
        let mut vol = json!({ "type": "udf_volume", "filesystem_type": "UDF" });
        let refuse = |mut vol: serde_json::Value, reason: String| {
            vol["udf_unreadable"] = json!(true);
            vol["udf_unreadable_reason"] = json!(reason);
            Ok(vec![Self::volume_record(artifact, vol)])
        };

        let anchor = match descriptors::find_anchor(ds.as_ref()) {
            Ok(a) => a,
            Err(e) => return refuse(vol, e),
        };
        vol["anchor_sector"] = json!(anchor.sector);
        vol["sector_size"] = json!(anchor.sector_size);
        let volume = match descriptors::read_vds(ds.as_ref(), anchor.main, anchor.sector_size) {
            Ok(v) => {
                vol["volume_descriptor_sequence"] = json!("main");
                v
            }
            Err(main_err) => {
                vol["main_volume_descriptor_sequence_error"] = json!(main_err);
                match descriptors::read_vds(ds.as_ref(), anchor.reserve, anchor.sector_size) {
                    Ok(v) => {
                        vol["volume_descriptor_sequence"] = json!("reserve");
                        v
                    }
                    Err(e) => {
                        return refuse(
                            vol,
                            format!("main sequence: {main_err}; reserve sequence: {e}"),
                        )
                    }
                }
            }
        };
        for (key, value) in [
            ("volume_identifier", &volume.volume_identifier),
            ("volume_set_identifier", &volume.volume_set_identifier),
            ("recorded", &volume.recorded),
        ] {
            if let Some(v) = value {
                vol[key] = json!(v);
            }
        }
        vol["logical_volume_identifier"] = json!(volume.logical_volume_identifier);
        vol["domain_identifier"] = json!(volume.domain_identifier);
        vol["block_size"] = json!(volume.block_size);
        if let Some(r) = volume.udf_revision {
            vol["udf_revision"] = json!(format!("{:x}.{:02x}", r >> 8, r & 0xFF));
        }
        if let Some(p) = volume.partitions.first() {
            vol["partition_start"] = json!(p.start);
            vol["partition_length"] = json!(p.length);
            vol["partition_contents"] = json!(p.contents);
            // A truncated acquisition: the partition runs past the end of
            // the evidence. Entries whose extents lie beyond it are flagged
            // one by one; the volume says so too.
            let end = (p.start as u64 + p.length as u64).saturating_mul(volume.block_size as u64);
            if end > ds.size() {
                vol["partition_extends_past_evidence"] = json!(true);
                vol["evidence_size"] = json!(ds.size());
            }
        }
        // UDF records the logical block size equal to the sector size
        // (OSTA UDF 2.1.5.1); a volume that says otherwise is not guessed at.
        if volume.block_size as u64 != anchor.sector_size {
            return refuse(
                vol,
                format!(
                    "logical block size {} differs from the sector size {} the anchor was found at",
                    volume.block_size, anchor.sector_size
                ),
            );
        }
        let block_size = volume.block_size as u64;
        let parts = match resolve::resolve(ds, &volume, block_size, &mut vol) {
            Ok(p) => p,
            Err(e) => {
                // A map of a kind this reader does not know is named as
                // unsupported; a known kind whose structures could not be
                // read (no VAT, no verifiable sparing table, neither
                // metadata file) is named as unresolved.
                let (key, name) = match e {
                    resolve::MapError::Unsupported(n) => ("udf_unsupported_partition_map", n),
                    resolve::MapError::Unresolved(n) => ("udf_partition_map_unresolved", n),
                };
                vol[key] = json!(name);
                return refuse(vol, format!("partition map not read: {name}"));
            }
        };
        let fileset = match resolve::read_file_set(ds.as_ref(), &parts, volume.fsd) {
            Ok(f) => f,
            Err(e) => return refuse(vol, e),
        };
        vol["file_set_identifier"] = json!(fileset.file_set_identifier);

        let mut walker = walk::Walker::new(ds, block_size, &parts, artifact.case_id, artifact.id);
        let root_status = walker.walk_root(fileset.root);
        vol["entries_emitted"] = json!(walker.produced.len());
        vol["records_seen"] = json!(walker.records_seen);
        if walker.any_incomplete {
            vol["directory_parse_incomplete"] = json!(true);
            if let Some(r) = root_status.or(walker.first_incomplete_reason) {
                vol["directory_parse_incomplete_reason"] = json!(r);
            }
        }
        info!("UDF parser produced {} file entries", walker.produced.len());
        let mut out = walker.produced;
        out.push(Self::volume_record(artifact, vol));
        Ok(out)
    }
}

impl UdfParser {
    fn volume_record(fs: &Artifact, meta: serde_json::Value) -> Artifact {
        Artifact::new(fs.case_id, ArtifactType::ParsedRecord, None, meta).with_parent(fs.id)
    }
}

#[cfg(test)]
mod tests;
