#![forbid(unsafe_code)]
//! SquashFS filesystem parser, registered as a [`ForensicsModule`].
//!
//! A SquashFS image (Android system partitions, live-CD/appliance roots,
//! firmware) enters the pipeline as raw evidence or a `.sqfs`/`.squashfs` file;
//! this reader enumerates its tree as `FileEntry` artifacts with content
//! attached, so the carver, hasher, search and every downstream parser see the
//! files inside. The reader itself is in [`squashfs`].

pub mod squashfs;

pub use squashfs::{SquashError, SquashReader, SuperBlock};

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

/// Largest image this reader will pull into memory to parse.
const MAX_IMAGE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Per-file content-extraction cap; larger files get metadata only.
const CONTENT_CAP: u64 = 256 * 1024 * 1024;

pub struct SquashFsParser;

impl ForensicsModule for SquashFsParser {
    fn id(&self) -> &str {
        "plugin.fs.squashfs"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // `FileSystem` is how a SquashFS volume inside a partition arrives:
        // the file-system detector recognises the magic in the partition
        // window and hands it on with subtype `squashfs` (HUNT-174). A bare
        // image arrives as `RawEvidence`, and one stored as a file as
        // `FileEntry`.
        vec![
            ArtifactType::RawEvidence,
            ArtifactType::FileEntry,
            ArtifactType::FileSystem,
        ]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }
    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // A FileSystem the detector named as something else is not ours.
        if artifact.artifact_type == ArtifactType::FileSystem
            && artifact.subtype() != Some("squashfs")
        {
            return Ok(Vec::new());
        }
        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };
        // Cheap magic pre-check before pulling the whole image into memory.
        let mut head = [0u8; 48];
        let head_len = data.read_at(0, &mut head).unwrap_or(0);
        if head_len < 4 || head[..4] != *b"hsqs" {
            return Ok(Vec::new());
        }
        // A volume inside a partition is followed by the rest of the
        // partition. The superblock's `bytes_used` says where the image ends,
        // so only that much is read (rounded up to the 4 KiB the tools pad
        // to); a count past the end of the source reads what is there, as a
        // bare image always did.
        let mut size = data.size();
        if head_len >= 48 {
            let bytes_used = u64::from_le_bytes(head[40..48].try_into().unwrap());
            if bytes_used >= 96 {
                size = size.min(bytes_used.div_ceil(4096).saturating_mul(4096));
            }
        }
        if size > MAX_IMAGE_BYTES {
            return Ok(vec![note(
                artifact,
                json!({
                    "type": "SquashFsSkipped",
                    "reason": "image larger than the in-memory parse cap",
                    "size": size,
                }),
            )]);
        }
        let mut image = vec![0u8; size as usize];
        let mut got = 0usize;
        while got < image.len() {
            match data.read_at(got as u64, &mut image[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => return Err(ModuleError::ParsingError(e.to_string())),
            }
        }
        image.truncate(got);
        // Shared (not copied per file) so every FileEntry's lazy content
        // reader can hold a reference to the same bytes without the image
        // being re-read or duplicated per file.
        let image: Arc<[u8]> = Arc::from(image);

        let reader = match SquashReader::open(image) {
            Ok(r) => r,
            Err(SquashError::NotSquashfs) => return Ok(Vec::new()),
            Err(e) => {
                warn!("SquashFS parse failed: {e}");
                return Ok(vec![note(
                    artifact,
                    json!({ "type": "SquashFsError", "error": e.to_string() }),
                )]);
            }
        };
        let entries = reader
            .entries(CONTENT_CAP)
            .map_err(|e| ModuleError::ParsingError(e.to_string()))?;
        debug!("SquashFS: {} entries", entries.len());

        let mut out = Vec::with_capacity(entries.len() + 1);
        out.push(note(
            artifact,
            json!({
                "type": "SquashFsVolume",
                "subtype": "filesystem",
                "compression": format!("{:?}", reader.superblock().compression),
                "block_size": reader.superblock().block_size,
                "inode_count": reader.superblock().inode_count,
                "entry_count": entries.len(),
            }),
        ));
        for e in entries {
            let mut meta = json!({
                "name": e.path.rsplit('/').next().unwrap_or(&e.path),
                "path": e.path,
                "is_directory": e.is_dir,
                "size": e.size,
                "filesystem": "squashfs",
            });
            if e.mtime != 0 {
                meta["mtime"] = json!(e.mtime);
                // Same instant under the key the rest of the app reads. The
                // file grid's date column, sorting, and the timeline projection
                // all look for `modified`; a SquashFS image that published only
                // the raw inode field name showed every file as undated and put
                // nothing on the timeline.
                meta["modified"] = json!(e.mtime);
            } else {
                // HUNT-174: a zero inode time is what `mksquashfs -all-time 0`
                // and reproducible builds (SOURCE_DATE_EPOCH=0) write. It says
                // no time was recorded, not that the file was modified in the
                // first second of 1970, so it is kept off the timeline and
                // said so.
                meta["mtime_not_recorded"] = json!(true);
            }
            if e.is_symlink {
                meta["symlink_target"] = json!(e.symlink_target);
            }
            // Already a lazy on-demand reader (see `squashfs::SquashFileSource`);
            // nothing here decompresses the file's content.
            let content = e.content;
            out.push(
                Artifact::new(artifact.case_id, ArtifactType::FileEntry, content, meta)
                    .with_parent(artifact.id),
            );
        }
        Ok(out)
    }
}

fn note(parent: &Artifact, meta: serde_json::Value) -> Artifact {
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, meta).with_parent(parent.id)
}
