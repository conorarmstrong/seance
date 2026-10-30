//! How long a recording is, and when the device says it was made.
//!
//! An audio or video file's own header carries two facts a case turns on more
//! often than its bytes do: **how long it runs**, and **when the recorder wrote
//! it**. Séance listed media files with neither — a folder of `.m4a` podcasts
//! and `.mp4` clips was a folder of sizes — so a question as ordinary as "how
//! long was the recording" could not be answered from the evidence that holds
//! the answer (`HUNT-097`).
//!
//! This reads the ISO base media file format (MP4, M4A, M4V, MOV, 3GP): the
//! `moov/mvhd` movie header, which every file in the family has and which
//! carries the timescale, the duration in that scale, and the creation and
//! modification times.
//!
//! Two things it is careful about, because both are ways to state a confident
//! falsehood:
//!
//! * **The epoch.** ISO-BMFF counts seconds from 1904-01-01 UTC. Read as a Unix
//!   time, every media file in a case is dated 66 years early.
//! * **The zeroes.** A writer that has no time to store writes 0, and a file
//!   whose `moov` was never written (an interrupted recording) has no duration
//!   at all. Neither becomes a date of 1904 or a duration of zero: the first is
//!   absent, the second is declared with the incompleteness pair.

#![forbid(unsafe_code)]

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

/// Seconds between 1904-01-01 and 1970-01-01, both UTC. ISO-BMFF counts from
/// the first; everything else in this product counts from the second.
const EPOCH_1904_TO_1970: i64 = 2_082_844_800;

/// How far into the file to look for `moov`. It is normally first or last; a
/// file that hides it past this is not read rather than being walked forever.
const MAX_SCAN_BYTES: u64 = 256 * 1024 * 1024;

/// Ceiling on a single box this reader will pull into memory.
const MAX_BOX_BYTES: u64 = 64 * 1024 * 1024;

/// Reads media container headers into duration and recording times.
#[derive(Debug, Default)]
pub struct MediaPropertiesModule;

impl MediaPropertiesModule {
    pub fn new() -> Self {
        Self
    }
}

/// The movie header's facts, as read.
#[derive(Debug, Default, PartialEq)]
pub struct MovieHeader {
    pub created: Option<i64>,
    pub modified: Option<i64>,
    pub timescale: u32,
    pub duration_units: u64,
}

impl MovieHeader {
    /// Duration in seconds, or `None` when the timescale makes it unanswerable.
    pub fn duration_seconds(&self) -> Option<f64> {
        if self.timescale == 0 {
            return None;
        }
        Some(self.duration_units as f64 / self.timescale as f64)
    }
}

/// `HH:MM:SS`, the form a human reads a running time in.
pub fn hms(seconds: f64) -> String {
    let total = seconds.round().max(0.0) as u64;
    format!(
        "{:02}:{:02}:{:02}",
        total / 3600,
        (total % 3600) / 60,
        total % 60
    )
}

/// A 1904-epoch timestamp as Unix seconds, or `None` when it was never set.
fn from_1904(value: u64) -> Option<i64> {
    // 0 is what a writer stores when it has nothing to store.
    if value == 0 {
        return None;
    }
    Some(value as i64 - EPOCH_1904_TO_1970)
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_be_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn be64(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_be_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Decode a `mvhd` payload (the bytes after the box header).
pub fn parse_mvhd(payload: &[u8]) -> Option<MovieHeader> {
    let version = *payload.first()?;
    match version {
        0 => Some(MovieHeader {
            created: from_1904(be32(payload, 4)? as u64),
            modified: from_1904(be32(payload, 8)? as u64),
            timescale: be32(payload, 12)?,
            duration_units: be32(payload, 16)? as u64,
        }),
        1 => Some(MovieHeader {
            created: from_1904(be64(payload, 4)?),
            modified: from_1904(be64(payload, 12)?),
            timescale: be32(payload, 20)?,
            duration_units: be64(payload, 24)?,
        }),
        // A version this reader does not know is not guessed at: the fields
        // move between versions, and reading v2 at v1's offsets would report a
        // confident wrong duration.
        _ => None,
    }
}

/// One box header: (payload offset, payload length, type).
fn read_box_header(
    source: &dyn seance_core::data_source::DataSource,
    at: u64,
) -> Option<(u64, u64, [u8; 4])> {
    let mut head = [0u8; 16];
    let read = source.read_at(at, &mut head).ok()?;
    if read < 8 {
        return None;
    }
    let size32 = u32::from_be_bytes(head[0..4].try_into().ok()?) as u64;
    let mut kind = [0u8; 4];
    kind.copy_from_slice(&head[4..8]);
    let (payload_at, payload_len) = match size32 {
        // 1: the real size is the 64-bit largesize that follows.
        1 => {
            if read < 16 {
                return None;
            }
            let large = u64::from_be_bytes(head[8..16].try_into().ok()?);
            (at + 16, large.checked_sub(16)?)
        }
        // 0: this box runs to the end of the file.
        0 => (at + 8, source.size().saturating_sub(at + 8)),
        n if n >= 8 => (at + 8, n - 8),
        // A size that cannot even hold its own header is corrupt; stopping is
        // the only safe move, because the next box cannot be located.
        _ => return None,
    };
    Some((payload_at, payload_len, kind))
}

/// Find `moov/mvhd` by walking the top-level boxes, then `moov`'s children.
fn find_mvhd(source: &dyn seance_core::data_source::DataSource) -> Option<Vec<u8>> {
    let end = source.size().min(MAX_SCAN_BYTES);
    let mut at = 0u64;
    while at < end {
        let (payload_at, payload_len, kind) = read_box_header(source, at)?;
        if &kind == b"moov" {
            let moov_end = payload_at.checked_add(payload_len)?;
            let mut inner = payload_at;
            while inner < moov_end {
                let (child_at, child_len, child_kind) = read_box_header(source, inner)?;
                if &child_kind == b"mvhd" {
                    let want = child_len.min(MAX_BOX_BYTES) as usize;
                    let mut buf = vec![0u8; want];
                    let read = source.read_at(child_at, &mut buf).ok()?;
                    buf.truncate(read);
                    return Some(buf);
                }
                inner = child_at.checked_add(child_len)?;
            }
            return None;
        }
        at = payload_at.checked_add(payload_len)?;
    }
    None
}

/// The `ftyp` brand, which is what says this file is one of the family.
fn major_brand(source: &dyn seance_core::data_source::DataSource) -> Option<String> {
    let (payload_at, payload_len, kind) = read_box_header(source, 0)?;
    if &kind != b"ftyp" || payload_len < 4 {
        return None;
    }
    let mut brand = [0u8; 4];
    source.read_at(payload_at, &mut brand).ok()?;
    Some(String::from_utf8_lossy(&brand).to_string())
}

fn rfc3339(unix: i64) -> Option<String> {
    chrono::DateTime::from_timestamp(unix, 0).map(|d| d.to_rfc3339())
}

impl ForensicsModule for MediaPropertiesModule {
    fn id(&self) -> &str {
        "plugin.media.properties"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let Some(data) = artifact.data.as_ref() else {
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
        // The brand is what makes this file one of the family. A name is not
        // evidence of a format, and a file that merely ends in `.mp4` and holds
        // something else must not be claimed (the HUNT-084 shape).
        let Some(brand) = major_brand(data.as_ref()) else {
            return Ok(Vec::new());
        };

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .and_then(|v| v.as_str())
            .unwrap_or(name);

        let header = find_mvhd(data.as_ref()).and_then(|payload| parse_mvhd(&payload));

        let mut metadata = serde_json::Map::new();
        metadata.insert("type".into(), json!("MediaProperties"));
        metadata.insert("name".into(), json!(format!("Media properties: {name}")));
        metadata.insert("source_file".into(), json!(path));
        metadata.insert("container".into(), json!("iso_bmff"));
        metadata.insert("major_brand".into(), json!(brand));

        match header {
            Some(header) => {
                metadata.insert("timescale".into(), json!(header.timescale));
                metadata.insert("duration_units".into(), json!(header.duration_units));
                match header.duration_seconds() {
                    Some(seconds) => {
                        metadata.insert("duration_seconds".into(), json!(seconds));
                        metadata.insert("duration_hms".into(), json!(hms(seconds)));
                    }
                    None => {
                        // A timescale of zero makes the duration unanswerable.
                        // Reporting 0 seconds would be a claim about the
                        // recording rather than about this header.
                        metadata.insert(CONTENT_INCOMPLETE.into(), json!(true));
                        metadata.insert(
                            CONTENT_INCOMPLETE_REASON.into(),
                            json!(IncompleteReason::UnresolvedStructure.as_str()),
                        );
                        metadata.insert(
                            "content_incomplete_detail".into(),
                            json!(
                                "the movie header declares a timescale of zero, so the duration \
                                 it records cannot be converted to seconds"
                            ),
                        );
                    }
                }
                if let Some(created) = header.created.and_then(rfc3339) {
                    metadata.insert("created".into(), json!(created));
                }
                if let Some(modified) = header.modified.and_then(rfc3339) {
                    metadata.insert("modified".into(), json!(modified));
                }
            }
            None => {
                debug!("{name}: no readable movie header");
                metadata.insert(CONTENT_INCOMPLETE.into(), json!(true));
                metadata.insert(
                    CONTENT_INCOMPLETE_REASON.into(),
                    json!(IncompleteReason::UnresolvedStructure.as_str()),
                );
                metadata.insert(
                    "content_incomplete_detail".into(),
                    json!(
                        "this file has no readable `moov`/`mvhd` movie header — an interrupted \
                         recording looks exactly like this — so how long it runs and when it was \
                         recorded are not in the evidence rather than being zero"
                    ),
                );
            }
        }

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::Value::Object(metadata),
        )
        .with_parent(artifact.id)])
    }
}

#[cfg(test)]
mod tests;
