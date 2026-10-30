//! Core artifact types and definitions for digital forensics.
//!
//! This module defines the fundamental data structures used throughout the Seance
//! forensics framework. The [`Artifact`] type is the primary unit of work that flows
//! through the processing pipeline.
//!
//! # Architecture Overview
//!
//! Artifacts form a hierarchical tree structure:
//! ```text
//! Container (E01, ZIP)
//!   └── RawEvidence (disk image)
//!         ├── Partition (GPT/MBR)
//!         │     └── FileSystem (NTFS, Ext4)
//!         │           └── FileEntry (file metadata)
//!         │                 └── SystemArtifact ($MFT, Registry)
//!         │                       └── ParsedRecord (extracted data)
//!         │                             └── TimelineEvent (normalized event)
//!         └── UnallocatedSpace (gaps between partitions)
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use seance_core::artifact::{Artifact, ArtifactType};
//! use uuid::Uuid;
//! use serde_json::json;
//!
//! let case_id = Uuid::new_v4();
//! let artifact = Artifact::new(
//!     case_id,
//!     ArtifactType::FileEntry,
//!     None,
//!     json!({"name": "document.txt", "size": 1024}),
//! );
//! ```

use crate::data_source::DataSource;
use anyhow::Error as AnyhowError;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use uuid::Uuid;

/// Classification of artifacts in the forensic processing pipeline.
///
/// Artifacts progress through a hierarchy from raw evidence containers down to
/// normalized timeline events. Each type represents a different level of processing
/// and abstraction.
///
/// # Processing Flow
///
/// 1. **Container** - Archive formats that wrap other data
/// 2. **RawEvidence** - Disk images or physical storage devices
/// 3. **Partition** - Logical partitions within storage
/// 4. **FileSystem** - Mounted file systems
/// 5. **FileEntry** - Individual file records with metadata
/// 6. **SystemArtifact** - Forensically significant files (MFT, Registry, EVTX)
/// 7. **ParsedRecord** - Extracted structured data from system artifacts
/// 8. **TimelineEvent** - Normalized events ready for timeline display
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactType {
    /// Container formats that wrap other data (E01, ZIP, TAR, 7Z, RAR)
    Container,
    /// Raw storage devices or disk images (DD, VHD, VMDK, physical disks)
    RawEvidence,
    /// A defined region of a disk (MBR partition, GPT partition)
    Partition,
    /// An identified filesystem (NTFS, Ext4, FAT32, APFS, HFS+)
    FileSystem,
    /// A file record with metadata (path, timestamps, permissions)
    FileEntry,
    /// The actual bytestream content of a file
    FileContent,
    /// Forensically interesting system files ($MFT, Registry, EVTX, SQLite)
    SystemArtifact,
    /// Parsed structured records (chat messages, browser history entries)
    ParsedRecord,
    /// Final normalized events for timeline UI
    TimelineEvent,
    /// Unallocated disk space between/around partitions, suitable for carving
    UnallocatedSpace,
    /// The unused tail of one live file's last allocated cluster (file slack),
    /// from the file's logical end to the end of that cluster
    /// (`seance_core::slack`, HUNT-124).
    ///
    /// Deliberately NOT [`UnallocatedSpace`](Self::UnallocatedSpace): slack is
    /// allocated to a live file, so a consumer that totals free space must not
    /// be able to count it by accident. Its own type makes every exhaustive
    /// match decide what slack means to it.
    SlackSpace,
}

/// Metadata key a [`FileEntry`](ArtifactType::FileEntry) producer sets to
/// `true` to declare that it emits its OWN timeline events for that file's
/// timestamps.
///
/// The storage layer projects a file's `created`/`modified`/`accessed`/
/// `changed`/`mft_modified`/`deleted_time` metadata onto the unified timeline,
/// so that a filesystem parser earns a timeline without writing one. A parser
/// that already builds richer events itself — the $MFT parser emits both
/// $STANDARD_INFORMATION and $FILE_NAME sets, carrying which attribute each
/// timestamp came from and the timestomping verdict — must set this key, or
/// every one of its files would be reported twice at the same instant.
///
/// Setting it is a promise: the producer emits an event for EVERY timestamp it
/// writes into the entry's metadata. A producer that covers only some of them
/// must leave this unset and let the projection cover all of them, because a
/// half-kept promise here is a timestamp that exists in the evidence and
/// appears nowhere on the timeline.
pub const FILE_TIMELINE_SELF_EMITTED_KEY: &str = "timeline_events_emitted";

impl fmt::Display for ArtifactType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl FromStr for ArtifactType {
    type Err = AnyhowError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Container" => Ok(ArtifactType::Container),
            "RawEvidence" => Ok(ArtifactType::RawEvidence),
            "Partition" => Ok(ArtifactType::Partition),
            "FileSystem" => Ok(ArtifactType::FileSystem),
            "FileEntry" => Ok(ArtifactType::FileEntry),
            "FileContent" => Ok(ArtifactType::FileContent),
            "SystemArtifact" => Ok(ArtifactType::SystemArtifact),
            "ParsedRecord" => Ok(ArtifactType::ParsedRecord),
            "TimelineEvent" => Ok(ArtifactType::TimelineEvent),
            "UnallocatedSpace" => Ok(ArtifactType::UnallocatedSpace),
            "SlackSpace" => Ok(ArtifactType::SlackSpace),
            _ => Err(anyhow::anyhow!("Unknown ArtifactType: {}", s)),
        }
    }
}

/// The primary unit of work in the Seance forensics pipeline.
///
/// An `Artifact` represents any discoverable item during forensic analysis, from
/// raw disk images to individual parsed records. Artifacts are immutable once created
/// and flow through the processing pipeline where modules can produce new child artifacts.
///
/// # Structure
///
/// - **id**: Globally unique identifier for this artifact
/// - **case_id**: Links the artifact to a specific investigation case
/// - **parent_id**: Establishes chain of custody (lineage) to parent artifact
/// - **artifact_type**: Classification determining processing behavior
/// - **data**: Optional lazy data source for reading content
/// - **metadata**: Structured JSON containing type-specific details
///
/// # Chain of Custody
///
/// The `parent_id` field establishes provenance. When a module processes an artifact
/// and produces derived artifacts, each child references the parent, creating an
/// auditable chain from raw evidence to final findings.
///
/// # Example
///
/// ```rust,ignore
/// use seance_core::artifact::{Artifact, ArtifactType};
/// use uuid::Uuid;
/// use serde_json::json;
///
/// let case_id = Uuid::new_v4();
/// let file_artifact = Artifact::new(
///     case_id,
///     ArtifactType::FileEntry,
///     None,
///     json!({
///         "name": "NTUSER.DAT",
///         "path": "/Users/suspect/NTUSER.DAT",
///         "size": 262144,
///         "modified": "2024-01-15T10:30:00Z"
///     }),
/// );
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    /// Globally unique identifier for this artifact.
    pub id: Uuid,

    /// Case identifier linking this artifact to a specific investigation.
    /// All artifacts in a case share this ID for filtering and organization.
    pub case_id: Uuid,

    /// Parent artifact ID establishing chain of custody.
    /// `None` for root artifacts (initial evidence).
    pub parent_id: Option<Uuid>,

    /// Classification determining how this artifact is processed and displayed.
    pub artifact_type: ArtifactType,

    /// Optional data source for reading artifact content.
    /// Uses lazy loading - data is only read when accessed.
    /// `None` for metadata-only artifacts like `TimelineEvent`.
    #[serde(skip)]
    pub data: Option<Arc<dyn DataSource>>,

    /// Structured metadata in JSON format.
    /// Contains type-specific fields like file names, timestamps, paths, etc.
    pub metadata: serde_json::Value,
}

impl Artifact {
    /// Creates a new artifact with a generated UUID.
    ///
    /// # Arguments
    ///
    /// * `case_id` - The investigation case this artifact belongs to
    /// * `artifact_type` - Classification of the artifact
    /// * `data` - Optional data source for reading content. **This is not the
    ///   parent.** The third argument is where the artifact's *bytes* come
    ///   from; an artifact with no content of its own passes `None`. The parent
    ///   is set separately with [`Artifact::with_parent`], because a great many
    ///   artifacts have a parent and no data, and threading both through one
    ///   positional list is what makes them easy to confuse. Passing a parent id
    ///   here is a type error rather than a silent misfiling, but it has been
    ///   written by mistake often enough to be worth saying outright.
    /// * `metadata` - Structured metadata as JSON
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // A parsed record: no bytes of its own, parented to the file it came from.
    /// let artifact = Artifact::new(
    ///     case_id,
    ///     ArtifactType::ParsedRecord,
    ///     None,
    ///     json!({"type": "EvtxEvent", "event_id": 4624}),
    /// )
    /// .with_parent(source_file.id);
    /// ```
    pub fn new(
        case_id: Uuid,
        artifact_type: ArtifactType,
        data: Option<Arc<dyn DataSource>>,
        metadata: serde_json::Value,
    ) -> Self {
        Self {
            id: Uuid::new_v4(),
            case_id,
            parent_id: None,
            artifact_type,
            data,
            metadata,
        }
    }

    /// Sets the parent artifact ID, establishing chain of custody.
    ///
    /// This builder method consumes and returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let child = Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
    ///     .with_parent(parent_artifact.id);
    /// ```
    pub fn with_parent(mut self, parent_id: Uuid) -> Self {
        self.parent_id = Some(parent_id);
        self
    }

    /// Gets the subtype from metadata.
    ///
    /// Subtypes provide additional classification within an artifact type,
    /// such as "ntfs" for a `FileSystem` or "evtx" for a `SystemArtifact`.
    ///
    /// # Returns
    ///
    /// The subtype string if present in metadata, otherwise `None`.
    pub fn subtype(&self) -> Option<&str> {
        self.metadata.get("subtype").and_then(|v| v.as_str())
    }

    /// Sets the subtype in metadata.
    ///
    /// This builder method consumes and returns `self` for method chaining.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let fs_artifact = Artifact::new(case_id, ArtifactType::FileSystem, data, metadata)
    ///     .with_subtype("ntfs");
    /// ```
    pub fn with_subtype(mut self, subtype: &str) -> Self {
        if let Some(obj) = self.metadata.as_object_mut() {
            obj.insert("subtype".to_string(), serde_json::json!(subtype));
        }
        self
    }
}

/// A human label for one artifact, for lists an examiner scans.
///
/// `ParsedRecord` is the largest artifact class in most cases — 556,020 of
/// 580,394 in one handset backup — and every one of them showed as the literal
/// word "ParsedRecord" in search results and recent-activity lists, because the
/// only name considered was a `name` key most parsers do not write. A column of
/// identical type names discriminates nothing; the record's own subject was
/// sitting in its metadata the whole time (LIVE-022).
///
/// The chain runs most-specific first: an explicit `name`, then the file the
/// record is about, then the kind of record it is, and only then the artifact
/// type — which is the answer that carries no information and so is last.
pub fn display_name(artifact_type: &str, metadata: &serde_json::Value) -> String {
    let text = |key: &str| {
        metadata
            .get(key)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
    };

    if let Some(name) = text("name") {
        return name.to_string();
    }

    // The file this record was read out of, however the parser spelled it.
    let subject = text("source_path")
        .or_else(|| text("path"))
        .and_then(|p| {
            std::path::Path::new(p)
                .file_name()
                .and_then(|n| n.to_str())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| text("source_name"))
        .or_else(|| text("filename"));

    // What kind of record it is. `subtype` is the narrower of the two.
    let kind = text("subtype")
        .or_else(|| text("record_type"))
        .or_else(|| text("analysis_type"))
        .or_else(|| text("type"));

    match (kind, subject) {
        (Some(kind), Some(subject)) => format!("{kind}: {subject}"),
        (Some(kind), None) => kind.to_string(),
        (None, Some(subject)) => subject.to_string(),
        (None, None) => artifact_type.to_string(),
    }
}

#[cfg(test)]
mod display_name_tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn an_explicit_name_wins() {
        assert_eq!(
            display_name(
                "ParsedRecord",
                &json!({"name": "Last login", "type": "utmp"})
            ),
            "Last login"
        );
    }

    /// The case that produced the bug: an EXIF record names its file with
    /// `source_name`, which nothing in the old chain looked at.
    #[test]
    fn an_exif_record_is_named_for_its_kind_and_its_file() {
        assert_eq!(
            display_name(
                "ParsedRecord",
                &json!({"type": "exif", "source_name": "FullSizeRender.jpg"})
            ),
            "exif: FullSizeRender.jpg"
        );
    }

    #[test]
    fn a_subtype_is_preferred_over_the_broad_type() {
        assert_eq!(
            display_name(
                "ParsedRecord",
                &json!({
                    "type": "FileSignatureAnalysis",
                    "subtype": "FileSignatureAnalysis",
                    "filename": "RSA_Root_Certificate.crt"
                })
            ),
            "FileSignatureAnalysis: RSA_Root_Certificate.crt"
        );
    }

    #[test]
    fn a_path_is_reduced_to_its_file_name() {
        assert_eq!(
            display_name(
                "ParsedRecord",
                &json!({"type": "plist", "source_path": "/Library/Preferences/com.apple.Safari.plist"})
            ),
            "plist: com.apple.Safari.plist"
        );
    }

    #[test]
    fn a_record_with_only_a_kind_is_named_for_it() {
        assert_eq!(
            display_name("ParsedRecord", &json!({"type": "CallLog"})),
            "CallLog"
        );
    }

    /// Only when the record says nothing about itself does the type stand in —
    /// and then it is the honest answer, not a default that hid a better one.
    #[test]
    fn a_record_that_says_nothing_falls_back_to_its_type() {
        assert_eq!(
            display_name("ParsedRecord", &json!({"count": 3})),
            "ParsedRecord"
        );
    }

    #[test]
    fn blank_strings_do_not_count_as_an_answer() {
        assert_eq!(
            display_name(
                "ParsedRecord",
                &json!({"name": "  ", "type": "exif", "source_name": "a.jpg"})
            ),
            "exif: a.jpg"
        );
    }
}
