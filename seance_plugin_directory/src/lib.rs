//! A folder of files is evidence, and until this module it read as nothing.
//!
//! Séance reads containers: disk images, archives, and the few formats whose
//! own parser walks a directory (an iOS backup). Point it at a **folder** — an
//! unpacked extraction, a Google Takeout, a logical acquisition, a mounted
//! share, the way an examiner actually receives half the material they are sent
//! — and it produced one `RawEvidence` artifact and nothing under it
//! (`HUNT-096`).
//!
//! This walks the tree and produces the file entries the rest of the pipeline
//! expects, carrying what the filesystem knows about each file: size, the three
//! timestamps, the permission bits and the owning ids. Those are the only
//! record of a file's history that a logical acquisition has.
//!
//! What it refuses to do:
//!
//! * **Follow symlinks.** A link is recorded as a link, with its target, and is
//!   not walked: following one leaves the evidence tree — a link to `/etc` would
//!   pull the examiner's own machine into the case — and can loop forever.
//! * **Walk a directory another parser owns.** An iOS backup is a folder, and
//!   its own reader turns `ab/abcdef…` blobs into named files with content. The
//!   walker would emit the blobs beside them, so it stands aside and says so.
//! * **Report a short walk as a complete one.** Every cap, every unreadable
//!   directory, every entry the directory would not yield and every name that
//!   had to be read lossily is counted and declared on a status record with
//!   the standard incompleteness pair — and a lossily-read name is flagged on
//!   its own entry too, because that is where somebody reads it. This claim
//!   was true of the first three and not of the fourth until 2026-09-17: a
//!   name that is not valid UTF-8 passed every check, went through
//!   `to_string_lossy`, and was counted nowhere.

#![forbid(unsafe_code)]

/// What a lossily-read name is.
const LOSSY_NAME_NOTE: &str = concat!(
    "This entry's name on the volume is not valid UTF-8, so the name shown is this walker's ",
    "reading of those bytes with U+FFFD in place of each byte it could not decode. It is NOT ",
    "the name on the volume, and a search for it will not find the file. The bytes are still ",
    "reachable through `source_path`."
);

use std::fs;
use std::path::{Path, PathBuf};

use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{DataSource, FileDataSource},
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::Arc;
use tracing::{debug, warn};

/// Ceiling on entries produced from one walk.
const MAX_ENTRIES: usize = 2_000_000;
/// Ceiling on directory depth.
const MAX_DEPTH: usize = 64;

/// Walks an ingested directory into file entries.
#[derive(Debug, Default)]
pub struct DirectoryWalkerModule;

impl DirectoryWalkerModule {
    pub fn new() -> Self {
        Self
    }
}

/// Does this directory belong to a parser that walks it itself?
///
/// Only the shapes whose own reader produces *better* artifacts than a raw walk
/// would: an iOS backup's files are content-addressed blobs that only its
/// `Manifest.db` can name. Adding a shape here is a decision to hide the raw
/// files, so the list is short and each entry says why.
fn owned_by_another_parser(dir: &Path) -> Option<&'static str> {
    if dir.join("Manifest.plist").is_file() && dir.join("Info.plist").is_file() {
        return Some("iOS backup");
    }
    None
}

/// The timestamps and the ownership bits, as JSON fields.
///
/// Each is written only when the platform supplied it. A missing time is left
/// missing: a file dated to the epoch because `stat` said nothing is a date on
/// a timeline that the evidence never carried.
///
/// **Only the modification time is written as a device time.** A folder handed
/// to an examiner is a *copy*, and the collection tools preserve mtime — that
/// is what `cp -p`, `rsync -a`, `tar` and `zip` all carry — while the access
/// and creation times on the copy record when the copy was read and when it was
/// written, by the collector, by a file manager, by this walk. Recorded as
/// `accessed`, the last of those became an "Accessed" timeline event dated to
/// the moment of ingest: on the ChromeOS image, 38,000 of them, burying the
/// case's real history under a record of the examination itself (HUNT-102).
/// They are kept under names that say whose times they are.
fn stat_fields(meta: &fs::Metadata, into: &mut serde_json::Map<String, serde_json::Value>) {
    fn rfc3339(t: std::io::Result<std::time::SystemTime>) -> Option<String> {
        let t = t.ok()?;
        let dt: chrono::DateTime<chrono::Utc> = t.into();
        Some(dt.to_rfc3339())
    }
    if let Some(v) = rfc3339(meta.modified()) {
        into.insert("modified".into(), json!(v));
    }
    if let Some(v) = rfc3339(meta.accessed()) {
        into.insert("accessed_on_collection_media".into(), json!(v));
    }
    if let Some(v) = rfc3339(meta.created()) {
        into.insert("created_on_collection_media".into(), json!(v));
    }
    into.insert(
        "times_note".into(),
        json!(
            "modified is the time the collection preserved from the device; the access and \
             creation times belong to the copy this walk read, not to the device, and are \
             recorded separately so they cannot be read as device activity"
        ),
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        into.insert(
            "mode".into(),
            json!(format!("{:o}", meta.permissions().mode() & 0o7777)),
        );
        into.insert("uid".into(), json!(meta.uid()));
        into.insert("gid".into(), json!(meta.gid()));
        into.insert("nlink".into(), json!(meta.nlink()));
        into.insert("inode".into(), json!(meta.ino()));
    }
}

/// What the walk could not do, for the status record.
#[derive(Debug, Default)]
struct Shortfall {
    /// Directories that could not be listed, with the reason.
    unreadable: Vec<String>,
    /// Entries the directory would not yield, or whose `symlink_metadata`
    /// failed: a permission error, or a file deleted between the listing and
    /// the stat. **Not a name** — this field was called `undecodable_names`
    /// and its JSON key `undecodable_entries`, which described something the
    /// walker does not count.
    unreadable_entries: usize,
    /// Entries whose **name is not valid UTF-8**, so the name on the record is
    /// this walker's lossy reading with replacement characters rather than the
    /// name on the volume. Counted here, and flagged on the entry itself.
    /// Before this, such a name reached the case as though it had been read.
    lossy_names: usize,
    /// True when [`MAX_ENTRIES`] stopped the walk.
    capped: bool,
    /// Directories not descended into because [`MAX_DEPTH`] was reached.
    too_deep: usize,
}

impl Shortfall {
    fn any(&self) -> bool {
        !self.unreadable.is_empty()
            || self.unreadable_entries > 0
            || self.lossy_names > 0
            || self.capped
            || self.too_deep > 0
    }
}

/// One walked file or directory, as an artifact.
fn entry_artifact(
    case_id: uuid::Uuid,
    parent_id: uuid::Uuid,
    root: &Path,
    path: &Path,
    meta: &fs::Metadata,
    symlink_target: Option<PathBuf>,
) -> Artifact {
    let relative = path.strip_prefix(root).unwrap_or(path);
    let display = format!("/{}", relative.to_string_lossy());
    let parent_display = relative
        .parent()
        .map(|p| {
            if p.as_os_str().is_empty() {
                "/".to_string()
            } else {
                format!("/{}", p.to_string_lossy())
            }
        })
        .unwrap_or_else(|| "/".to_string());

    let is_dir = meta.is_dir();
    let mut metadata = serde_json::Map::new();
    // A name that is not valid UTF-8 is reported as this walker's lossy
    // reading of it — with U+FFFD where the undecodable bytes were — and the
    // record says so. A substituted name is a name an examiner cannot search
    // for, and nothing on the record used to distinguish one from a name that
    // was read. Same class as the ANSI shortcut paths in `seance_plugin_lnk`.
    let file_name = path.file_name();
    let name_is_lossy = file_name.is_some_and(|n| n.to_str().is_none());
    metadata.insert(
        "name".into(),
        json!(file_name
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default()),
    );
    if name_is_lossy {
        metadata.insert("name_read_lossily".into(), json!(true));
        metadata.insert("name_decode_note".into(), json!(LOSSY_NAME_NOTE));
    }
    metadata.insert("path".into(), json!(display));
    metadata.insert("parent_path".into(), json!(parent_display));
    metadata.insert("is_directory".into(), json!(is_dir));
    if !is_dir {
        metadata.insert("size".into(), json!(meta.len()));
    }
    // Where the bytes are on this machine, so the API can serve the file's
    // content later without re-walking the tree.
    metadata.insert("source_path".into(), json!(path.to_string_lossy()));
    metadata.insert("source".into(), json!("directory"));
    stat_fields(meta, &mut metadata);
    let is_symlink = symlink_target.is_some();
    if let Some(target) = symlink_target {
        metadata.insert("is_symlink".into(), json!(true));
        metadata.insert("symlink_target".into(), json!(target.to_string_lossy()));
        // A link's target is recorded and NOT followed: following one leaves
        // the evidence tree, and a loop never ends.
        metadata.insert("content_omitted".into(), json!("symlink_not_followed"));
    }

    // Deferred: the source is sized now and opened at the first read, so a
    // tree of forty thousand files does not hold forty thousand descriptors
    // before the first is processed — past the default `ulimit -n` that
    // failed silently and left entries with no content (HUNT-114). A file
    // that cannot be sized says so on the entry rather than losing its bytes
    // without a word.
    let data: Option<Arc<dyn DataSource>> = if is_dir || is_symlink {
        None
    } else {
        match FileDataSource::deferred(path.to_path_buf()) {
            Ok(source) => Some(Arc::new(source) as Arc<dyn DataSource>),
            Err(err) => {
                metadata.insert(CONTENT_INCOMPLETE.into(), json!(true));
                metadata.insert(
                    CONTENT_INCOMPLETE_REASON.into(),
                    json!(IncompleteReason::UnresolvedStructure.as_str()),
                );
                metadata.insert("content_omitted".into(), json!("file_could_not_be_opened"));
                metadata.insert("open_error".into(), json!(err.to_string()));
                None
            }
        }
    };

    Artifact::new(
        case_id,
        ArtifactType::FileEntry,
        data,
        serde_json::Value::Object(metadata),
    )
    .with_parent(parent_id)
}

impl ForensicsModule for DirectoryWalkerModule {
    fn id(&self) -> &str {
        "plugin.filesystem.directory_walker"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::RawEvidence]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            != Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(path) = artifact.metadata.get("path").and_then(|v| v.as_str()) else {
            return Ok(Vec::new());
        };
        let root = PathBuf::from(path);
        if !root.is_dir() {
            return Ok(Vec::new());
        }
        if let Some(owner) = owned_by_another_parser(&root) {
            debug!("{path} is a {owner}; leaving it to that parser");
            return Ok(vec![Artifact::new(
                artifact.case_id,
                ArtifactType::ParsedRecord,
                None,
                json!({
                    "type": "DirectoryWalkSkipped",
                    "name": format!("Directory left to the {owner} reader"),
                    "source_path": path,
                    "owner": owner,
                    "message": format!(
                        "this directory is a {owner}, whose own reader names and decrypts its \
                         files; walking it here as loose files would list the same evidence \
                         twice, once unusably"
                    ),
                }),
            )
            .with_parent(artifact.id)]);
        }

        let mut produced = Vec::new();
        let mut shortfall = Shortfall::default();
        let mut stack: Vec<(PathBuf, usize)> = vec![(root.clone(), 0)];

        while let Some((dir, depth)) = stack.pop() {
            let entries = match fs::read_dir(&dir) {
                Ok(e) => e,
                Err(err) => {
                    // A directory that cannot be listed is not an empty one.
                    warn!("directory walk: cannot list {}: {err}", dir.display());
                    shortfall
                        .unreadable
                        .push(format!("{}: {err}", dir.display()));
                    continue;
                }
            };
            for entry in entries {
                if produced.len() >= MAX_ENTRIES {
                    shortfall.capped = true;
                    break;
                }
                let Ok(entry) = entry else {
                    shortfall.unreadable_entries += 1;
                    continue;
                };
                let child = entry.path();
                // `symlink_metadata` does not follow: a link is described as
                // itself, and what it points at is recorded rather than read.
                let Ok(meta) = fs::symlink_metadata(&child) else {
                    shortfall.unreadable_entries += 1;
                    continue;
                };
                let link_target = if meta.file_type().is_symlink() {
                    Some(fs::read_link(&child).unwrap_or_else(|_| PathBuf::from("(unreadable)")))
                } else {
                    None
                };
                // Counted here as well as flagged on the entry, so the
                // status record carries the population and the entry carries
                // the fact.
                if child.file_name().is_some_and(|n| n.to_str().is_none()) {
                    shortfall.lossy_names += 1;
                }
                produced.push(entry_artifact(
                    artifact.case_id,
                    artifact.id,
                    &root,
                    &child,
                    &meta,
                    link_target.clone(),
                ));
                if meta.is_dir() && link_target.is_none() {
                    if depth + 1 > MAX_DEPTH {
                        shortfall.too_deep += 1;
                    } else {
                        stack.push((child, depth + 1));
                    }
                }
            }
            if shortfall.capped {
                break;
            }
        }

        let files = produced
            .iter()
            .filter(|a| a.metadata["is_directory"] != json!(true))
            .count();
        debug!(
            "directory walk of {path}: {} entries ({files} files)",
            produced.len()
        );

        if shortfall.any() {
            produced.push(walk_status(artifact, path, produced.len(), &shortfall));
        }
        Ok(produced)
    }
}

/// The record that says the listing is short of what the folder holds.
fn walk_status(artifact: &Artifact, path: &str, entries: usize, shortfall: &Shortfall) -> Artifact {
    let reason = if shortfall.capped {
        IncompleteReason::CapReached
    } else {
        IncompleteReason::UnresolvedStructure
    };
    let mut detail = Vec::new();
    if shortfall.capped {
        detail.push(format!(
            "the walk stopped at the {MAX_ENTRIES} entry cap; everything after it was never \
             listed"
        ));
    }
    if !shortfall.unreadable.is_empty() {
        detail.push(format!(
            "{} director(y|ies) could not be listed: {}",
            shortfall.unreadable.len(),
            shortfall
                .unreadable
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    if shortfall.unreadable_entries > 0 {
        detail.push(format!(
            "{} entr(y|ies) could not be read from their directory",
            shortfall.unreadable_entries
        ));
    }
    if shortfall.lossy_names > 0 {
        detail.push(format!(
            "{} entr(y|ies) have a name that is not valid UTF-8, so the name on the record is \
             this walker's lossy reading of it and not the name on the volume; each such entry \
             is flagged `name_read_lossily`",
            shortfall.lossy_names
        ));
    }
    if shortfall.too_deep > 0 {
        detail.push(format!(
            "{} director(y|ies) were deeper than the {MAX_DEPTH}-level limit and were not \
             descended into",
            shortfall.too_deep
        ));
    }

    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "DirectoryWalkStatus",
            "name": "Directory listing is short of what the folder holds",
            "source_path": path,
            "entries_listed": entries,
            "unreadable_directories": shortfall.unreadable.len(),
            "unreadable_entries": shortfall.unreadable_entries,
            "names_read_lossily": shortfall.lossy_names,
            "directories_too_deep": shortfall.too_deep,
            "inventory_incomplete": true,
            "inventory_incomplete_reason": reason.as_str(),
            "inventory_incomplete_detail": detail.join("; "),
            CONTENT_INCOMPLETE: false,
            CONTENT_INCOMPLETE_REASON: serde_json::Value::Null,
        }),
    )
    .with_parent(artifact.id)
}

#[cfg(test)]
mod tests;
