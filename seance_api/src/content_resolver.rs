//! Content resolution for derived artifacts.
//!
//! Rebuilds a readable [`DataSource`] stack for any artifact by walking its
//! parent chain up to the root evidence file, then applying each recorded
//! transformation downward:
//!
//! - container decoding (E01/VHD/VMDK/QCOW2 re-opened via their reader
//!   modules; ZIP entries extracted in memory),
//! - partition / unallocated-space / filesystem windows (`offset_bytes` +
//!   `size_bytes`),
//! - filesystem file content (`data_runs` relative to the filesystem window,
//!   sparse runs read as zeros; NTFS resident data via `resident_data_b64`),
//! - APFS decmpfs content, decoded on demand from the compressed location the
//!   parser recorded (`decmpfs_attribute_b64`, `compressed_data_runs`),
//! - carved files (`carving_offset` + `carving_size` relative to the input
//!   artifact's window).
//!
//! Nothing is fabricated: when the chain lacks the metadata needed to locate
//! content, resolution fails with an error naming what is missing.

use std::io::Read;
use std::num::NonZeroUsize;
use std::path::Path;
use std::sync::{Arc, Mutex, OnceLock};

use lru::LruCache;

use base64::Engine;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{
        ByteSliceDataSource, DataSource, DeviceImageSource, ExtentPrecision, ExtentSource,
        FileDataSource, RunListDataSource, SourceCursor, WindowSource,
    },
    db::DatabaseConnection,
    io::{IncompleteReason, CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON},
    module::ForensicsModule,
};
use seance_db::SqliteConnection;
use uuid::Uuid;

use crate::{ApiError, EvidenceRootPolicy};

/// Maximum parent-chain depth walked before assuming a cycle.
const MAX_CHAIN_DEPTH: usize = 64;

/// Cap for materializing a ZIP entry in memory (ZIP has no random-access
/// decompressed view, so entries are extracted fully).
const MAX_ZIP_ENTRY_BYTES: u64 = 64 * 1024 * 1024;

/// Absolute ceiling on a single materialized or decompressed artifact served
/// through the API. The sizes that drive these allocations come from parsed
/// evidence metadata (an image's own claimed file/extent sizes), i.e. they are
/// attacker-controlled. Anything larger is rejected rather than allowed to OOM
/// and abort the whole server process. 4 GiB comfortably covers legitimate
/// single-file content while bounding a hostile `size`/`ram_len`.
const MAX_RESOLVED_CONTENT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Ceiling on inline (`resident_data_b64`) content. Resident/inline data is a
/// filesystem structure that lives inside one inode or MFT record — NTFS
/// resident attributes, ext/F2FS/XFS inline data, btrfs inline extents — so it
/// is at most a few KiB in practice. 16 MiB is a hostile-metadata ceiling, not
/// an expectation.
const MAX_RESIDENT_DATA_BYTES: u64 = 16 * 1024 * 1024;

/// Validate an evidence-metadata-derived allocation request against a ceiling,
/// returning the size as `usize` or an error instead of allocating unbounded.
fn guard_alloc(requested: u64, ceiling: u64, what: &str, id: Uuid) -> Result<usize, ApiError> {
    if requested > ceiling {
        return Err(ApiError::InvalidRequest(format!(
            "Artifact {id}: {what} ({requested} bytes) exceeds the {ceiling}-byte \
             content limit; refusing to allocate"
        )));
    }
    Ok(requested as usize)
}

/// The metadata key by which the producing parser declared this artifact's
/// stored bytes to be ciphertext, if it did.
///
/// fscrypt (ext4/F2FS), NTFS EFS, btrfs per-extent encryption and the iOS
/// backup parser all record *where* a file's bytes live while saying those
/// bytes are not the file's own content: `encrypted` / `efs_encrypted` /
/// `content_ciphertext` for display, the standard `content_incomplete` pair for
/// machines. Rebuilding from the recorded location streams ciphertext under a
/// plaintext-sized entry, and a re-hash of it is filed in the same digest
/// columns as a plaintext hash, where it reads as the file's own digest
/// (HUNT-004, HUNT-014).
fn ciphertext_marker(artifact: &Artifact) -> Option<&'static str> {
    let md = &artifact.metadata;
    let flag = |key: &str| md.get(key).and_then(|v| v.as_bool()) == Some(true);

    if md.get("content_ciphertext").is_some_and(|v| !v.is_null()) {
        return Some("content_ciphertext");
    }
    if flag("encrypted") {
        return Some("encrypted");
    }
    if flag("efs_encrypted") {
        return Some("efs_encrypted");
    }
    // The markers above are per-parser; the incompleteness pair is the contract
    // every producer writes. Only `encrypted` means "these are not the file's
    // bytes because a key is missing" — `unmapped`, for instance, describes a
    // sparse file whose content really is the zeros the run list yields.
    if flag(CONTENT_INCOMPLETE)
        && md
            .get(CONTENT_INCOMPLETE_REASON)
            .and_then(|v| v.as_str())
            .and_then(IncompleteReason::from_str)
            == Some(IncompleteReason::Encrypted)
    {
        return Some(CONTENT_INCOMPLETE_REASON);
    }
    None
}

/// A reconstructed, readable view of an artifact's content.
pub struct ResolvedContent {
    pub source: Arc<dyn DataSource>,
    pub size: u64,
    /// Display name of the target artifact, for content-type guessing.
    pub name: Option<String>,
    /// Stored MD5 of the target artifact's content, if recorded in metadata.
    pub md5: Option<String>,
    /// Stored SHA1 of the target artifact's content, if recorded in metadata.
    pub sha1: Option<String>,
    /// Stored SHA256 of the target artifact's content, if recorded in metadata.
    pub sha256: Option<String>,
}

/// Resolve the content of `artifact_id` (scoped to `case_id`) into a
/// random-access [`DataSource`].
///
/// The root evidence path is checked against the evidence-root policy before
/// any file is opened. All blocking work (file opens, container parsing,
/// ZIP extraction) runs on the blocking thread pool.
pub async fn resolve_artifact_content(
    db: &SqliteConnection,
    policy: &EvidenceRootPolicy,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<ResolvedContent, ApiError> {
    resolve_chain(db, policy, case_id, artifact_id, false).await
}

/// The content of the artifact, or — with `through_parent` — of the nearest
/// ancestor that has any.
///
/// A record is not always a thing with bytes. The memory pipeline's
/// `MemoryImage` record IS the memory image as far as every later stage is
/// concerned, and at ingest it carries the parent's data source; loaded back
/// from the database it carries nothing, so re-running the analysis on it was
/// refused for having "no recorded content location" — while running it on the
/// file underneath was declined by the module, which does not subscribe to raw
/// evidence. The one action the product tells an examiner to take after
/// fetching symbols — *re-run the memory analysis* — was impossible from the
/// API (`HUNT-103`).
///
/// Only a module run asks for this. A preview or an export must not hand back
/// a 5 GB image because the record it was asked for has no bytes of its own.
pub async fn resolve_artifact_content_through_parent(
    db: &SqliteConnection,
    policy: &EvidenceRootPolicy,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<ResolvedContent, ApiError> {
    resolve_chain(db, policy, case_id, artifact_id, true).await
}

async fn resolve_chain(
    db: &SqliteConnection,
    policy: &EvidenceRootPolicy,
    case_id: Uuid,
    artifact_id: Uuid,
    through_parent: bool,
) -> Result<ResolvedContent, ApiError> {
    let mut chain = build_chain(db, case_id, artifact_id).await?;
    if through_parent {
        // Walk up while the tail has nothing of its own to read. The chain is
        // root-first, so this drops the target and then its parent, and stops
        // at the first ancestor that can be resolved — the evidence the record
        // was made from.
        while chain.len() > 1 && !has_own_content(chain.last().expect("non-empty")) {
            chain.pop();
        }
    }
    let policy = policy.clone();
    tokio::task::spawn_blocking(move || build_stack(&chain, &policy))
        .await
        .map_err(|e| {
            ApiError::InternalServerError(format!("Content resolution task failed: {}", e))
        })?
}

/// The on-disk directory an artifact stands for, or `None` when it is not a
/// directory artifact.
///
/// A directory artifact — an iOS backup folder, an unpacked file-system export,
/// a mobile extraction directory — holds no bytes of its own: the module that
/// handles it walks the tree from its `path`. [`resolve_artifact_content`] has
/// nothing to open for it and fails, so an ad-hoc run asks this first and runs
/// the module with no data source.
///
/// The path is checked against the evidence-root policy and must still be a
/// directory. Evidence that has moved away is refused rather than quietly
/// treated as an empty folder.
pub async fn resolve_artifact_directory(
    db: &SqliteConnection,
    policy: &EvidenceRootPolicy,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<Option<std::path::PathBuf>, ApiError> {
    let artifact = db
        .get_artifact_details(case_id, artifact_id)
        .await
        .map_err(|_| ApiError::ResourceNotFound("Artifact not found".to_string()))?;

    if artifact
        .metadata
        .get("is_directory")
        .and_then(|v| v.as_bool())
        != Some(true)
    {
        return Ok(None);
    }
    let Some(path) = artifact.metadata.get("path").and_then(|v| v.as_str()) else {
        return Ok(None);
    };

    let checked = policy
        .check(Path::new(path))
        .map_err(ApiError::InvalidRequest)?;
    if !checked.is_dir() {
        return Err(ApiError::InvalidRequest(format!(
            "Artifact {} is recorded as a directory but {} is not one now; the evidence may have moved",
            artifact_id, path
        )));
    }
    Ok(Some(checked))
}

/// Walk an artifact's parent chain to the root evidence, returning it root-first.
///
/// The target fetch scopes the artifact to the case; parents are fetched by ID
/// because they belong to the same recorded chain.
async fn build_chain(
    db: &SqliteConnection,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<Vec<Artifact>, ApiError> {
    let target = db
        .get_artifact_details(case_id, artifact_id)
        .await
        .map_err(|_| {
            ApiError::ResourceNotFound("Artifact not found or database error".to_string())
        })?;

    let mut chain = vec![target];
    while let Some(parent_id) = chain.last().and_then(|a| a.parent_id) {
        if chain.len() >= MAX_CHAIN_DEPTH {
            return Err(ApiError::InvalidRequest(format!(
                "Artifact parent chain exceeds {} levels; refusing to resolve",
                MAX_CHAIN_DEPTH
            )));
        }
        let parent = db
            .get_artifact(parent_id)
            .await
            .map_err(|e| {
                ApiError::InternalServerError(format!(
                    "Failed to fetch parent artifact {}: {}",
                    parent_id, e
                ))
            })?
            .ok_or_else(|| {
                ApiError::InvalidRequest(format!(
                    "Parent artifact {} is missing; cannot rebuild the evidence chain",
                    parent_id
                ))
            })?;
        // Refuse to cross case boundaries: a corrupt/malicious parent_id
        // pointing at another case must not leak that case's evidence or let
        // its content be rebuilt into this chain (BUG-015).
        if parent.case_id != case_id {
            return Err(ApiError::InvalidRequest(format!(
                "Parent artifact {} belongs to a different case; refusing to resolve",
                parent_id
            )));
        }
        chain.push(parent);
    }
    chain.reverse();
    Ok(chain)
}

/// The locked volume above `artifact_id`: the parent of the nearest artifact
/// in its chain (itself included) that is a volume decrypted in memory
/// (`bitlocker_decrypted` / `luks_decrypted`), with that flag. `None` when
/// nothing in the chain is such a volume (HUNT-254).
pub async fn decrypted_volume_above(
    db: &SqliteConnection,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<Option<(Uuid, &'static str)>, ApiError> {
    let chain = build_chain(db, case_id, artifact_id).await?;
    for a in chain.iter().rev() {
        for flag in ["bitlocker_decrypted", "luks_decrypted"] {
            if a.metadata.get(flag).and_then(|v| v.as_bool()) == Some(true) {
                return Ok(a.parent_id.map(|p| (p, flag)));
            }
        }
    }
    Ok(None)
}

/// Drop every source this resolver caches between requests (containers,
/// decompressed content, VSS reconstructions). Called when a volume unlocked
/// for reading is forgotten: a cached source built beneath it holds the
/// decrypting view — and so its key — and would otherwise keep both alive
/// until evicted (HUNT-254). The caches are only a speed-up; the next read
/// rebuilds what it needs, through the refusal if the volume is locked.
pub fn forget_cached_views() {
    container_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    decompressed_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
    vss_reconstruction_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clear();
}

/// Does this artifact name any bytes of its own?
///
/// A record produced *about* evidence — a memory image record, a parsed row —
/// carries none of the locations the resolver can read: no runs, no resident
/// data, no carve offset, no window, and no file of its own.
fn has_own_content(artifact: &Artifact) -> bool {
    const LOCATIONS: &[&str] = &[
        "data_runs",
        "resident_data_b64",
        "carved_offset",
        "partition_offset",
        "source_path",
        "offset",
    ];
    LOCATIONS
        .iter()
        .any(|key| artifact.metadata.get(*key).is_some())
        || artifact.artifact_type != ArtifactType::ParsedRecord
}

/// Build the data-source stack for a root-first artifact chain.
fn build_stack(
    chain: &[Artifact],
    policy: &EvidenceRootPolicy,
) -> Result<ResolvedContent, ApiError> {
    let target = chain.last().expect("chain is never empty");

    // Find the deepest artifact in the chain that is itself a physical file — an
    // iOS-backup file on disk at `<backup_path>/<ab>/<file_id>` (or flat for old
    // backups). Resolve from there and apply only the remaining derivations down
    // to the target. This covers both a bare backup file AND a container entry
    // nested inside one (e.g. an icon inside an `.ipa` within the backup), whose
    // RawEvidence-directory root carries no `source_path`.
    let mut direct = None;
    for i in (0..chain.len()).rev() {
        // An artifact that names its own file on disk is read from it. The
        // directory walker stamps `source_path` on every file it lists, so a
        // folder-sourced case serves content the same way an image-sourced one
        // does, without re-walking the tree (HUNT-096).
        if let Some(path) = chain[i]
            .metadata
            .get("source_path")
            .and_then(|v| v.as_str())
            .filter(|_| {
                chain[i]
                    .metadata
                    .get("is_directory")
                    .and_then(|v| v.as_bool())
                    != Some(true)
            })
        {
            if i > 0 || chain.len() == 1 {
                direct = Some((i, open_checked_file(path, policy)?));
                break;
            }
        }
        if let Some(src) = direct_backup_file_source(&chain[i], policy)? {
            direct = Some((i, src));
            break;
        }
    }

    let (mut current, start_idx) = match direct {
        Some((i, src)) => (src, i),
        None => {
            let root = &chain[0];
            let source_path = root
                .metadata
                .get("source_path")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    ApiError::InvalidRequest(format!(
                        "Root artifact {} has no source_path; the physical evidence file cannot be located",
                        root.id
                    ))
                })?;
            (open_checked_file(source_path, policy)?, 0)
        }
    };
    for i in (start_idx + 1)..chain.len() {
        current = apply_step(current, &chain[i], &chain[i - 1], policy)?;
    }

    // Prefer the canonical md5/sha1/sha256 keys, falling back to the legacy
    // *_hash keys older records may carry.
    let stored_hash = |primary: &str, legacy: &str| {
        target
            .metadata
            .get(primary)
            .or_else(|| target.metadata.get(legacy))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    };
    Ok(ResolvedContent {
        size: current.size(),
        source: current,
        name: target
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        md5: stored_hash("md5", "md5_hash"),
        sha1: stored_hash("sha1", "sha1_hash"),
        sha256: stored_hash("sha256", "sha256_hash"),
    })
}

/// Open a metadata-supplied path after confining it to the evidence roots.
fn open_checked_file(
    path: &str,
    policy: &EvidenceRootPolicy,
) -> Result<Arc<dyn DataSource>, ApiError> {
    let checked = policy
        .check(Path::new(path))
        .map_err(ApiError::InvalidRequest)?;
    let source = FileDataSource::new(checked.clone()).map_err(|e| {
        ApiError::InternalServerError(format!("Failed to open evidence file {:?}: {}", checked, e))
    })?;
    Ok(Arc::new(source))
}

/// Resolve an iOS-backup file to its on-disk source, confined to the evidence
/// roots. iOS backups store each file at `<backup_path>/<ab>/<file_id>` (the
/// modern 2-char fan-out) or flat `<backup_path>/<file_id>` (older backups).
/// Returns `None` for anything that is not a content-bearing backup file (no
/// `backup_path`/`file_id`, or a directory record) so the caller falls back to
/// the normal chain walk.
///
/// For an *encrypted* backup the on-disk file is ciphertext — the per-file keys
/// are unwrapped from the keybag with the backup password at ingest and the
/// plaintext only ever exists in memory — so this returns an error rather than
/// the stored blob (HUNT-004), unless the backup is unlocked for reading in the
/// artifact's case, in which case the plaintext is decrypted again from the
/// held class keys (BUG-026).
fn direct_backup_file_source(
    artifact: &Artifact,
    policy: &EvidenceRootPolicy,
) -> Result<Option<Arc<dyn DataSource>>, ApiError> {
    let (Some(backup_path), Some(file_id)) = (
        artifact
            .metadata
            .get("backup_path")
            .and_then(|v| v.as_str()),
        artifact.metadata.get("file_id").and_then(|v| v.as_str()),
    ) else {
        return Ok(None);
    };
    // Directory records carry no content.
    if artifact
        .metadata
        .get("is_directory")
        .and_then(|v| v.as_bool())
        .unwrap_or(false)
    {
        return Ok(None);
    }

    // The stored blob of an encrypted backup is ciphertext. Serving
    // `<backup_path>/<file_id>` here would hand download, hex, export and
    // re-hash the ciphertext under a plaintext-sized entry, and the digest of
    // those bytes would be filed as this file's digest (HUNT-004). The password
    // is not retained after ingest; the plaintext is produced again only while
    // an examiner has unlocked this backup for reading in this case — the class
    // keys held in process memory, with a TTL (BUG-026).
    if let Some(marker) = ciphertext_marker(artifact) {
        let checked = policy
            .check(Path::new(backup_path))
            .map_err(ApiError::InvalidRequest)?;
        let key = crate::backup_keyring::source_key(&checked);
        if let Some(unlocked) = crate::backup_keyring::ios_backups().get(artifact.case_id, &key) {
            return unlocked.open_file(file_id).map(Some).map_err(|e| {
                ApiError::InvalidRequest(format!(
                    "Artifact {}: the backup is unlocked for reading, but this file could not \
                     be decrypted: {e}. Refusing to serve ciphertext as file content.",
                    artifact.id
                ))
            });
        }
        return Err(ApiError::InvalidRequest(format!(
            "Artifact {} is an iOS-backup file whose stored copy is ciphertext ({}): the \
             backup password is not retained after ingest, and this backup is not unlocked \
             for reading in this case. Unlock it with the backup password (POST \
             /api/v1/cases/{}/artifacts/{}/unlock, kind ios_backup_password) to read its \
             content; until then, refusing to serve ciphertext as file content.",
            artifact.id, marker, artifact.case_id, artifact.id
        )));
    }

    let base = Path::new(backup_path);
    let two_level = (file_id.len() >= 2).then(|| base.join(&file_id[..2]).join(file_id));
    let candidate = match two_level {
        Some(p) if p.exists() => p,
        _ => base.join(file_id),
    };

    Ok(Some(open_checked_file(
        &candidate.to_string_lossy(),
        policy,
    )?))
}

/// Apply one artifact's recorded transformation to the source built so far.
///
/// `current` is the resolved content of `parent`; the return value is the
/// resolved content of `artifact`.
fn apply_step(
    current: Arc<dyn DataSource>,
    artifact: &Artifact,
    parent: &Artifact,
    policy: &EvidenceRootPolicy,
) -> Result<Arc<dyn DataSource>, ApiError> {
    let md = &artifact.metadata;

    // 0. A volume the BitLocker or LUKS decryptor opened in memory. Its
    //    `offset_bytes: 0` / `size_bytes` describe the plaintext view, and the
    //    only bytes this resolver can reach are the parent's ciphertext:
    //    windowing them served ciphertext as the volume's — and every file
    //    beneath it's — content. The key is not retained after the run that
    //    derived it (HUNT-120). It is served in the clear only while an
    //    examiner has unlocked the locked volume (`parent`) for reading in this
    //    case — the decrypting view held in process memory, with a TTL
    //    (HUNT-254). Otherwise fail closed, as for every other ciphertext
    //    (HUNT-014), and name the route that opens it.
    for flag in ["bitlocker_decrypted", "luks_decrypted"] {
        if md.get(flag).and_then(|v| v.as_bool()) == Some(true) {
            if let Some(view) = crate::unlocked_volumes::lookup(artifact.case_id, parent.id) {
                return Ok(view);
            }
            let kinds = if flag == "bitlocker_decrypted" {
                "bitlocker_password or bitlocker_recovery_password"
            } else {
                "luks_passphrase"
            };
            return Err(ApiError::InvalidRequest(format!(
                "Artifact {} is a volume decrypted in memory during a module run ({flag}); \
                 the key is not retained after that run, the bytes on the evidence are \
                 ciphertext, and the volume is not unlocked for reading in this case. \
                 Unlock it (POST /api/v1/cases/{}/artifacts/{}/unlock, kind {kinds}) to read \
                 it and everything beneath it; until then, refusing to serve ciphertext as its \
                 content — or as the content of anything beneath it.",
                artifact.id, artifact.case_id, parent.id
            )));
        }
    }

    // 1. Container-decoded artifacts. E01/VHD/VMDK/QCOW2 readers emit a
    //    RawEvidence child tagged with `container`; the ZIP extractor tags
    //    each entry FileEntry itself.
    if let Some(kind) = md.get("container").and_then(|v| v.as_str()) {
        return match kind {
            "zip" => extract_zip_entry(current, artifact),
            "tar" => extract_tar_entry(current, artifact),
            "gzip" | "bzip2" | "xz" => reopen_compressed(kind, current, parent),
            #[cfg(feature = "e01")]
            "ewf_logical" => reopen_logical_entry(artifact, parent, policy),
            _ => reopen_container(kind, current, parent, policy),
        };
    }

    // 1b. VSS shadow-copy snapshot: point-in-time content reconstructed from the
    //     shadow store chain. The reconstruction is virtual (bytes assembled from
    //     scattered diff-area locations, not a run list) so it cannot be persisted
    //     as data_runs; rebuild it on demand from the volume window `current`,
    //     cached per artifact so the chain is built once across range requests.
    if md.get("subtype").and_then(|v| v.as_str()) == Some("vss_snapshot")
        && md.get("content_reconstruction").and_then(|v| v.as_str()) == Some("reconstructed")
    {
        if let Some(cached) = vss_reconstruction_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact.id)
            .cloned()
        {
            return Ok(cached);
        }
        let stack = md
            .get("stack_position")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| {
                ApiError::InvalidRequest(format!(
                    "VSS snapshot {} is missing stack_position; re-ingest to enable content access",
                    artifact.id
                ))
            })?;
        let ds = seance_plugin_vss::reconstruct_snapshot_content(current.clone(), stack)
            .ok_or_else(|| {
                ApiError::InvalidRequest(format!(
                    "Could not reconstruct VSS snapshot {} content from the volume",
                    artifact.id
                ))
            })?;
        vss_reconstruction_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(artifact.id, ds.clone());
        return Ok(ds);
    }

    // 2. NTFS resident data: full content captured inline at parse time.
    if let Some(b64) = md.get("resident_data_b64").and_then(|v| v.as_str()) {
        // The encoded blob comes from parsed evidence metadata, so its length is
        // attacker-controlled. Bound the decode before it allocates (BUG-248);
        // the encoded length caps the decoded length at ~3/4 of it.
        guard_alloc(
            b64.len() as u64,
            MAX_RESIDENT_DATA_BYTES,
            "resident_data_b64",
            artifact.id,
        )?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .map_err(|e| {
                ApiError::InvalidRequest(format!(
                    "Artifact {} has invalid resident_data_b64: {}",
                    artifact.id, e
                ))
            })?;
        return Ok(Arc::new(ByteSliceDataSource::new(bytes)));
    }

    // 2b. btrfs compressed content: a per-extent descriptor. Decompress each
    //     extent on demand and assemble the logical file (no size cap).
    if md.get("compression").and_then(|v| v.as_str()) == Some("btrfs") {
        if let Some(cached) = decompressed_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact.id)
            .cloned()
        {
            return Ok(cached);
        }
        if let Some(exts) = md.get("btrfs_extents").and_then(|v| v.as_array()) {
            let size = md.get("size").and_then(|v| v.as_u64()).unwrap_or(0);
            let data = assemble_btrfs_compressed(&current, exts, size, artifact.id)?;
            return Ok(cache_decompressed(artifact.id, data));
        }
        // Recorded as btrfs-compressed but without the per-extent descriptor
        // needed to decompress: falling through would serve the compressed
        // extent bytes as plaintext content (BUG-183, same class as BUG-182).
        return Err(ApiError::InvalidRequest(format!(
            "Artifact {} is btrfs-compressed but has no btrfs_extents metadata; \
             refusing to serve compressed bytes as file content",
            artifact.id
        )));
    }

    // 2c. APFS decmpfs (transparent compression): a compressed file has NO
    //     data-stream extents of its own — its bytes are the compressed stream
    //     inside the `com.apple.decmpfs` xattr, or in the resource fork the
    //     xattr points at — so none of the branches below located them and
    //     every transparently compressed file on a macOS volume fell through to
    //     "no recorded content location": unreadable, unexportable, unhashable
    //     once ingest's decoded buffer was gone (LIVE-001). The parser persists
    //     that location; rebuild the plaintext from it here, in the
    //     filesystem-window coordinate space `current` is already in — the same
    //     space `data_runs` uses. Fail-closed like the decoder underneath: the
    //     file's complete decoded bytes or an error, never the compressed
    //     stream served as content (BUG-156).
    if md.get("compression").and_then(|v| v.as_str()) == Some("apfs_decmpfs") {
        if let Some(cached) = decompressed_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&artifact.id)
            .cloned()
        {
            return Ok(cached);
        }
        let data = seance_plugin_apfs::reconstruct_decmpfs_content(current, md).map_err(|e| {
            ApiError::InvalidRequest(format!(
                "Artifact {} is APFS decmpfs-compressed and its content could not be rebuilt \
                 from the recorded compressed location: {}. Refusing to serve compressed bytes \
                 as file content.",
                artifact.id, e
            ))
        })?;
        return Ok(cache_decompressed(artifact.id, data));
    }

    // 3. File data runs: [offset_bytes|null, length_bytes] pairs relative to
    //    the containing filesystem window; null offsets are sparse (zeros).
    if let Some(runs_value) = md.get("data_runs") {
        // A stream read from a bare `$MFT`: its runs address a volume that was
        // not supplied, and applied to the `$MFT` file they land on other MFT
        // records (HUNT-161).
        if md.get("volume_not_in_evidence").and_then(|v| v.as_bool()) == Some(true) {
            return Err(ApiError::InvalidRequest(format!(
                "Artifact {} is a stream whose clusters are on a volume that is not in \
                 evidence (only its $MFT was supplied); refusing to serve other bytes as its \
                 content",
                artifact.id
            )));
        }
        // If the FS parser flagged the run list as incomplete (run cap hit or
        // ATTR_LIST truncated), refuse to serve it. The reconstruction would be
        // short of the real file, yet a hash of it can still match the hash
        // computed at ingest from the same truncated runs -- integrity would
        // look fine while content is silently incomplete (BUG-047).
        if md.get("data_runs_complete").and_then(|v| v.as_bool()) == Some(false) {
            return Err(ApiError::InvalidRequest(format!(
                "Artifact {} has an incomplete data_runs list; refusing to serve partial content",
                artifact.id
            )));
        }
        // The runs of an fscrypt (ext4/F2FS), NTFS EFS or btrfs-encrypted file
        // address ciphertext this product does not decrypt. Rebuilding them
        // serves those bytes as the file's content, and a re-hash of them lands
        // in the same digest columns as a plaintext hash -- integrity then
        // "verifies" a digest of the wrong bytes. Fail closed, the same way the
        // compression paths below do (HUNT-014).
        if let Some(marker) = ciphertext_marker(artifact) {
            return Err(ApiError::InvalidRequest(format!(
                "Artifact {} is recorded as encrypted at rest ({}); its data_runs address \
                 ciphertext, not this file's content. Refusing to serve ciphertext as file \
                 content.",
                artifact.id, marker
            )));
        }
        let runs = parse_data_runs(runs_value).map_err(|e| {
            ApiError::InvalidRequest(format!(
                "Artifact {} has invalid data_runs: {}",
                artifact.id, e
            ))
        })?;
        let recorded_size = md.get("size").and_then(|v| v.as_u64());

        // Compressed content: the runs point at compressed clusters. Decompress
        // on demand (no size cap, no inlined bytes in the DB).
        if md.get("compression").and_then(|v| v.as_str()) == Some("ntfs_lznt1") {
            if let Some(cached) = decompressed_cache()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&artifact.id)
                .cloned()
            {
                return Ok(cached);
            }
            let unit = md
                .get("compression_unit_bytes")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let logical = recorded_size.unwrap_or(0);
            if unit > 0 && logical > 0 {
                // `logical` is the file's own claimed size from the image; bound
                // it before building the whole decompressed file in RAM.
                guard_alloc(
                    logical,
                    MAX_RESOLVED_CONTENT_BYTES,
                    "NTFS logical size",
                    artifact.id,
                )?;
                let data =
                    seance_core::compression::decompress_ntfs_data(&current, &runs, unit, logical)
                        .map_err(|e| {
                            ApiError::InvalidRequest(format!(
                                "Artifact {} NTFS-compressed content is truncated or corrupt: {}",
                                artifact.id, e
                            ))
                        })?;
                return Ok(cache_decompressed(artifact.id, data));
            }
            // The artifact is recorded as LZNT1-compressed but the metadata
            // needed to decompress it is missing. Falling through here would
            // serve the raw compressed cluster bytes as if they were the file's
            // plaintext -- and a re-hash of that wrong view could even "verify"
            // against a hash computed the same wrong way. Fail closed (BUG-182).
            return Err(ApiError::InvalidRequest(format!(
                "Artifact {} is NTFS-compressed but its decompression metadata is \
                 incomplete (compression_unit_bytes={}, size={}); refusing to serve \
                 compressed bytes as file content",
                artifact.id, unit, logical
            )));
        }

        // Logical size exceeds the allocated runs: the file has a trailing
        // sparse / unallocated hole the FS parser omitted from the run list.
        // Extend with an explicit zero run so download, hex, export and re-hash
        // see the full logical length — matching TSK/Autopsy — instead of a
        // silently truncated view (BUG-154). The `data_runs_complete` guard
        // above already refuses genuinely-truncated run lists, so any shortfall
        // here is a real hole, not lost data.
        let runs = extend_runs_to_logical(runs, recorded_size);
        // `from_allocation`, then windowed below. The runs have already been
        // grown to the logical size where it exceeded them; the shrink is the
        // `WindowSource` a few lines down, which is kept rather than folded
        // into the constructor because it is what makes `recorded_size`
        // authoritative over a run list that disagrees with it.
        let run_source: Arc<dyn DataSource> =
            Arc::new(RunListDataSource::from_allocation(current, runs));
        // Data runs are cluster/block-aligned, so their total can exceed the
        // real file size by up to one allocation unit of trailing slack. Cap at
        // the recorded size so served and downloaded content is exactly the
        // file — and matches the hash computed at ingest. Only shrink here;
        // growth to logical size was handled by the sparse-hole extension above.
        if let Some(size) = recorded_size {
            if size < run_source.size() {
                return Ok(Arc::new(WindowSource::new(run_source, 0, size)));
            }
        }
        return Ok(run_source);
    }

    // 4. Carved files: a window into the input artifact's data.
    if let Some(offset) = md.get("carving_offset").and_then(|v| v.as_u64()) {
        let size = md
            .get("carving_size")
            .and_then(|v| v.as_u64())
            .or_else(|| md.get("size").and_then(|v| v.as_u64()))
            .ok_or_else(|| {
                ApiError::InvalidRequest(format!(
                    "Carved artifact {} has no carving_size or size metadata",
                    artifact.id
                ))
            })?;
        return Ok(Arc::new(WindowSource::new(current, offset, size)));
    }

    // 5. Disk-layout windows.
    match artifact.artifact_type {
        // A slack region's window is in its FileSystem parent's coordinate
        // space, exactly like a free region's.
        ArtifactType::Partition | ArtifactType::UnallocatedSpace | ArtifactType::SlackSpace => {
            let offset = require_u64(artifact, "offset_bytes")?;
            let size = require_u64(artifact, "size_bytes")?;
            Ok(Arc::new(WindowSource::new(current, offset, size)))
        }
        ArtifactType::FileSystem => {
            // FileSystem offset_bytes/size_bytes are copied from the parent
            // partition (same coordinate space as the partition window), so
            // when the parent step already applied that window this is a
            // no-op. A filesystem detected directly on RawEvidence records
            // its own window (offset 0).
            if matches!(
                parent.artifact_type,
                ArtifactType::Partition | ArtifactType::UnallocatedSpace
            ) {
                Ok(current)
            } else if let (Some(offset), Some(size)) = (
                md.get("offset_bytes").and_then(|v| v.as_u64()),
                md.get("size_bytes").and_then(|v| v.as_u64()),
            ) {
                Ok(Arc::new(WindowSource::new(current, offset, size)))
            } else {
                Ok(current)
            }
        }
        _ => {
            // Nodes ingested as standalone files carry their own source_path.
            if let Some(path) = md.get("source_path").and_then(|v| v.as_str()) {
                return open_checked_file(path, policy);
            }
            Err(ApiError::InvalidRequest(format!(
                "Artifact {} ({:?}) has no recorded content location: no data_runs, resident data, \
                 carving offset, or partition window. Re-ingest the evidence with the updated \
                 parsers to enable content access.",
                artifact.id, artifact.artifact_type
            )))
        }
    }
}

/// Cache of re-opened container data sources, keyed by (kind, evidence path).
/// Re-opening an E01 re-globs its segments and re-initialises libewf on every
/// content request; caching the decoded source avoids that when many requests
/// hit the same container (e.g. a gallery over an E01-backed case). Bounded so
/// at most this many container handles stay open at once. The cached sources
/// are `Send + Sync` and serialize their own reads, so sharing is safe.
fn container_cache() -> &'static Mutex<LruCache<(String, String), Arc<dyn DataSource>>> {
    static CACHE: OnceLock<Mutex<LruCache<(String, String), Arc<dyn DataSource>>>> =
        OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(LruCache::new(NonZeroUsize::new(8).unwrap())))
}

/// Largest decompressed file kept in the cache below. Range requests (hex/text
/// previews fetch a file in chunks) otherwise re-decompress the whole file per
/// chunk; caching avoids that. Bounded per-entry so the cache can't hold huge
/// files in memory.
const DECOMPRESSED_CACHE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Cache of fully decompressed artifact content, keyed by artifact id. An
/// artifact's content is a pure function of its (immutable) metadata, so the
/// bytes are stable. Bounded; large files (> the cap above) are not cached.
/// # A poisoned cache must not deny an examiner the evidence
///
/// Every cache lock in this module recovers from poisoning with
/// `unwrap_or_else(|e| e.into_inner())` rather than unwrapping.
///
/// `Mutex::lock` returns `Err` once any thread has panicked while holding the
/// guard, and it returns `Err` for every caller after that, forever. Unwrapping
/// turned one request-level panic — a single malformed artifact reaching a
/// decoder — into a permanent, process-wide failure of content resolution: no
/// artifact's bytes could be fetched again until the server was restarted, and
/// the examiner's only symptom was that the tool had stopped showing evidence.
///
/// Recovering is safe here because what these hold is *derived* data: a decoded
/// buffer, a container handle, a reconstruction. The worst case of using a
/// guard from a poisoned lock is a stale or partially-written cache entry,
/// which is bounded and self-correcting. The worst case of refusing is that the
/// evidence becomes unreachable.
fn decompressed_cache() -> &'static Mutex<LruCache<Uuid, Arc<dyn DataSource>>> {
    static CACHE: OnceLock<Mutex<LruCache<Uuid, Arc<dyn DataSource>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(LruCache::new(NonZeroUsize::new(4).unwrap())))
}

/// Cache of reconstructed VSS shadow-copy data sources, keyed by snapshot
/// artifact id. Each reconstruction rebuilds the whole store chain (reads every
/// stack's diff area + bitmaps), so caching the resulting virtual source avoids
/// redoing that on every byte-range request during hex-paging / download. The
/// source is virtual (volume-sized, no materialized bytes), so caching the
/// handle is cheap regardless of the shadow's logical size.
fn vss_reconstruction_cache() -> &'static Mutex<LruCache<Uuid, Arc<dyn DataSource>>> {
    static CACHE: OnceLock<Mutex<LruCache<Uuid, Arc<dyn DataSource>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(LruCache::new(NonZeroUsize::new(4).unwrap())))
}

/// Wrap decompressed bytes in a data source, caching it under `id` when small
/// enough to be worth keeping for subsequent range requests.
fn cache_decompressed(id: Uuid, data: Vec<u8>) -> Arc<dyn DataSource> {
    let small = data.len() <= DECOMPRESSED_CACHE_MAX_BYTES;
    let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(data));
    if small {
        decompressed_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(id, ds.clone());
    }
    ds
}

/// Re-open a container format (E01/VHD/VMDK/QCOW2) by re-running its reader
/// module on a synthetic copy of the parent artifact backed by `current`.
fn reopen_container(
    kind: &str,
    current: Arc<dyn DataSource>,
    parent: &Artifact,
    policy: &EvidenceRootPolicy,
) -> Result<Arc<dyn DataSource>, ApiError> {
    // Container modules may open paths from metadata (the E01 reader opens
    // metadata["path"] directly); confine any such path first.
    let cache_path = parent.metadata.get("path").and_then(|v| v.as_str());
    if let Some(path) = cache_path {
        policy
            .check(Path::new(path))
            .map_err(ApiError::InvalidRequest)?;
    }

    // Cache only E01/EWF: its reader opens metadata["path"] directly (re-globbing
    // segments + re-initialising libewf), so (kind, path) fully identifies the
    // handle and the re-open cost is what the cache targets. Other containers
    // re-open per request as before.
    let cache_key = cache_path
        .filter(|_| matches!(kind, "e01" | "ewf"))
        .map(|p| (kind.to_string(), p.to_string()));
    if let Some(key) = &cache_key {
        if let Some(cached) = container_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(key)
            .cloned()
        {
            return Ok(cached);
        }
    }

    let synthetic = Artifact::new(
        parent.case_id,
        parent.artifact_type.clone(),
        Some(current),
        parent.metadata.clone(),
    );

    let produced = match kind {
        #[cfg(feature = "e01")]
        "e01" | "ewf" => seance_container_e01::E01ContainerModule.process(&synthetic),
        "aff4" => seance_container_aff4::Aff4ContainerModule.process(&synthetic),
        "vhd" => seance_container_vdisk::VhdContainerModule.process(&synthetic),
        "vhdx" => seance_container_vdisk::VhdxContainerModule.process(&synthetic),
        "vmdk" => seance_container_vdisk::VmdkContainerModule.process(&synthetic),
        "qcow2" => seance_container_vdisk::Qcow2ContainerModule.process(&synthetic),
        "sparseimage" => {
            seance_container_sparseimage::SparseImageContainerModule.process(&synthetic)
        }
        other => {
            return Err(ApiError::InvalidRequest(format!(
                "Content resolution for '{}' containers is not supported",
                other
            )))
        }
    }
    .map_err(|e| {
        ApiError::InvalidRequest(format!("Failed to re-open {} container: {}", kind, e))
    })?;

    let source = produced.into_iter().find_map(|a| a.data).ok_or_else(|| {
        ApiError::InvalidRequest(format!(
            "Could not re-open {} container from artifact {}; the reader produced no data source",
            kind, parent.id
        ))
    })?;

    // The decoded image is the physical device for offset purposes: an offset
    // into it is the physical offset on the acquired disk (the container's
    // on-file compression is transparent here). Mark it so `physical_map`
    // treats offsets as device-absolute and stops projecting further down.
    let source: Arc<dyn DataSource> = Arc::new(DeviceImageSource::new(source));

    if let Some(key) = cache_key {
        container_cache()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .put(key, source.clone());
    }
    Ok(source)
}

/// Re-open one entry of an EWF logical evidence file (`.L01`, HUNT-144).
///
/// The L01 is re-opened through libewf (in the isolated helper by default), its
/// entry tree walked, and the entry found by `l01_index_path` — its position in
/// the tree, which, unlike its name, is unique. The entry's source is cached per
/// artifact so a hex or text preview's range requests do not re-walk the tree
/// each time; the cache is small, and each entry held keeps one helper alive.
#[cfg(feature = "e01")]
fn reopen_logical_entry(
    artifact: &Artifact,
    parent: &Artifact,
    policy: &EvidenceRootPolicy,
) -> Result<Arc<dyn DataSource>, ApiError> {
    if let Some(cached) = decompressed_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&artifact.id)
        .cloned()
    {
        return Ok(cached);
    }
    let path = parent
        .metadata
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "L01 entry {} has a parent with no recorded path; the logical evidence file \
                 cannot be located",
                artifact.id
            ))
        })?;
    policy
        .check(Path::new(path))
        .map_err(ApiError::InvalidRequest)?;
    let index_path: Vec<u32> = artifact
        .metadata
        .get("l01_index_path")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "L01 entry {} carries no l01_index_path; re-ingest to enable content access",
                artifact.id
            ))
        })?;
    // HUNT-246: a `<dir>:l01_directory_data` stream carries its directory's
    // index path and is re-opened as that directory's data, never as a file.
    let directory_data = artifact
        .metadata
        .get("l01_record_kind")
        .and_then(|v| v.as_str())
        == Some("directory_data");
    let opened = if directory_data {
        seance_container_e01::open_logical_directory_data(path, &index_path)
    } else {
        seance_container_e01::open_logical_entry(path, &index_path)
    };
    let source = opened.map_err(|e| {
        ApiError::InvalidRequest(format!("Failed to re-open L01 entry {}: {e}", artifact.id))
    })?;
    decompressed_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .put(artifact.id, source.clone());
    Ok(source)
}

/// Re-open a stream-compressed container (gzip/bzip2/xz) by re-running its
/// expander on a synthetic copy of the parent backed by `current`. The expander
/// spills the decompressed bytes to a temp file and returns a random-access
/// source over them. Cached under the parent (the compressed file) so a tar
/// inside it, or a multi-range download, does not re-decompress each time.
fn reopen_compressed(
    kind: &str,
    current: Arc<dyn DataSource>,
    parent: &Artifact,
) -> Result<Arc<dyn DataSource>, ApiError> {
    if let Some(cached) = decompressed_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .get(&parent.id)
        .cloned()
    {
        return Ok(cached);
    }

    let synthetic = Artifact::new(
        parent.case_id,
        parent.artifact_type.clone(),
        Some(current),
        parent.metadata.clone(),
    );

    let produced = match kind {
        "gzip" => seance_container_archive::GzipExpanderModule.process(&synthetic),
        "bzip2" => seance_container_archive::Bzip2ExpanderModule.process(&synthetic),
        "xz" => seance_container_archive::XzExpanderModule.process(&synthetic),
        other => {
            return Err(ApiError::InvalidRequest(format!(
                "Content resolution for '{}' streams is not supported",
                other
            )))
        }
    }
    .map_err(|e| {
        ApiError::InvalidRequest(format!("Failed to decompress {} stream: {}", kind, e))
    })?;

    let source = produced.into_iter().find_map(|a| a.data).ok_or_else(|| {
        ApiError::InvalidRequest(format!(
            "Could not decompress {} stream from artifact {}; the expander produced no data",
            kind, parent.id
        ))
    })?;

    // The temp-file-backed handle is cheap to retain (bytes live on disk, not in
    // the cache), so keep it regardless of decompressed size.
    decompressed_cache()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .put(parent.id, source.clone());
    Ok(source)
}

/// Recover an archive entry's internal name from the flat-model `path` the
/// archive extractors store, which is the entry name with exactly one `/`
/// prepended.
///
/// Only that one slash may come off. An entry the archive itself names
/// `/absolute.txt` is stored as `//absolute.txt`, and stripping *every* leading
/// slash asked the archive for `absolute.txt` — a name it does not contain — so
/// the entry could never be read back through the product (LIVE-005). Records
/// written before `path` carried the prefix have no leading slash and are
/// returned unchanged.
fn archive_internal_path(stored_path: &str) -> &str {
    stored_path.strip_prefix('/').unwrap_or(stored_path)
}

/// Re-open one tar entry's bytes from the decompressed tar `current`, matched by
/// the entry's stored archive-internal path (`path` minus its leading `/`).
fn extract_tar_entry(
    current: Arc<dyn DataSource>,
    artifact: &Artifact,
) -> Result<Arc<dyn DataSource>, ApiError> {
    let internal = artifact
        .metadata
        .get("path")
        .and_then(|v| v.as_str())
        .map(|p| archive_internal_path(p).to_string())
        .or_else(|| {
            artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "tar entry artifact {} has no path/name metadata",
                artifact.id
            ))
        })?;

    seance_container_archive::extract_tar_entry_source(current, &internal).ok_or_else(|| {
        ApiError::ResourceNotFound(format!("tar entry '{}' not found in archive", internal))
    })
}

/// Extract a ZIP entry into memory (capped) from the archive source.
fn extract_zip_entry(
    archive_source: Arc<dyn DataSource>,
    artifact: &Artifact,
) -> Result<Arc<dyn DataSource>, ApiError> {
    // `original_name` is the archive's OWN key, recorded by the reader whenever
    // path resolution changed the stored name — which it does for every entry
    // in an archive that stores absolute paths, and an iOS full-file-system
    // extraction stores nothing else. Rebuilding a key from the display path
    // then addresses an entry the archive does not have (HUNT-100).
    //
    // After it: the flat-model path minus its leading slash, and then `name`
    // for records written before `path` was stored.
    let entry_name = artifact
        .metadata
        .get("original_name")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| {
            artifact
                .metadata
                .get("path")
                .and_then(|v| v.as_str())
                .map(|p| archive_internal_path(p).to_string())
        })
        .or_else(|| {
            artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "ZIP entry artifact {} has no path/name metadata",
                artifact.id
            ))
        })?;
    let entry_name = entry_name.as_str();

    let mut archive = zip::ZipArchive::new(SourceCursor::new(archive_source.clone()))
        .map_err(|e| ApiError::InvalidRequest(format!("Failed to open ZIP container: {}", e)))?;
    let mut entry = archive.by_name(entry_name).map_err(|e| {
        ApiError::ResourceNotFound(format!("ZIP entry '{}' not found: {}", entry_name, e))
    })?;

    if entry.size() > MAX_ZIP_ENTRY_BYTES {
        return Err(ApiError::PayloadTooLarge(format!(
            "ZIP entry '{}' is {} bytes; content access is capped at {} bytes",
            entry_name,
            entry.size(),
            MAX_ZIP_ENTRY_BYTES
        )));
    }

    let mut buf = Vec::with_capacity(entry.size() as usize);
    (&mut entry)
        .take(MAX_ZIP_ENTRY_BYTES + 1)
        .read_to_end(&mut buf)
        .map_err(|e| {
            ApiError::InternalServerError(format!(
                "Failed to read ZIP entry '{}': {}",
                entry_name, e
            ))
        })?;

    // The materialised length must match the central-directory claim: a
    // truncated (short) or over-claiming/bomb entry must fail closed, not be
    // served as complete content (BUG-084), matching ZipEntrySource (BUG-050).
    if buf.len() as u64 != entry.size() {
        return Err(ApiError::InvalidRequest(format!(
            "ZIP entry '{}' materialised {} bytes but its directory claims {}; \
             refusing to serve a mismatched/truncated entry",
            entry_name,
            buf.len(),
            entry.size()
        )));
    }

    // Materialised, but still able to reach its neighbours. A SQLite database
    // in an archive keeps its `-wal` in the same archive, and the newest rows
    // live there; handing the parser a bare buffer silently drops them
    // (HUNT-101).
    Ok(Arc::new(ZipEntryBytes {
        bytes: ByteSliceDataSource::new(buf),
        archive: archive_source,
        entry_name: entry_name.to_string(),
    }))
}

/// A materialised ZIP entry that can still be asked for its siblings.
///
/// `extract_zip_entry` has to decompress the whole entry — ZIP has no
/// random-access view — but the archive it came from is still open, so the
/// entry's neighbours are one lookup away. Without this a database resolved
/// through the API parses without its write-ahead log while the same database
/// parsed during ingest has it: the same evidence, two answers.
#[derive(Debug)]
struct ZipEntryBytes {
    bytes: ByteSliceDataSource,
    archive: Arc<dyn DataSource>,
    entry_name: String,
}

impl DataSource for ZipEntryBytes {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        self.bytes.read_at(offset, buf)
    }

    fn size(&self) -> u64 {
        self.bytes.size()
    }

    fn supports_siblings(&self) -> bool {
        true
    }

    fn open_relative(&self, relative: &str) -> Option<Arc<dyn DataSource>> {
        if !seance_core::data_source::relative_path_is_plain(relative) {
            return None;
        }
        let dir = match self.entry_name.rsplit_once('/') {
            Some((dir, _)) => format!("{dir}/"),
            None => String::new(),
        };
        let probe = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            serde_json::json!({"original_name": format!("{dir}{relative}"), "container": "zip"}),
        );
        extract_zip_entry(self.archive.clone(), &probe).ok()
    }

    fn supports_ancestors(&self) -> bool {
        true
    }

    /// A unified log's `../<XX>/<rest>` in a zipped `.logarchive`: up a
    /// bounded number of directories, inside the same archive (ROADMAP §1.6).
    fn open_from_ancestor(&self, levels: usize, relative: &str) -> Option<Arc<dyn DataSource>> {
        if !seance_core::data_source::relative_path_is_plain(relative) {
            return None;
        }
        let prefix = seance_core::data_source::ancestor_prefix(&self.entry_name, levels)?;
        let probe = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            serde_json::json!({"original_name": format!("{prefix}{relative}"), "container": "zip"}),
        );
        extract_zip_entry(self.archive.clone(), &probe).ok()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        let sibling = format!("{}{}", self.entry_name, suffix);
        let probe = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            serde_json::json!({"original_name": sibling, "container": "zip"}),
        );
        extract_zip_entry(self.archive.clone(), &probe).ok()
    }
}

/// Read `buf.len()` bytes from `src` at `offset`. Returns `true` only if the
/// whole buffer was filled; a short read (EOF/error) returns `false` so callers
/// fail closed instead of serving the unread tail as real zero bytes.
#[must_use]
fn read_into(src: &dyn DataSource, offset: u64, buf: &mut [u8]) -> bool {
    let mut o = 0usize;
    while o < buf.len() {
        // A read offset that would pass u64::MAX cannot be satisfied; wrapping
        // it would read the wrong bytes from the start of the device. Stop, so
        // the short-read contract makes the caller fail closed.
        let Some(at) = offset.checked_add(o as u64) else {
            break;
        };
        match src.read_at(at, &mut buf[o..]) {
            Ok(0) => break,
            Ok(n) => o += n,
            Err(_) => break,
        }
    }
    o == buf.len()
}

/// Assemble a btrfs file's logical content from its per-extent compression
/// descriptor. Each entry is `[file_off, phys|null, disk_len, ram_len, comp,
/// ext_off, num]`: read `disk_len` at `phys`, decompress (`comp`) to `ram_len`,
/// then place `num` bytes starting at `ext_off` at file offset `file_off`.
/// A `null` phys is a sparse hole (zeros).
fn assemble_btrfs_compressed(
    src: &Arc<dyn DataSource>,
    exts: &[serde_json::Value],
    size: u64,
    artifact_id: Uuid,
) -> Result<Vec<u8>, ApiError> {
    // `size` is the file's claimed length from the image; bound the output
    // buffer before allocating it.
    guard_alloc(
        size,
        MAX_RESOLVED_CONTENT_BYTES,
        "btrfs file size",
        artifact_id,
    )?;
    let src_len = src.size();
    let mut out = vec![0u8; size as usize];
    for e in exts {
        let arr = e.as_array().ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "Artifact {}: malformed btrfs_extents entry",
                artifact_id
            ))
        })?;
        let f = |i: usize| arr.get(i).and_then(|v| v.as_u64());
        let file_off = f(0).unwrap_or(0) as usize;
        let phys = arr.get(1).and_then(|v| v.as_u64()); // null = sparse
                                                        // A compressed blob cannot legitimately be larger than the source it is
                                                        // read from; clamp both the compressed-input and decompressed-output
                                                        // allocations so a crafted extent descriptor can't OOM the process.
        let disk_len = (f(2).unwrap_or(0)).min(src_len) as usize;
        let ram_len = guard_alloc(
            f(3).unwrap_or(0),
            MAX_RESOLVED_CONTENT_BYTES,
            "btrfs extent decompressed size",
            artifact_id,
        )?;
        let comp = f(4).unwrap_or(0) as u8;
        let ext_off = f(5).unwrap_or(0) as usize;
        let num = f(6).unwrap_or(0) as usize;
        if file_off >= out.len() {
            continue;
        }
        // saturating_add: `num` comes straight from image metadata, so a crafted
        // extent can push `file_off + num` past usize and wrap to an end below
        // `file_off`, which would panic the slice below (a 500 instead of an
        // answer). Clamping to the buffer keeps the copy in range.
        let end = file_off.saturating_add(num).min(out.len());
        let Some(p) = phys else { continue }; // sparse leaves zeros
        if comp == 0 {
            // A short read must not leave the extent zero-padded and served as
            // real content: fail closed on truncated/corrupt btrfs data (BUG-054).
            if !read_into(src.as_ref(), p, &mut out[file_off..end]) {
                return Err(ApiError::InvalidRequest(format!(
                    "Artifact {}: short read of btrfs extent; refusing to zero-pad",
                    artifact_id
                )));
            }
        } else {
            let mut blob = vec![0u8; disk_len];
            if !read_into(src.as_ref(), p, &mut blob) {
                return Err(ApiError::InvalidRequest(format!(
                    "Artifact {}: short read of compressed btrfs extent; refusing to decode partial data",
                    artifact_id
                )));
            }
            let dec = seance_core::compression::btrfs_decompress_blob(comp, &blob, ram_len)
                .ok_or_else(|| {
                    ApiError::InvalidRequest(format!(
                        "Artifact {}: btrfs extent decompression failed",
                        artifact_id
                    ))
                })?;
            let s = ext_off.min(dec.len());
            let want = end - file_off;
            // A short decompress must not leave the extent's tail as pre-zeroed
            // `out` and serve it as real content: fail closed exactly like the
            // uncompressed path above (BUG-160). Genuinely-sparse regions are
            // the `phys == null` branch, not a truncated decode.
            if dec.len().saturating_sub(s) < want {
                return Err(ApiError::InvalidRequest(format!(
                    "Artifact {}: btrfs extent decompressed short ({} of {} bytes); refusing to zero-pad",
                    artifact_id,
                    dec.len().saturating_sub(s),
                    want
                )));
            }
            out[file_off..end].copy_from_slice(&dec[s..s + want]);
        }
    }
    Ok(out)
}

/// Extend a run list with a trailing sparse (zero) run so it covers the file's
/// full logical `size`. When the run total is shorter than `size` the file has
/// a trailing sparse hole the FS parser omitted from the run list; serving the
/// runs as-is truncates downloads, hex, export and re-hash (BUG-154). A run
/// total already >= `size` (or an unknown size) is returned unchanged — the
/// caller shrinks oversize run lists with a `WindowSource`.
fn extend_runs_to_logical(
    mut runs: Vec<(Option<u64>, u64)>,
    size: Option<u64>,
) -> Vec<(Option<u64>, u64)> {
    if let Some(size) = size {
        // Saturate rather than wrap, exactly as `RunListDataSource::from_allocation` does
        // (BUG-093): a corrupt run list whose lengths sum past u64::MAX would
        // otherwise fold to a small total and this function would append a
        // multi-exabyte sparse "hole", fabricating zero bytes into every
        // download, hash and export of the file.
        let run_total: u64 = runs
            .iter()
            .fold(0u64, |acc, (_, len)| acc.saturating_add(*len));
        if let Some(hole) = size.checked_sub(run_total) {
            if hole > 0 {
                runs.push((None, hole));
            }
        }
    }
    runs
}

/// Parse the `data_runs` metadata array of `[offset|null, length]` pairs.
fn parse_data_runs(value: &serde_json::Value) -> Result<Vec<(Option<u64>, u64)>, String> {
    let arr = value.as_array().ok_or("not an array")?;
    let mut runs = Vec::with_capacity(arr.len());
    for run in arr {
        let pair = run
            .as_array()
            .filter(|p| p.len() == 2)
            .ok_or("entry is not an [offset, length] pair")?;
        let offset = if pair[0].is_null() {
            None
        } else {
            Some(
                pair[0]
                    .as_u64()
                    .ok_or("offset is not an unsigned integer")?,
            )
        };
        let length = pair[1]
            .as_u64()
            .ok_or("length is not an unsigned integer")?;
        runs.push((offset, length));
    }
    Ok(runs)
}

fn require_u64(artifact: &Artifact, key: &str) -> Result<u64, ApiError> {
    artifact
        .metadata
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "Artifact {} ({:?}) is missing required {} metadata",
                artifact.id, artifact.artifact_type, key
            ))
        })
}

/// Read as many bytes as the source can provide for `buf`, looping over
/// partial reads. Returns the number of bytes actually read.
pub(crate) fn read_fully(
    source: &dyn DataSource,
    mut offset: u64,
    buf: &mut [u8],
) -> std::io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = source.read_at(offset, &mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
        // An offset past u64::MAX cannot be read; wrapping would silently
        // continue the read from the start of the source. Stop instead and let
        // the caller see a short read.
        match offset.checked_add(n as u64) {
            Some(next) => offset = next,
            None => break,
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Physical location: where an artifact's bytes live on the backing device.
// ---------------------------------------------------------------------------

/// Assumed sector size for reporting sector numbers alongside byte offsets.
const REPORT_SECTOR_SIZE: u64 = 512;

/// The backing device the physical offsets are relative to.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DeviceRef {
    pub artifact_id: String,
    pub name: Option<String>,
    pub artifact_type: String,
    pub path: Option<String>,
    /// True when the device is a decoded container image (E01/VHD/VMDK/QCOW2):
    /// offsets are into the decoded disk, i.e. physical disk offsets.
    pub decoded_container: bool,
}

/// One contiguous extent of an artifact's content on its backing source.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PhysicalExtentDto {
    /// Byte offset in the source named by [`PhysicalExtentDto::source`], or
    /// `null` for a sparse/synthetic gap.
    pub device_offset: Option<u64>,
    pub length: u64,
    /// `device_offset / sector_size`, when device-backed and sector-aligned.
    ///
    /// `null` for an auxiliary extent even when the offset divides evenly: a
    /// sector number is a coordinate on the *device*, and quoting one for bytes
    /// that live in a pagefile would invite an examiner to go looking for that
    /// sector on the disk.
    pub sector: Option<u64>,
    /// True for a sparse (hole) region: no bytes on the device, reads as zeros.
    pub sparse: bool,
    /// Which source the offset belongs to: `"device"` for the evidence image,
    /// otherwise the auxiliary source's name — a pagefile, a swap device.
    ///
    /// The bytes of a swapped-out page are real and recoverable, but they are
    /// not in the memory image and were not in RAM at acquisition; they may
    /// predate it considerably. An examiner has to be able to tell the two
    /// apart, so the source travels with every extent.
    pub source: String,
}

/// One level of the artifact's ancestry, annotated with its coordinate mapping.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainLevelDto {
    pub artifact_id: String,
    pub name: Option<String>,
    pub artifact_type: String,
    /// Window/carve offset this level applies within its parent, if any.
    pub offset_in_parent: Option<u64>,
    /// The transform this level introduces: `container:e01`, `runs`, `carve`,
    /// `compressed:ntfs_lznt1`, `resident`, `reconstructed:vss`, ...
    pub transform: Option<String>,
    /// Number of fragments (data runs) at this level, if it is a run list.
    pub fragment_count: Option<u64>,
}

/// The physical location of an artifact's content on the backing device,
/// resolved through the whole container/filesystem chain.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PhysicalLocation {
    pub device: DeviceRef,
    /// Device-image extents in logical order (fragmentation-aware, coalesced).
    pub extents: Vec<PhysicalExtentDto>,
    /// Worst-case precision: `exact` | `encrypted` | `compressed` | `synthetic`.
    pub precision: String,
    /// Plain-language explanation when precision is not `exact`.
    pub note: Option<String>,
    /// True when the artifact's data runs were truncated (extremely fragmented),
    /// so the extent list is incomplete.
    pub truncated: bool,
    pub logical_size: u64,
    /// Total device-backed bytes (excludes sparse/synthetic regions).
    pub located_bytes: u64,
    pub sector_size: u64,
    /// Ancestry root-first, each level annotated with its mapping.
    pub chain: Vec<ChainLevelDto>,
}

/// Best-effort display name for an artifact (name, else path, else id).
fn artifact_label(a: &Artifact) -> Option<String> {
    a.metadata
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| a.metadata.get("path").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
}

/// Describe the transform + per-parent offset each chain level introduces.
fn annotate_chain(chain: &[Artifact]) -> Vec<ChainLevelDto> {
    chain
        .iter()
        .map(|a| {
            let md = &a.metadata;
            let container = md
                .get("container")
                .and_then(|v| v.as_str())
                .filter(|k| *k != "zip");
            let transform = if let Some(kind) = container {
                Some(format!("container:{kind}"))
            } else if md.get("container").and_then(|v| v.as_str()) == Some("zip") {
                Some("zip".to_string())
            } else if md.get("subtype").and_then(|v| v.as_str()) == Some("vss_snapshot")
                && md.get("content_reconstruction").and_then(|v| v.as_str())
                    == Some("reconstructed")
            {
                Some("reconstructed:vss".to_string())
            } else if md.get("resident_data_b64").is_some() {
                Some("resident".to_string())
            } else if let Some(comp) = md.get("compression").and_then(|v| v.as_str()) {
                Some(format!("compressed:{comp}"))
            } else if md.get("carving_offset").is_some() {
                Some("carve".to_string())
            } else if md.get("data_runs").is_some() {
                Some("runs".to_string())
            } else {
                None
            };

            let offset_in_parent = md
                .get("carving_offset")
                .and_then(|v| v.as_u64())
                .or_else(|| md.get("offset_bytes").and_then(|v| v.as_u64()));

            let fragment_count = md
                .get("data_runs")
                .and_then(|v| v.as_array())
                .map(|a| a.len() as u64);

            ChainLevelDto {
                artifact_id: a.id.to_string(),
                name: artifact_label(a),
                artifact_type: format!("{:?}", a.artifact_type),
                offset_in_parent,
                transform,
                fragment_count,
            }
        })
        .collect()
}

/// The chain index whose coordinate the device-absolute offsets are relative to:
/// the deepest (innermost) container decode, or the root when there is none.
/// A container decode inserts a `DeviceImageSource` that stops projection, so
/// offsets are relative to that decoded image (the physical disk it represents).
fn device_level(chain: &[Artifact]) -> usize {
    chain
        .iter()
        .enumerate()
        .rev()
        .find(|(_, a)| {
            a.metadata
                .get("container")
                .and_then(|v| v.as_str())
                .is_some_and(|k| k != "zip")
        })
        .map(|(i, _)| i)
        .unwrap_or(0)
}

/// Human-readable explanation for a non-exact precision.
fn precision_note(precision: ExtentPrecision, device_name: &str) -> Option<String> {
    match precision {
        ExtentPrecision::Exact => None,
        ExtentPrecision::Encrypted => Some(
            "The bytes at these offsets are encrypted on the device; the decryption key is \
             required to read them."
                .to_string(),
        ),
        ExtentPrecision::Compressed => Some(
            "The backing is compressed: the offsets locate the compressed data on the device, \
             not the exact logical byte."
                .to_string(),
        ),
        ExtentPrecision::Synthetic => Some(format!(
            "This content has no single device byte range: it is reconstructed or held in memory \
             (NTFS resident data, a decompressed file, a VSS shadow copy, or a ZIP entry). It \
             resides within {device_name}."
        )),
    }
}

/// Resolve the device-absolute physical location of `artifact_id`'s content.
///
/// Walks the parent chain, rebuilds the read stack, and projects the artifact's
/// whole logical range down to the backing device via [`DataSource::physical_map`].
pub async fn resolve_physical_location(
    db: &SqliteConnection,
    policy: &EvidenceRootPolicy,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<PhysicalLocation, ApiError> {
    let chain = build_chain(db, case_id, artifact_id).await?;
    let policy = policy.clone();

    tokio::task::spawn_blocking(move || {
        let target = chain.last().expect("chain is never empty").clone();
        let md = &target.metadata;

        // A compressed file's read stack yields decompressed bytes (no device
        // mapping). But we still know where the *compressed clusters* live: they
        // are the file's `data_runs` over the parent filesystem window. Project
        // those directly and label the precision `compressed`, so the on-disk
        // location is surfaced honestly rather than lost to "synthetic".
        let compressed = md.get("compression").is_some() && md.get("data_runs").is_some();
        // Encrypted-at-rest content has the same shape: the read stack refuses
        // to serve it (HUNT-014), but the run list still says where the
        // ciphertext sits on the device, and "where is this file?" stays a
        // legitimate question about a file nobody can read.
        let encrypted = ciphertext_marker(&target).is_some() && md.get("data_runs").is_some();

        let (map, forced_precision, logical_size) = if (compressed || encrypted) && chain.len() >= 2
        {
            let runs =
                parse_data_runs(md.get("data_runs").expect("checked present")).map_err(|e| {
                    ApiError::InvalidRequest(format!(
                        "Artifact {} has invalid data_runs: {}",
                        target.id, e
                    ))
                })?;
            let parent_stack = build_stack(&chain[..chain.len() - 1], &policy)?;
            // These runs are the *compressed* clusters, and `logical` below is
            // the decompressed length. The extent map should cover what is
            // actually on the disk, so the allocation is the content here — the
            // same distinction `seance_core::compression` draws.
            let run_source = RunListDataSource::from_allocation(parent_stack.source, runs);
            let logical = md
                .get("size")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| run_source.size());
            let m = run_source.physical_map(0, run_source.size()).coalesce();
            // Encryption outranks compression when a file carries both markers:
            // it is the missing key, not the codec, that stands between these
            // offsets and readable bytes.
            let forced = if encrypted {
                ExtentPrecision::Encrypted
            } else {
                ExtentPrecision::Compressed
            };
            (m, Some(forced), logical)
        } else {
            let resolved = build_stack(&chain, &policy)?;
            let ls = resolved.size;
            let m = resolved.source.physical_map(0, ls).coalesce();
            (m, None, ls)
        };

        let mut precision = forced_precision.unwrap_or(map.precision);
        // Belt and braces: never report byte-exact for a compressed artifact.
        if precision == ExtentPrecision::Exact && md.get("compression").is_some() {
            precision = ExtentPrecision::Compressed;
        }
        // Nor for one whose recorded bytes are ciphertext: "exact" would tell an
        // examiner the file is readable at these offsets (HUNT-014).
        if precision == ExtentPrecision::Exact && ciphertext_marker(&target).is_some() {
            precision = ExtentPrecision::Encrypted;
        }

        let dev_idx = device_level(&chain);
        let dev = &chain[dev_idx];
        let device = DeviceRef {
            artifact_id: dev.id.to_string(),
            name: artifact_label(dev),
            artifact_type: format!("{:?}", dev.artifact_type),
            path: dev
                .metadata
                .get("source_path")
                .or_else(|| dev.metadata.get("path"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            decoded_container: dev_idx != 0
                || dev
                    .metadata
                    .get("container")
                    .and_then(|v| v.as_str())
                    .is_some_and(|k| k != "zip"),
        };

        let device_name = device
            .name
            .clone()
            .unwrap_or_else(|| "the backing device".to_string());

        let extents = map
            .extents
            .iter()
            .map(|e| PhysicalExtentDto {
                device_offset: e.device_offset,
                length: e.length,
                // Sector numbers are device coordinates, so they are quoted
                // only for device-backed extents.
                sector: (!e.is_auxiliary())
                    .then(|| {
                        e.device_offset.and_then(|o| {
                            (o % REPORT_SECTOR_SIZE == 0).then_some(o / REPORT_SECTOR_SIZE)
                        })
                    })
                    .flatten(),
                sparse: e.device_offset.is_none() && precision != ExtentPrecision::Synthetic,
                source: match e.source {
                    ExtentSource::Device => "device".to_string(),
                    // An index with no name behind it should be impossible —
                    // `absorb` demotes a dangling index to `Device` — but if one
                    // ever arrives, say so rather than implying the image.
                    ExtentSource::Auxiliary(i) => map
                        .auxiliary_sources
                        .get(i as usize)
                        .cloned()
                        .unwrap_or_else(|| "an unnamed auxiliary source".to_string()),
                },
            })
            .collect();

        let truncated = md.get("data_runs_complete").and_then(|v| v.as_bool()) == Some(false);

        Ok(PhysicalLocation {
            note: precision_note(precision, &device_name),
            precision: precision.as_str().to_string(),
            device,
            extents,
            truncated,
            logical_size,
            located_bytes: map.located_len(),
            sector_size: REPORT_SECTOR_SIZE,
            chain: annotate_chain(&chain),
        })
    })
    .await
    .map_err(|e| {
        ApiError::InternalServerError(format!("Physical-location resolution task failed: {}", e))
    })?
}

#[cfg(test)]
mod cache_tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;

    #[test]
    fn container_cache_returns_same_handle_on_hit() {
        // A cache hit must return the exact stored handle (no re-open), which is
        // what avoids re-globbing the E01 on every content request.
        let key = (
            "e01".to_string(),
            "/evidence/unit-test-cache.E01".to_string(),
        );
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![1, 2, 3]));
        container_cache()
            .lock()
            .unwrap()
            .put(key.clone(), Arc::clone(&src));
        let got = container_cache()
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .expect("cached handle retrievable");
        assert!(Arc::ptr_eq(&src, &got));
    }

    #[test]
    fn decompressed_cache_caches_small_but_not_huge() {
        // A small decompressed file is cached (subsequent range requests reuse
        // it); an over-cap file is served but not retained.
        let small = Uuid::new_v4();
        let ds = cache_decompressed(small, vec![7u8; 1024]);
        let hit = decompressed_cache().lock().unwrap().get(&small).cloned();
        assert!(hit.map(|h| Arc::ptr_eq(&h, &ds)).unwrap_or(false));

        let huge = Uuid::new_v4();
        let _ = cache_decompressed(huge, vec![0u8; DECOMPRESSED_CACHE_MAX_BYTES + 1]);
        assert!(decompressed_cache().lock().unwrap().get(&huge).is_none());
    }

    #[test]
    fn guard_alloc_rejects_over_ceiling() {
        let id = Uuid::new_v4();
        // Within the ceiling: allowed.
        assert_eq!(
            guard_alloc(1024, MAX_RESOLVED_CONTENT_BYTES, "x", id).unwrap(),
            1024
        );
        // Over the ceiling: rejected, not allocated.
        assert!(guard_alloc(
            MAX_RESOLVED_CONTENT_BYTES + 1,
            MAX_RESOLVED_CONTENT_BYTES,
            "x",
            id
        )
        .is_err());
    }

    fn artifact(kind: ArtifactType, md: serde_json::Value) -> Artifact {
        Artifact::new(Uuid::new_v4(), kind, None, md)
    }

    #[test]
    fn resident_data_is_bounded_before_decoding() {
        // Inline/resident content is a few KiB of filesystem structure. A
        // hostile `resident_data_b64` must be refused, not decoded into a
        // multi-GiB allocation (BUG-248).
        let parent = artifact(ArtifactType::FileSystem, serde_json::json!({}));
        let policy = EvidenceRootPolicy::unrestricted();
        let current: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 8]));

        let oversize = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "hostile.bin",
                "resident_data_b64": "A".repeat(MAX_RESIDENT_DATA_BYTES as usize + 4),
            }),
        );
        let err = apply_step(current.clone(), &oversize, &parent, &policy)
            .expect_err("over-ceiling resident data must be refused");
        assert!(
            format!("{err:?}").contains("resident_data_b64"),
            "error should name the offending field: {err:?}"
        );

        // A normal resident attribute still resolves to its exact bytes.
        let ok = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "small.txt",
                "resident_data_b64": base64::engine::general_purpose::STANDARD.encode(b"hello"),
            }),
        );
        let resolved = apply_step(current, &ok, &parent, &policy).expect("small resident data");
        assert_eq!(resolved.size(), 5);
    }

    /// HUNT-014: an fscrypt (ext4/F2FS/btrfs) or NTFS EFS file keeps its
    /// `data_runs`, but those runs address ciphertext. Rebuilding them served
    /// the ciphertext as the file's content, and a re-hash of it is filed in the
    /// same digest columns as a plaintext hash, where a known-file lookup reads
    /// it as the file's own digest.
    #[test]
    fn encrypted_at_rest_data_runs_are_refused_instead_of_served_as_content() {
        let parent = artifact(ArtifactType::FileSystem, serde_json::json!({}));
        let policy = EvidenceRootPolicy::unrestricted();
        let current: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xAB; 64]));

        // Every marker form a parser uses to say "these bytes are ciphertext".
        let markers = [
            // ext4/F2FS/btrfs fscrypt
            serde_json::json!({"encrypted": true, "content_ciphertext": "ext4_fscrypt"}),
            // NTFS EFS
            serde_json::json!({"efs_encrypted": true}),
            // The producer-side incompleteness contract on its own.
            serde_json::json!({
                "content_incomplete": true,
                "content_incomplete_reason": "encrypted",
            }),
        ];
        for extra in markers {
            let mut md = serde_json::json!({
                "name": "secret.txt",
                "size": 16,
                "data_runs": [[0, 16]],
            });
            for (key, value) in extra.as_object().expect("marker object") {
                md[key.as_str()] = value.clone();
            }
            let encrypted = artifact(ArtifactType::FileEntry, md);
            let err = apply_step(current.clone(), &encrypted, &parent, &policy)
                .expect_err("ciphertext runs must not be rebuilt into served content");
            assert!(
                format!("{err:?}").contains("ciphertext"),
                "the refusal must say the runs address ciphertext: {err:?}"
            );
        }

        // The same runs with no encryption marker still resolve: the guard must
        // refuse ciphertext, not ordinary file content.
        let plain = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "notes.txt",
                "size": 16,
                "data_runs": [[0, 16]],
            }),
        );
        let resolved =
            apply_step(current, &plain, &parent, &policy).expect("plaintext runs must resolve");
        assert_eq!(resolved.size(), 16);
        assert_eq!(read_all(&resolved), vec![0xABu8; 16]);
    }

    /// HUNT-004: an encrypted iOS backup stores ciphertext on disk; the per-file
    /// key is unwrapped with the backup password at ingest and the plaintext
    /// only ever exists in memory. The on-demand shortcut re-opened
    /// `<backup_path>/<file_id>` regardless, so content, hex, export and re-hash
    /// served ciphertext under a plaintext-sized entry.
    #[test]
    fn an_encrypted_ios_backup_file_is_not_resolved_to_its_stored_ciphertext() {
        let policy = EvidenceRootPolicy::unrestricted();
        let backup = tempfile::tempdir().expect("temp backup dir");
        let backup_path = backup.path().to_string_lossy().to_string();
        let write_blob = |file_id: &str, bytes: &[u8]| {
            let dir = backup.path().join(&file_id[..2]);
            std::fs::create_dir_all(&dir).expect("fan-out dir");
            std::fs::write(dir.join(file_id), bytes).expect("stored blob");
        };

        let cipher_id = "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
        write_blob(cipher_id, b"CIPHERTEXTCIPHERTEXT");
        // `decrypted: true` is what ingest stamps after decrypting in memory --
        // nothing plaintext was written, so the stored blob is still ciphertext.
        let encrypted = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "Notes.sqlite",
                "file_id": cipher_id,
                "backup_path": backup_path.clone(),
                "is_directory": false,
                "size": 20,
                "encrypted": true,
                "decrypted": true,
            }),
        );
        let err = direct_backup_file_source(&encrypted, &policy)
            .expect_err("an encrypted backup's stored blob must not be served as content");
        assert!(
            format!("{err:?}").contains("ciphertext"),
            "the refusal must say the stored bytes are ciphertext: {err:?}"
        );

        // A file from an unencrypted backup still resolves from the same layout.
        let plain_id = "0f1e2d3c4b5a69788796a5b4c3d2e1f001234567";
        write_blob(plain_id, b"plaintext");
        let plain = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "Notes.sqlite",
                "file_id": plain_id,
                "backup_path": backup_path,
                "is_directory": false,
                "size": 9,
            }),
        );
        let source = direct_backup_file_source(&plain, &policy)
            .expect("an unencrypted backup file must still resolve")
            .expect("a content-bearing backup file yields a source");
        assert_eq!(source.size(), 9);
    }

    /// BUG-026: the synthetic encrypted backup (same keybag, key-wrap and AES
    /// code as ingest — a mechanism fixture, not validation against a real
    /// device) and the ingest-shaped record for its one file.
    fn unlockable_backup_file() -> (std::path::PathBuf, String, Artifact, &'static [u8]) {
        use seance_plugin_ios_backup::test_support::{build_encrypted_backup, KeyShape};
        const PLAIN: &[u8] = b"sms.db plaintext re-read after ingest";
        let file_id = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
        let (dir, password) = build_encrypted_backup(&[(
            file_id,
            "Library/SMS/sms.db",
            1,
            PLAIN,
            KeyShape::ClassFieldAndKey,
        )]);
        let record = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "type": "IosBackupFile",
                "name": "sms.db",
                "file_id": file_id,
                "backup_path": dir.to_string_lossy(),
                "is_directory": false,
                "size": PLAIN.len(),
                "encrypted": true,
                "decrypted": true,
            }),
        );
        (dir, password, record, PLAIN)
    }

    #[test]
    fn an_encrypted_ios_backup_file_is_refused_with_the_unlock_route_named_while_no_keys_are_held()
    {
        let (dir, _password, record, _) = unlockable_backup_file();
        let err = direct_backup_file_source(&record, &EvidenceRootPolicy::unrestricted())
            .expect_err("no keys held: still refused");
        let msg = format!("{err:?}");
        assert!(msg.contains("ciphertext"), "{msg}");
        assert!(
            msg.contains("/unlock"),
            "the refusal names the unlock route: {msg}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_encrypted_ios_backup_file_resolves_to_plaintext_while_its_keys_are_held() {
        use sha2::{Digest, Sha256};
        let (dir, password, record, plain) = unlockable_backup_file();
        let unlocked =
            seance_plugin_ios_backup::unlock_backup(&dir, &password).expect("password unlocks");
        let ring = crate::backup_keyring::ios_backups();
        ring.insert(
            record.case_id,
            &crate::backup_keyring::source_key(&dir),
            unlocked,
        );

        let src = direct_backup_file_source(&record, &EvidenceRootPolicy::unrestricted())
            .expect("keys held: resolves")
            .expect("a content-bearing backup file yields a source");
        let bytes = read_all(&src);
        assert_eq!(bytes, plain);
        assert_eq!(Sha256::digest(&bytes), Sha256::digest(plain));

        ring.remove(record.case_id, &crate::backup_keyring::source_key(&dir));
        assert!(
            direct_backup_file_source(&record, &EvidenceRootPolicy::unrestricted()).is_err(),
            "locked again: refused again"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_held_key_for_another_case_does_not_unlock_this_artifact() {
        let (dir, password, record, _) = unlockable_backup_file();
        let unlocked =
            seance_plugin_ios_backup::unlock_backup(&dir, &password).expect("password unlocks");
        let other_case = Uuid::new_v4();
        let ring = crate::backup_keyring::ios_backups();
        ring.insert(
            other_case,
            &crate::backup_keyring::source_key(&dir),
            unlocked,
        );

        let err = direct_backup_file_source(&record, &EvidenceRootPolicy::unrestricted())
            .expect_err("keys held for another case do not open this case's artifact");
        assert!(format!("{err:?}").contains("ciphertext"), "{err:?}");
        ring.clear_case(other_case);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A volume decrypted in memory records a plaintext window (`offset_bytes:
    /// 0`) over a parent whose bytes are ciphertext. Resolved as a window, the
    /// volume and every file beneath it were served as ciphertext.
    #[test]
    fn a_volume_decrypted_in_memory_is_refused_not_served_as_ciphertext() {
        let parent = artifact(ArtifactType::Partition, serde_json::json!({}));
        let policy = EvidenceRootPolicy::unrestricted();
        let current: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xCD; 64]));
        for flag in ["bitlocker_decrypted", "luks_decrypted"] {
            let volume = artifact(
                ArtifactType::Partition,
                serde_json::json!({flag: true, "offset_bytes": 0, "size_bytes": 64}),
            );
            let err = apply_step(current.clone(), &volume, &parent, &policy)
                .expect_err("a decrypted view must not be rebuilt from ciphertext");
            assert!(format!("{err:?}").contains("ciphertext"), "{err:?}");
            assert!(
                format!("{err:?}").contains("/unlock"),
                "the refusal names the unlock-for-reading route: {err:?}"
            );
        }
    }

    /// HUNT-254: forgetting an unlocked volume drops every cached source
    /// that could hold its decrypting view, so the key is not kept alive by a
    /// cache after the lock.
    #[test]
    fn forgetting_cached_views_releases_every_cached_handle() {
        let view: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![1u8; 8]));
        let id = Uuid::new_v4();
        vss_reconstruction_cache()
            .lock()
            .unwrap()
            .put(id, view.clone());
        decompressed_cache().lock().unwrap().put(id, view.clone());
        container_cache()
            .lock()
            .unwrap()
            .put((id.to_string(), "k".to_string()), view.clone());
        // (Other tests share these caches and may evict entries, so only the
        // end state is asserted.)
        forget_cached_views();
        assert_eq!(
            Arc::strong_count(&view),
            1,
            "a cache still holds the view after it was forgotten"
        );
    }

    /// BUG-026: locking an iOS backup again drops every cached source too. A
    /// gzip or a zip inside a backup file is cached as plaintext while the
    /// backup is unlocked; the lock must not leave it alive in a cache.
    #[test]
    fn locking_an_ios_backup_releases_every_cached_handle() {
        let view: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![2u8; 8]));
        let id = Uuid::new_v4();
        decompressed_cache().lock().unwrap().put(id, view.clone());
        container_cache()
            .lock()
            .unwrap()
            .put((id.to_string(), "k".to_string()), view.clone());
        crate::unlock_route::forget_ios_backup(Uuid::new_v4(), "/no/such/backup");
        assert_eq!(
            Arc::strong_count(&view),
            1,
            "a cache still holds a plaintext view after the backup was locked"
        );
    }

    /// HUNT-254: once the locked volume is unlocked for reading in this case,
    /// the decrypted view resolves to the held plaintext — and a file window
    /// beneath it reads through it — and locking it again brings the refusal
    /// back. The decrypting source here is a stand-in (a synthetic fixture
    /// pinning the mechanism); real decryption is graded in the route test on
    /// `test_data/bdetogo.raw`.
    #[test]
    fn a_decrypted_volume_with_a_retained_key_resolves_to_plaintext_until_locked() {
        use crate::unlocked_volumes::{volume_key, volumes, UnlockedVolumeView};
        let case = Uuid::new_v4();
        let mut locked = artifact(ArtifactType::Partition, serde_json::json!({}));
        locked.case_id = case;
        let policy = EvidenceRootPolicy::unrestricted();
        let ciphertext: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xCD; 64]));
        let plaintext: Vec<u8> = (0u8..64).collect();
        for flag in ["bitlocker_decrypted", "luks_decrypted"] {
            let mut volume = artifact(
                ArtifactType::Partition,
                serde_json::json!({flag: true, "offset_bytes": 0, "size_bytes": 64,
                    "volume_artifact_id": locked.id.to_string()}),
            );
            volume.case_id = case;
            volumes().insert(
                case,
                &volume_key(locked.id),
                UnlockedVolumeView {
                    kind: "bitlocker_password",
                    source: Arc::new(ByteSliceDataSource::new(plaintext.clone())),
                },
            );
            let view = apply_step(ciphertext.clone(), &volume, &locked, &policy)
                .expect("an unlocked volume resolves");
            let mut buf = vec![0u8; 64];
            assert_eq!(view.read_at(0, &mut buf).unwrap(), 64);
            assert_eq!(buf, plaintext, "{flag}: the held plaintext, not ciphertext");

            let mut child = artifact(
                ArtifactType::Partition,
                serde_json::json!({"offset_bytes": 8, "size_bytes": 4}),
            );
            child.case_id = case;
            let file = apply_step(view, &child, &volume, &policy).expect("window");
            let mut buf = vec![0u8; 4];
            assert_eq!(file.read_at(0, &mut buf).unwrap(), 4);
            assert_eq!(buf, vec![8, 9, 10, 11], "a window beneath reads plaintext");

            // Another case holding the same artifact ids is still refused.
            let mut foreign = volume.clone();
            foreign.case_id = Uuid::new_v4();
            let mut foreign_parent = locked.clone();
            foreign_parent.case_id = foreign.case_id;
            assert!(apply_step(ciphertext.clone(), &foreign, &foreign_parent, &policy).is_err());

            assert!(volumes().remove(case, &volume_key(locked.id)));
            let err = apply_step(ciphertext.clone(), &volume, &locked, &policy)
                .expect_err("locked again: refused");
            assert!(format!("{err:?}").contains("ciphertext"), "{err:?}");
        }
    }

    #[test]
    fn ciphertext_marker_does_not_fire_on_a_negative_encryption_flag() {
        // APFS stamps `encrypted: false` on every unlocked volume, and the
        // incompleteness pair carries reasons that are not encryption. Neither
        // may block content resolution.
        let unlocked_volume = artifact(
            ArtifactType::FileSystem,
            serde_json::json!({"filesystem_type": "APFS", "encrypted": false}),
        );
        assert!(ciphertext_marker(&unlocked_volume).is_none());

        let sparse = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "content_incomplete": true,
                "content_incomplete_reason": "unmapped",
            }),
        );
        assert!(ciphertext_marker(&sparse).is_none());

        let efs = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({"content_ciphertext": "ntfs_efs"}),
        );
        assert_eq!(ciphertext_marker(&efs), Some("content_ciphertext"));
    }

    #[test]
    fn extend_runs_to_logical_appends_trailing_sparse_hole() {
        // Runs cover 6 bytes; logical size is 10 -> a 4-byte trailing sparse
        // hole must be appended so downloads/hashes see the full length.
        let runs = vec![(Some(0u64), 4u64), (Some(4u64), 2u64)];
        let out = extend_runs_to_logical(runs, Some(10));
        assert_eq!(out.last().copied(), Some((None, 4)));
        let total: u64 = out.iter().map(|(_, l)| l).sum();
        assert_eq!(total, 10);
    }

    #[test]
    fn extend_runs_to_logical_leaves_exact_and_oversize_unchanged() {
        // Exactly logical: no hole appended.
        let exact = extend_runs_to_logical(vec![(Some(0u64), 8u64)], Some(8));
        assert_eq!(exact, vec![(Some(0), 8)]);
        // Runs already exceed logical (allocation slack): unchanged; the caller
        // shrinks with a WindowSource.
        let oversize = extend_runs_to_logical(vec![(Some(0u64), 12u64)], Some(8));
        assert_eq!(oversize, vec![(Some(0), 12)]);
        // Unknown size: unchanged.
        let unknown = extend_runs_to_logical(vec![(Some(0u64), 3u64)], None);
        assert_eq!(unknown, vec![(Some(0), 3)]);
    }

    /// B3-007: run lengths that sum past u64::MAX must saturate, not wrap.
    /// A wrapped total looks smaller than the logical size, so this function
    /// would append a sparse hole and the examiner would download a file whose
    /// tail is fabricated zeroes that exist nowhere in the evidence.
    #[test]
    fn extend_runs_to_logical_does_not_fabricate_a_hole_on_overflow() {
        let runs = vec![(Some(0u64), u64::MAX), (Some(0u64), 32u64)];
        let out = extend_runs_to_logical(runs.clone(), Some(4096));
        assert_eq!(
            out, runs,
            "an overflowing run total must leave the run list untouched"
        );
        assert!(
            !out.iter().any(|(off, _)| off.is_none()),
            "no sparse hole may be appended when the run total overflows"
        );
    }

    fn zlib(data: &[u8]) -> Vec<u8> {
        use flate2::{write::ZlibEncoder, Compression};
        use std::io::Write;
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn assemble_btrfs_compressed_fails_closed_on_short_decompress() {
        // A compressed extent that decompresses to fewer bytes than it claims
        // (ram_len/num = 16 but the blob only yields 3) must error, not serve a
        // zero-padded tail as real content (BUG-160).
        let blob = zlib(b"abc");
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(blob.clone()));
        // [file_off, phys, disk_len, ram_len, comp=zlib(1), ext_off, num]
        let exts = vec![serde_json::json!([0, 0, blob.len(), 16, 1, 0, 16])];
        let err = assemble_btrfs_compressed(&src, &exts, 16, Uuid::new_v4());
        assert!(err.is_err(), "short decompress must fail closed");
    }

    #[test]
    fn assemble_btrfs_compressed_full_decompress_succeeds() {
        // A well-formed compressed extent that yields exactly `num` bytes.
        let plain = b"hello world 1234";
        let blob = zlib(plain);
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(blob.clone()));
        let exts = vec![serde_json::json!([
            0,
            0,
            blob.len(),
            plain.len(),
            1,
            0,
            plain.len()
        ])];
        let out =
            assemble_btrfs_compressed(&src, &exts, plain.len() as u64, Uuid::new_v4()).unwrap();
        assert_eq!(out, plain);
    }

    #[test]
    fn device_level_picks_innermost_container_decode() {
        // dd (raw) root, no container -> level 0.
        let raw = vec![
            artifact(
                ArtifactType::RawEvidence,
                serde_json::json!({"source_path": "/e.dd"}),
            ),
            artifact(
                ArtifactType::Partition,
                serde_json::json!({"offset_bytes": 2048}),
            ),
        ];
        assert_eq!(device_level(&raw), 0);

        // E01 container: the decoded RawEvidence at index 1 is the device.
        let e01 = vec![
            artifact(
                ArtifactType::Container,
                serde_json::json!({"source_path": "/e.E01"}),
            ),
            artifact(
                ArtifactType::RawEvidence,
                serde_json::json!({"container": "e01"}),
            ),
            artifact(
                ArtifactType::Partition,
                serde_json::json!({"offset_bytes": 1048576}),
            ),
        ];
        assert_eq!(device_level(&e01), 1);

        // A ZIP entry is not a block device: it must not count as a container.
        let zip = vec![
            artifact(
                ArtifactType::RawEvidence,
                serde_json::json!({"source_path": "/e.dd"}),
            ),
            artifact(
                ArtifactType::FileEntry,
                serde_json::json!({"container": "zip"}),
            ),
        ];
        assert_eq!(device_level(&zip), 0);
    }

    #[test]
    fn annotate_chain_labels_transforms_and_fragments() {
        let chain = vec![
            artifact(
                ArtifactType::Partition,
                serde_json::json!({"name": "p1", "offset_bytes": 2048}),
            ),
            artifact(
                ArtifactType::FileEntry,
                serde_json::json!({
                    "name": "secret.jpg",
                    "data_runs": [[100, 400], [10000, 600]],
                }),
            ),
        ];
        let ann = annotate_chain(&chain);
        assert_eq!(ann[0].transform.as_deref(), None);
        assert_eq!(ann[0].offset_in_parent, Some(2048));
        assert_eq!(ann[1].transform.as_deref(), Some("runs"));
        assert_eq!(ann[1].fragment_count, Some(2));
        assert_eq!(ann[1].name.as_deref(), Some("secret.jpg"));
    }

    #[test]
    fn assemble_btrfs_rejects_hostile_sizes_instead_of_oom() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 64]));
        let id = Uuid::new_v4();
        // A crafted image claiming a 100 GiB file must be rejected, not allocated.
        let err = assemble_btrfs_compressed(&src, &[], 100 * 1024 * 1024 * 1024, id);
        assert!(err.is_err(), "oversized btrfs file size must be rejected");

        // A crafted per-extent decompressed length must also be rejected.
        let exts = vec![serde_json::json!([
            0u64,
            0u64,
            8u64,
            100u64 * 1024 * 1024 * 1024,
            1u64,
            0u64,
            8u64
        ])];
        let err = assemble_btrfs_compressed(&src, &exts, 8, id);
        assert!(
            err.is_err(),
            "oversized btrfs extent ram_len must be rejected"
        );
    }

    /// One ustar header block for `name` plus its NUL-padded payload. Built by
    /// hand so the test drives the real archive readers without a writer crate.
    fn tar_block(name: &str, data: &[u8]) -> Vec<u8> {
        let mut header = [0u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        header[100..107].copy_from_slice(b"0000644"); // mode
        header[108..115].copy_from_slice(b"0000000"); // uid
        header[116..123].copy_from_slice(b"0000000"); // gid
        header[124..135].copy_from_slice(format!("{:011o}", data.len()).as_bytes());
        header[136..147].copy_from_slice(b"00000000000"); // mtime
        header[156] = b'0'; // regular file
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        // Checksum is computed with the checksum field itself read as spaces.
        let sum: u32 = header[..148]
            .iter()
            .chain(header[156..].iter())
            .map(|b| *b as u32)
            .sum::<u32>()
            + 8 * 32;
        header[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());

        let mut out = header.to_vec();
        out.extend_from_slice(data);
        out.resize(out.len().div_ceil(512) * 512, 0);
        out
    }

    fn read_all(src: &Arc<dyn DataSource>) -> Vec<u8> {
        let mut buf = vec![0u8; src.size() as usize];
        assert!(read_into(src.as_ref(), 0, &mut buf), "short read");
        buf
    }

    /// LIVE-005: an entry the archive itself names `/absolute.txt` is stored by
    /// ingest as `//absolute.txt` (its own `/` prefix on a name that already had
    /// one). Stripping every leading slash asked the tar for `absolute.txt`, a
    /// name it does not contain, so the entry 404'd and was unreachable through
    /// the product even though its bytes were sitting in the evidence.
    #[test]
    fn tar_entry_whose_archive_name_begins_with_a_slash_resolves() {
        let mut tar = tar_block("data/alpha.txt", b"alpha");
        tar.extend_from_slice(&tar_block("/absolute.txt", b"absolute"));
        tar.extend_from_slice(&[0u8; 1024]); // end-of-archive marker
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(tar));

        let absolute = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "absolute.txt",
                "path": "//absolute.txt",
                "container": "tar",
            }),
        );
        let resolved = extract_tar_entry(Arc::clone(&src), &absolute)
            .expect("an absolute-path tar entry must resolve to its bytes");
        assert_eq!(&read_all(&resolved)[..], b"absolute");

        // And the ordinary case still resolves: exactly one slash comes off.
        let alpha = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "alpha.txt",
                "path": "/data/alpha.txt",
                "container": "tar",
            }),
        );
        let resolved =
            extract_tar_entry(src, &alpha).expect("an ordinary tar entry must still resolve");
        assert_eq!(&read_all(&resolved)[..], b"alpha");
    }

    fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        for (name, data) in entries {
            writer.start_file(*name, options).unwrap();
            writer.write_all(data).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    /// HUNT-101. A SQLite database inside an archive keeps its `-wal` in the
    /// same archive, and the newest rows live there. `extract_zip_entry` has to
    /// decompress the whole entry, and handing the parser a bare buffer meant a
    /// database resolved through the API parsed without its write-ahead log
    /// while the same database parsed during ingest had it: the same evidence,
    /// two answers.
    #[test]
    fn a_materialised_zip_entry_can_still_reach_its_wal() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(zip_bytes(&[
            ("/var/Cache.sqlite", &b"main database"[..]),
            ("/var/Cache.sqlite-wal", &b"write ahead log"[..]),
        ])));

        let entry = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "Cache.sqlite",
                "path": "/var/Cache.sqlite",
                "original_name": "/var/Cache.sqlite",
                "container": "zip",
            }),
        );
        let resolved = extract_zip_entry(Arc::clone(&src), &entry).expect("the entry resolves");
        assert_eq!(&read_all(&resolved)[..], b"main database");

        assert!(resolved.supports_siblings());
        let wal = resolved
            .open_sibling("-wal")
            .expect("the -wal is in the same archive");
        assert_eq!(&read_all(&wal)[..], b"write ahead log");
        assert!(resolved.open_sibling("-journal").is_none());
    }

    /// ROADMAP §1.6. A unified log resolved out of a zipped `.logarchive`
    /// reaches its format strings one directory up, inside the same archive.
    #[test]
    fn a_materialised_zip_entry_can_reach_an_ancestor_directory() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(zip_bytes(&[
            ("/a.logarchive/Persist/1.tracev3", &b"log"[..]),
            ("/a.logarchive/AB/CDEF", &b"strings"[..]),
        ])));
        let entry = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "1.tracev3",
                "path": "/a.logarchive/Persist/1.tracev3",
                "original_name": "/a.logarchive/Persist/1.tracev3",
                "container": "zip",
            }),
        );
        let resolved = extract_zip_entry(Arc::clone(&src), &entry).expect("the entry resolves");
        assert!(resolved.supports_ancestors());
        let strings = resolved
            .open_from_ancestor(1, "AB/CDEF")
            .expect("one directory up, in the same archive");
        assert_eq!(&read_all(&strings)[..], b"strings");
        assert!(resolved.open_from_ancestor(1, "../AB/CDEF").is_none());
        assert!(resolved.open_from_ancestor(4, "AB/CDEF").is_none());
    }

    /// HUNT-100. The zip reader records the archive's own key in
    /// `original_name` whenever path resolution changed it — and an iOS full
    /// file system extraction stores every entry with a leading slash, so every
    /// one of them was changed. The resolver rebuilt a key from the *display*
    /// path instead, and the archive does not have an entry by that name: on a
    /// 545,000-artifact case not one nested file's bytes could be served,
    /// previewed, exported or re-parsed.
    #[test]
    fn zip_entry_resolves_by_the_archives_own_key() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(zip_bytes(&[(
            "/private/var/mobile/Cache.sqlite",
            &b"sqlite bytes"[..],
        )])));

        let entry = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "Cache.sqlite",
                "path": "/private/var/mobile/Cache.sqlite",
                "original_name": "/private/var/mobile/Cache.sqlite",
                "container": "zip",
            }),
        );
        let resolved = extract_zip_entry(Arc::clone(&src), &entry)
            .expect("the archive's own key is what addresses the entry");
        assert_eq!(&read_all(&resolved)[..], b"sqlite bytes");
    }

    /// The ZIP half of LIVE-005: zip ingest prefixes the stored `path` the same
    /// way, so an entry named `/absolute.txt` was looked up as `absolute.txt`
    /// and reported missing from an archive that contains it.
    #[test]
    fn zip_entry_whose_archive_name_begins_with_a_slash_resolves() {
        let src: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(zip_bytes(&[
            ("data/alpha.txt", &b"alpha"[..]),
            ("/absolute.txt", &b"absolute"[..]),
        ])));

        let absolute = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "absolute.txt",
                "path": "//absolute.txt",
                "container": "zip",
            }),
        );
        let resolved = extract_zip_entry(Arc::clone(&src), &absolute)
            .expect("an absolute-path ZIP entry must resolve to its bytes");
        assert_eq!(&read_all(&resolved)[..], b"absolute");

        let alpha = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "alpha.txt",
                "path": "/data/alpha.txt",
                "container": "zip",
            }),
        );
        let resolved =
            extract_zip_entry(src, &alpha).expect("an ordinary ZIP entry must still resolve");
        assert_eq!(&read_all(&resolved)[..], b"alpha");
    }

    /// A `com.apple.decmpfs` attribute: the 16-byte header (`fpmc`, compression
    /// type, logical size) followed by the compressed stream, exactly as the
    /// xattr is stored on the volume.
    fn decmpfs_attribute(compression_type: u32, logical: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(DECMPFS_HEADER_BYTES + payload.len());
        // The magic is the u32 0x636d7066 stored little-endian, i.e. `fpmc`.
        out.extend_from_slice(b"fpmc");
        out.extend_from_slice(&compression_type.to_le_bytes());
        out.extend_from_slice(&logical.to_le_bytes());
        out.extend_from_slice(payload);
        out
    }

    const DECMPFS_HEADER_BYTES: usize = 16;

    /// The parsed artifact carrying `name`, or a panic naming what is absent.
    fn parsed_entry<'a>(parsed: &'a [Artifact], name: &str) -> &'a Artifact {
        parsed
            .iter()
            .find(|a| a.metadata.get("name").and_then(|v| v.as_str()) == Some(name))
            .unwrap_or_else(|| panic!("{name} must be in the inventory"))
    }

    /// LIVE-001: a decmpfs (transparently compressed) file has no data-stream
    /// extents of its own, so nothing in the recorded chain located its bytes
    /// and it fell through every branch to "no recorded content location" —
    /// unreadable, unexportable and unhashable once ingest's decoded buffer was
    /// gone. `test_data/` is not in the repository, so the real-image test below
    /// skips wherever the corpus is absent; this one always runs and is what
    /// holds the branch in place.
    #[test]
    fn a_decmpfs_artifact_resolves_through_the_decoder_and_ordinary_runs_are_untouched() {
        let policy = EvidenceRootPolicy::unrestricted();
        let parent = artifact(ArtifactType::FileSystem, serde_json::json!({}));
        // A volume window whose bytes are nothing like the file's plaintext: if
        // the resolver ever served the window (or the compressed stream) instead
        // of decoding, the comparison below would catch it.
        let current: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0xCD; 4096]));

        let plaintext = b"SEANCE decmpfs test. ".repeat(64);
        // Type 3 is zlib stored inline in the attribute itself.
        let attribute = decmpfs_attribute(3, plaintext.len() as u64, &zlib(&plaintext));
        let attribute_b64 = base64::engine::general_purpose::STANDARD.encode(&attribute);
        let compressed = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "notes.txt",
                "size": plaintext.len(),
                "compression": "apfs_decmpfs",
                "compression_format": "decmpfs_zlib_inline",
                "decmpfs_attribute_b64": attribute_b64,
            }),
        );
        let resolved = apply_step(Arc::clone(&current), &compressed, &parent, &policy)
            .expect("a decmpfs artifact must resolve to content, not to \"no content location\"");
        assert_eq!(resolved.size(), plaintext.len() as u64);
        assert_eq!(
            read_all(&resolved),
            plaintext,
            "the resolved bytes must be the file's plaintext"
        );

        // An artifact labelled decmpfs whose location was never recorded (an
        // ingest that predates the parser writing it) must refuse, not fall
        // back to whatever bytes the window happens to hold.
        let no_location = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "notes.txt",
                "size": plaintext.len(),
                "compression": "apfs_decmpfs",
            }),
        );
        let err = apply_step(Arc::clone(&current), &no_location, &parent, &policy)
            .expect_err("a decmpfs artifact with no recorded location must refuse");
        assert!(
            format!("{err:?}").contains("decmpfs_attribute_b64"),
            "the refusal must name what is missing: {err:?}"
        );

        // The control: an ordinary file is routed by its `data_runs` exactly as
        // before. Mis-routing this branch would corrupt every file on a volume.
        let ordinary = artifact(
            ArtifactType::FileEntry,
            serde_json::json!({
                "name": "plain.bin",
                "size": 16,
                "data_runs": [[0, 16]],
            }),
        );
        let resolved =
            apply_step(current, &ordinary, &parent, &policy).expect("ordinary runs must resolve");
        assert_eq!(read_all(&resolved), vec![0xCDu8; 16]);
    }

    /// LIVE-001 against the real volume. `apfs_compressed.dmg` holds a
    /// 4,200,000-byte decmpfs file in ~36 KB of resource fork plus an
    /// incompressible control. The parse runs for real, then everything the
    /// parser held in memory is thrown away and only what the database keeps —
    /// the metadata — is used to rebuild, which is the situation an examiner's
    /// content request is actually in.
    ///
    /// The control is the other half of the fix: a change that mis-routed
    /// ordinary files would corrupt every file on a normal volume, so its bytes
    /// must come back identical to what the parser reads from its own extents.
    #[test]
    fn an_apfs_decmpfs_file_resolves_to_its_decoded_plaintext_from_metadata_alone() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../test_data/apfs_compressed.dmg");
        if !path.exists() {
            eprintln!("skipping the APFS decmpfs resolution test: image absent");
            return;
        }
        // The APFS container starts 20480 bytes into the .dmg. Both `data_runs`
        // and `compressed_data_runs` are relative to this window, which is
        // precisely what the resolver hands a FileEntry step as `current`.
        const CONTAINER_OFFSET: u64 = 20480;
        let file_len = std::fs::metadata(&path).expect("image metadata").len();
        let image: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).expect("open image"));
        let fs_window: Arc<dyn DataSource> = Arc::new(WindowSource::new(
            image,
            CONTAINER_OFFSET,
            file_len - CONTAINER_OFFSET,
        ));

        let fs_artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileSystem,
            Some(Arc::clone(&fs_window)),
            serde_json::json!({ "subtype": "apfs" }),
        );
        let parsed = seance_plugin_apfs::ApfsParser
            .process(&fs_artifact)
            .expect("the APFS parser must read the fixture");
        // Only metadata survives ingest; the decoded buffer does not.
        let stored = |name: &str| {
            Artifact::new(
                Uuid::new_v4(),
                ArtifactType::FileEntry,
                None,
                parsed_entry(&parsed, name).metadata.clone(),
            )
        };

        let policy = EvidenceRootPolicy::unrestricted();
        let parent = artifact(ArtifactType::FileSystem, serde_json::json!({}));

        let compressed = stored("highly_compressible.txt");
        let resolved = apply_step(Arc::clone(&fs_window), &compressed, &parent, &policy)
            .expect("a decmpfs file must resolve to content, not to \"no content location\"");
        assert_eq!(resolved.size(), 4_200_000);
        let bytes = read_all(&resolved);
        let pattern = b"SEANCE decmpfs test. ";
        assert!(
            bytes
                .iter()
                .enumerate()
                .all(|(i, b)| *b == pattern[i % pattern.len()]),
            "the resolved bytes must be the file's known plaintext, not its compressed stream"
        );

        // The incompressible control: byte-identical to what the parser read
        // straight from the extents at ingest.
        let at_ingest = parsed_entry(&parsed, "incompressible.bin")
            .data
            .clone()
            .expect("the control file carries content at ingest");
        let control = apply_step(fs_window, &stored("incompressible.bin"), &parent, &policy)
            .expect("an ordinary file must still resolve");
        assert_eq!(control.size(), 2_097_152);
        assert_eq!(at_ingest.size(), 2_097_152);
        // Compared as a boolean: a mismatch here is 2 MiB of bytes, and dumping
        // it would bury the failure rather than report it.
        assert!(
            read_all(&control) == read_all(&at_ingest),
            "an ordinary uncompressed file must resolve byte-identically"
        );
    }

    /// HUNT-154: a `VssPriorVersion` is parented to its `VssSnapshot`, so its
    /// `data_runs` resolve against the rebuilt snapshot stream (step 1b), never
    /// against the live volume. Gated on the dfir_ntfs corpus
    /// (`SEANCE_VSS_CORPUS` holding `vss_2003.raw`); record 79 of the stack-1
    /// snapshot is 7,106 bytes of `1` there, and the live clusters it names
    /// now hold another file's `3`s.
    #[test]
    fn a_vss_prior_version_resolves_against_the_rebuilt_snapshot() {
        let Some(dir) = std::env::var_os("SEANCE_VSS_CORPUS") else {
            return;
        };
        let image = std::path::PathBuf::from(dir).join("vss_2003.raw");
        if !image.exists() {
            return;
        }
        let file: Arc<dyn DataSource> = Arc::new(FileDataSource::new(image.clone()).unwrap());
        let offset = 63 * 512;
        let size = file.size() - offset;
        let case = Uuid::new_v4();
        let root = Artifact::new(
            case,
            ArtifactType::RawEvidence,
            None,
            serde_json::json!({ "source_path": image.to_string_lossy() }),
        );
        let volume: Arc<dyn DataSource> = Arc::new(WindowSource::new(file, offset, size));
        let fs = Artifact::new(
            case,
            ArtifactType::FileSystem,
            Some(volume),
            serde_json::json!({ "filesystem_type": "NTFS", "offset_bytes": offset, "size_bytes": size }),
        )
        .with_parent(root.id);
        let out = seance_plugin_vss::VssEnumerator.process(&fs).unwrap();
        let prior = out
            .iter()
            .find(|a| {
                a.metadata["type"] == "VssPriorVersion"
                    && a.metadata["vss_stack_position"] == 1
                    && a.metadata["record_number"] == 79
            })
            .expect("record 79 is a prior version in the stack-1 snapshot");
        let snapshot = out
            .iter()
            .find(|a| Some(a.id) == prior.parent_id)
            .expect("parented to its snapshot");

        // The records as the database holds them: metadata only.
        let strip = |a: &Artifact| {
            let mut a = a.clone();
            a.data = None;
            a
        };
        let chain = vec![root, strip(&fs), strip(snapshot), strip(prior)];
        let resolved = build_stack(&chain, &EvidenceRootPolicy::unrestricted()).unwrap();
        let mut bytes = vec![0u8; resolved.size as usize];
        seance_core::io::read_exact_or_fail(resolved.source.as_ref(), 0, &mut bytes, "t").unwrap();
        assert_eq!(bytes, vec![b'1'; 7106], "served from the rebuilt snapshot");
    }
}
