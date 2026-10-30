use serde::Serialize;
use std::collections::HashMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use tokio::sync::broadcast::Sender as BroadcastSender;
use tokio::sync::mpsc::UnboundedSender;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::artifact::{Artifact, ArtifactType};
use crate::data_source::DataSource;
use crate::db::DatabaseConnection;
use crate::hashing::HashResult;
use crate::module::ModuleError;
use crate::orchestrator::{ActiveTaskGuard, OrchestratorEvent};

/// Chunk size for streaming acquisition/verification hashing.
///
/// Larger than a single page-cache read so the OS read-ahead has room to work
/// and syscall overhead is amortised over more bytes; the pipelined hasher keeps
/// two of these in flight, so the transient cost is `2 * HASH_CHUNK_BYTES`.
const HASH_CHUNK_BYTES: usize = 8 * 1024 * 1024;

/// Position of an EWF segment extension within its set, following libewf's
/// naming: `E01` is 1 ... `E99` is 99, then `EAA` is 100, `EAB` 101 ... `EZZ`
/// 775 (all lower case for a set named in lower case). The same scheme applies to the SMART (`s01`) and logical (`L01`)
/// variants. Returns `None` for anything that is not a segment extension —
/// including `.E00`, since segment numbering starts at one.
fn ewf_segment_ordinal(ext: &str) -> Option<u32> {
    let b = ext.as_bytes();
    if b.len() != 3 || !matches!(b[0], b'E' | b'e' | b'S' | b's' | b'L' | b'l') {
        return None;
    }
    let (hi, lo) = (b[1], b[2]);
    if hi.is_ascii_digit() && lo.is_ascii_digit() {
        let n = (hi - b'0') as u32 * 10 + (lo - b'0') as u32;
        return (n >= 1).then_some(n);
    }
    // Letter pairs are either both upper case (`EAA`) or both lower case
    // (`eaa`): a tool that writes `.e01` writes `.eaa` after `.e99`. A lower
    // case pair rejected here left segments 100 and up out of the set and out
    // of the baseline with nothing reported missing. A mixed pair (`eAa`) is
    // not a name any tool writes and stays rejected.
    let both = |f: fn(&u8) -> bool| f(&hi) && f(&lo);
    if both(u8::is_ascii_uppercase) || both(u8::is_ascii_lowercase) {
        let (hi, lo) = (hi.to_ascii_uppercase(), lo.to_ascii_uppercase());
        return Some(100 + (hi - b'A') as u32 * 26 + (lo - b'A') as u32);
    }
    None
}

/// The family letter of a segment extension, upper-cased: `E` (EnCase), `S`
/// (SMART) or `L` (logical). Only meaningful for an extension that
/// [`ewf_segment_ordinal`] accepted.
fn ewf_segment_family(ext: &str) -> Option<u8> {
    ext.as_bytes().first().map(u8::to_ascii_uppercase)
}

/// Whether `path` starts with an EWF segment-file signature.
///
/// Every EWF segment — first or fortieth — begins with an 8-byte signature:
/// `EVF\x09\x0d\x0a\xff\x00` for EnCase (`.E01`) and SMART (`.S01`), and
/// `LVF\x09\x0d\x0a\xff\x00` for logical evidence (`.L01`).
///
/// The extension alone CANNOT decide this. `ewf_segment_ordinal` accepts any
/// three-character `E`/`S`/`L` extension whose last two characters are two
/// digits or two letters of one case, which is also the shape of `.EXE` (702),
/// `.EVT` (665), `.LOG` (470), `.LNK` (448), `.SYS` (742) and `.EML` (423) —
/// all of them ordinary evidence an examiner ingests directly. Deciding on the
/// name alone made every one of those look like segment 702 of a set whose
/// first 701 segments are missing, and the incomplete-set refusal below then
/// rejected the file outright. Content is the only honest discriminator.
///
/// `Err` means the file could not be read at all, which is a different answer
/// from "not a segment" and is never flattened into one.
fn has_ewf_signature(path: &Path) -> std::io::Result<bool> {
    let mut file = std::fs::File::open(path)?;
    let mut head = [0u8; 8];
    let mut filled = 0usize;
    while filled < head.len() {
        match file.read(&mut head[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    // A file too short to hold the signature cannot be a segment.
    Ok(filled == head.len()
        && matches!(head[0], b'E' | b'L' | b'S')
        && &head[1..8] == b"VF\x09\x0d\x0a\xff\x00")
}

/// Missing segment numbers named in a refusal message, before it is summarised.
/// A refusal has to be readable: an examiner needs "segment 2 is absent", not
/// several hundred numbers.
const MAX_NAMED_MISSING_SEGMENTS: usize = 10;

/// A multi-segment EWF (E01) set as it exists on disk.
struct EwfSegmentSet {
    /// Every segment file sharing the stem and family of the path we were
    /// given, in segment order — the order libewf reads them, and therefore
    /// the only order in which a digest over the set is reproducible.
    paths: Vec<PathBuf>,
    /// Combined on-disk size of those files. Zero for a size we could not stat,
    /// which is the same file the hash is about to fail to read.
    total_bytes: u64,
    /// Why the files on disk are not a well-formed `1..n` run. A non-empty list
    /// means no acquisition baseline may be recorded for this source: a hash
    /// labelled "the set" that covers a set with a hole in it states a coverage
    /// that is not true.
    inconsistencies: Vec<String>,
}

/// The EWF segment files belonging with `path`, in segment order.
///
/// `None` when `path` is not an EWF segment at all — an ordinary `.raw`/`.dd`
/// image, or a file whose extension merely parses as a segment ordinal
/// (`.EXE`, `.EVT`, `.LOG`) but which carries no EWF signature — in which case
/// the source is the single file it names. A lone `.E01` still returns a
/// one-element set. Membership is decided by [`has_ewf_signature`], never by
/// the name alone.
///
/// Only segments of the same family are collected: `disk.E01` and `disk.L01`
/// are two different acquisitions of the same evidence that happen to share a
/// stem, never one set.
fn ewf_segment_set(path: &str) -> Option<EwfSegmentSet> {
    let p = Path::new(path);
    let ext = p.extension().and_then(|e| e.to_str())?;
    // The path must itself name a segment. The ordinal of the file we were
    // handed is not used: the set is enumerated from the directory, so the
    // caller may name any member of it.
    ewf_segment_ordinal(ext)?;
    // ...and it must actually BE one. A `.EXE`/`.EVT`/`.LOG` matches the naming
    // rule; only the file signature separates those from evidence segments. A
    // file we cannot open is not treated as a set either: it is hashed as the
    // single source it names, and that open failure is then reported by the
    // hasher with the real errno instead of being recycled here into a
    // "segment set is incomplete" that says nothing true.
    if !has_ewf_signature(p).unwrap_or(false) {
        return None;
    }
    let family = ewf_segment_family(ext)?;
    let stem = p.file_stem()?.to_str()?;
    // A bare `disk.E01` has an empty parent, which is not a readable directory.
    let dir = p
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    let mut inconsistencies: Vec<String> = Vec::new();
    let mut found: Vec<(u32, PathBuf, u64)> = Vec::new();
    // By here the file IS an EWF segment. If its directory cannot be listed we
    // cannot tell whether it is one file or forty, and "one file" is a guess,
    // not an answer: refuse rather than record a baseline labelled as covering
    // a set whose membership was never established.
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(err) => {
            return Some(EwfSegmentSet {
                paths: vec![p.to_path_buf()],
                total_bytes: 0,
                inconsistencies: vec![format!(
                    "the directory holding this EWF segment cannot be listed ({}), so the \
                     rest of the segment set cannot be identified",
                    err
                )],
            })
        }
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some((s, e)) = name.rsplit_once('.') else {
            continue;
        };
        if s != stem {
            continue;
        }
        let (Some(ordinal), Some(fam)) = (ewf_segment_ordinal(e), ewf_segment_family(e)) else {
            continue;
        };
        if fam != family {
            continue;
        }
        let candidate = entry.path();
        // Same three answers as for the named path, kept distinct: a sibling
        // that merely shares the naming shape (`disk.E01` next to `disk.EXE`)
        // is not a segment and must not be digested into the baseline, while a
        // sibling we cannot read is an unknown that has to be reported.
        match has_ewf_signature(&candidate) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(err) => {
                inconsistencies.push(format!("segment '{}' cannot be read: {}", name, err));
            }
        }
        // A segment we cannot stat is a segment we cannot account for; say so
        // rather than counting it as zero bytes of evidence. Stat the target,
        // not the directory entry: `DirEntry::metadata` does not follow
        // symlinks, so a segment reached through a link reported the link's
        // size while the reader hashed the file behind it, and the byte-count
        // check below then refused an intact set.
        let size = match std::fs::metadata(&candidate) {
            Ok(md) => md.len(),
            Err(err) => {
                inconsistencies.push(format!("segment '{}' cannot be sized: {}", name, err));
                0
            }
        };
        found.push((ordinal, candidate, size));
    }
    if found.is_empty() {
        // The directory listed, but the EWF segment we were handed is not in
        // it — it was removed under us, or its name does not round-trip
        // through the listing. Either way the set is unknown, and an unknown
        // set is not the same fact as a one-file set.
        return Some(EwfSegmentSet {
            paths: vec![p.to_path_buf()],
            total_bytes: 0,
            inconsistencies: vec![format!(
                "'{}' is an EWF segment but does not appear in its own directory listing, \
                 so the segment set cannot be established",
                source_file_label(p)
            )],
        });
    }
    found.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

    // Non-empty: the early return above covers the empty case.
    let highest = found[found.len() - 1].0;
    let present: std::collections::BTreeSet<u32> = found.iter().map(|(o, ..)| *o).collect();
    let missing: Vec<u32> = (1..=highest).filter(|o| !present.contains(o)).collect();
    if !missing.is_empty() {
        let named: Vec<String> = missing
            .iter()
            .take(MAX_NAMED_MISSING_SEGMENTS)
            .map(|o| o.to_string())
            .collect();
        let rest = missing.len() - named.len();
        let tail = if rest > 0 {
            format!(" and {} more", rest)
        } else {
            String::new()
        };
        inconsistencies.push(format!(
            "segment(s) {}{} of {} are absent",
            named.join(", "),
            tail,
            highest
        ));
    }
    if present.len() != found.len() {
        // Two files claiming the same segment number (possible on a
        // case-sensitive filesystem: `disk.E01` and `disk.e01`). Which one
        // belongs to the set is unknowable, so refuse to guess.
        inconsistencies.push("two files claim the same segment number".to_string());
    }

    let total_bytes: u64 = found.iter().map(|(_, _, size)| *size).sum();
    Some(EwfSegmentSet {
        paths: found.into_iter().map(|(_, p, _)| p).collect(),
        total_bytes,
        inconsistencies,
    })
}

/// Reads a sequence of files back-to-back as one continuous byte stream.
///
/// A multi-segment evidence set is one object split across several files; the
/// acquisition digest has to see all of them, in segment order, or the baseline
/// covers a fraction of the evidence while claiming to cover the evidence.
struct SegmentSetReader {
    remaining: std::vec::IntoIter<PathBuf>,
    current: Option<std::fs::File>,
}

impl SegmentSetReader {
    fn open(paths: Vec<PathBuf>) -> std::io::Result<Self> {
        let mut remaining = paths.into_iter();
        let current = match remaining.next() {
            Some(p) => Some(Self::open_one(&p)?),
            None => None,
        };
        Ok(Self { remaining, current })
    }

    /// Open one segment, naming it in any error: "permission denied" without a
    /// file name is useless to the examiner holding a 40-part image.
    fn open_one(path: &Path) -> std::io::Result<std::fs::File> {
        std::fs::File::open(path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("segment '{}': {}", path.display(), e))
        })
    }
}

impl Read for SegmentSetReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            let read = match self.current.as_mut() {
                Some(file) => file.read(buf)?,
                None => return Ok(0),
            };
            if read > 0 {
                return Ok(read);
            }
            // End of this segment: advance. A failure to open the next one
            // propagates, so a set we cannot read whole is never hashed as
            // though it were complete.
            self.current = match self.remaining.next() {
                Some(p) => Some(Self::open_one(&p)?),
                None => None,
            };
        }
    }
}

/// The name to record for one hashed file: its final component, or the whole
/// path when it has none.
fn source_file_label(path: &Path) -> String {
    path.file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string())
}

/// What the acquisition hashes actually cover.
///
/// Recorded next to the digests so the baseline is interpretable and
/// independently reproducible: a third party handed the evidence can see which
/// files, in which order, and how many bytes went into the digest, and repeat
/// it. A hash whose coverage is not stated cannot be checked.
struct AcquisitionCoverage {
    /// File names hashed, in the order their bytes entered the digest.
    files: Vec<String>,
    /// Total bytes fed to the digests.
    bytes_hashed: u64,
    /// True when `files` is a multi-segment EWF set rather than a single file.
    segment_set: bool,
    /// The source file's modification time (Unix seconds) when known, recorded
    /// with the baseline as provenance of when the source was last modified.
    source_mtime: Option<i64>,
}

/// The value written in place of a redacted secret, so the metadata still
/// records that a credential was supplied without recording the credential.
pub const REDACTED_SECRET: &str = "[redacted: not persisted]";

/// True for an ingest-metadata key that carries a volume-unlock secret.
///
/// This is applied ONLY to the operator-supplied metadata of a root evidence
/// artifact (`ingest_artifact` / `ingest_artifact_background`), whose keys are
/// ingest parameters — name, path, size, subtype and unlock credentials. It is
/// never applied to records a parser produced, so a password *recovered from
/// the evidence* (a browser credential store, a keychain entry) is untouched:
/// that is evidence, not a secret of ours.
fn is_secret_metadata_key(key: &str) -> bool {
    let k = key.to_ascii_lowercase();
    matches!(
        k.as_str(),
        "passphrase" | "password" | "recovery_key" | "recovery_password" | "pin"
    ) || k.ends_with("_passphrase")
        || k.ends_with("_password")
        || k.ends_with("_recovery_key")
        || k.ends_with("_pin")
}

/// Replace every unlock secret in `metadata` with [`REDACTED_SECRET`], returning
/// the key paths that were redacted.
///
/// Volume-unlock credentials reach ingest through artifact metadata, and that
/// metadata is written verbatim to `artifacts.metadata_json` and served back by
/// the artifact-detail API. Persisting the secret would leave the key to the
/// evidence sitting next to the evidence, in every DB backup and every export,
/// readable by any authorised case reader. The credential is passed to the
/// decryptor module in process memory instead; this strips it before anything
/// durable sees it.
///
/// Redaction is deliberately non-destructive of the *fact*: an examiner still
/// sees that `luks_passphrase` was supplied, which is chain-of-custody
/// relevant, without the value.
pub fn redact_secret_metadata(metadata: &mut serde_json::Value) -> Vec<String> {
    fn walk(value: &mut serde_json::Value, prefix: &str, found: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map.iter_mut() {
                    let path = if prefix.is_empty() {
                        key.clone()
                    } else {
                        format!("{prefix}.{key}")
                    };
                    if is_secret_metadata_key(key) {
                        if *child != serde_json::Value::Null {
                            *child = serde_json::json!(REDACTED_SECRET);
                            found.push(path);
                        }
                    } else {
                        walk(child, &path, found);
                    }
                }
            }
            serde_json::Value::Array(items) => {
                for (i, child) in items.iter_mut().enumerate() {
                    walk(child, &format!("{prefix}[{i}]"), found);
                }
            }
            _ => {}
        }
    }

    let mut found = Vec::new();
    walk(metadata, "", &mut found);
    found
}

/// Where a background ingest has got to. Deliberately only the two states this
/// service can vouch for: it has been accepted and not yet started reading
/// bytes, or it is reading them. Anything after that is no longer "in flight" —
/// it is an artifact, or an audited failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcquisitionPhase {
    /// Accepted, nothing read yet. There is no percentage to report and the
    /// entry must not invent one.
    Queued,
    /// Streaming the source to compute the acquisition baseline.
    Hashing,
}

/// One background ingest this process is currently carrying out.
///
/// The acquisition phase used to be observable only by whoever held the
/// broadcast the submitting request opened: a second tab, a colleague at
/// another desk, or the same examiner after a reload saw nothing at all while a
/// 1 TB exhibit hashed for an hour. This is the same fact held in shared state
/// so that ANY reader can ask the question, rather than having had to be
/// listening at the right moment.
///
/// It is process state, not a record: it exists only while the ingest is
/// running and disappears the moment it ends. The durable record of an ingest
/// is the artifact row and the audit log.
#[derive(Debug, Clone, Serialize)]
pub struct AcquisitionInFlight {
    pub case_id: Uuid,
    /// The artifact ID the ingest was accepted under — the same ID the API
    /// returned to the submitter, so a caller can join this to the artifact row
    /// once one exists.
    pub artifact_id: Uuid,
    /// The evidence file being hashed. `None` for a source with no bytes of its
    /// own (a directory), which is never hashed.
    pub source_path: Option<String>,
    /// The exhibit name from the ingest metadata, when it carried one.
    pub name: Option<String>,
    pub phase: AcquisitionPhase,
    pub bytes_done: u64,
    /// Total bytes the baseline will cover, once known — the whole segment set
    /// for a multi-segment EWF. `None` while queued, and for a source whose
    /// length cannot be stat'ed (a block device), where a percentage would be
    /// a guess.
    pub bytes_total: Option<u64>,
    /// Unix seconds when the ingest was accepted, so a reader can say how long
    /// an acquisition has been running.
    pub started_at: i64,
    /// Unix seconds of the last progress this process recorded.
    pub updated_at: i64,
}

/// Removes an in-flight entry when dropped.
///
/// The ordinary path removes it explicitly, before the outcome is announced, so
/// that a client reacting to the announcement cannot read the acquisition back
/// as still running. This is the backstop for the path with no announcement at
/// all: a background task that ends by panicking would otherwise leave the case
/// claiming an acquisition that stopped — a status bar stuck at "hashing 43%"
/// forever, which is precisely the kind of statement this product must not
/// make. Removing an entry twice is harmless.
struct InFlightGuard {
    registry: Arc<Mutex<HashMap<Uuid, AcquisitionInFlight>>>,
    artifact_id: Uuid,
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        self.registry
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.artifact_id);
    }
}

/// What a successful background ingest actually left in the case, so its audit
/// line can state that rather than assume it.
///
/// Not every ingest hashes anything. A directory has no bytes of its own, which
/// is why [`IngestionService::finish_background_ingest`] takes the
/// persist-and-queue branch for it and why the API reports its status as
/// "queued" rather than "hashing". The completion event used to say "the
/// evidence row and its acquisition record are in the case" for both branches;
/// for the sourceless one that asserted a chain-of-custody baseline — digests,
/// coverage, an `evidence_acquisition_hashed` record — that was never computed
/// and does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcquisitionRecorded {
    /// The source's bytes were hashed and the baseline is on the record.
    ///
    /// A service with no database attached records neither the baseline nor an
    /// audit event, so nothing claims a baseline that is not there: this value
    /// is only ever read to write the completion line, and that line is only
    /// written when there is a case database to write it to.
    Baseline,
    /// The exhibit has no source file of its own, so nothing was hashed and no
    /// baseline exists to claim.
    NoSourceToHash,
}

impl AcquisitionRecorded {
    /// The half of the completion sentence that describes what the case now
    /// holds. Kept here so the two branches cannot drift apart in wording.
    fn completion_clause(self) -> &'static str {
        match self {
            Self::Baseline => "the evidence row and its acquisition record are in the case.",
            Self::NoSourceToHash => {
                "the evidence row is in the case. No acquisition baseline was computed: this \
                 exhibit has no source file of its own to hash, so the case holds no digests \
                 for it."
            }
        }
    }
}

/// Service for ingesting initial artifacts into the orchestrator pipeline.
/// This ensures proper persistence, SSE broadcasting, and task tracking.
#[derive(Clone)]
pub struct IngestionService {
    db: Option<Arc<dyn DatabaseConnection>>,
    task_sender: UnboundedSender<Artifact>,
    event_broadcaster: BroadcastSender<Artifact>,
    active_tasks: Arc<AtomicUsize>,
    /// Optional orchestrator status bus for progress/completion events.
    status_sender: Option<BroadcastSender<OrchestratorEvent>>,
    /// Background ingests currently running, keyed by artifact ID.
    ///
    /// Shared by every clone of the service — including the per-request clone
    /// the API makes to attach a status bus — because the whole point is that a
    /// request which did NOT start the ingest can still see it. Bounded by the
    /// number of concurrent ingests: an entry is added when one is accepted and
    /// removed when it ends, either way.
    in_flight: Arc<Mutex<HashMap<Uuid, AcquisitionInFlight>>>,
}

impl IngestionService {
    pub fn new(
        db: Option<Arc<dyn DatabaseConnection>>,
        task_sender: UnboundedSender<Artifact>,
        event_broadcaster: BroadcastSender<Artifact>,
        active_tasks: Arc<AtomicUsize>,
    ) -> Self {
        Self {
            db,
            task_sender,
            event_broadcaster,
            active_tasks,
            status_sender: None,
            in_flight: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The background ingests this process is currently running for `case_id`,
    /// oldest first.
    ///
    /// The population is exactly that: ingests accepted by THIS process that
    /// have not yet reported an outcome. It says nothing about ingests a
    /// previous run of the server accepted (a restart loses them — the audit
    /// log is where those are answered from), and nothing about evidence
    /// already ingested.
    pub fn acquisitions_in_flight(&self, case_id: Uuid) -> Vec<AcquisitionInFlight> {
        let mut listed: Vec<AcquisitionInFlight> = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .values()
            .filter(|a| a.case_id == case_id)
            .cloned()
            .collect();
        listed.sort_by_key(|a| (a.started_at, a.artifact_id));
        listed
    }

    /// Record that an ingest has been accepted and is running.
    fn track_in_flight(&self, artifact: &Artifact) {
        let now = chrono::Utc::now().timestamp();
        let entry = AcquisitionInFlight {
            case_id: artifact.case_id,
            artifact_id: artifact.id,
            source_path: artifact
                .metadata
                .get("source_path")
                .and_then(|v| v.as_str())
                .map(String::from),
            name: artifact
                .metadata
                .get("name")
                .and_then(|v| v.as_str())
                .map(String::from),
            phase: AcquisitionPhase::Queued,
            bytes_done: 0,
            bytes_total: None,
            started_at: now,
            updated_at: now,
        };
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(artifact.id, entry);
    }

    /// Record acquisition-hash progress against a tracked ingest.
    ///
    /// A missing entry is not an error: the blocking ingest path hashes without
    /// ever being tracked, and there the caller is holding the result anyway.
    fn record_hash_progress(&self, artifact_id: Uuid, bytes_done: u64, bytes_total: u64) {
        if let Some(entry) = self
            .in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_mut(&artifact_id)
        {
            entry.phase = AcquisitionPhase::Hashing;
            entry.bytes_done = bytes_done;
            // A source whose length could not be determined reports no total,
            // rather than a zero that would render as "0 bytes" or "100%".
            entry.bytes_total = (bytes_total > 0).then_some(bytes_total);
            entry.updated_at = chrono::Utc::now().timestamp();
        }
    }

    /// Stop reporting an ingest as running. Called on BOTH outcomes, and before
    /// the outcome is announced, so a client that reacts to the announcement
    /// never reads a finished acquisition back as still in flight.
    fn untrack_in_flight(&self, artifact_id: Uuid) {
        self.in_flight
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&artifact_id);
    }

    /// Attach an orchestrator status bus. When set, acquisition hashing emits
    /// `AcquisitionHashProgress` events and background ingests emit
    /// `IngestCompleted` / `IngestFailed`.
    pub fn with_status_sender(mut self, sender: BroadcastSender<OrchestratorEvent>) -> Self {
        self.status_sender = Some(sender);
        self
    }

    /// Ingest an initial artifact into the system.
    /// This method:
    /// 1. Computes acquisition hashes (MD5/SHA1/SHA256) of the source file,
    ///    storing them in metadata as an immutable baseline
    /// 2. Creates the artifact and persists it to the database (if available)
    /// 3. Records an integrity_checks baseline row and an audit event
    /// 4. Broadcasts a "queued" event via SSE
    /// 5. Increments active task counter
    /// 6. Sends artifact to orchestrator for processing
    pub async fn ingest_artifact(
        &self,
        case_id: Uuid,
        artifact_type: ArtifactType,
        data: Option<Arc<dyn DataSource>>,
        mut metadata: serde_json::Value,
    ) -> Result<Artifact, ModuleError> {
        // LIVE-001, at the level the class lives at. Everything below —
        // acquisition hashing above all — happens before `persist_and_queue`
        // increments the counter, so without this guard the orchestrator sees
        // an empty queue and a zero task count for the whole of it, takes the
        // idle branch, exits, and the ingest that follows hits a closed channel.
        let _pre_queue = self.pre_queue_guard();

        Self::scrub_secrets(&mut metadata);

        // 1. Acquisition hashing: baseline hashes of the source evidence file
        // (every file of it, for a multi-segment set). These are the
        // authoritative chain-of-custody reference; verification compares
        // against them and must never overwrite them.
        let source_path = metadata
            .get("source_path")
            .and_then(|v| v.as_str())
            .map(String::from);

        let acquisition = if let Some(path) = &source_path {
            // No artifact ID yet on this path — the artifact is built below —
            // and nothing to report progress against: the blocking ingest is
            // not tracked in the in-flight list because its caller is holding
            // the call and learns the outcome from its return value.
            let (hashes, coverage) = self.hash_source(case_id, None, path).await?;
            Self::insert_acquisition_metadata(&mut metadata, &hashes, &coverage);
            Some(hashes)
        } else {
            None
        };

        let artifact = Artifact::new(case_id, artifact_type, data, metadata);
        let queued = self.persist_and_queue(artifact, acquisition.as_ref()).await;
        // `_pre_queue` is released here, after persist_and_queue has taken its
        // own count for the queued artifact — the count never dips to zero
        // between the two.
        queued
    }

    /// Non-blocking ingest for large evidence sources.
    ///
    /// The artifact is created immediately (with a stable ID the caller can
    /// track) and returned; persistence, queueing and acquisition hashing run
    /// in a spawned background task. Progress is reported via
    /// `AcquisitionHashProgress` and the outcome via `IngestCompleted` /
    /// `IngestFailed` on the orchestrator status bus.
    ///
    /// Three facts about it are readable without holding that bus, because a
    /// broadcast nobody replays is not a record:
    ///
    /// - while it runs, the attempt is listed by [`Self::acquisitions_in_flight`]
    ///   for the case, so any reader can see which exhibit is being acquired
    ///   and how far along it is;
    /// - the row is persisted BEFORE hashing (marked `integrity_state:
    ///   verifying`, then `baseline_recorded`), so the exhibit is in the case
    ///   from the start and never silently absent for the length of the hash;
    /// - the outcome is written to the audit log as
    ///   `evidence_ingest_completed` / `evidence_ingest_failed`, pairing with
    ///   the request-time event the caller records.
    pub fn ingest_artifact_background(
        &self,
        case_id: Uuid,
        artifact_type: ArtifactType,
        data: Option<Arc<dyn DataSource>>,
        mut metadata: serde_json::Value,
    ) -> Artifact {
        Self::scrub_secrets(&mut metadata);
        let artifact = Artifact::new(case_id, artifact_type, data, metadata);
        let returned = artifact.clone();
        let service = self.clone();
        // Registered BEFORE the spawn, for the same reason the pre-queue guard
        // is taken here: between this function returning and the task first
        // being polled, a reader asking "what is this case acquiring?" would
        // otherwise be told "nothing" about an ingest that has already been
        // accepted.
        self.track_in_flight(&artifact);
        let in_flight_guard = InFlightGuard {
            registry: self.in_flight.clone(),
            artifact_id: artifact.id,
        };
        // Taken HERE, not inside the spawned task: between this function
        // returning and the task first being polled the orchestrator would
        // otherwise see zero work outstanding for an ingest that is very much
        // outstanding. `finish_background_ingest` takes its own as well, so the
        // invariant holds for any future caller of either.
        let pre_queue = self.pre_queue_guard();

        tokio::spawn(async move {
            let _pre_queue = pre_queue;
            let _in_flight = in_flight_guard;
            let artifact_id = artifact.id;
            let case_id = artifact.case_id;
            // Kept for the outcome record: `finish_background_ingest` consumes
            // the artifact, and an audit line that named only a UUID would be
            // useless to the examiner reading it.
            let source_label = Self::source_label(&artifact);
            let outcome = service.finish_background_ingest(artifact).await;
            // Untracked before the outcome is announced: a client that reloads
            // the in-flight list on hearing the event must not be told the
            // acquisition is still running.
            service.untrack_in_flight(artifact_id);
            match outcome {
                Ok(acquisition) => {
                    service
                        .audit_ingest_outcome(
                            case_id,
                            artifact_id,
                            "evidence_ingest_completed",
                            &format!(
                                "Background ingest of {source_label} completed: {}",
                                acquisition.completion_clause()
                            ),
                        )
                        .await;
                    if let Some(sender) = &service.status_sender {
                        let _ = sender.send(OrchestratorEvent::IngestCompleted {
                            case_id,
                            artifact_id,
                        });
                    }
                }
                Err(e) => {
                    error!(
                        "Background ingest of artifact {} failed: {}",
                        artifact_id, e
                    );
                    // The durable half of the fix. The SSE event below reaches
                    // whoever happens to be connected; this reaches the examiner
                    // who was elsewhere, and examiner B three weeks later.
                    //
                    // Read back rather than inferred: "the ingest failed" means
                    // two different things to an examiner — the exhibit is in
                    // the case carrying a failed-acquisition marker, or it is
                    // not in the case at all — and the only way to state which
                    // truthfully is to ask what the case now holds.
                    service
                        .audit_ingest_outcome(
                            case_id,
                            artifact_id,
                            "evidence_ingest_failed",
                            &format!(
                                "Background ingest of {source_label} FAILED: {}. {}",
                                e,
                                service.evidence_row_disposition(artifact_id).await
                            ),
                        )
                        .await;
                    if let Some(sender) = &service.status_sender {
                        let _ = sender.send(OrchestratorEvent::IngestFailed {
                            case_id,
                            artifact_id,
                            error: e.to_string(),
                        });
                    }
                }
            }
        });

        returned
    }

    /// How an audit line should name the thing that was ingested: the source
    /// path when there is one (that is what the examiner recognises and what
    /// the request-time event recorded), else the declared name, else nothing
    /// but the artifact ID the event already carries.
    fn source_label(artifact: &Artifact) -> String {
        let field = |key: &str| {
            artifact
                .metadata
                .get(key)
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(String::from)
        };
        match field("source_path")
            .or_else(|| field("path"))
            .or_else(|| field("name"))
        {
            Some(label) => format!("'{label}'"),
            None => format!("artifact {}", artifact.id),
        }
    }

    /// What the case holds for a failed ingest, as a sentence for the audit
    /// record. Stated from a read-back of the artifact table, so it describes
    /// the case as it actually is rather than as this task believes it left it.
    async fn evidence_row_disposition(&self, artifact_id: Uuid) -> &'static str {
        let Some(db_conn) = &self.db else {
            return "No database is attached to this ingest service, so whether an evidence row \
                    exists is unknown.";
        };
        match db_conn.get_artifact(artifact_id).await {
            Ok(Some(_)) => {
                "An evidence row for it exists in the case and carries the failure; see its \
                 integrity record."
            }
            Ok(None) => {
                "No evidence row was created: the exhibit is NOT in the case and must be \
                 ingested again."
            }
            Err(_) => {
                "Whether an evidence row exists could not be determined — the artifact table \
                 could not be read."
            }
        }
    }

    /// Write the terminal outcome of a background ingest to the audit log.
    ///
    /// Best-effort, and logged when it fails: the ingest itself has already
    /// happened (or already failed), and refusing to report an outcome because
    /// the outcome could not be written would leave the examiner with strictly
    /// less. The request-time `evidence_ingest_requested` event written by the
    /// API is mandatory precisely because it is the one that can still refuse.
    ///
    /// Recorded as "system": the background task acts on nobody's behalf by the
    /// time it runs, and attributing a hash failure to the examiner who
    /// requested the ingest would misstate who did what.
    async fn audit_ingest_outcome(
        &self,
        case_id: Uuid,
        artifact_id: Uuid,
        action: &str,
        details: &str,
    ) {
        let Some(db_conn) = &self.db else {
            return;
        };
        if let Err(e) = db_conn
            .record_audit_event(
                Some(case_id),
                "system",
                action,
                Some("artifact"),
                Some(artifact_id),
                Some(details),
            )
            .await
        {
            error!(
                "Failed to record '{}' audit event for artifact {}: {}",
                action, artifact_id, e
            );
        }
    }

    /// Queue then hash for the background ingest path (parse-while-hashing).
    ///
    /// Unlike the blocking `ingest_artifact`, this queues the artifact for
    /// processing FIRST, marked `integrity_state: verifying`, then records the
    /// acquisition baseline and verifies the decoded media concurrently — so an
    /// examiner's evidence starts being processed immediately instead of waiting
    /// out a minutes-long hash. The baseline is still recorded in full and any
    /// integrity failure is still surfaced; only the ordering relaxes.
    ///
    /// The `pre_queue_guard` is held across the whole method, hashing included:
    /// the queued artifact keeps the orchestrator busy, and the guard covers the
    /// window where that artifact has been processed but the baseline is still
    /// hashing, so a server flipped to idle-exit cannot exit mid-hash (LIVE-001).
    ///
    /// Returns what the ingest actually recorded, because the two branches leave
    /// the case in different states and the caller writes an audit line that
    /// says which.
    async fn finish_background_ingest(
        &self,
        mut artifact: Artifact,
    ) -> Result<AcquisitionRecorded, ModuleError> {
        let _pre_queue = self.pre_queue_guard();

        // Defence in depth: scrub before anything is persisted, so no future
        // caller can route a secret into metadata_json by adding an ingest path.
        Self::scrub_secrets(&mut artifact.metadata);

        let source_path = artifact
            .metadata
            .get("source_path")
            .and_then(|v| v.as_str())
            .map(String::from);

        match source_path {
            Some(path) => {
                // Mark integrity pending and persist the artifact so its baseline
                // has a row to attach to.
                if let Some(obj) = artifact.metadata.as_object_mut() {
                    obj.insert("integrity_state".into(), serde_json::json!("verifying"));
                }
                self.persist_artifact(&artifact).await?;
                self.record_ingest_run_start(&artifact).await;

                // Queue it for processing so parsing can start immediately. A
                // send failure means no live orchestrator is draining the queue;
                // that is a processing-availability problem, NOT a reason to skip
                // the chain-of-custody baseline, which is recorded next either
                // way. The error is surfaced only after the baseline is safely on
                // record.
                let enqueue_result = self.enqueue(artifact.clone());

                // Record the acquisition baseline (and verify decoded media)
                // concurrently with processing — always, regardless of whether
                // the queue send above succeeded.
                if let Err(failure) = self.record_integrity_after_queue(&artifact, &path).await {
                    // The evidence was ingested and may already be processing, so
                    // it cannot vanish: a baseline that could not be established
                    // is itself a finding. Mark it, write a durable custody record
                    // (integrity-check row + audit event, not just a metadata
                    // field that scrolls past), and surface the error (CR-003).
                    // A decoded-media verification failure is a different fact:
                    // the baseline IS on record, so it is marked and audited as
                    // what it is and the baseline state is left alone.
                    let (state, error_key, audit_action, summary, e) = match failure {
                        IntegrityStageError::Baseline(e) => (
                            "acquisition_failed",
                            "acquisition_error",
                            "evidence_acquisition_failed",
                            "Acquisition hash baseline could not be established",
                            e,
                        ),
                        IntegrityStageError::DecodedVerification(e) => (
                            "decoded_verification_failed",
                            "decoded_verification_error",
                            "evidence_decoded_verification_failed",
                            "Decoded-media verification could not be completed after the \
                             acquisition baseline was recorded",
                            e,
                        ),
                    };
                    if let Some(db_conn) = &self.db {
                        let patch = serde_json::json!({
                            "integrity_state": state,
                            error_key: e.to_string(),
                        });
                        let _ = db_conn
                            .merge_artifact_metadata(artifact.case_id, artifact.id, &patch)
                            .await;
                        Self::record_integrity_failure(
                            db_conn.as_ref(),
                            &artifact,
                            state,
                            audit_action,
                            &format!("{summary}: {e}"),
                        )
                        .await;
                    }
                    return Err(e);
                }

                // Evidence and baseline are recorded. If queueing for processing
                // failed, report that now.
                enqueue_result.map(|_| AcquisitionRecorded::Baseline)
            }
            // No source file to hash — nothing to run concurrently, so this is
            // the ordinary persist-and-queue.
            None => {
                self.persist_and_queue(artifact, None).await?;
                Ok(AcquisitionRecorded::NoSourceToHash)
            }
        }
    }

    /// Mark the orchestrator busy for the pre-queue phase of an ingest, until
    /// the returned guard is dropped.
    ///
    /// EVERY entry point that does work before reaching `persist_and_queue`
    /// must hold one of these for the whole of that work. Acquisition hashing
    /// of a real image takes minutes, and for that whole time an orchestrator
    /// started with `with_exit_on_idle(true)` sees an empty queue and a zero
    /// task count — it exits, and the ingest that follows finds a closed
    /// channel with nothing examined and no evidence recorded (LIVE-001).
    ///
    /// Cost is one atomic increment when the orchestrator is not idle-counting.
    /// Grep for this method to enumerate the pre-queue entry points.
    fn pre_queue_guard(&self) -> ActiveTaskGuard {
        ActiveTaskGuard::new(self.active_tasks.clone())
    }

    /// Strip unlock secrets from ingest metadata, logging the key names (never
    /// the values) so the redaction itself is auditable.
    fn scrub_secrets(metadata: &mut serde_json::Value) {
        let redacted = redact_secret_metadata(metadata);
        if !redacted.is_empty() {
            warn!(
                "Redacted {} unlock secret(s) from ingest metadata before persistence: {}",
                redacted.len(),
                redacted.join(", ")
            );
        }
    }

    /// Hash the source evidence on the blocking pool, emitting case-scoped
    /// `AcquisitionHashProgress` (at most ~1/sec) when a status bus is attached.
    ///
    /// BUG-006: a multi-segment EWF set is ONE piece of evidence spread over
    /// several files, so the baseline covers every segment, streamed in segment
    /// order. Hashing only the `.E01` recorded a chain-of-custody digest over
    /// the first few megabytes of a set that may be forty files long, while the
    /// record said "acquisition hash" without qualification.
    ///
    /// Returns the digests and an [`AcquisitionCoverage`] stating exactly what
    /// they cover, so the baseline is reproducible by anyone holding the files.
    async fn hash_source(
        &self,
        case_id: Uuid,
        artifact_id: Option<Uuid>,
        path: &str,
    ) -> Result<(HashResult, AcquisitionCoverage), ModuleError> {
        let set = ewf_segment_set(path);

        // Fail closed on a set that is not a complete 1..n run. Hashing
        // whatever happens to be on disk and filing it as the acquisition
        // baseline for the set would assert a coverage that is not true — and
        // an EWF set with a hole in it cannot be decoded either, so there is
        // nothing to ingest.
        if let Some(s) = &set {
            if !s.inconsistencies.is_empty() {
                return Err(ModuleError::FatalError(format!(
                    "EWF segment set for '{}' is incomplete: {}. Refusing to record an \
                     acquisition baseline that would appear to cover the whole set.",
                    path,
                    s.inconsistencies.join("; ")
                )));
            }
        }

        let paths: Vec<PathBuf> = match &set {
            Some(s) => s.paths.clone(),
            None => vec![PathBuf::from(path)],
        };
        let files: Vec<String> = paths.iter().map(|p| source_file_label(p)).collect();
        let segment_set = set.as_ref().is_some_and(|s| s.paths.len() > 1);
        // Size of the whole source, for the progress bar and for the coverage
        // check below. Unknown (0) for a source that cannot be stat'ed — which
        // is about to fail to open — and for a block device, where the length a
        // stat reports is not the device's size. The coverage check below only
        // applies when this is a known, non-zero length.
        let bytes_total = match &set {
            Some(s) => s.total_bytes,
            None => std::fs::metadata(path).map(|m| m.len()).unwrap_or(0),
        };
        // Only advertise a set (>1 file); a lone .E01 is just a single image.
        let segment_count = segment_set.then_some(paths.len());
        let segment_bytes_total = segment_set.then_some(bytes_total);

        // Modification time of a single-file source, recorded with the baseline
        // as provenance (when the source was last modified at acquisition). A
        // segment set's identity is more than one file's mtime, so it is
        // single-file only.
        //
        // NOTE: mtime is NOT used to skip hashing. An earlier build reused a
        // prior artifact's digests when (path, size, mtime) matched, but that
        // identity is forgeable — a tampered file of the same length with a
        // restored mtime would have inherited the old, clean baseline (CR-001),
        // and the lookup was not even case-scoped (CR-002). A chain-of-custody
        // digest must be read from the bytes, so every ingest re-hashes.
        let source_mtime = if set.is_none() {
            std::fs::metadata(path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs() as i64)
        } else {
            None
        };

        let path_for_task = path.to_string();
        let status_sender = self.status_sender.clone();
        // The same progress the status bus broadcasts, also written to the
        // in-flight list — the bus reaches whoever is connected right now, the
        // list answers a reader who arrives at any point during the hour this
        // may take. Announce the phase before the first chunk so the entry says
        // "hashing 0 of 400 GB" rather than sitting at "queued" for a whole
        // 8 MB read.
        let progress = artifact_id.map(|id| (self.clone(), id));
        if let Some((service, id)) = &progress {
            service.record_hash_progress(*id, 0, bytes_total);
        }
        // The hasher reports progress but does not return a byte count, and the
        // count is what makes the coverage checkable, so capture the last value
        // it reported — which it always reports once, at end of stream.
        let hashed_bytes = Arc::new(AtomicU64::new(0));
        let counted = hashed_bytes.clone();
        // Hash on a blocking thread so large images don't stall the runtime
        let hashes = tokio::task::spawn_blocking(move || -> std::io::Result<HashResult> {
            let mut reader = SegmentSetReader::open(paths)?;
            crate::hashing::compute_hashes_streaming_with_progress(
                &mut reader,
                HASH_CHUNK_BYTES,
                |bytes_done| {
                    counted.store(bytes_done, Ordering::SeqCst);
                    if let Some((service, id)) = &progress {
                        service.record_hash_progress(*id, bytes_done, bytes_total);
                    }
                    if let Some(sender) = &status_sender {
                        let _ = sender.send(OrchestratorEvent::AcquisitionHashProgress {
                            case_id,
                            source: path_for_task.clone(),
                            bytes_done,
                            bytes_total,
                            segment_count,
                            segment_bytes_total,
                        });
                    }
                },
            )
        })
        .await
        .map_err(|e| ModuleError::FatalError(format!("Acquisition hashing task failed: {}", e)))?
        .map_err(|e| {
            ModuleError::FatalError(format!(
                "Failed to compute acquisition hashes for '{}': {}",
                path, e
            ))
        })?;

        let bytes_hashed = hashed_bytes.load(Ordering::SeqCst);
        // A digest over fewer bytes than the source holds is the digest of a
        // fragment. Recording it as the baseline turns "we could not read this
        // evidence" into a value an examiner will later testify to.
        if bytes_total > 0 && bytes_hashed != bytes_total {
            return Err(ModuleError::FatalError(format!(
                "Acquisition hashing of '{}' covered {} of {} bytes; the source changed \
                 size or could not be read whole, so no baseline was recorded",
                path, bytes_hashed, bytes_total
            )));
        }

        Ok((
            hashes,
            AcquisitionCoverage {
                files,
                bytes_hashed,
                segment_set,
                source_mtime,
            },
        ))
    }

    fn insert_acquisition_metadata(
        metadata: &mut serde_json::Value,
        hashes: &HashResult,
        coverage: &AcquisitionCoverage,
    ) {
        if let Some(obj) = metadata.as_object_mut() {
            obj.insert("acquisition_md5".to_string(), serde_json::json!(hashes.md5));
            obj.insert(
                "acquisition_sha1".to_string(),
                serde_json::json!(hashes.sha1),
            );
            obj.insert(
                "acquisition_sha256".to_string(),
                serde_json::json!(hashes.sha256),
            );
            obj.insert(
                "acquisition_hashed_at".to_string(),
                serde_json::json!(chrono::Utc::now().timestamp()),
            );
            // What the digests cover, recorded with them: an unqualified
            // "acquisition hash" over a 40-file set is unverifiable by the
            // person who has to check it. Surfaced verbatim by the artifact's
            // raw-metadata view.
            let scope = if coverage.segment_set {
                "ewf_segment_set"
            } else {
                "single_file"
            };
            obj.insert(
                "acquisition_hash_scope".to_string(),
                serde_json::json!(scope),
            );
            obj.insert(
                "acquisition_bytes_hashed".to_string(),
                serde_json::json!(coverage.bytes_hashed),
            );
            // The source mtime, recorded with the baseline as provenance of when
            // the source was last modified at acquisition.
            if let Some(mtime) = coverage.source_mtime {
                obj.insert(
                    "acquisition_source_mtime".to_string(),
                    serde_json::json!(mtime),
                );
            }
            if coverage.segment_set {
                obj.insert(
                    "acquisition_segment_files".to_string(),
                    serde_json::json!(coverage.files),
                );
            }
        }
    }

    /// Record the acquisition-hash baseline: one `baseline` integrity-check row
    /// and one `evidence_acquisition_hashed` audit event carrying the digests.
    ///
    /// Shared by the blocking and concurrent ingest paths so the chain-of-custody
    /// wording can never diverge between them (CR-006). Every baseline is a fresh
    /// hash of the bytes read at this ingest — there is no reuse path (CR-001).
    async fn record_acquisition_baseline(
        db_conn: &dyn DatabaseConnection,
        artifact: &Artifact,
        hashes: &HashResult,
    ) -> Result<(), ModuleError> {
        db_conn
            .record_integrity_check(
                artifact.case_id,
                artifact.id,
                Some(&hashes.md5),
                Some(&hashes.sha1),
                Some(&hashes.sha256),
                None,
                None,
                None,
                "baseline",
                Some("Acquisition hash baseline recorded at ingest"),
            )
            .await
            .map_err(|e| {
                ModuleError::FatalError(format!("Failed to record acquisition baseline: {}", e))
            })?;
        db_conn
            .record_audit_event(
                Some(artifact.case_id),
                "system",
                "evidence_acquisition_hashed",
                Some("artifact"),
                Some(artifact.id),
                Some(&format!(
                    "md5={} sha1={} sha256={}",
                    hashes.md5, hashes.sha1, hashes.sha256
                )),
            )
            .await
            .map_err(|e| {
                ModuleError::FatalError(format!("Failed to record acquisition audit event: {}", e))
            })?;
        Ok(())
    }

    /// Record an integrity-stage FAILURE as a durable chain-of-custody record:
    /// an integrity-check row with status `state` and an audit event with
    /// `audit_action`.
    ///
    /// Used on the parse-while-hashing path when a source is persisted and queued
    /// but then cannot be hashed (`acquisition_failed`, CR-003) or its decoded
    /// media cannot be verified (`decoded_verification_failed`). The evidence
    /// cannot be un-ingested once processing may have started, so the failure
    /// must be on the record, not merely a transient status. Best-effort: if
    /// writing the custody record itself fails, the original error still
    /// surfaces, so these do not use `?`.
    async fn record_integrity_failure(
        db_conn: &dyn DatabaseConnection,
        artifact: &Artifact,
        state: &str,
        audit_action: &str,
        detail: &str,
    ) {
        let _ = db_conn
            .record_integrity_check(
                artifact.case_id,
                artifact.id,
                None,
                None,
                None,
                None,
                None,
                None,
                state,
                Some(detail),
            )
            .await;
        let _ = db_conn
            .record_audit_event(
                Some(artifact.case_id),
                "system",
                audit_action,
                Some("artifact"),
                Some(artifact.id),
                Some(detail),
            )
            .await;
    }

    /// Hash a container's DECODED media stream and compare it to the hash the
    /// acquisition tool recorded inside the container (E01 stored_md5/stored_sha1).
    /// Records a pass/fail integrity row + audit event so a mismatch (the image
    /// does not read back as acquired) is surfaced, never silent.
    async fn verify_decoded_media(
        &self,
        db_conn: &dyn DatabaseConnection,
        case_id: Uuid,
        artifact_id: Uuid,
        decoded: Arc<dyn DataSource>,
        expected_md5: String,
        expected_sha1: Option<String>,
    ) -> Result<(), ModuleError> {
        // Images can be large; hash the decoded stream on the blocking pool, and
        // report progress the same way the acquisition pass does so this second
        // full read of a big image is not a silent minutes-long wait.
        let bytes_total = decoded.size();
        let status_sender = self.status_sender.clone();
        let hashes = tokio::task::spawn_blocking(move || {
            let mut cursor = crate::data_source::SourceCursor::new(decoded);
            crate::hashing::compute_hashes_streaming_with_progress(
                &mut cursor,
                HASH_CHUNK_BYTES,
                |bytes_done| {
                    if let Some(sender) = &status_sender {
                        let _ = sender.send(OrchestratorEvent::DecodedMediaHashProgress {
                            case_id,
                            artifact_id,
                            bytes_done,
                            bytes_total,
                        });
                    }
                },
            )
        })
        .await
        .map_err(|e| ModuleError::FatalError(format!("Decoded-media hashing task failed: {}", e)))?
        .map_err(|e| ModuleError::FatalError(format!("Failed to hash decoded media: {}", e)))?;

        let md5_match = hashes.md5.eq_ignore_ascii_case(&expected_md5);
        let sha1_match = expected_sha1
            .as_ref()
            .map(|s| hashes.sha1.eq_ignore_ascii_case(s))
            .unwrap_or(true);
        let verified = md5_match && sha1_match;
        let status = if verified {
            "verified"
        } else {
            "integrity_failed"
        };
        let sha1_detail = match &expected_sha1 {
            Some(s) => format!(
                ", sha1 {} (computed {}, expected {})",
                if sha1_match { "MATCH" } else { "MISMATCH" },
                hashes.sha1,
                s
            ),
            None => String::new(),
        };
        let details = format!(
            "Decoded-media vs container-recorded hash: md5 {} (computed {}, expected {}){}",
            if md5_match { "MATCH" } else { "MISMATCH" },
            hashes.md5,
            expected_md5,
            sha1_detail
        );

        db_conn
            .record_integrity_check(
                case_id,
                artifact_id,
                Some(&hashes.md5),
                Some(&hashes.sha1),
                Some(&hashes.sha256),
                Some(&expected_md5),
                expected_sha1.as_deref(),
                // The container-recorded baseline — E01 only, the one
                // container reader that publishes one — carries MD5/SHA-1
                // and never SHA-256.
                None,
                status,
                Some(&details),
            )
            .await
            .map_err(|e| {
                ModuleError::FatalError(format!("Failed to record decoded-media integrity: {}", e))
            })?;

        db_conn
            .record_audit_event(
                Some(case_id),
                "system",
                if verified {
                    "evidence_decoded_verified"
                } else {
                    "evidence_decoded_integrity_failed"
                },
                Some("artifact"),
                Some(artifact_id),
                Some(&details),
            )
            .await
            .map_err(|e| {
                ModuleError::FatalError(format!(
                    "Failed to record decoded-media audit event: {}",
                    e
                ))
            })?;

        if verified {
            info!(
                "Decoded-media integrity verified for artifact {}",
                artifact_id
            );
        } else {
            error!(
                "Decoded-media integrity check FAILED for artifact {}: {}",
                artifact_id, details
            );
        }
        Ok(())
    }

    /// Verify the decoded media against the container-recorded hash when the
    /// artifact carries one (`stored_md5`, optionally `stored_sha1`) and a
    /// decoded stream. Shared by both ingest paths so the rule lives once.
    ///
    /// `case_id` is passed explicitly because the two callers take it from
    /// different places.
    async fn verify_stored_hash_if_present(
        &self,
        db_conn: &dyn DatabaseConnection,
        case_id: Uuid,
        artifact: &Artifact,
    ) -> Result<(), ModuleError> {
        let stored_md5 = artifact.metadata.get("stored_md5").and_then(|v| v.as_str());
        let stored_sha1 = artifact
            .metadata
            .get("stored_sha1")
            .and_then(|v| v.as_str());
        if let (Some(decoded), Some(exp_md5)) = (artifact.data.as_ref(), stored_md5) {
            self.verify_decoded_media(
                db_conn,
                case_id,
                artifact.id,
                Arc::clone(decoded),
                exp_md5.to_string(),
                stored_sha1.map(str::to_string),
            )
            .await?;
        }
        Ok(())
    }

    /// Persist the artifact + baseline records, then broadcast and queue it.
    ///
    /// Note that this too is pre-queue work, and not brief: the decoded-media
    /// verification in step 3b hashes an entire decoded image before step 5
    /// increments the task counter. Both callers hold a [`Self::pre_queue_guard`]
    /// across this call, which is what keeps that window visible to the
    /// orchestrator's idle check.
    async fn persist_and_queue(
        &self,
        mut artifact: Artifact,
        acquisition: Option<&HashResult>,
    ) -> Result<Artifact, ModuleError> {
        // Single choke point for the DB write, the SSE broadcast and the queue.
        // Scrubbing here as well as at the entry points means no future caller
        // can route a secret into metadata_json by adding another ingest path.
        Self::scrub_secrets(&mut artifact.metadata);

        info!(
            "Ingesting initial artifact: {:?} (ID: {}) for case {}",
            artifact.artifact_type, artifact.id, artifact.case_id
        );

        // 2. Persist to database
        if let Some(db_conn) = &self.db {
            db_conn.record_artifact(&artifact).await.map_err(|e| {
                ModuleError::FatalError(format!("Failed to record initial artifact to DB: {}", e))
            })?;

            // 3. Record integrity baseline + audit trail
            if let Some(hashes) = acquisition {
                Self::record_acquisition_baseline(db_conn.as_ref(), &artifact, hashes).await?;
            }

            // 3b. Container decoded-stream verification. `hash_source` above
            // hashes the container FILE(S) on disk (every segment of a
            // compressed E01 set), which is not the acquisition-authoritative
            // value for the media inside it. When the container
            // recorded its own hash of the DECODED media (stored_md5/stored_sha1)
            // and we have that decoded stream, hash the decoded bytes and compare:
            // this is the check that proves the image reads back as it was
            // acquired. Recorded as a pass/fail integrity row, not silently.
            self.verify_stored_hash_if_present(db_conn.as_ref(), artifact.case_id, &artifact)
                .await?;
        }

        self.record_ingest_run_start(&artifact).await;
        self.enqueue(artifact)
    }

    /// Open an ingest-run row for a root exhibit about to be queued (HUNT-113).
    ///
    /// Only roots: the row is what lets the next start tell a walk that ended
    /// from one that was killed part-way, and a child artifact's processing
    /// belongs to its root's run. Failure to write it is logged, not fatal —
    /// the exhibit still ingests — but it means an interruption of this run
    /// could not be seen, and the log says so.
    async fn record_ingest_run_start(&self, artifact: &Artifact) {
        if artifact.parent_id.is_some() {
            return;
        }
        let Some(db) = &self.db else { return };
        let run = crate::profile::IngestRun {
            id: Uuid::new_v4(),
            case_id: artifact.case_id,
            source_artifact_id: artifact.id,
            source_label: Self::source_label(artifact),
            started_at: chrono::Utc::now().timestamp(),
            finished_at: None,
            status: crate::profile::IngestRun::RUNNING.to_string(),
            artifacts_recorded: None,
            detail: None,
        };
        if let Err(e) = db.start_ingest_run(&run).await {
            warn!(
                "Could not record the start of ingesting {} in case {}: {}. If this process \
                 stops before the walk ends, nothing will mark the source interrupted.",
                run.source_label, run.case_id, e
            );
        }
    }

    /// Broadcast, count and queue an artifact for processing.
    ///
    /// The LIVE-001-sensitive tail shared by [`Self::persist_and_queue`] and
    /// [`Self::finish_background_ingest`], which calls it directly: the counter is incremented
    /// exactly when the artifact reaches the queue, and rolled back if the send
    /// fails, so a queued artifact and the active-task count never disagree.
    fn enqueue(&self, artifact: Artifact) -> Result<Artifact, ModuleError> {
        // Broadcast "queued" event.
        let _ = self.event_broadcaster.send(artifact.clone());

        // Increment the active task counter (decremented when processed).
        self.active_tasks.fetch_add(1, Ordering::SeqCst);

        if let Err(e) = self.task_sender.send(artifact.clone()) {
            // The artifact never reached the queue, so nothing downstream will
            // decrement the counter we just incremented. Roll it back here or
            // active_tasks stays >0 forever and idle-exit never fires.
            self.active_tasks.fetch_sub(1, Ordering::SeqCst);
            return Err(ModuleError::FatalError(format!(
                "Failed to send artifact to queue: {:?}",
                e.0
            )));
        }
        Ok(artifact)
    }

    /// Persist and queue an artifact WITHOUT recording its acquisition baseline
    /// or verifying its decoded media — that integrity work runs concurrently in
    /// [`Self::record_integrity_after_queue`] so processing can start while the
    /// evidence is still being hashed.
    async fn persist_artifact(&self, artifact: &Artifact) -> Result<(), ModuleError> {
        info!(
            "Persisting artifact before integrity hashing: {:?} (ID: {}) for case {}",
            artifact.artifact_type, artifact.id, artifact.case_id
        );
        if let Some(db_conn) = &self.db {
            db_conn.record_artifact(artifact).await.map_err(|e| {
                ModuleError::FatalError(format!("Failed to record initial artifact to DB: {}", e))
            })?;
        }
        Ok(())
    }

    /// The acquisition baseline and decoded-media verification, recorded AFTER
    /// the artifact was queued — the slow work that used to gate processing now
    /// runs alongside it. The baseline is still recorded in full and any decoded
    /// mismatch is still surfaced; when it lands, the artifact's `integrity_state`
    /// flips from `verifying` to `baseline_recorded`.
    ///
    /// Errors here are real (hashing failed, DB write failed) and propagate to
    /// the caller, which reports the ingest as failed — the same as the blocking
    /// path. A decoded-media hash *mismatch* is not an error: it is recorded as
    /// an `integrity_failed` row by [`Self::verify_decoded_media`], exactly as
    /// before.
    async fn record_integrity_after_queue(
        &self,
        artifact: &Artifact,
        source_path: &str,
    ) -> Result<(), IntegrityStageError> {
        use IntegrityStageError::{Baseline, DecodedVerification};
        let case_id = artifact.case_id;
        let (hashes, coverage) = self
            .hash_source(case_id, Some(artifact.id), source_path)
            .await
            .map_err(Baseline)?;

        if let Some(db_conn) = &self.db {
            Self::record_acquisition_baseline(db_conn.as_ref(), artifact, &hashes)
                .await
                .map_err(Baseline)?;

            // Attach the baseline to the already-persisted artifact and flip its
            // integrity state, so the case record carries the acquisition_*
            // fields.
            let mut patch = serde_json::Map::new();
            let mut patched = serde_json::json!({});
            Self::insert_acquisition_metadata(&mut patched, &hashes, &coverage);
            if let Some(obj) = patched.as_object() {
                for (k, v) in obj {
                    patch.insert(k.clone(), v.clone());
                }
            }
            patch.insert(
                "integrity_state".into(),
                serde_json::json!("baseline_recorded"),
            );
            db_conn
                .merge_artifact_metadata(case_id, artifact.id, &serde_json::Value::Object(patch))
                .await
                .map_err(|e| {
                    Baseline(ModuleError::FatalError(format!(
                        "Failed to attach acquisition baseline: {}",
                        e
                    )))
                })?;

            // Decoded-media verification against the container's recorded hash,
            // now concurrent with processing rather than gating it. From here
            // the baseline is on record: a failure is its own stage.
            self.verify_stored_hash_if_present(db_conn.as_ref(), case_id, artifact)
                .await
                .map_err(DecodedVerification)?;
        }
        Ok(())
    }
}

/// Which stage of [`IngestionService::record_integrity_after_queue`] failed.
/// The two are different custody facts: a missing baseline, versus a baseline
/// that is recorded beside a decoded stream that could not be verified.
enum IntegrityStageError {
    /// Hashing the source, or recording / attaching its baseline, failed.
    Baseline(ModuleError),
    /// The baseline is recorded; verifying the decoded media failed.
    DecodedVerification(ModuleError),
}

#[cfg(test)]
mod ingest_harness {
    use super::*;

    /// An `IngestionService` with no database, sharing `active` so a test can
    /// observe exactly what the orchestrator's idle check would observe.
    /// The receiver is returned because dropping it closes the task queue.
    pub(super) fn service(
        active: Arc<AtomicUsize>,
    ) -> (
        IngestionService,
        tokio::sync::mpsc::UnboundedReceiver<Artifact>,
    ) {
        let (task_sender, task_receiver) = tokio::sync::mpsc::unbounded_channel();
        let (event_broadcaster, _) = tokio::sync::broadcast::channel(16);
        (
            IngestionService::new(None, task_sender, event_broadcaster, active),
            task_receiver,
        )
    }

    /// The 8-byte signature every real EWF segment file begins with.
    ///
    /// Synthetic segments in these tests carry it because segment-set detection
    /// is content-based: a `.E01` without this is an ordinary file that merely
    /// looks like evidence, and is hashed as the single file it is.
    pub(super) const EWF_MAGIC: &[u8; 8] = b"EVF\x09\x0d\x0a\xff\x00";

    /// Write a synthetic EWF segment (signature + `len` copies of `byte`) and
    /// return the exact bytes written, which is what the digest must cover.
    pub(super) fn write_segment(
        dir: &std::path::Path,
        name: &str,
        byte: u8,
        len: usize,
    ) -> Vec<u8> {
        let mut body = EWF_MAGIC.to_vec();
        body.extend_from_slice(&vec![byte; len]);
        std::fs::write(dir.join(name), &body).unwrap();
        body
    }
}

/// BUG-006. A multi-segment EWF set is one piece of evidence in several files;
/// the acquisition baseline covered the first file only.
#[cfg(test)]
mod acquisition_coverage_tests {
    use super::ingest_harness::{service, write_segment};
    use super::*;
    use serde_json::json;

    fn write(dir: &std::path::Path, name: &str, body: &[u8]) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[tokio::test]
    async fn acquisition_hash_covers_every_segment_of_the_set() {
        let dir = tempfile::tempdir().unwrap();
        let mut whole = Vec::new();
        let mut first_body = Vec::new();
        for (name, byte, len) in [
            ("m.E01", b'1', 5000usize),
            ("m.E02", b'2', 4000),
            ("m.E03", b'3', 3000),
            ("m.E04", b'4', 111),
        ] {
            let body = write_segment(dir.path(), name, byte, len);
            if first_body.is_empty() {
                first_body = body.clone();
            }
            whole.extend_from_slice(&body);
        }
        let first = dir.path().join("m.E01");

        let (svc, _queue) = service(Arc::new(AtomicUsize::new(0)));
        let artifact = svc
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                json!({ "source_path": first.to_str().unwrap() }),
            )
            .await
            .expect("ingest of a complete four-segment set");

        let whole_set = crate::hashing::compute_hashes(&whole);
        let first_only = crate::hashing::compute_hashes(&first_body);

        assert_ne!(
            artifact.metadata["acquisition_sha256"],
            json!(first_only.sha256),
            "BUG-006: the baseline covered only .E01 of a four-segment set"
        );
        assert_eq!(
            artifact.metadata["acquisition_sha256"],
            json!(whole_set.sha256)
        );
        assert_eq!(artifact.metadata["acquisition_md5"], json!(whole_set.md5));
        assert_eq!(artifact.metadata["acquisition_sha1"], json!(whole_set.sha1));

        // The record has to say what the digests cover, or nobody can check it.
        assert_eq!(
            artifact.metadata["acquisition_hash_scope"],
            "ewf_segment_set"
        );
        assert_eq!(
            artifact.metadata["acquisition_bytes_hashed"],
            json!(whole.len() as u64)
        );
        assert_eq!(
            artifact.metadata["acquisition_segment_files"],
            json!(["m.E01", "m.E02", "m.E03", "m.E04"])
        );
    }

    #[tokio::test]
    async fn a_single_file_source_still_records_its_own_scope() {
        let dir = tempfile::tempdir().unwrap();
        write(dir.path(), "disk.raw", b"evidence bytes");
        let path = dir.path().join("disk.raw");

        let (svc, _queue) = service(Arc::new(AtomicUsize::new(0)));
        let artifact = svc
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                json!({ "source_path": path.to_str().unwrap() }),
            )
            .await
            .unwrap();

        let expected = crate::hashing::compute_hashes(b"evidence bytes");
        assert_eq!(
            artifact.metadata["acquisition_sha256"],
            json!(expected.sha256)
        );
        assert_eq!(artifact.metadata["acquisition_hash_scope"], "single_file");
        assert_eq!(artifact.metadata["acquisition_bytes_hashed"], json!(14));
        let segments = artifact.metadata.get("acquisition_segment_files");
        assert!(segments.is_none(), "a single file is not a segment set");
    }

    /// Fail closed: a set with a segment missing is not hashed at all. Recording
    /// a digest over {E01, E03} under a name that reads as the whole set would
    /// be an incomplete baseline presented as a complete one.
    #[tokio::test]
    async fn an_incomplete_set_refuses_to_record_a_baseline() {
        let dir = tempfile::tempdir().unwrap();
        write_segment(dir.path(), "gap.E01", b'a', 4);
        write_segment(dir.path(), "gap.E03", b'c', 4);
        let first = dir.path().join("gap.E01");

        let (svc, _queue) = service(Arc::new(AtomicUsize::new(0)));
        let err = svc
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                json!({ "source_path": first.to_str().unwrap() }),
            )
            .await
            .expect_err("a set with a hole in it must not produce a baseline");
        let msg = err.to_string();
        assert!(msg.contains("incomplete"), "{msg}");
        assert!(
            msg.contains('2'),
            "the error names the missing segment: {msg}"
        );
    }

    /// The refusal above must fire ONLY on real EWF sets.
    ///
    /// `.EXE`, `.EVT`, `.LOG`, `.LNK`, `.SYS` and `.EML` all match the EWF
    /// segment NAMING rule (three characters, `E`/`S`/`L`, then two uppercase
    /// letters), so a name-only test reads `EVIDENCE.EVT` as segment 665 of a
    /// set missing its first 664 segments and refuses to ingest the file at
    /// all. These are ordinary evidence; a completeness check that rejects them
    /// is worse than the gap it was closing.
    #[tokio::test]
    async fn ordinary_uppercase_extensions_are_not_ewf_segment_sets() {
        for (name, body) in [
            ("EVIDENCE.EVT", &b"eventlog bytes"[..]),
            ("SETUP.EXE", &b"MZ\x90\x00 not evidence of a set"[..]),
            ("SYSTEM.LOG", &b"log line one"[..]),
            ("SHORTCUT.LNK", &b"L\x00\x00\x00"[..]),
        ] {
            let dir = tempfile::tempdir().unwrap();
            write(dir.path(), name, body);
            let path = dir.path().join(name);

            let (svc, _queue) = service(Arc::new(AtomicUsize::new(0)));
            let artifact = svc
                .ingest_artifact(
                    Uuid::new_v4(),
                    ArtifactType::RawEvidence,
                    None,
                    json!({ "source_path": path.to_str().unwrap() }),
                )
                .await
                .unwrap_or_else(|e| panic!("{name} must ingest as an ordinary file, got {e}"));

            let expected = crate::hashing::compute_hashes(body);
            assert_eq!(
                artifact.metadata["acquisition_sha256"],
                json!(expected.sha256),
                "{name}"
            );
            assert_eq!(
                artifact.metadata["acquisition_hash_scope"],
                json!("single_file"),
                "{name}"
            );
        }
    }

    /// A file that only shares the stem and the naming shape is not part of the
    /// set: its bytes must not enter the baseline digest, and its absurd segment
    /// number must not turn a perfectly good single-segment E01 into an
    /// "incomplete set".
    #[tokio::test]
    async fn a_look_alike_sibling_is_neither_hashed_nor_counted() {
        let dir = tempfile::tempdir().unwrap();
        let segment = write_segment(dir.path(), "disk.E01", b'z', 32);
        write(dir.path(), "disk.EXE", b"an installer, not segment 702");
        let first = dir.path().join("disk.E01");

        let (svc, _queue) = service(Arc::new(AtomicUsize::new(0)));
        let artifact = svc
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                json!({ "source_path": first.to_str().unwrap() }),
            )
            .await
            .expect("a single-segment E01 beside an unrelated file must still ingest");

        let expected = crate::hashing::compute_hashes(&segment);
        assert_eq!(
            artifact.metadata["acquisition_sha256"],
            json!(expected.sha256)
        );
        assert_eq!(artifact.metadata["acquisition_hash_scope"], "single_file");
        assert_eq!(
            artifact.metadata["acquisition_bytes_hashed"],
            json!(segment.len() as u64)
        );
    }

    /// The real four-segment set built for this finding
    /// (`~/forensic_images/deferred`, see its GROUND_TRUTH.md). Point
    /// `SEANCE_DEFERRED_IMAGES` at that directory to run it.
    #[tokio::test]
    async fn real_multi_segment_ewf_set_hashes_whole() {
        let Ok(dir) = std::env::var("SEANCE_DEFERRED_IMAGES") else {
            eprintln!("SEANCE_DEFERRED_IMAGES unset; skipping real EWF-set check");
            return;
        };
        let first = std::path::Path::new(&dir).join("multiseg.E01");
        if !first.exists() {
            eprintln!("{} absent; skipping", first.display());
            return;
        }

        let (svc, _queue) = service(Arc::new(AtomicUsize::new(0)));
        let artifact = svc
            .ingest_artifact(
                Uuid::new_v4(),
                ArtifactType::RawEvidence,
                None,
                json!({ "source_path": first.to_str().unwrap() }),
            )
            .await
            .unwrap();

        // Ground truth: sha256 over multiseg.E01..E04 concatenated in segment
        // order, and the sha256 of the .E01 alone that the defect produced.
        assert_ne!(
            artifact.metadata["acquisition_sha256"],
            json!("889b4777e8e46c6c4438b7a7e8920c7f9617351cf4a734e31a3ebc774c16691f"),
            "BUG-006: this is the .E01-only digest"
        );
        assert_eq!(
            artifact.metadata["acquisition_sha256"],
            json!("85c1ef805bdd85a582f716ba8080d5ee0501deb5b0fc68a66d09f20909add1da")
        );
        assert_eq!(
            artifact.metadata["acquisition_bytes_hashed"],
            json!(12_594_462u64)
        );
        assert_eq!(
            artifact.metadata["acquisition_segment_files"],
            json!([
                "multiseg.E01",
                "multiseg.E02",
                "multiseg.E03",
                "multiseg.E04"
            ])
        );
    }
}

/// LIVE-001, at the level the class lives at: every pre-queue ingest phase must
/// keep the orchestrator's task count above zero, or an idle-exit run closes
/// the queue while acquisition hashing is still going.
#[cfg(test)]
mod pre_queue_guard_tests {
    use super::ingest_harness::service;
    use super::*;
    use serde_json::json;
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    #[tokio::test]
    async fn acquisition_hashing_keeps_the_run_observably_busy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("big.raw");
        // Sparse: 64 MiB to hash, no 64 MiB to write.
        std::fs::File::create(&path)
            .unwrap()
            .set_len(64 * 1024 * 1024)
            .unwrap();

        let active = Arc::new(AtomicUsize::new(0));
        let (svc, _queue) = service(active.clone());
        let mut fut = Box::pin(svc.ingest_artifact(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            None,
            json!({ "source_path": path.to_str().unwrap() }),
        ));

        // Poll once by hand: this runs the ingest up to its first await, which
        // is the hashing task. No sleeps, so nothing here is timing-dependent.
        let waker = Waker::noop().clone();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(fut.as_mut().poll(&mut cx), Poll::Pending),
            "64 MiB of acquisition hashing cannot have completed already"
        );
        assert!(
            active.load(Ordering::SeqCst) >= 1,
            "LIVE-001: the orchestrator saw zero work outstanding while acquisition \
             hashing was running, so an idle-exit run would close the queue under it"
        );

        drop(fut);
        assert_eq!(
            active.load(Ordering::SeqCst),
            0,
            "an abandoned ingest must give the count back, or the run never goes idle"
        );
    }

    #[tokio::test]
    async fn background_ingest_is_busy_before_its_task_is_polled() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("evidence.raw");
        std::fs::write(&path, b"evidence").unwrap();

        let active = Arc::new(AtomicUsize::new(0));
        let (svc, _queue) = service(active.clone());
        let _artifact = svc.ingest_artifact_background(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            None,
            json!({ "source_path": path.to_str().unwrap() }),
        );

        // Nothing is awaited between the call above and this read, so on the
        // current-thread runtime the spawned task has not run yet. That gap is
        // exactly where an idle-exit orchestrator would decide it was finished.
        assert!(
            active.load(Ordering::SeqCst) >= 1,
            "LIVE-001: a background ingest was invisible to the idle check \
             between being requested and being scheduled"
        );
    }
}

#[cfg(test)]
mod secret_redaction_tests {
    use super::{redact_secret_metadata, REDACTED_SECRET};
    use serde_json::json;

    /// B3-060. The CLI attached `luks_passphrase` / `bitlocker_password` /
    /// `bitlocker_recovery_key` to the root evidence artifact's metadata, which
    /// is written to `artifacts.metadata_json` and served by the artifact-detail
    /// API. The unlock key must never reach anything durable.
    #[test]
    fn volume_unlock_secrets_never_survive_into_metadata() {
        let mut md = json!({
            "name": "disk.raw",
            "source_path": "/evidence/disk.raw",
            "luks_passphrase": "correct horse battery staple",
            "bitlocker_password": "hunter2",
            "bitlocker_recovery_key": "123456-123456-123456-123456-123456-123456-123456-123456",
        });

        let redacted = redact_secret_metadata(&mut md);

        assert_eq!(
            redacted.len(),
            3,
            "all three secrets redacted: {redacted:?}"
        );
        let serialised = md.to_string();
        for secret in [
            "correct horse battery staple",
            "hunter2",
            "123456-123456-123456-123456-123456-123456-123456-123456",
        ] {
            assert!(
                !serialised.contains(secret),
                "secret leaked into persisted metadata: {serialised}"
            );
        }
        // The fact a credential was supplied is chain-of-custody relevant and
        // is kept; only the value goes.
        assert_eq!(md["luks_passphrase"], json!(REDACTED_SECRET));
        assert_eq!(md["name"], json!("disk.raw"));
        assert_eq!(md["source_path"], json!("/evidence/disk.raw"));
    }

    /// The same class, not just the three known keys: any future
    /// `*_password` / `*_passphrase` / `*_recovery_key` / `*_pin` ingest
    /// parameter is stripped without another code change.
    #[test]
    fn the_whole_secret_key_class_is_stripped_including_nested() {
        let mut md = json!({
            "veracrypt_password": "vc",
            "apfs_passphrase": "ap",
            "android_pin": "1234",
            "options": { "signal_passphrase": "sig" },
            "keys": [ { "recovery_key": "rk" } ],
        });

        let redacted = redact_secret_metadata(&mut md);

        assert_eq!(redacted.len(), 5, "redacted: {redacted:?}");
        let serialised = md.to_string();
        for secret in ["\"vc\"", "\"ap\"", "\"1234\"", "\"sig\"", "\"rk\""] {
            assert!(
                !serialised.contains(secret),
                "leaked {secret} in {serialised}"
            );
        }
    }

    /// Credentials RECOVERED FROM the evidence are findings, not our secrets,
    /// and must survive. Redaction only ever runs on root ingest metadata, and
    /// only matches key names, so a recovered value stored under a normal key
    /// is untouched.
    #[test]
    fn recovered_evidence_values_are_not_redacted() {
        let mut md = json!({
            "type": "BrowserCredential",
            "origin": "https://example.com",
            "username": "victim",
            "recovered_value": "s3cret-from-evidence",
        });
        assert!(redact_secret_metadata(&mut md).is_empty());
        assert_eq!(md["recovered_value"], json!("s3cret-from-evidence"));
    }

    /// An absent key must not be materialised as a redaction marker: that would
    /// tell an examiner a credential was supplied when none was.
    #[test]
    fn absent_or_null_secrets_are_left_alone() {
        let mut md = json!({ "name": "disk.raw", "luks_passphrase": null });
        assert!(redact_secret_metadata(&mut md).is_empty());
        assert_eq!(md["luks_passphrase"], serde_json::Value::Null);
        assert!(md.get("bitlocker_password").is_none());
    }
}

#[cfg(test)]
mod ewf_set_tests {
    use super::ingest_harness::write_segment;
    use super::{ewf_segment_ordinal, ewf_segment_set, SegmentSetReader};
    use std::io::Read;

    /// A file carrying a segment's NAME but not its content. Detection is by
    /// signature, so this must never join a set.
    fn write_look_alike(dir: &std::path::Path, name: &str, body: &[u8]) {
        std::fs::write(dir.join(name), body).unwrap();
    }

    #[test]
    fn recognizes_ewf_segment_extensions() {
        for ext in ["E01", "e01", "E99", "EAA", "EZZ", "S01", "L01"] {
            assert!(
                ewf_segment_ordinal(ext).is_some(),
                "{ext} should be an EWF segment"
            );
        }
        for ext in ["dd", "raw", "E0", "E011", "zip", "e0z", "E00"] {
            assert!(ewf_segment_ordinal(ext).is_none(), "{ext} should not be");
        }
    }

    /// Segment order is the order the digest sees the bytes in, so the ordinals
    /// must follow libewf's own numbering across the digit/letter boundary.
    #[test]
    fn segment_ordinals_follow_libewf_numbering() {
        assert_eq!(ewf_segment_ordinal("E01"), Some(1));
        assert_eq!(ewf_segment_ordinal("E09"), Some(9));
        assert_eq!(ewf_segment_ordinal("E10"), Some(10));
        assert_eq!(ewf_segment_ordinal("E99"), Some(99));
        assert_eq!(ewf_segment_ordinal("EAA"), Some(100));
        assert_eq!(ewf_segment_ordinal("EAB"), Some(101));
        assert_eq!(ewf_segment_ordinal("EZZ"), Some(775));
        // E10 must sort after E09, and EAA after E99.
        assert!(ewf_segment_ordinal("E10") > ewf_segment_ordinal("E09"));
        assert!(ewf_segment_ordinal("EAA") > ewf_segment_ordinal("E99"));
    }

    #[test]
    fn lower_case_letter_extensions_count_as_segments_past_e99() {
        assert_eq!(ewf_segment_ordinal("eaa"), Some(100));
        assert_eq!(ewf_segment_ordinal("eab"), Some(101));
        assert_eq!(ewf_segment_ordinal("ezz"), Some(775));
        assert!(
            ewf_segment_ordinal("eAa").is_none(),
            "mixed case is not a segment"
        );
    }

    #[test]
    fn a_lower_case_set_past_e99_is_collected_whole() {
        let dir = tempfile::tempdir().unwrap();
        let mut names: Vec<String> = (1..=99).map(|n| format!("disk.e{n:02}")).collect();
        names.push("disk.eaa".into());
        names.push("disk.eab".into());
        for name in &names {
            write_segment(dir.path(), name, 0, 4);
        }
        let first = dir.path().join("disk.e01");
        let set = ewf_segment_set(first.to_str().unwrap()).unwrap();
        assert!(set.inconsistencies.is_empty(), "{:?}", set.inconsistencies);
        assert_eq!(set.paths.len(), 101);
        let per_segment = (super::ingest_harness::EWF_MAGIC.len() + 4) as u64;
        assert_eq!(set.total_bytes, per_segment * 101);

        // Segment 100 absent: the hole is reported, not hidden.
        std::fs::remove_file(dir.path().join("disk.eaa")).unwrap();
        let set = ewf_segment_set(first.to_str().unwrap()).unwrap();
        assert!(
            set.inconsistencies.iter().any(|i| i.contains("100")),
            "{:?}",
            set.inconsistencies
        );
    }

    #[test]
    fn collects_a_multi_segment_set_in_order() {
        let dir = tempfile::tempdir().unwrap();
        // Created out of order on purpose: the set must be ordered by segment
        // number, not by directory-listing order.
        let per_segment = super::ingest_harness::EWF_MAGIC.len() + 10;
        for ext in ["E03", "E01", "E02"] {
            write_segment(dir.path(), &format!("001.{ext}"), 0, 10);
        }
        // Unrelated files, a different acquisition sharing the stem, and a
        // look-alike whose extension parses as segment 702 must all stay out.
        write_segment(dir.path(), "notes.txt", b'x', 1);
        write_segment(dir.path(), "001.L01", 0, 999);
        write_look_alike(dir.path(), "001.EXE", b"an installer, not segment 702");

        let first = dir.path().join("001.E01");
        let set = ewf_segment_set(first.to_str().unwrap()).unwrap();
        assert!(set.inconsistencies.is_empty(), "{:?}", set.inconsistencies);
        assert_eq!(set.total_bytes, (per_segment * 3) as u64);
        let names: Vec<String> = set
            .paths
            .iter()
            .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(names, vec!["001.E01", "001.E02", "001.E03"]);
    }

    #[test]
    fn a_lone_segment_is_a_one_file_set_and_non_ewf_is_not_a_set() {
        let dir = tempfile::tempdir().unwrap();
        write_segment(dir.path(), "solo.E01", 1, 4);
        write_segment(dir.path(), "disk.dd", 1, 4);

        let solo_path = dir.path().join("solo.E01");
        let solo = ewf_segment_set(solo_path.to_str().unwrap()).unwrap();
        assert_eq!(solo.paths.len(), 1);
        assert!(solo.inconsistencies.is_empty());

        let raw_path = dir.path().join("disk.dd");
        assert!(ewf_segment_set(raw_path.to_str().unwrap()).is_none());
    }

    /// The name is not the evidence. A file called `.E01` that does not carry
    /// the EWF signature is an ordinary file, hashed as itself.
    #[test]
    fn a_segment_named_file_without_the_signature_is_not_a_set() {
        let dir = tempfile::tempdir().unwrap();
        write_look_alike(dir.path(), "pretend.E01", b"no EWF signature here at all");
        let path = dir.path().join("pretend.E01");
        assert!(ewf_segment_set(path.to_str().unwrap()).is_none());
    }

    /// Every extension that parses as a segment ordinal but belongs to an
    /// ordinary file. Name-only detection turned each of these into an
    /// "incomplete set" and refused the ingest outright.
    #[test]
    fn ordinary_uppercase_extensions_are_never_segment_sets() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "EVIDENCE.EVT",
            "SETUP.EXE",
            "SYSTEM.LOG",
            "SHORTCUT.LNK",
            "DRIVER.SYS",
            "MAIL.EML",
        ] {
            // Long enough to hold a signature, so the check is about content.
            write_look_alike(dir.path(), name, b"ordinary evidence, not a segment");
            let path = dir.path().join(name);
            assert!(
                ewf_segment_set(path.to_str().unwrap()).is_none(),
                "{name} must not be read as an EWF segment set"
            );
        }
    }

    /// "One segment" and "we could not find out" are different facts. A real
    /// segment whose directory cannot be listed must not be recorded as a
    /// complete single-file source.
    #[cfg(unix)]
    #[test]
    fn an_unlistable_directory_is_reported_not_guessed() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let inner = dir.path().join("evidence");
        std::fs::create_dir(&inner).unwrap();
        write_segment(&inner, "img.E01", b'q', 16);
        let path = inner.join("img.E01");

        // Search but not read: the segment still opens, the directory does not
        // list. Restored before the assertions so cleanup always works.
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o111)).unwrap();
        let listable = std::fs::read_dir(&inner).is_ok();
        let set = ewf_segment_set(path.to_str().unwrap());
        std::fs::set_permissions(&inner, std::fs::Permissions::from_mode(0o755)).unwrap();

        if listable {
            // Running as root, where the permission bits do not apply.
            return;
        }
        let set = set.expect("an EWF segment whose set cannot be established");
        assert_eq!(set.paths.len(), 1);
        assert!(
            set.inconsistencies
                .iter()
                .any(|i| i.contains("cannot be listed")),
            "{:?}",
            set.inconsistencies
        );
    }

    /// A set with a hole in it is reported, so hashing can refuse it rather
    /// than record a baseline that appears to cover the whole acquisition.
    #[test]
    fn a_gap_in_the_run_is_an_inconsistency() {
        let dir = tempfile::tempdir().unwrap();
        for ext in ["E01", "E03"] {
            write_segment(dir.path(), &format!("gap.{ext}"), 0, 8);
        }
        let first = dir.path().join("gap.E01");
        let set = ewf_segment_set(first.to_str().unwrap()).unwrap();
        assert_eq!(set.inconsistencies.len(), 1, "{:?}", set.inconsistencies);
        assert!(set.inconsistencies[0].contains('2'), "names the gap");
    }

    #[test]
    fn segment_reader_streams_every_file_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let mut expected = Vec::new();
        for (name, byte, len) in [
            ("a.E01", b'a', 3usize),
            ("a.E02", b'b', 2),
            ("a.E03", b'c', 4),
        ] {
            expected.extend_from_slice(&write_segment(dir.path(), name, byte, len));
        }

        let first = dir.path().join("a.E01");
        let set = ewf_segment_set(first.to_str().unwrap()).unwrap();
        let mut reader = SegmentSetReader::open(set.paths).unwrap();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, expected);
    }

    /// A segment that cannot be opened must fail the read, never end the
    /// stream early: a short stream would hash as a complete acquisition.
    #[test]
    fn segment_reader_fails_when_a_later_segment_is_unreadable() {
        let dir = tempfile::tempdir().unwrap();
        write_segment(dir.path(), "a.E01", b'a', 3);
        let paths = vec![dir.path().join("a.E01"), dir.path().join("a.E02")];
        let mut reader = SegmentSetReader::open(paths).unwrap();
        let mut out = Vec::new();
        let err = reader.read_to_end(&mut out).unwrap_err();
        assert!(
            err.to_string().contains("a.E02"),
            "error must name the segment: {err}"
        );
    }
}
