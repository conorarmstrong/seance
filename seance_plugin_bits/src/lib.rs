#![forbid(unsafe_code)]
//! Background Intelligent Transfer Service (BITS) job queues.
//!
//! BITS is the Windows service that downloads (and uploads) files in the
//! background for Windows Update, Office, browsers — and for anything else that
//! asks, which is why attackers use it: a BITS job survives reboots, runs as the
//! owner it was created under, and can launch a command when its transfer
//! completes. The queue on disk names every job's source URL, the local path the
//! file was written to, the account that owns it and when it was created.
//!
//! # The files
//!
//! - `qmgr0.dat` / `qmgr1.dat` (Windows XP to 8.1, Server 2003 to 2012 R2):
//!   a binary state file, written alternately. Read by [`qmgr_dat`].
//! - `qmgr.db` (Windows 10 and later): an ESE database with `Jobs` and
//!   `Files` tables whose blobs carry the same job header and file record.
//!   Read by [`qmgr_db`] (feature `esedb`). Transaction logs are not replayed,
//!   and a dirty database says so.
//!
//! # What is and is not claimed
//!
//! The binary layout is undocumented. [`qmgr_dat`] is a clean-room reading of
//! the bytes of real queue files (NIST CFReDS Data Leakage, Windows 7; DFIR
//! Madness case 001 DC01, Server 2012 R2): the header, queue and file-list
//! GUIDs, the job header and the file records were measured there. Every
//! record says where it was read from, and every job carries the byte offset of
//! its delimiter so an examiner can check the reading by hand.
//!
//! Credentials and custom headers are stored as DPAPI blobs. They are reported
//! as present, with the blob's own description and master-key GUID, and are
//! **never** decrypted.
//!
//! Bytes past the live structure's closing GUID hold earlier states of the
//! queue. File records found there are reported as carved, labelled with the
//! offset, and never as jobs: the job header that owned them (its name, owner
//! and state) has been overwritten, so a carved record is evidence that a
//! transfer was once queued, not that it still was.

pub mod qmgr_dat;
#[cfg(feature = "esedb")]
pub mod qmgr_db;

use chrono::DateTime;
use qmgr_dat::{CarvedFile, Job, QueueFile};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::read_exact_or_fail,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value};
use tracing::debug;
use uuid::Uuid;

/// Cap on a buffered queue file. Real `qmgr*.dat` files are 4 MiB; the cap
/// bounds a hostile or corrupt size rather than letting it OOM the worker.
const MAX_QUEUE_BYTES: u64 = 64 * 1024 * 1024;

/// The documented `BG_JOB_TYPE` names, by value.
pub fn job_type_name(v: u32) -> Option<&'static str> {
    ["download", "upload", "upload_reply"]
        .get(v as usize)
        .copied()
}

/// The documented `BG_JOB_PRIORITY` names, by value.
pub fn priority_name(v: u32) -> Option<&'static str> {
    ["foreground", "high", "normal", "low"]
        .get(v as usize)
        .copied()
}

/// The documented `BG_JOB_STATE` names, by value.
pub fn state_name(v: u32) -> Option<&'static str> {
    [
        "queued",
        "connecting",
        "transferring",
        "suspended",
        "error",
        "transient_error",
        "transferred",
        "acknowledged",
        "cancelled",
    ]
    .get(v as usize)
    .copied()
}

/// A FILETIME as RFC 3339, or `None` for zero, all-ones or out of range.
pub fn filetime_rfc3339(ft: u64) -> Option<String> {
    filetime_unix(ft).and_then(|(s, n)| DateTime::from_timestamp(s, n).map(|d| d.to_rfc3339()))
}

fn filetime_unix(ft: u64) -> Option<(i64, u32)> {
    if ft == 0 || ft == u64::MAX {
        return None;
    }
    const EPOCH_DIFF: u64 = 116_444_736_000_000_000;
    let since = ft.checked_sub(EPOCH_DIFF)?;
    let secs = (since / 10_000_000) as i64;
    let nanos = ((since % 10_000_000) * 100) as u32;
    Some((secs, nanos))
}

/// What a record carved past a `.dat` queue's live structure is evidence of.
const STALE_NOTE: &str = "found in bytes past the end of the live queue structure, an earlier \
    state of this file; the job that owned it (name, owner, state, times) was overwritten and \
    is not recovered, so this is evidence the transfer was once queued, not that it still was";

/// Why a `qmgr.db` job carries no files and no times.
const HEADER_ONLY_NOTE: &str =
    "only the job header (type, priority, state, id, name, description, \
    notify command, owner) was read from this Jobs row; the part of the blob after it, which holds \
    the job's file list and its times, is not decoded, so this record's lack of files, URLs and \
    creation or modification time is not a finding that the job had none. The database's Files \
    rows are published as separate BitsFileTransfer records and are not linked to this job";

/// What a record found by byte scan of a `qmgr.db` is evidence of.
#[cfg(feature = "esedb")]
const DB_SCAN_NOTE: &str = "found by a byte scan of the database file, in bytes no table row the \
    walk returned holds (a free or superseded page, or one the walk did not reach); the job that \
    owned it is not identified, so this is evidence the transfer was once queued, not that it \
    still was";

pub struct BitsParser;

/// Copy `ds` to a temporary file (libesedb opens paths) a chunk at a time.
#[cfg(feature = "esedb")]
fn stage(
    ds: &dyn seance_core::data_source::DataSource,
) -> Result<seance_core::temp_spill::TempSpill, String> {
    use std::io::Write;
    const CHUNK: u64 = 8 * 1024 * 1024;
    let spill = seance_core::temp_spill::TempSpill::write(&[], "bits", "db").map_err(|e| {
        format!("the database could not be staged to a temporary file for libesedb ({e})")
    })?;
    let mut out = std::fs::OpenOptions::new()
        .append(true)
        .open(spill.path())
        .map_err(|e| format!("the temporary file could not be opened ({e})"))?;
    let size = ds.size();
    let mut buf = vec![0u8; CHUNK.min(size) as usize];
    let mut at = 0u64;
    while at < size {
        let n = CHUNK.min(size - at) as usize;
        read_exact_or_fail(ds, at, &mut buf[..n], "ESE database")
            .map_err(|e| format!("the file could not be read at byte {at} ({e})"))?;
        out.write_all(&buf[..n])
            .map_err(|e| format!("the temporary file could not be written ({e})"))?;
        at += n as u64;
    }
    Ok(spill)
}

impl BitsParser {
    pub fn new() -> Self {
        Self
    }

    fn file_name(artifact: &Artifact) -> String {
        // A prior version's `name` carries the shadow-copy label.
        seance_core::shadow_copy::original_name(artifact)
            .unwrap_or_default()
            .to_string()
    }

    /// A file named like a binary queue, whatever its content.
    fn named_like_queue(name: &str) -> bool {
        let lower = name.to_ascii_lowercase();
        lower == "qmgr0.dat" || lower == "qmgr1.dat"
    }

    /// A file named like the Windows 10+ database queue.
    fn named_like_queue_db(name: &str) -> bool {
        name.eq_ignore_ascii_case("qmgr.db")
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
                "type": "BitsQueueIncomplete",
                "subtype": "parse_incomplete",
                "status": status,
                "source_file": source,
                "content_incomplete": true,
                "content_incomplete_reason": detail,
                "content_incomplete_detail": detail,
                "detail": detail,
                "name": format!("BITS queue {source}: {detail}"),
            }),
        )
        .with_parent(parent_id)
        .with_subtype("parse_incomplete")
    }

    /// One job. `locator` says where it was read: `queue_index` for a `.dat`
    /// job, `row_id` for a `qmgr.db` row. `header_only` is set for a
    /// `qmgr.db` job, whose blob decoder reads the job header and nothing
    /// after it: its files and times were not read, and the record says so
    /// instead of showing a job that queued nothing.
    fn job_record(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        format: &str,
        locator: (&str, Value),
        job: &Job,
        header_only: bool,
    ) -> Artifact {
        let mut m = Map::new();
        m.insert("type".into(), json!("BitsJob"));
        m.insert("source_file".into(), json!(source));
        m.insert("source_format".into(), json!(format));
        m.insert(locator.0.into(), locator.1);
        m.insert("offset".into(), json!(job.offset));
        m.insert("job_id".into(), json!(job.job_id));
        m.insert("job_name".into(), json!(job.name));
        m.insert("description".into(), json!(job.description));
        m.insert("notify_command".into(), json!(job.command));
        m.insert("notify_arguments".into(), json!(job.arguments));
        m.insert("owner_sid".into(), json!(job.owner_sid));
        m.insert("notify_flags".into(), json!(job.notify_flags));
        m.insert("job_type".into(), json!(job.job_type));
        m.insert("priority".into(), json!(job.priority));
        m.insert("state".into(), json!(job.state));
        if let Some(n) = job_type_name(job.job_type) {
            m.insert("job_type_name".into(), json!(n));
        }
        if let Some(n) = priority_name(job.priority) {
            m.insert("priority_name".into(), json!(n));
        }
        if let Some(n) = state_name(job.state) {
            m.insert("state_name".into(), json!(n));
        }
        m.insert("files_read".into(), json!(!header_only));
        m.insert("times_read".into(), json!(!header_only));
        let files: Vec<Value> = job
            .files
            .iter()
            .map(|f| {
                json!({
                    "offset": f.offset,
                    "local_path": f.local_path,
                    "remote_url": f.remote_url,
                    "temp_path": f.temp_path,
                    "bytes_transferred": f.bytes_transferred,
                    "bytes_total": f.bytes_total.map(|v| json!(v)).unwrap_or(json!("unknown")),
                    "volume": f.volume,
                })
            })
            .collect();
        if !header_only {
            m.insert("file_count".into(), json!(files.len()));
            if let Some(d) = job.declared_files {
                m.insert("declared_file_count".into(), json!(d));
            }
            m.insert("files".into(), Value::Array(files));
            let urls: Vec<&str> = job.files.iter().map(|f| f.remote_url.as_str()).collect();
            m.insert("remote_urls".into(), json!(urls));
        }

        match &job.times {
            None if header_only => {
                m.insert("creation_time".into(), json!("not_read"));
                m.insert("modification_time".into(), json!("not_read"));
            }
            Some(t) => {
                let label = |ft: u64| {
                    filetime_rfc3339(ft)
                        .map(Value::from)
                        .unwrap_or(json!("unavailable"))
                };
                m.insert("creation_time".into(), label(t.raw[0]));
                m.insert("modification_time".into(), label(t.raw[1]));
                m.insert("unnamed_time_3".into(), label(t.raw[2]));
                m.insert("unnamed_time_4".into(), label(t.raw[3]));
                m.insert("times_offset".into(), json!(t.offset));
                m.insert(
                    "times_basis".into(),
                    json!(
                        "four FILETIMEs located by shape in the job trailer; the first two are \
                         labelled creation and modification by position, and ANSSI's bits_parser \
                         reads the same two the same way on the Data Leakage jobs; the third and \
                         fourth are not named, because nothing here establishes what they record"
                    ),
                );
                if let Some((s, _)) = filetime_unix(t.raw[0]) {
                    m.insert("timestamp".into(), json!(s));
                }
            }
            None => {
                m.insert("creation_time".into(), json!("unavailable"));
            }
        }

        let has = |needle: &str| {
            job.dpapi_blobs
                .iter()
                .any(|b| b.description.to_ascii_lowercase().contains(needle))
        };
        m.insert("credentials_present".into(), json!(has("credentials")));
        m.insert(
            "custom_headers_present".into(),
            json!(has("custom headers")),
        );
        m.insert(
            "dpapi_blobs".into(),
            json!(job
                .dpapi_blobs
                .iter()
                .map(|b| json!({
                    "offset": b.offset,
                    "description": b.description,
                    "master_key_guid": b.master_key_guid,
                }))
                .collect::<Vec<_>>()),
        );
        m.insert("secrets_decrypted".into(), json!(false));
        let mut gaps: Vec<String> = Vec::new();
        if header_only {
            gaps.push(HEADER_ONLY_NOTE.to_string());
        }
        if let Some(why) = &job.incomplete {
            gaps.push(why.clone());
        }
        if !gaps.is_empty() {
            let why = gaps.join("; ");
            m.insert("content_incomplete".into(), json!(true));
            m.insert("content_incomplete_reason".into(), json!(why));
            m.insert("content_incomplete_detail".into(), json!(why));
        }
        let label = if job.name.is_empty() {
            "(unnamed job)"
        } else {
            job.name.as_str()
        };
        let what = if header_only {
            "(job header only; files and times not read)"
        } else {
            job.files
                .first()
                .map(|f| f.remote_url.as_str())
                .unwrap_or("(no file)")
        };
        m.insert("name".into(), json!(format!("BITS job {label}: {what}")));

        Artifact::new(case_id, ArtifactType::ParsedRecord, None, Value::Object(m))
            .with_parent(parent_id)
            .with_subtype("bits_job")
    }

    /// A file record found by a byte scan. `how` names the method and `note`
    /// says what the record is and is not evidence of.
    fn carved_record(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        (format, how, note): (&str, &str, &str),
        page: Option<u64>,
        c: &CarvedFile,
    ) -> Artifact {
        let mut metadata = json!({
            "type": "BitsCarvedFileTransfer",
            "source_file": source,
            "source_format": format,
            "recovery_method": how,
            "offset": c.offset,
            "copies": c.copies,
            "local_path": c.local_path,
            "remote_url": c.remote_url,
            "temp_path": c.temp_path,
            "bytes_transferred": c.bytes_transferred,
            "bytes_total": c.bytes_total.map(|v| json!(v)).unwrap_or(json!("unknown")),
            "recovery_note": note,
            "name": format!("BITS file transfer (carved, not live): {}", c.remote_url),
        });
        if let Some(p) = page {
            metadata["page"] = json!(p);
        }
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(parent_id)
            .with_subtype("bits_carved_file_transfer")
    }

    fn summary_record(case_id: Uuid, parent_id: Uuid, source: &str, q: &QueueFile) -> Artifact {
        let jobs: usize = q.queues.iter().map(|x| x.jobs.len()).sum();
        let queues: Vec<Value> = q
            .queues
            .iter()
            .map(|x| json!({"index": x.index, "offset": x.offset, "declared_jobs": x.declared_jobs, "jobs_decoded": x.jobs.len()}))
            .collect();
        let status = if q.incomplete.is_some() {
            format!("queue partly read, {jobs} job(s) decoded")
        } else {
            format!("queue read, {jobs} job(s)")
        };
        let mut m = json!({
            "type": "BitsQueueFile",
            "source_file": source,
            "source_format": "qmgr_dat",
            "file_guid": q.file_guid,
            "header_guid_offset": q.header_guid_offset,
            "queues": queues,
            "jobs_decoded": jobs,
            "live_structure_end": q.live_end,
            "carved_file_transfers": q.carved.len(),
            "status": status,
            "name": format!("BITS queue {source}: {status}"),
        });
        if let Some(why) = &q.incomplete {
            let map = m.as_object_mut().expect("object");
            map.insert("content_incomplete".into(), json!(true));
            map.insert("content_incomplete_reason".into(), json!(why));
            map.insert("content_incomplete_detail".into(), json!(why));
        }
        Artifact::new(case_id, ArtifactType::ParsedRecord, None, m)
            .with_parent(parent_id)
            .with_subtype("bits_queue_file")
    }

    /// Every record one `qmgr.db` yields; nothing for an ESE database that is
    /// not a BITS queue.
    #[cfg(feature = "esedb")]
    pub fn records_for_db(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        path: &std::path::Path,
        bytes: &[u8],
    ) -> Vec<Artifact> {
        match qmgr_db::read_db(path, bytes) {
            Ok(Some(q)) => Self::records_from_queue_db(case_id, parent_id, source, &q),
            Ok(None) => Vec::new(),
            Err(why) => {
                // Every ESE file reaches here; only one named like the queue
                // earns a refusal record.
                if source.eq_ignore_ascii_case("qmgr.db") {
                    return vec![Self::marker(
                        case_id,
                        parent_id,
                        source,
                        "NotDecoded",
                        &format!("not decoded: {why}; no job in it was read"),
                    )];
                }
                Vec::new()
            }
        }
    }

    /// Every record one read of a `qmgr.db` yields. Split from
    /// [`Self::records_for_db`] so a decoded `Jobs` row — which no real
    /// database held has yet returned — can be run through the same path.
    #[cfg(feature = "esedb")]
    pub fn records_from_queue_db(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        q: &qmgr_db::QueueDb,
    ) -> Vec<Artifact> {
        let mut out = Vec::new();
        for (row, job) in &q.jobs {
            out.push(Self::job_record(
                case_id,
                parent_id,
                source,
                "qmgr_db",
                ("row_id", json!(row)),
                job,
                true,
            ));
        }
        for (row, f) in &q.files {
            out.push(
                Artifact::new(
                    case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    json!({
                        "type": "BitsFileTransfer",
                        "source_file": source,
                        "source_format": "qmgr_db",
                        "row_id": row,
                        "local_path": f.local_path,
                        "remote_url": f.remote_url,
                        "temp_path": f.temp_path,
                        "bytes_transferred": f.bytes_transferred,
                        "bytes_total": f.bytes_total.map(|v| json!(v)).unwrap_or(json!("unknown")),
                        "volume": f.volume,
                        "name": format!("BITS file transfer: {}", f.remote_url),
                    }),
                )
                .with_parent(parent_id)
                .with_subtype("bits_file_transfer"),
            );
        }
        let page_size = q.page_size.filter(|p| p.is_power_of_two() && *p >= 2048);
        for c in &q.carved {
            // ESE's first two pages are the header and its shadow; page 1 of
            // the database starts after them.
            let page = page_size.map(|ps| (c.offset as u64 / ps as u64).saturating_sub(1));
            out.push(Self::carved_record(
                case_id,
                parent_id,
                source,
                ("qmgr_db", "database_byte_scan", DB_SCAN_NOTE),
                page,
                c,
            ));
        }

        let mut problems: Vec<String> = Vec::new();
        if q.db_state == Some(2) {
            problems.push(
                "the database header says dirty shutdown: it was copied from a running system \
                 or never closed, and the transaction logs beside it (edb*.log) hold changes \
                 that are not in this file and are not replayed here, so a table that reads \
                 empty here may not have been empty on the machine"
                    .into(),
            );
        }
        for (name, st) in [("Jobs", &q.jobs_walk), ("Files", &q.files_walk)] {
            if let Some(r) = st.reason() {
                problems.push(format!(
                    "the {name} table walk fell short ({r}; {} row(s) skipped)",
                    st.rows_skipped
                ));
            }
        }
        if q.undecoded_blobs > 0 {
            problems.push(format!(
                "{} row blob(s) did not decode and are absent",
                q.undecoded_blobs
            ));
        }
        let status = format!(
            "tables read: {} job row(s), {} file row(s); {} decoded",
            q.jobs_rows,
            q.files_rows,
            q.jobs.len() + q.files.len()
        );
        let mut m = json!({
            "type": "BitsQueueDatabase",
            "source_file": source,
            "source_format": "qmgr_db",
            "tables_opened": ["Jobs", "Files"],
            "jobs_rows": q.jobs_rows,
            "files_rows": q.files_rows,
            "jobs_decoded": q.jobs.len(),
            "files_decoded": q.files.len(),
            "database_state": q.state_name(),
            "page_size": q.page_size,
            "carved_file_transfers": q.carved.len(),
            "file_rows_linked_to_jobs": false,
            "status": status,
            "name": format!("BITS queue database {source}: {status}"),
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
                if q.db_state == Some(2) {
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
                .with_subtype("bits_queue_database"),
        );
        out
    }

    /// An ESE database: staged to a temporary file (libesedb reads paths) and
    /// read only when it carries the BITS tables.
    #[cfg(feature = "esedb")]
    fn process_db(
        artifact: &Artifact,
        ds: &dyn seance_core::data_source::DataSource,
        name: &str,
    ) -> Vec<Artifact> {
        let source = if name.is_empty() { "qmgr.db" } else { name };
        let size = ds.size();
        if size > MAX_QUEUE_BYTES {
            // Only a file named like the queue earns a refusal; every other
            // large ESE database is simply not this module's.
            if source.eq_ignore_ascii_case("qmgr.db") {
                return vec![Self::marker(
                    artifact.case_id,
                    artifact.id,
                    source,
                    "NotDecoded",
                    &format!("not decoded: {size} bytes exceeds the {MAX_QUEUE_BYTES}-byte cap"),
                )];
            }
            return Vec::new();
        }
        // A read or staging failure is a "could not look" for a file named
        // like the queue; any other ESE database is simply not this module's.
        let could_not = |why: String| {
            if source.eq_ignore_ascii_case("qmgr.db") {
                vec![Self::marker(
                    artifact.case_id,
                    artifact.id,
                    source,
                    "NotDecoded",
                    &format!("not decoded: {why}; no job in it was read"),
                )]
            } else {
                Vec::new()
            }
        };
        // Staged in chunks, not buffered: every ESE database in a case reaches
        // here, and only the queue's own bytes are read back for the scan.
        let spill = match stage(ds) {
            Ok(s) => s,
            Err(why) => return could_not(why),
        };
        match qmgr_db::has_queue_tables(spill.path()) {
            Ok(true) => {}
            Ok(false) => {
                return could_not(
                    "the ESE database opened but lacks the BITS Jobs and Files tables (Id, Blob), \
                     so it is not a queue this build reads"
                        .into(),
                )
            }
            Err(why) => return could_not(why),
        }
        let bytes = match std::fs::read(spill.path()) {
            Ok(b) => b,
            Err(e) => {
                return could_not(format!("the staged database could not be read back ({e})"))
            }
        };
        Self::records_for_db(artifact.case_id, artifact.id, source, spill.path(), &bytes)
    }

    /// Every record one queue file yields.
    pub fn records_for(
        case_id: Uuid,
        parent_id: Uuid,
        source: &str,
        bytes: &[u8],
    ) -> Vec<Artifact> {
        let Some(q) = qmgr_dat::parse(bytes) else {
            return vec![Self::marker(
                case_id,
                parent_id,
                source,
                "NotDecoded",
                "not decoded: the file does not open with the BITS queue-file GUIDs, so no job \
                 in it was read (this is not a finding that the queue was empty)",
            )];
        };
        let mut out = Vec::new();
        for queue in &q.queues {
            for job in &queue.jobs {
                out.push(Self::job_record(
                    case_id,
                    parent_id,
                    source,
                    "qmgr_dat",
                    ("queue_index", json!(queue.index)),
                    job,
                    false,
                ));
            }
        }
        for c in &q.carved {
            out.push(Self::carved_record(
                case_id,
                parent_id,
                source,
                ("qmgr_dat", "stale_region_carve", STALE_NOTE),
                None,
                c,
            ));
        }
        if let Some(why) = &q.incomplete {
            out.push(Self::marker(
                case_id,
                parent_id,
                source,
                "QueueWalkIncomplete",
                why,
            ));
        }
        out.push(Self::summary_record(case_id, parent_id, source, &q));
        out
    }
}

impl Default for BitsParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for BitsParser {
    fn id(&self) -> &str {
        "plugin.windows.bits"
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

impl BitsParser {
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
        let name = Self::file_name(artifact);
        let size = ds.size();
        let named = Self::named_like_queue(&name) || Self::named_like_queue_db(&name);
        let mut head = vec![0u8; size.min(64) as usize];
        if let Err(e) = read_exact_or_fail(ds.as_ref(), 0, &mut head, "BITS queue header") {
            if named {
                return Ok(vec![Self::marker(
                    artifact.case_id,
                    artifact.id,
                    &name,
                    "NotDecoded",
                    &format!(
                        "not decoded: the file could not be read ({e}); no job in it was read"
                    ),
                )]);
            }
            return Ok(Vec::new());
        }
        let is_ese = seance_core::file_detection::detect_file_type(ds.as_ref())
            == seance_core::file_detection::DetectedFileType::EseDatabase;
        #[cfg(feature = "esedb")]
        if is_ese {
            return Ok(Self::process_db(artifact, ds.as_ref(), &name));
        }
        if Self::named_like_queue_db(&name) {
            let why = if is_ese {
                "not decoded: this build was made without the esedb feature, so the ESE \
                 database was not opened; no job in it was read"
            } else {
                "not decoded: the file is named like the Windows 10+ BITS queue but is not an \
                 ESE database (its header lacks the ESE signature), so no job in it was read \
                 (this is not a finding that the queue was empty)"
            };
            return Ok(vec![Self::marker(
                artifact.case_id,
                artifact.id,
                &name,
                "NotDecoded",
                why,
            )]);
        }
        let shaped = qmgr_dat::looks_like_queue(&head);
        if !shaped && !Self::named_like_queue(&name) {
            return Ok(Vec::new());
        }
        let source = if name.is_empty() {
            "qmgr.dat".to_string()
        } else {
            name
        };
        if size > MAX_QUEUE_BYTES {
            return Ok(vec![Self::marker(
                artifact.case_id,
                artifact.id,
                &source,
                "NotDecoded",
                &format!("not decoded: {size} bytes exceeds the {MAX_QUEUE_BYTES}-byte cap"),
            )]);
        }
        let mut bytes = vec![0u8; size as usize];
        read_exact_or_fail(ds.as_ref(), 0, &mut bytes, "BITS queue")
            .map_err(|e| ModuleError::ParsingError(format!("failed to read BITS queue: {e}")))?;
        let out = Self::records_for(artifact.case_id, artifact.id, &source, &bytes);
        debug!("BITS: {} record(s) from {source}", out.len());
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
