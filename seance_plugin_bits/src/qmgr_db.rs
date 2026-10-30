//! The Windows 10+ BITS queue, `qmgr.db` — an ESE database.
//!
//! # What was measured
//!
//! The only real `qmgr.db` held (LoneWolf, Windows 10 1709) carries two tables,
//! `Jobs` and `Files`, each with two columns, `Id` and `Blob`. It was imaged
//! from a running machine: its header says **dirty shutdown**, both tables hold
//! no rows, and the queue's recent state is in the `edb*.log` transaction logs
//! beside it, which libesedb does not replay. The blob layouts were therefore
//! read off record images elsewhere in real bytes:
//!
//! - a `Jobs` record image in `edb00001.log` holds a 16-byte GUID followed by
//!   exactly the job header `qmgr0.dat` carries after its delimiter — type,
//!   priority, state, a u32, the job GUID, then the length-prefixed strings —
//!   so [`read_job_header`](crate::qmgr_dat::read_job_header) reads both;
//! - `Files` record images in the database's own unreferenced pages hold a
//!   short prefix and then the `.dat` file record — local path, URL, temp path,
//!   byte counts — so [`read_file_record`](crate::qmgr_dat::read_file_record)
//!   reads both.
//!
//! Neither decoder has yet been run on a row a table walk returned: no real
//! `qmgr.db` held has one. Both locate their record by shape in the first 64
//! bytes of the blob rather than at a measured offset, and say so.
//!
//! # Collision safety
//!
//! Every ESE database in a case reaches this module (`SRUDB.dat`,
//! `WebCacheV01.dat`, `Windows.edb`, the UAL `.mdb`s). A database without both
//! a `Jobs` and a `Files` table carrying `Id` and `Blob` produces nothing.

use crate::qmgr_dat::{
    carve_file_records, read_dpapi_blobs, read_file_record, read_job_header, CarvedFile,
    FileTransfer, Job,
};
use libesedb::{EseDb, Table, Value};
use seance_ese_util::{get_column_names, WalkStatus};
use std::path::Path;

/// How far into a blob the record is looked for.
const BLOB_PREFIX_SEARCH: usize = 64;

/// What reading one `qmgr.db` found.
#[derive(Debug, Clone, Default)]
pub struct QueueDb {
    /// The ESE header's database state (2 = dirty shutdown, 3 = clean).
    pub db_state: Option<u32>,
    pub page_size: Option<u32>,
    /// Rows of `Jobs` whose blob decoded, with the row's `Id`.
    pub jobs: Vec<(Option<String>, Job)>,
    /// Rows of `Files` whose blob decoded, with the row's `Id`.
    pub files: Vec<(Option<String>, FileTransfer)>,
    pub jobs_rows: usize,
    pub files_rows: usize,
    pub jobs_walk: WalkStatus,
    pub files_walk: WalkStatus,
    /// Rows whose blob did not decode.
    pub undecoded_blobs: usize,
    /// File records found by a byte scan of the database that are not rows the
    /// walk returned.
    pub carved: Vec<CarvedFile>,
}

impl QueueDb {
    /// The name of the header's database state, as libyal's ESE format
    /// documentation numbers it.
    pub fn state_name(&self) -> &'static str {
        match self.db_state {
            Some(1) => "just_created",
            Some(2) => "dirty_shutdown",
            Some(3) => "clean_shutdown",
            Some(4) => "being_converted",
            Some(5) => "force_detach",
            Some(_) => "unknown",
            None => "unread",
        }
    }
}

fn le32(b: &[u8], at: usize) -> Option<u32> {
    b.get(at..at + 4)
        .map(|s| u32::from_le_bytes(s.try_into().expect("4 bytes")))
}

/// The ESE header's database state (offset 52) and page size (offset 236).
pub fn header_state(bytes: &[u8]) -> (Option<u32>, Option<u32>) {
    (le32(bytes, 52), le32(bytes, 236))
}

/// A `Jobs` blob: a 16-byte GUID and the job header, the pair located by shape
/// in the blob's first 64 bytes — a plausible type, priority and state, a name,
/// and an owner that reads as a SID.
pub fn decode_job_blob(blob: &[u8]) -> Option<Job> {
    for at in 0..BLOB_PREFIX_SEARCH.min(blob.len()) {
        let mut job = Job {
            offset: at,
            ..Default::default()
        };
        let Some(after) = read_job_header(blob, at + 16, &mut job) else {
            continue;
        };
        if job.job_type <= 2
            && job.priority <= 3
            && job.state <= 8
            && job.owner_sid.starts_with("S-1-")
        {
            job.dpapi_blobs = read_dpapi_blobs(blob, after);
            return Some(job);
        }
    }
    None
}

/// A `Files` blob: one file record located by shape in the blob's first 64
/// bytes — three path-like strings, the second a transfer source.
pub fn decode_file_blob(blob: &[u8]) -> Option<FileTransfer> {
    (0..BLOB_PREFIX_SEARCH.min(blob.len())).find_map(|at| {
        let (f, _) = read_file_record(blob, at)?;
        (crate::qmgr_dat::path_like(&f.local_path)
            && crate::qmgr_dat::url_like(&f.remote_url)
            && crate::qmgr_dat::path_like(&f.temp_path))
        .then_some(f)
    })
}

/// A table's `Id` and `Blob` columns, or `None` when it lacks either.
fn id_blob_columns(table: &Table) -> Option<(i32, i32)> {
    let cols = get_column_names(table).ok()?;
    let id = cols.iter().position(|c| c == "Id")? as i32;
    let blob = cols.iter().position(|c| c == "Blob")? as i32;
    Some((id, blob))
}

fn row_id(v: Option<Value>) -> Option<String> {
    match v? {
        Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b) if b.len() == 16 => {
            let g: [u8; 16] = b[..16].try_into().ok()?;
            Some(crate::qmgr_dat::guid_string(&g))
        }
        Value::Guid(b) if b.len() == 16 => {
            let g: [u8; 16] = b[..16].try_into().ok()?;
            Some(crate::qmgr_dat::guid_string(&g))
        }
        other => Some(format!("{other:?}")),
    }
}

fn blob_bytes(v: Option<Value>) -> Option<Vec<u8>> {
    match v? {
        Value::Binary(b) | Value::LargeBinary(b) | Value::SuperLarge(b) => Some(b),
        _ => None,
    }
}

/// Walk one `Id`/`Blob` table, handing each row's id and blob to `each`.
/// Returns the row count the walk reached.
fn walk(
    table: &Table,
    (id_col, blob_col): (i32, i32),
    status: &mut WalkStatus,
    mut each: impl FnMut(Option<String>, Option<Vec<u8>>),
) -> usize {
    let Ok(records) = table.iter_records() else {
        *status = WalkStatus::unreadable("records");
        return 0;
    };
    let mut rows = 0;
    for rec in records {
        let Ok(rec) = rec else {
            status.rows_skipped += 1;
            continue;
        };
        rows += 1;
        each(
            row_id(rec.value(id_col).ok()),
            blob_bytes(rec.value(blob_col).ok()),
        );
    }
    rows
}

/// Whether the database at `db_path` carries the BITS `Jobs` and `Files`
/// tables with `Id` and `Blob` columns. Lets a caller stage an ESE database
/// without buffering it, and read its bytes only when it is the queue.
pub fn has_queue_tables(db_path: &Path) -> Result<bool, String> {
    let db = EseDb::open(db_path).map_err(|e| format!("the ESE database would not open: {e}"))?;
    let (Ok(jobs), Ok(files)) = (db.table_by_name("Jobs"), db.table_by_name("Files")) else {
        return Ok(false);
    };
    Ok(id_blob_columns(&jobs).is_some() && id_blob_columns(&files).is_some())
}

/// Open `db_path` (whose bytes are `bytes`) and read it when it carries the
/// BITS `Jobs` and `Files` tables. `Ok(None)` for any other ESE database.
pub fn read_db(db_path: &Path, bytes: &[u8]) -> Result<Option<QueueDb>, String> {
    let db = EseDb::open(db_path).map_err(|e| format!("the ESE database would not open: {e}"))?;
    let (Ok(jobs), Ok(files)) = (db.table_by_name("Jobs"), db.table_by_name("Files")) else {
        return Ok(None);
    };
    let (Some(jcols), Some(fcols)) = (id_blob_columns(&jobs), id_blob_columns(&files)) else {
        return Ok(None);
    };
    let (db_state, page_size) = header_state(bytes);
    let mut out = QueueDb {
        db_state,
        page_size,
        ..Default::default()
    };

    let mut undecoded = 0usize;
    let mut decoded_jobs = Vec::new();
    out.jobs_rows = walk(&jobs, jcols, &mut out.jobs_walk, |id, blob| {
        match blob.as_deref().and_then(decode_job_blob) {
            Some(job) => decoded_jobs.push((id, job)),
            None => undecoded += 1,
        }
    });
    let mut decoded_files = Vec::new();
    out.files_rows = walk(&files, fcols, &mut out.files_walk, |id, blob| {
        match blob.as_deref().and_then(decode_file_blob) {
            Some(f) => decoded_files.push((id, f)),
            None => undecoded += 1,
        }
    });
    out.jobs = decoded_jobs;
    out.files = decoded_files;
    out.undecoded_blobs = undecoded;

    // The byte scan, less anything a row already gave.
    out.carved = carve_file_records(bytes, 0)
        .into_iter()
        .filter(|c| {
            !out.files.iter().any(|(_, f)| {
                f.local_path == c.local_path
                    && f.remote_url == c.remote_url
                    && f.temp_path == c.temp_path
            })
        })
        .collect();
    Ok(Some(out))
}
