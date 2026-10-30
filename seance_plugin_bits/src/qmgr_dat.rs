//! The binary BITS queue, `qmgr0.dat` / `qmgr1.dat` (Windows XP to 8.1,
//! Server 2003 to 2012 R2).
//!
//! # The layout, as measured
//!
//! Microsoft does not document this file. Everything below was read off the
//! bytes of real queues — NIST CFReDS Data Leakage (Windows 7) and DFIR
//! Madness case 001 DC01 (Server 2012 R2) — and nothing else:
//!
//! ```text
//! file GUID (16)  [8 bytes, Server 2012 R2 only]  header GUID H (16)
//!   queue GUID Q (16)  job count u32  job...  queue GUID Q (16)     (repeated; two seen)
//! header GUID H (16)  file GUID (16)                                 <- live structure ends
//! stale bytes: earlier states of the file
//! ```
//!
//! The file GUID differs by build (one value on Windows 7, another on Server
//! 2012 R2); H and Q were the same on both. A file is taken to be a queue when
//! H sits at offset 16 or 24 and Q follows it.
//!
//! A job opens and closes with the same 16-byte delimiter. Inside it:
//! `type u32, priority u32, state u32, u32, job GUID, name, description,
//! notify command, notify arguments, owner SID` (each string a u32 count of
//! UTF-16 units including the terminating NUL), `notify flags u32`, then a
//! stretch holding notification and security data that is not decoded, then
//! the file-list GUID F, a u32 file count and the files, then F again and the
//! job trailer, in which the job's FILETIMEs are located by shape.
//!
//! A file record is `local path, remote URL, temp path, u64 bytes
//! transferred, u64 bytes total` (all ones is BITS's "size unknown"), `u8, volume
//! root, volume GUID path, u32, u32 volume serial, u64, u32, 9 bytes, FILETIME,
//! 16 bytes, u32 n, n × 16 bytes`. Only the first five fields and the volume
//! root are reported; the tail is walked to reach the next record, and a tail
//! that does not lead to one stops the file walk with a stated reason.
//!
//! Credentials and custom headers are DPAPI blobs (provider GUID
//! `{DF9D8CD0-1501-11D1-8C7A-00C04FC297EB}`); their own description and
//! master-key GUID are read, their content never is.

/// GUID `{C82BF713-9940-4A12-9F1A-3AAEBD894EEA}` — the header GUID, seen on
/// Windows 7 and Server 2012 R2.
const HEADER_GUID: [u8; 16] = [
    0x13, 0xf7, 0x2b, 0xc8, 0x40, 0x99, 0x12, 0x4a, 0x9f, 0x1a, 0x3a, 0xae, 0xbd, 0x89, 0x4e, 0xea,
];
/// GUID `{005F4447-BDA9-44BA-9851-C47BB6C07ACE}` — opens and closes each queue.
const QUEUE_GUID: [u8; 16] = [
    0x47, 0x44, 0x5f, 0x00, 0xa9, 0xbd, 0xba, 0x44, 0x98, 0x51, 0xc4, 0x7b, 0xb6, 0xc0, 0x7a, 0xce,
];
/// GUID `{7756DA36-516F-435A-ACAC-44A248FFF34D}` — opens a job's file list and
/// its trailer.
const FILE_LIST_GUID: [u8; 16] = [
    0x36, 0xda, 0x56, 0x77, 0x6f, 0x51, 0x5a, 0x43, 0xac, 0xac, 0x44, 0xa2, 0x48, 0xff, 0xf3, 0x4d,
];
/// The DPAPI provider GUID `{DF9D8CD0-1501-11D1-8C7A-00C04FC297EB}`.
const DPAPI_PROVIDER: [u8; 16] = [
    0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15, 0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb,
];

/// Bounds on counts read from the file; a larger declared count is not trusted.
const MAX_JOBS: u32 = 100_000;
const MAX_FILES: u32 = 100_000;
const MAX_RANGES: u32 = 1_000_000;
/// A string longer than this many UTF-16 units is not taken as a string.
const MAX_STRING_UNITS: u32 = 32_768;

/// What reading one queue file found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QueueFile {
    /// The file GUID: the first 16 bytes, repeated as the live structure's
    /// last 16. Not the header GUID H, which follows it.
    pub file_guid: String,
    /// Where the header GUID H was found (16, or 24 on Server 2012 R2).
    pub header_guid_offset: usize,
    /// The queues the live structure holds, in file order.
    pub queues: Vec<Queue>,
    /// Byte offset one past the live structure's closing GUID; `None` when the
    /// structure could not be followed to its end.
    pub live_end: Option<usize>,
    /// File-transfer records found in bytes past the live structure.
    pub carved: Vec<CarvedFile>,
    /// Why the live structure could not be read to its end, when it could not.
    pub incomplete: Option<String>,
}

/// One queue: its declared job count and the jobs that decoded.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Queue {
    pub index: usize,
    pub offset: usize,
    pub declared_jobs: u32,
    pub jobs: Vec<Job>,
}

/// One BITS job.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Job {
    pub offset: usize,
    pub job_type: u32,
    pub priority: u32,
    pub state: u32,
    pub job_id: String,
    pub name: String,
    pub description: String,
    pub command: String,
    pub arguments: String,
    pub owner_sid: String,
    pub notify_flags: u32,
    pub declared_files: Option<u32>,
    pub files: Vec<FileTransfer>,
    pub times: Option<JobTimes>,
    pub dpapi_blobs: Vec<DpapiBlob>,
    /// Why part of this job could not be decoded, when part could not.
    pub incomplete: Option<String>,
}

/// One file of a job.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct FileTransfer {
    pub offset: usize,
    pub local_path: String,
    pub remote_url: String,
    pub temp_path: String,
    pub bytes_transferred: u64,
    /// `None` when the file holds BITS's "size unknown" value (all ones).
    pub bytes_total: Option<u64>,
    pub volume: Option<String>,
}

/// The job's times, located by shape in the job trailer.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct JobTimes {
    pub offset: usize,
    /// Raw FILETIMEs in trailer order; 0 is "unset".
    pub raw: [u64; 4],
}

/// A DPAPI-protected blob inside a job (credentials, custom headers).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DpapiBlob {
    pub offset: usize,
    pub description: String,
    pub master_key_guid: String,
}

/// A file-transfer record carved from bytes past the live structure.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CarvedFile {
    pub offset: usize,
    pub local_path: String,
    pub remote_url: String,
    pub temp_path: String,
    pub bytes_transferred: Option<u64>,
    pub bytes_total: Option<u64>,
    /// How many byte-identical copies of this record the region held.
    pub copies: usize,
}

/// A bounds-checked little-endian cursor.
struct Cur<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cur<'a> {
    fn new(b: &'a [u8], p: usize) -> Self {
        Self { b, p }
    }
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.p.checked_add(n)?;
        let s = self.b.get(self.p..end)?;
        self.p = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        self.take(1).map(|s| s[0])
    }
    fn u32(&mut self) -> Option<u32> {
        self.take(4)
            .map(|s| u32::from_le_bytes(s.try_into().expect("4 bytes")))
    }
    fn u64(&mut self) -> Option<u64> {
        self.take(8)
            .map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
    }
    fn guid(&mut self) -> Option<[u8; 16]> {
        self.take(16).map(|s| s.try_into().expect("16 bytes"))
    }
    /// A u32 count of UTF-16 units (NUL included) and the units.
    fn string(&mut self) -> Option<String> {
        let n = self.u32()?;
        if n > MAX_STRING_UNITS {
            return None;
        }
        let raw = self.take(n as usize * 2)?;
        let units: Vec<u16> = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect();
        let trimmed = match units.iter().position(|&u| u == 0) {
            Some(i) => &units[..i],
            None => &units[..],
        };
        Some(String::from_utf16_lossy(trimmed))
    }
}

/// Mixed-endian GUID text, `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
pub fn guid_string(g: &[u8; 16]) -> String {
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        u32::from_le_bytes([g[0], g[1], g[2], g[3]]),
        u16::from_le_bytes([g[4], g[5]]),
        u16::from_le_bytes([g[6], g[7]]),
        g[8],
        g[9],
        g[10],
        g[11],
        g[12],
        g[13],
        g[14],
        g[15]
    )
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|i| i + from)
}

/// Offset of the header GUID when the bytes open like a queue file.
fn header_at(bytes: &[u8]) -> Option<usize> {
    [16usize, 24].into_iter().find(|&at| {
        bytes.get(at..at + 16) == Some(&HEADER_GUID[..])
            && bytes.get(at + 16..at + 32) == Some(&QUEUE_GUID[..])
    })
}

/// Whether `bytes` opens like a BITS binary queue file.
pub fn looks_like_queue(bytes: &[u8]) -> bool {
    header_at(bytes).is_some()
}

/// A FILETIME that lands between 1995 and 2100.
fn plausible_filetime(v: u64) -> bool {
    (0x01BA_0000_0000_0000..0x0240_0000_0000_0000).contains(&v)
}

/// Read a queue file. `None` when it does not open like one.
pub fn parse(bytes: &[u8]) -> Option<QueueFile> {
    let h = header_at(bytes)?;
    let file_guid: [u8; 16] = bytes[..16].try_into().ok()?;
    let mut out = QueueFile {
        file_guid: guid_string(&file_guid),
        header_guid_offset: h,
        ..Default::default()
    };
    let mut p = h + 16;
    let mut index = 0usize;
    let mut stopped_at = None;
    while bytes.get(p..p + 16) == Some(&QUEUE_GUID[..]) {
        let offset = p;
        let mut c = Cur::new(bytes, p + 16);
        let Some(declared) = c.u32() else {
            out.incomplete = Some(format!("queue {index} at {offset:#x}: job count cut off"));
            stopped_at = Some(offset);
            break;
        };
        let mut queue = Queue {
            index,
            offset,
            declared_jobs: declared,
            jobs: Vec::new(),
        };
        if declared > MAX_JOBS || (declared as usize).saturating_mul(64) > bytes.len() {
            out.incomplete = Some(format!(
                "queue {index} at {offset:#x} declares {declared} jobs, more than the file can hold; \
                 none was read"
            ));
            out.queues.push(queue);
            stopped_at = Some(offset);
            break;
        }
        let mut q = c.p;
        let mut failed = None;
        for n in 0..declared {
            match parse_job(bytes, q) {
                Ok((job, next)) => {
                    queue.jobs.push(job);
                    q = next;
                }
                Err(why) => {
                    failed = Some(format!(
                        "queue {index}: job {} of {declared} at {q:#x} could not be read: {why}",
                        n + 1
                    ));
                    break;
                }
            }
        }
        out.queues.push(queue);
        if let Some(why) = failed {
            out.incomplete = Some(why);
            stopped_at = Some(q);
            break;
        }
        if bytes.get(q..q + 16) != Some(&QUEUE_GUID[..]) {
            out.incomplete = Some(format!(
                "queue {index}: the closing queue GUID is not at {q:#x} where its last job ends"
            ));
            stopped_at = Some(q);
            break;
        }
        p = q + 16;
        index += 1;
    }
    if out.incomplete.is_none() {
        if bytes.get(p..p + 16) == Some(&HEADER_GUID[..])
            && bytes.get(p + 16..p + 32) == Some(&file_guid[..])
        {
            out.live_end = Some(p + 32);
        } else {
            out.incomplete = Some(format!(
                "the closing header and file GUIDs are not at {p:#x}, where the last queue ends"
            ));
            stopped_at = Some(p);
        }
    }
    // Carve past the point the live walk reached, so nothing it read twice.
    let carve_from = out.live_end.or(stopped_at).unwrap_or(bytes.len());
    out.carved = carve_file_records(bytes, carve_from);
    Some(out)
}

/// The job header — type, priority, state, a u32, the job GUID, name,
/// description, notify command and arguments, owner SID, notify flags — read
/// from `at`. Returns the offset past it. Shared by the `.dat` walk and the
/// `qmgr.db` blob decoder, which carry the same header.
pub fn read_job_header(body: &[u8], at: usize, job: &mut Job) -> Option<usize> {
    let mut c = Cur::new(body, at);
    job.job_type = c.u32()?;
    job.priority = c.u32()?;
    job.state = c.u32()?;
    c.u32()?;
    job.job_id = guid_string(&c.guid()?);
    job.name = c.string()?;
    job.description = c.string()?;
    job.command = c.string()?;
    job.arguments = c.string()?;
    job.owner_sid = c.string()?;
    job.notify_flags = c.u32()?;
    Some(c.p)
}

/// Every DPAPI blob in `body` from `from`: the u32 version precedes the
/// provider GUID; the master-key GUID and description are read, nothing else.
pub fn read_dpapi_blobs(body: &[u8], from: usize) -> Vec<DpapiBlob> {
    let mut out = Vec::new();
    let mut s = from;
    while let Some(g) = find(body, &DPAPI_PROVIDER, s) {
        let mut b = Cur::new(body, g + 16);
        let parsed = (|| {
            b.u32()?;
            let mk = guid_string(&b.guid()?);
            b.u32()?;
            let len = b.u32()?;
            if len > 2 * MAX_STRING_UNITS || len % 2 != 0 {
                return None;
            }
            let raw = b.take(len as usize)?;
            let units: Vec<u16> = raw
                .as_chunks::<2>()
                .0
                .iter()
                .map(|x| u16::from_le_bytes(*x))
                .take_while(|&u| u != 0)
                .collect();
            Some((mk, String::from_utf16_lossy(&units)))
        })();
        if let Some((master_key_guid, description)) = parsed {
            out.push(DpapiBlob {
                offset: g.saturating_sub(4),
                description,
                master_key_guid,
            });
        }
        s = g + 16;
    }
    out
}

/// One whole file record at `at`, and the offset past it.
pub fn read_file_record(bytes: &[u8], at: usize) -> Option<(FileTransfer, usize)> {
    let mut c = Cur::new(bytes, at);
    let f = parse_file(&mut c)?;
    Some((FileTransfer { offset: at, ..f }, c.p))
}

/// One job starting at its opening delimiter; returns the offset past its
/// closing delimiter.
fn parse_job(bytes: &[u8], at: usize) -> Result<(Job, usize), String> {
    let delim: [u8; 16] = bytes
        .get(at..at + 16)
        .and_then(|s| s.try_into().ok())
        .ok_or("the file ends before the job delimiter")?;
    if delim == QUEUE_GUID || delim == HEADER_GUID || delim == [0u8; 16] {
        return Err(format!("no job delimiter at {at:#x}"));
    }
    let body_start = at + 16;
    let end = find(bytes, &delim, body_start).ok_or("the job's closing delimiter was not found")?;
    let body = &bytes[..end];
    let mut job = Job {
        offset: at,
        ..Default::default()
    };
    let Some(after_header) = read_job_header(body, body_start, &mut job) else {
        return Err("the job header did not decode".into());
    };
    job.dpapi_blobs = read_dpapi_blobs(body, after_header);

    // The file list.
    let Some(fl) = find(body, &FILE_LIST_GUID, after_header) else {
        job.incomplete = Some("the file-list GUID was not found; no file was read".into());
        return Ok((job, end + 16));
    };
    let mut c = Cur::new(body, fl + 16);
    let count = match c.u32() {
        Some(n) if n <= MAX_FILES => n,
        Some(n) => {
            job.incomplete = Some(format!("the job declares {n} files; none was read"));
            return Ok((job, end + 16));
        }
        None => {
            job.incomplete = Some("the file count is cut off".into());
            return Ok((job, end + 16));
        }
    };
    job.declared_files = Some(count);
    for n in 0..count {
        let start = c.p;
        match parse_file(&mut c) {
            Some(f) => job.files.push(FileTransfer { offset: start, ..f }),
            None => {
                job.incomplete = Some(format!(
                    "file {} of {count} at {start:#x} did not decode; it and any after it are absent",
                    n + 1
                ));
                break;
            }
        }
    }

    // The trailer, and the times in it.
    let trailer =
        if job.incomplete.is_none() && body.get(c.p..c.p + 16) == Some(&FILE_LIST_GUID[..]) {
            Some(c.p + 16)
        } else {
            find(body, &FILE_LIST_GUID, fl + 16).map(|t| t + 16)
        };
    match trailer.and_then(|t| locate_times(body, t)) {
        Some(times) => job.times = Some(times),
        None => {
            let why = "the job's times were not found in its trailer";
            job.incomplete = Some(match job.incomplete.take() {
                Some(prev) => format!("{prev}; {why}"),
                None => why.to_string(),
            });
        }
    }
    Ok((job, end + 16))
}

/// One file record, the cursor left at the next record.
fn parse_file(c: &mut Cur) -> Option<FileTransfer> {
    let local_path = c.string()?;
    let remote_url = c.string()?;
    let temp_path = c.string()?;
    let bytes_transferred = c.u64()?;
    let total = c.u64()?;
    c.u8()?;
    let volume = c.string()?;
    c.string()?; // volume GUID path
    c.u32()?;
    c.u32()?; // volume serial
    c.u64()?;
    c.u32()?;
    c.take(9)?;
    c.u64()?; // a FILETIME, not named
    c.take(16)?;
    let ranges = c.u32()?;
    if ranges > MAX_RANGES {
        return None;
    }
    c.take(ranges as usize * 16)?;
    Some(FileTransfer {
        offset: 0,
        local_path,
        remote_url,
        temp_path,
        bytes_transferred,
        bytes_total: (total != u64::MAX).then_some(total),
        volume: (!volume.is_empty()).then_some(volume),
    })
}

/// The first run, in the first 96 bytes of the trailer, of three plausible
/// FILETIMEs followed by a fourth that is plausible or zero.
fn locate_times(body: &[u8], trailer: usize) -> Option<JobTimes> {
    let read = |o: usize| {
        body.get(o..o + 8)
            .map(|s| u64::from_le_bytes(s.try_into().expect("8 bytes")))
    };
    for o in trailer..trailer + 96 {
        let (Some(a), Some(b), Some(c), Some(d)) =
            (read(o), read(o + 8), read(o + 16), read(o + 24))
        else {
            return None;
        };
        if plausible_filetime(a)
            && plausible_filetime(b)
            && plausible_filetime(c)
            && (d == 0 || plausible_filetime(d))
        {
            return Some(JobTimes {
                offset: o,
                raw: [a, b, c, d],
            });
        }
    }
    None
}

/// A path-like string: at least three characters, a backslash, and nothing
/// that is a control character, a replacement character or a noncharacter.
pub(crate) fn path_like(s: &str) -> bool {
    s.chars().count() >= 3
        && s.contains('\\')
        && s.chars()
            .all(|ch| !ch.is_control() && ch != '\u{FFFD}' && ch != '\u{FFFF}')
}

/// A transfer source BITS can name: HTTP(S), or a UNC share. A Win32 device
/// or volume path (`\\?\`, `\\.\`) is the volume field of a file record, not a
/// source, and is not taken as one.
pub(crate) fn url_like(s: &str) -> bool {
    let l = s.to_ascii_lowercase();
    if l.starts_with("\\\\?\\") || l.starts_with("\\\\.\\") {
        return false;
    }
    ["http://", "https://", "ftp://", "file://", "\\\\"]
        .iter()
        .any(|p| l.starts_with(p))
}

/// File records past `from`: three length-prefixed strings whose second is a
/// URL, then the two byte counts. Identical records are counted, not repeated.
pub fn carve_file_records(bytes: &[u8], from: usize) -> Vec<CarvedFile> {
    let mut out: Vec<CarvedFile> = Vec::new();
    let mut p = from;
    while p + 4 <= bytes.len() {
        // Cheap reject: a plausible count whose high bytes are zero.
        let n = u32::from_le_bytes(bytes[p..p + 4].try_into().expect("4 bytes"));
        if !(3..=MAX_STRING_UNITS).contains(&n) {
            p += 1;
            continue;
        }
        let mut c = Cur::new(bytes, p);
        let rec = (|| {
            let local = c.string()?;
            if !path_like(&local) || local.chars().count() + 1 != n as usize {
                return None;
            }
            let url = c.string()?;
            if !url_like(&url) {
                return None;
            }
            let temp = c.string()?;
            if !path_like(&temp) {
                return None;
            }
            let after_strings = c.p;
            let counts = (|| Some((c.u64()?, c.u64()?)))();
            Some((local, url, temp, counts, after_strings))
        })();
        match rec {
            Some((local_path, remote_url, temp_path, counts, after)) => {
                let (bytes_transferred, bytes_total) = match counts {
                    Some((t, total)) => (Some(t), (total != u64::MAX).then_some(total)),
                    None => (None, None),
                };
                if let Some(same) = out.iter_mut().find(|x| {
                    x.local_path == local_path
                        && x.remote_url == remote_url
                        && x.temp_path == temp_path
                        && x.bytes_transferred == bytes_transferred
                        && x.bytes_total == bytes_total
                }) {
                    same.copies += 1;
                } else {
                    out.push(CarvedFile {
                        offset: p,
                        local_path,
                        remote_url,
                        temp_path,
                        bytes_transferred,
                        bytes_total,
                        copies: 1,
                    });
                }
                p = after;
            }
            None => p += 1,
        }
    }
    out
}
