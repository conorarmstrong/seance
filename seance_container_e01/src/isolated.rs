//! Process isolation for E01 parsing.
//!
//! libewf is a C library reached over FFI. A malformed/adversarial E01 can make
//! it segfault or corrupt memory, and a SIGSEGV is not catchable in-process
//! (the orchestrator's `catch_unwind` only covers Rust panics), so an in-process
//! crash takes down the whole server. Evidence is untrusted by definition.
//!
//! This module runs all libewf interaction in a dedicated child process (the
//! `seance-ewf-helper` binary). The child owns the libewf handle and serves
//! random reads over a pipe; if it crashes, the parent sees a broken pipe and
//! returns an I/O error instead of dying. [`IsolatedE01DataSource`] is the
//! parent-side client; [`run_helper`] is the child-side loop.
//!
//! Wire protocol (little-endian, framed):
//!   Handshake (child -> parent, once at startup):
//!     status: u8 (0 = ok, 1 = error)
//!     ok:    size: u64, meta_len: u32, meta_json: [u8; meta_len]
//!     error: msg_len: u32, msg: [u8; msg_len]
//!   Request (parent -> child): offset: u64, len: u32   (closing stdin = shutdown)
//!   Response (child -> parent):
//!     status: u8 (0 = ok, 1 = error)
//!     ok:    n: u32, bytes: [u8; n]
//!     error: msg_len: u32, msg: [u8; msg_len]
//!
//! Logical mode (`seance-ewf-helper --logical <path>`, for an `.L01`; HUNT-144):
//!   Handshake: as above, then the entry-tree walk —
//!     header_len: u32, header_json (the walk with no entries),
//!     count: u32, then count x (entry_len: u32, entry_json)
//!   Request (parent -> child): entry: u32 (position in the walk), offset: u64,
//!     len: u32
//!   Response: as above.

use std::io::{self, BufReader, Read, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::Mutex;

use seance_core::data_source::{CachingDataSource, DataSource};
use tracing::{info, warn};

/// Defensive cap on a single isolated read, so a bug can't make either side
/// allocate unbounded. Far above any real filesystem read unit.
const MAX_ISOLATED_READ: usize = 64 * 1024 * 1024;

// --- Child side ---------------------------------------------------------

/// Entry point for the `seance-ewf-helper` binary: open `path` with libewf and
/// serve read requests over stdio until the parent closes the pipe. Never
/// returns on the happy path except at EOF. All logging must go to stderr; this
/// process must not init a stdout tracing subscriber or the protocol corrupts.
pub fn run_helper(path: &str) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    // Open in THIS process (the isolated one). If libewf segfaults here, only
    // this child dies and the parent reports a failed open.
    let source = match crate::E01DataSource::open(path) {
        Ok(s) => s,
        Err(e) => {
            let _ = write_handshake_err(&mut out, &e.to_string());
            return;
        }
    };
    let size = source.size();
    let meta = source
        .get_metadata()
        .unwrap_or_else(|_| serde_json::json!({}));
    let meta_bytes = serde_json::to_vec(&meta).unwrap_or_else(|_| b"{}".to_vec());
    if write_handshake_ok(&mut out, size, &meta_bytes).is_err() {
        return;
    }

    let stdin = io::stdin();
    let mut inp = stdin.lock();
    loop {
        let (offset, len) = match read_request(&mut inp) {
            Ok(Some(req)) => req,
            Ok(None) => break, // parent closed stdin -> shutdown
            Err(_) => break,
        };
        let len = (len as usize).min(MAX_ISOLATED_READ);
        let mut buf = vec![0u8; len];
        match source.read_at(offset, &mut buf) {
            Ok(n) => {
                if write_response_ok(&mut out, &buf[..n]).is_err() {
                    break;
                }
            }
            Err(e) => {
                if write_response_err(&mut out, &e.to_string()).is_err() {
                    break;
                }
            }
        }
    }
}

/// Entry point for `seance-ewf-helper --logical <path>`: open a logical
/// evidence file (`.L01`) with libewf, walk its entry tree in THIS process,
/// send the walk, then serve entry reads until the parent closes the pipe
/// (HUNT-144). The wire format is in the module documentation.
pub fn run_logical_helper(path: &str) {
    let stdout = io::stdout();
    let mut out = stdout.lock();

    let source = match crate::E01DataSource::open(path) {
        Ok(s) => s,
        Err(e) => {
            let _ = write_handshake_err(&mut out, &e.to_string());
            return;
        }
    };
    let walk = match source.walk_logical(crate::logical::WalkLimits::default()) {
        Ok(w) => w,
        Err(e) => {
            let _ = write_handshake_err(&mut out, &e.to_string());
            return;
        }
    };
    let meta = source
        .get_metadata()
        .unwrap_or_else(|_| serde_json::json!({}));
    let meta_bytes = serde_json::to_vec(&meta).unwrap_or_else(|_| b"{}".to_vec());
    if write_handshake_ok(&mut out, source.size(), &meta_bytes).is_err()
        || write_logical_walk(&mut out, &walk).is_err()
    {
        return;
    }

    let stdin = io::stdin();
    let mut inp = stdin.lock();
    // A closed stdin (shutdown) or a malformed request ends the loop.
    while let Ok(Some((ordinal, offset, len))) = read_logical_request(&mut inp) {
        let len = (len as usize).min(MAX_ISOLATED_READ);
        let reply = match walk.entries.get(ordinal as usize) {
            None => write_response_err(
                &mut out,
                &format!("no entry {ordinal}: the walk holds {}", walk.entries.len()),
            ),
            Some(entry) => {
                let mut buf = vec![0u8; len];
                match source.read_logical_entry(&entry.index_path, offset, &mut buf) {
                    Ok(n) => write_response_ok(&mut out, &buf[..n.min(len)]),
                    Err(e) => write_response_err(&mut out, &e.to_string()),
                }
            }
        };
        if reply.is_err() {
            break;
        }
    }
}

/// The walk after the handshake: a length-prefixed JSON header (the walk with
/// no entries), a `u32` entry count, then one length-prefixed JSON frame per
/// entry. Streamed per entry so a large L01 never needs one frame the size of
/// its whole table.
fn write_logical_walk(out: &mut impl Write, walk: &crate::logical::LogicalWalk) -> io::Result<()> {
    let header = crate::logical::LogicalWalk {
        entries: Vec::new(),
        ..walk.clone()
    };
    write_frame(out, &serde_json::to_vec(&header).map_err(io::Error::other)?)?;
    out.write_all(&(walk.entries.len() as u32).to_le_bytes())?;
    for entry in &walk.entries {
        write_frame(out, &serde_json::to_vec(entry).map_err(io::Error::other)?)?;
    }
    out.flush()
}

fn write_frame(out: &mut impl Write, bytes: &[u8]) -> io::Result<()> {
    out.write_all(&(bytes.len() as u32).to_le_bytes())?;
    out.write_all(bytes)
}

fn read_logical_request(inp: &mut impl Read) -> io::Result<Option<(u32, u64, u32)>> {
    let mut ord = [0u8; 4];
    match inp.read_exact(&mut ord) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut off = [0u8; 8];
    inp.read_exact(&mut off)?;
    let mut len = [0u8; 4];
    inp.read_exact(&mut len)?;
    Ok(Some((
        u32::from_le_bytes(ord),
        u64::from_le_bytes(off),
        u32::from_le_bytes(len),
    )))
}

fn write_handshake_ok(out: &mut impl Write, size: u64, meta: &[u8]) -> io::Result<()> {
    out.write_all(&[0u8])?;
    out.write_all(&size.to_le_bytes())?;
    out.write_all(&(meta.len() as u32).to_le_bytes())?;
    out.write_all(meta)?;
    out.flush()
}

fn write_handshake_err(out: &mut impl Write, msg: &str) -> io::Result<()> {
    out.write_all(&[1u8])?;
    out.write_all(&(msg.len() as u32).to_le_bytes())?;
    out.write_all(msg.as_bytes())?;
    out.flush()
}

fn read_request(inp: &mut impl Read) -> io::Result<Option<(u64, u32)>> {
    let mut off = [0u8; 8];
    match inp.read_exact(&mut off) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let mut len = [0u8; 4];
    inp.read_exact(&mut len)?;
    Ok(Some((u64::from_le_bytes(off), u32::from_le_bytes(len))))
}

fn write_response_ok(out: &mut impl Write, data: &[u8]) -> io::Result<()> {
    out.write_all(&[0u8])?;
    out.write_all(&(data.len() as u32).to_le_bytes())?;
    out.write_all(data)?;
    out.flush()
}

fn write_response_err(out: &mut impl Write, msg: &str) -> io::Result<()> {
    out.write_all(&[1u8])?;
    out.write_all(&(msg.len() as u32).to_le_bytes())?;
    out.write_all(msg.as_bytes())?;
    out.flush()
}

// --- Parent side --------------------------------------------------------

#[derive(Debug)]
struct HelperIo {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// Parent-side client: a [`DataSource`] backed by a `seance-ewf-helper` child.
#[derive(Debug)]
pub struct IsolatedE01DataSource {
    // Kept for Drop (kill the child); never read.
    child: Mutex<Child>,
    io: Mutex<HelperIo>,
    size: u64,
    metadata: serde_json::Value,
    path: String,
    /// Set once the helper has broken the frame protocol. Every later read
    /// fails rather than decoding from the middle of a frame the child
    /// over-declared: bytes served from a desynchronised stream would be
    /// attributed to an offset they did not come from.
    desynchronised: std::sync::atomic::AtomicBool,
}

impl IsolatedE01DataSource {
    /// Spawn a helper for `path` and complete the handshake. `helper` is the
    /// path to the `seance-ewf-helper` binary.
    pub fn spawn(helper: &std::path::Path, path: &str) -> io::Result<Self> {
        let mut child = Command::new(helper)
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no child stdin"))?;
        let mut stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("no child stdout"))?,
        );

        // Read handshake. Decoded by the same function the fuzz target drives,
        // so what is proved there is what runs here.
        let (size, metadata) = match decode_handshake(&mut stdout) {
            Ok(v) => v,
            Err(e) => {
                // Reap the child so it doesn't linger.
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };

        Ok(Self {
            child: Mutex::new(child),
            io: Mutex::new(HelperIo { stdin, stdout }),
            size,
            metadata,
            path: path.to_string(),
            desynchronised: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// The decoded-media metadata (stored_md5/sha1, header values) the helper
    /// read at open time.
    pub fn get_metadata(&self) -> serde_json::Value {
        self.metadata.clone()
    }
}

fn read_len_prefixed(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb)?;
    let n = u32::from_le_bytes(lb) as usize;
    if n > MAX_ISOLATED_READ {
        return Err(io::Error::other("isolated frame too large"));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Decode a handshake frame from the helper.
///
/// # Why this is a trust boundary
///
/// The helper exists because libewf is a C library that a malformed E01 can
/// crash or corrupt. That isolation only holds if the parent treats everything
/// coming back across the pipe as hostile: a compromised child can say the
/// image is `u64::MAX` bytes, or declare a frame length it does not send, and
/// the parent must answer with an error rather than a panic or an allocation
/// sized by the attacker.
///
/// Split out from the spawn path so it can be tested and fuzzed without a live
/// child process. `fuzz_targets/e01_isolated_protocol.rs` drives it.
#[doc(hidden)]
pub fn decode_handshake(r: &mut impl Read) -> io::Result<(u64, serde_json::Value)> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status)?;
    if status[0] != 0 {
        let msg = read_len_prefixed(r)?;
        return Err(io::Error::other(format!(
            "E01 helper failed to open image: {}",
            String::from_utf8_lossy(&msg)
        )));
    }
    let mut size_buf = [0u8; 8];
    r.read_exact(&mut size_buf)?;
    let size = u64::from_le_bytes(size_buf);
    let meta_bytes = read_len_prefixed(r)?;
    // Malformed JSON is not fatal: the metadata is descriptive, and refusing to
    // open an otherwise-readable image over it would be the wrong trade.
    let metadata: serde_json::Value =
        serde_json::from_slice(&meta_bytes).unwrap_or_else(|_| serde_json::json!({}));
    Ok((size, metadata))
}

/// Decode a read-response frame into `buf`, returning how many bytes it filled.
///
/// A child declaring more bytes than were asked for has broken the protocol,
/// and the frame is refused rather than clamped to the buffer. Clamping stops
/// the overrun but leaves the surplus in the pipe, so every later frame on
/// that handle decodes from the middle of this one — bytes then reach a parser
/// under an offset they did not come from, which is worse than a failed read.
/// See [`decode_handshake`] for why the child is treated as hostile.
#[doc(hidden)]
pub fn decode_read_response(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status)?;
    if status[0] != 0 {
        let msg = read_len_prefixed(r)?;
        return Err(io::Error::other(format!(
            "E01 helper read error: {}",
            String::from_utf8_lossy(&msg)
        )));
    }
    let mut nb = [0u8; 4];
    r.read_exact(&mut nb)?;
    let declared = u32::from_le_bytes(nb) as usize;
    if declared > buf.len() {
        return Err(io::Error::other(format!(
            "E01 helper declared {declared} bytes for a {} byte request; the frame stream can no \
             longer be trusted",
            buf.len()
        )));
    }
    r.read_exact(&mut buf[..declared])?;
    Ok(declared)
}

/// The largest single entry frame the parent accepts. An entry is a name
/// (bounded at 64 KiB by the child), a handful of numbers and libewf's error
/// sentences; a frame bigger than this is not an entry.
const MAX_ENTRY_FRAME: usize = 1024 * 1024;

fn read_bounded_frame(r: &mut impl Read, cap: usize, what: &str) -> io::Result<Vec<u8>> {
    let mut lb = [0u8; 4];
    r.read_exact(&mut lb)?;
    let n = u32::from_le_bytes(lb) as usize;
    if n > cap {
        return Err(io::Error::other(format!(
            "isolated {what} frame of {n} bytes is over the {cap}-byte bound"
        )));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)?;
    Ok(buf)
}

/// Decode the entry-tree walk the logical helper sends after its handshake.
///
/// Same trust boundary as [`decode_handshake`]: the child is treated as
/// hostile. The declared entry count is held to the walk ceiling before
/// anything is allocated for it, every frame is bounded, and the tree's shape
/// is checked — every parent precedes its child and sits one level above it —
/// because the parent builds paths by following those links, and a link
/// pointing forward or out of range would otherwise be followed.
/// `fuzz_targets/e01_isolated_protocol.rs` drives it.
#[doc(hidden)]
pub fn decode_logical_walk(r: &mut impl Read) -> io::Result<crate::logical::LogicalWalk> {
    let header = read_bounded_frame(r, MAX_ENTRY_FRAME, "walk header")?;
    let mut walk: crate::logical::LogicalWalk = serde_json::from_slice(&header)
        .map_err(|e| io::Error::other(format!("walk header is not a walk: {e}")))?;
    if !walk.entries.is_empty() {
        return Err(io::Error::other("walk header carried entries of its own"));
    }
    let mut nb = [0u8; 4];
    r.read_exact(&mut nb)?;
    let count = u32::from_le_bytes(nb) as usize;
    if count > crate::logical::MAX_L01_ENTRIES {
        return Err(io::Error::other(format!(
            "helper declared {count} entries, over the {} ceiling",
            crate::logical::MAX_L01_ENTRIES
        )));
    }
    let mut entries = Vec::with_capacity(count.min(4096));
    for i in 0..count {
        let frame = read_bounded_frame(r, MAX_ENTRY_FRAME, "entry")?;
        let entry: crate::logical::LogicalEntry = serde_json::from_slice(&frame)
            .map_err(|e| io::Error::other(format!("entry frame {i} is not an entry: {e}")))?;
        let shape_ok = match entry.parent {
            None => i == 0 && entry.depth == 0 && entry.index_path.is_empty(),
            Some(p) => {
                let p = p as usize;
                p < i
                    && entries
                        .get(p)
                        .is_some_and(|pe: &crate::logical::LogicalEntry| {
                            pe.depth + 1 == entry.depth
                                && entry.index_path.len() == entry.depth as usize
                                && entry.index_path.starts_with(&pe.index_path)
                        })
            }
        };
        if !shape_ok {
            return Err(io::Error::other(format!(
                "entry frame {i} does not fit the tree before it (parent {:?}, depth {})",
                entry.parent, entry.depth
            )));
        }
        entries.push(entry);
    }
    if walk.root_present != !entries.is_empty() && !(walk.root_present && walk.entry_cap_reached) {
        return Err(io::Error::other(
            "walk header and entry count disagree about whether there is a root",
        ));
    }
    walk.entries = entries;
    Ok(walk)
}

/// Parent-side client for a `seance-ewf-helper --logical` child: serves the
/// bytes of the entries the child walked, by their position in that walk.
#[derive(Debug)]
pub struct IsolatedLogicalBackend {
    child: Mutex<Child>,
    io: Mutex<HelperIo>,
    desynchronised: std::sync::atomic::AtomicBool,
}

impl IsolatedLogicalBackend {
    /// Spawn the helper in logical mode and read its handshake and walk.
    pub fn spawn(
        helper: &std::path::Path,
        path: &str,
    ) -> io::Result<(Self, u64, serde_json::Value, crate::logical::LogicalWalk)> {
        let mut child = Command::new(helper)
            .arg("--logical")
            .arg(path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| io::Error::other("no child stdin"))?;
        let mut stdout = BufReader::new(
            child
                .stdout
                .take()
                .ok_or_else(|| io::Error::other("no child stdout"))?,
        );
        let decoded = decode_handshake(&mut stdout)
            .and_then(|(size, meta)| decode_logical_walk(&mut stdout).map(|w| (size, meta, w)));
        let (size, metadata, walk) = match decoded {
            Ok(v) => v,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(e);
            }
        };
        Ok((
            Self {
                child: Mutex::new(child),
                io: Mutex::new(HelperIo { stdin, stdout }),
                desynchronised: std::sync::atomic::AtomicBool::new(false),
            },
            size,
            metadata,
            walk,
        ))
    }
}

impl crate::logical::LogicalBackend for IsolatedLogicalBackend {
    fn read_entry(&self, ordinal: u32, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self
            .desynchronised
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(io::Error::other(
                "E01 logical helper broke the frame protocol on an earlier read; this logical \
                 evidence file is not being read further",
            ));
        }
        let want = buf.len().min(MAX_ISOLATED_READ);
        let mut io = self
            .io
            .lock()
            .map_err(|_| io::Error::other("E01 logical helper channel poisoned"))?;
        io.stdin.write_all(&ordinal.to_le_bytes())?;
        io.stdin.write_all(&offset.to_le_bytes())?;
        io.stdin.write_all(&(want as u32).to_le_bytes())?;
        io.stdin.flush()?;
        let out = decode_read_response(&mut io.stdout, &mut buf[..want]);
        if out.is_err() {
            self.desynchronised
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        out
    }

    fn isolated(&self) -> bool {
        true
    }
}

impl Drop for IsolatedLogicalBackend {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

impl DataSource for IsolatedE01DataSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self
            .desynchronised
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            return Err(io::Error::other(
                "E01 helper broke the frame protocol on an earlier read; this image is not being \
                 read further rather than served bytes from a desynchronised stream",
            ));
        }
        let want = buf.len().min(MAX_ISOLATED_READ);
        let mut io = self
            .io
            .lock()
            .map_err(|_| io::Error::other("E01 helper channel poisoned"))?;

        // Request.
        io.stdin.write_all(&offset.to_le_bytes())?;
        io.stdin.write_all(&(want as u32).to_le_bytes())?;
        io.stdin.flush()?;

        // Response. A broken pipe / EOF here means the helper died (e.g. libewf
        // segfaulted on this read) -- surfaced as an I/O error, not a crash.
        let out = decode_read_response(&mut io.stdout, &mut buf[..want]);
        if out.is_err() {
            // Whatever went wrong, the stream's framing is no longer known to
            // be in step. Nothing more is read from it.
            self.desynchronised
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        out
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        Some(PathBuf::from(&self.path))
    }
}

impl Drop for IsolatedE01DataSource {
    fn drop(&mut self) {
        if let Ok(mut child) = self.child.lock() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// --- Helper discovery + open factory ------------------------------------

/// Locate the `seance-ewf-helper` binary: explicit `SEANCE_EWF_HELPER`, else
/// alongside the current executable, else one directory up (covers
/// `target/<profile>/deps/<test-bin>` -> `target/<profile>/seance-ewf-helper`).
fn helper_path() -> Option<PathBuf> {
    let exe_name = if cfg!(windows) {
        "seance-ewf-helper.exe"
    } else {
        "seance-ewf-helper"
    };
    if let Ok(p) = std::env::var("SEANCE_EWF_HELPER") {
        let p = PathBuf::from(p);
        if p.is_file() {
            return Some(p);
        }
    }
    let exe = std::env::current_exe().ok()?;
    let dir = exe.parent()?;
    let candidate = dir.join(exe_name);
    if candidate.is_file() {
        return Some(candidate);
    }
    let up = dir.parent()?.join(exe_name);
    if up.is_file() {
        return Some(up);
    }
    None
}

/// True unless `SEANCE_E01_ISOLATED` is explicitly falsey.
fn isolation_enabled() -> bool {
    match std::env::var("SEANCE_E01_ISOLATED") {
        Ok(v) => !(v.eq_ignore_ascii_case("false") || v == "0"),
        Err(_) => true,
    }
}

/// An opened E01, decoupled from whether it is isolated or in-process.
pub struct OpenedE01 {
    pub source: std::sync::Arc<dyn DataSource>,
    pub size: u64,
    pub metadata: serde_json::Value,
    pub isolated: bool,
}

/// Open an E01, preferring an isolated helper subprocess so a libewf crash on
/// hostile input cannot take down the caller. Falls back to in-process parsing
/// (with a warning) only when isolation is disabled or the helper binary is not
/// found, so development and tests still work without the helper present.
pub fn open_e01(path: &str) -> anyhow::Result<OpenedE01> {
    if isolation_enabled() {
        match helper_path() {
            Some(helper) => match IsolatedE01DataSource::spawn(&helper, path) {
                Ok(src) => {
                    let size = src.size();
                    let metadata = src.get_metadata();
                    info!("E01 opened in isolated helper process ({} bytes)", size);
                    // Cache decoded chunks: every read here is a pipe round-trip
                    // to the helper, so a parser's small reads within one chunk
                    // must not each cross the process boundary.
                    let raw: std::sync::Arc<dyn DataSource> = std::sync::Arc::new(src);
                    return Ok(OpenedE01 {
                        source: std::sync::Arc::new(CachingDataSource::with_defaults(raw)),
                        size,
                        metadata,
                        isolated: true,
                    });
                }
                Err(e) => return Err(anyhow::anyhow!("isolated E01 open failed: {}", e)),
            },
            None => warn!(
                "E01 process isolation requested but seance-ewf-helper was not found; \
                 falling back to IN-PROCESS parsing. A malformed E01 can crash this process. \
                 Build/ship seance-ewf-helper or set SEANCE_EWF_HELPER."
            ),
        }
    }

    // In-process fallback.
    let src = crate::E01DataSource::open(path)?;
    let size = src.size();
    let metadata = src.get_metadata()?;
    // Cache decoded chunks: each libewf read re-decompresses the whole containing
    // EWF chunk, so small reads within a chunk must hit memory, not re-decode.
    let raw: std::sync::Arc<dyn DataSource> = std::sync::Arc::new(src);
    Ok(OpenedE01 {
        source: std::sync::Arc::new(CachingDataSource::with_defaults(raw)),
        size,
        metadata,
        isolated: false,
    })
}

/// An opened logical evidence file: its walked entry tree and a backend that
/// reads any walked entry's bytes, isolated or in process.
pub struct OpenedL01 {
    pub backend: std::sync::Arc<dyn crate::logical::LogicalBackend>,
    pub walk: crate::logical::LogicalWalk,
    /// libewf's media size for the L01 — the size of the stream EnCase packed
    /// the entries' data into, not of any device.
    pub media_size: u64,
    pub metadata: serde_json::Value,
    pub isolated: bool,
}

/// Open a logical evidence file and walk its entry tree, with the same
/// isolation default, helper discovery and in-process fallback as
/// [`open_e01`]: libewf parses the entry table in the helper unless isolation
/// is turned off or the helper binary cannot be found.
pub fn open_l01(path: &str) -> anyhow::Result<OpenedL01> {
    if isolation_enabled() {
        match helper_path() {
            Some(helper) => match IsolatedLogicalBackend::spawn(&helper, path) {
                Ok((backend, media_size, metadata, walk)) => {
                    info!(
                        "L01 opened in isolated helper process ({} entries)",
                        walk.entries.len()
                    );
                    return Ok(OpenedL01 {
                        backend: std::sync::Arc::new(backend),
                        walk,
                        media_size,
                        metadata,
                        isolated: true,
                    });
                }
                Err(e) => return Err(anyhow::anyhow!("isolated L01 open failed: {}", e)),
            },
            None => warn!(
                "E01 process isolation requested but seance-ewf-helper was not found; \
                 walking the logical evidence file IN-PROCESS. A malformed L01 can crash this \
                 process. Build/ship seance-ewf-helper or set SEANCE_EWF_HELPER."
            ),
        }
    }

    let src = crate::E01DataSource::open(path)?;
    let walk = src.walk_logical(crate::logical::WalkLimits::default())?;
    let media_size = src.size();
    let metadata = src.get_metadata()?;
    let backend = crate::logical::InProcessLogicalBackend::new(src, &walk);
    Ok(OpenedL01 {
        backend: std::sync::Arc::new(backend),
        walk,
        media_size,
        metadata,
        isolated: false,
    })
}

#[cfg(test)]
mod protocol_tests {
    use super::*;

    /// A child claiming a frame far larger than the cap must be refused before
    /// anything is allocated for it. The cap is the only thing standing between
    /// a compromised helper and a 4 GiB allocation chosen by whoever wrote the
    /// E01.
    #[test]
    fn a_frame_longer_than_the_cap_is_refused_not_allocated() {
        let mut frame = vec![1u8]; // status: error, so a message frame follows
        frame.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = decode_handshake(&mut frame.as_slice()).expect_err("must refuse");
        assert!(
            err.to_string().contains("too large"),
            "expected the size cap to reject it, got: {err}"
        );
    }

    /// A declared length the child does not then send must end as an I/O error.
    /// Trusting the declaration would read uninitialised or stale bytes.
    #[test]
    fn a_declared_length_longer_than_the_data_is_an_error() {
        let mut frame = vec![0u8]; // ok
        frame.extend_from_slice(&64u64.to_le_bytes()); // size
        frame.extend_from_slice(&1024u32.to_le_bytes()); // metadata length...
        frame.extend_from_slice(b"{}"); // ...but only two bytes follow
        assert!(decode_handshake(&mut frame.as_slice()).is_err());
    }

    /// **A child declaring more than was asked for is refused, not clamped.**
    ///
    /// Clamping to the caller's buffer stopped the overrun and left the
    /// surplus in the pipe, so the next frame decoded from the middle of this
    /// one: after a single over-declaration every later read returned bytes
    /// under an offset they did not come from. A failed read is recoverable;
    /// silently misattributed evidence is not.
    #[test]
    fn a_response_longer_than_the_buffer_is_refused_not_clamped() {
        let payload = vec![0xABu8; 4096];
        let mut frame = vec![0u8];
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);

        let mut buf = [0u8; 16];
        let err = decode_read_response(&mut frame.as_slice(), &mut buf)
            .expect_err("an over-declared frame must not decode");
        assert!(
            err.to_string().contains("4096"),
            "the error must name what was declared: {err}"
        );
        assert!(
            buf.iter().all(|b| *b == 0),
            "nothing may be written from a frame that was refused"
        );
    }

    /// A short response is the ordinary case at the end of an image and stays
    /// a success: fewer bytes than asked for, reported as fewer bytes.
    #[test]
    fn a_response_shorter_than_the_buffer_is_a_short_read_not_an_error() {
        let payload = vec![0x5Au8; 8];
        let mut frame = vec![0u8];
        frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        frame.extend_from_slice(&payload);

        let mut buf = [0u8; 32];
        let n = decode_read_response(&mut frame.as_slice(), &mut buf).expect("decode");
        assert_eq!(n, 8);
        assert!(buf[..8].iter().all(|b| *b == 0x5A));
        assert!(buf[8..].iter().all(|b| *b == 0));
    }

    /// Truncation anywhere in the frame is an error, never a partial success
    /// reported as a whole one.
    #[test]
    fn truncation_at_every_point_is_an_error_and_never_a_panic() {
        let payload = vec![7u8; 32];
        let mut whole = vec![0u8];
        whole.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        whole.extend_from_slice(&payload);

        for cut in 0..whole.len() {
            let mut buf = [0u8; 32];
            let r = decode_read_response(&mut &whole[..cut], &mut buf);
            assert!(
                r.is_err(),
                "a frame cut at {cut} of {} must not decode",
                whole.len()
            );
        }
        // The whole frame still works, so the loop above is not passing because
        // the decoder rejects everything.
        let mut buf = [0u8; 32];
        assert_eq!(
            decode_read_response(&mut whole.as_slice(), &mut buf).expect("whole frame"),
            32
        );
    }

    /// Metadata that is not JSON is descriptive, not structural: the image is
    /// still readable, so it must not fail the open.
    #[test]
    fn unparseable_metadata_does_not_fail_the_handshake() {
        let junk = b"\xff\xfe not json";
        let mut frame = vec![0u8];
        frame.extend_from_slice(&4096u64.to_le_bytes());
        frame.extend_from_slice(&(junk.len() as u32).to_le_bytes());
        frame.extend_from_slice(junk);

        let (size, meta) = decode_handshake(&mut frame.as_slice()).expect("must still open");
        assert_eq!(size, 4096);
        assert_eq!(meta, serde_json::json!({}));
    }
    fn sample_walk() -> crate::logical::LogicalWalk {
        let e = |index_path: Vec<u32>, parent: Option<u32>| crate::logical::LogicalEntry {
            depth: index_path.len() as u32,
            index_path,
            parent,
            facts: crate::logical::EntryFacts::default(),
            sub_entries: Some(0),
            sub_entries_not_walked: 0,
        };
        crate::logical::LogicalWalk {
            root_present: true,
            entries: vec![e(vec![], None), e(vec![0], Some(0)), e(vec![0, 0], Some(1))],
            limits: Some(crate::logical::WalkLimits::default()),
            ..crate::logical::LogicalWalk::default()
        }
    }

    fn encode(walk: &crate::logical::LogicalWalk) -> Vec<u8> {
        let mut out = Vec::new();
        write_logical_walk(&mut out, walk).unwrap();
        out
    }

    /// What the helper writes is what the parent reads back.
    #[test]
    fn a_logical_walk_round_trips_through_the_frame_protocol() {
        let walk = sample_walk();
        let decoded = decode_logical_walk(&mut encode(&walk).as_slice()).expect("decode");
        assert_eq!(decoded, walk);
    }

    /// A child declaring more entries than the walk ceiling is refused before
    /// anything is allocated for them.
    #[test]
    fn an_entry_count_over_the_ceiling_is_refused() {
        let mut header = crate::logical::LogicalWalk {
            entries: Vec::new(),
            ..sample_walk()
        };
        header.root_present = true;
        let mut frame = Vec::new();
        write_frame(&mut frame, &serde_json::to_vec(&header).unwrap()).unwrap();
        frame.extend_from_slice(&u32::MAX.to_le_bytes());
        let err = decode_logical_walk(&mut frame.as_slice()).expect_err("must refuse");
        assert!(err.to_string().contains("ceiling"), "{err}");
    }

    /// The parent builds paths by following parent links, so a link that
    /// points forward, at itself, or skips a level is refused rather than
    /// followed.
    #[test]
    fn an_entry_that_does_not_fit_the_tree_before_it_is_refused() {
        for bad in [Some(2u32), Some(1), None] {
            let mut walk = sample_walk();
            walk.entries[1].parent = bad;
            assert!(
                decode_logical_walk(&mut encode(&walk).as_slice()).is_err(),
                "parent {bad:?} for entry 1 must not decode"
            );
        }
        let mut walk = sample_walk();
        walk.entries[2].depth = 5;
        assert!(decode_logical_walk(&mut encode(&walk).as_slice()).is_err());
        let mut walk = sample_walk();
        walk.entries[2].index_path = vec![7, 0];
        assert!(decode_logical_walk(&mut encode(&walk).as_slice()).is_err());
    }

    /// Cut anywhere, a walk is an error and never a shorter walk passed off as
    /// the whole one.
    #[test]
    fn a_truncated_walk_is_an_error_at_every_cut() {
        let whole = encode(&sample_walk());
        for cut in 0..whole.len() {
            assert!(
                decode_logical_walk(&mut &whole[..cut]).is_err(),
                "a walk cut at {cut} of {} must not decode",
                whole.len()
            );
        }
    }
}
