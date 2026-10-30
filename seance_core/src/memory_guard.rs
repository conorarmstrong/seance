//! A memory governor: the safety net under the ingest pipeline.
//!
//! # Why this exists
//!
//! An ingest whose footprint outgrows the host is not stopped by anything in
//! the pipeline: the kernel's OOM killer stops it, with `SIGKILL`, at a moment
//! of its choosing, and takes the desktop session, `sshd` or a virtual machine
//! down with it when it is slow about it. A process killed that way leaves no
//! record of why it stopped. The examination it was part of reads, afterwards,
//! as a run that simply never finished.
//!
//! This module does not reduce the footprint (the queue spills, `SEANCE_WORKERS`
//! bounds concurrency, and what a worker retains is the orchestrator's own
//! business). It watches the footprint against a **budget** and, when the
//! budget is about to be exceeded, degrades in steps that are all recoverable
//! and all recorded:
//!
//! | [`Pressure`] | Meaning | What the orchestrator does |
//! |---|---|---|
//! | `Ok` | Comfortably inside the budget. | Nothing. |
//! | `High` | Approaching it. | Runs **one** task at a time and shrinks the task queue's in-memory window so new work spills to disk at once. |
//! | `Critical` | About to exceed it. | Dispatches nothing new. If that does not bring it back within the grace period, **stops the run cleanly**. |
//!
//! Stopping cleanly is the point. The run is cancelled through the same path an
//! examiner's cancel takes: in-flight module runs finish, their batches are
//! flushed, queued work drains *unprocessed*, and every source still being
//! walked is stamped incomplete with a message that names the memory limit and
//! how to re-run. Nothing is dropped silently; the case says it is partial.
//!
//! # What it reads
//!
//! * **Process**: `RssAnon + RssShmem` from `/proc/self/status` — the memory the
//!   kernel cannot simply drop. The resident size of evidence pages mapped from
//!   a file is reclaimable on demand and is deliberately not counted; counting
//!   it would make a large image look like a leak. `/proc/self/statm` is the
//!   fallback, and its resident total is the peak RSS reported.
//! * **Host**: `MemAvailable` and `MemTotal` from `/proc/meminfo` (on a kernel without
//!   `MemAvailable`, `MemFree + Buffers + Cached` as an estimate).
//! * **cgroup**: `memory.max` and `memory.stat` (v2), or
//!   `memory.limit_in_bytes` and `memory.stat` (v1), for the tightest limit on
//!   this process's cgroup or any ancestor — which is where `systemd-run -p
//!   MemoryMax=` and a container's `--memory` put it.
//!
//! Outside Linux none of those files exist; the governor then reports that it
//! has nothing to read and stays out of the way (pressure is always `Ok`).
//!
//! # Configuration
//!
//! | Variable | Meaning |
//! |---|---|
//! | `SEANCE_MEMORY_LIMIT` | The budget: `12G`, `12GiB`, `8192M`, `80%` (of `MemAvailable` when the process starts), or `off`/`0` to disable. Default: the smaller of the cgroup limit and 75% of `MemTotal`. |
//! | `SEANCE_MEMORY_GRACE_SECS` | How long `Critical` may last, with nothing recovering, before the run is stopped. Default 30; a value that is not whole seconds is ignored with a warning. |
//! | `SEANCE_OOM_SCORE_ADJ` | Opt-in: raise this process's `oom_score_adj` (0 to 1000) so the kernel picks it before the desktop session. Never lowers it. |
//!
//! # A neighbour is not this process's fault
//!
//! The host-wide `MemAvailable` signal only counts when this process itself
//! holds at least [`MIN_OWN_FOOTPRINT`]. A small process must not fail a job
//! because something else on the machine is hogging memory: stopping it would
//! free nothing the kernel needs, and the job is lost for no gain.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tracing::{info, warn};

/// Below this footprint the host-wide availability signal is ignored; see the
/// module docs.
pub const MIN_OWN_FOOTPRINT: u64 = 1 << 30;

/// How long `Critical` may last, unrecovered, before the run is stopped.
pub const DEFAULT_GRACE: Duration = Duration::from_secs(30);

/// How often the monitor samples.
pub const POLL_INTERVAL: Duration = Duration::from_millis(250);

/// The share of the host's `MemTotal` used as the budget when nothing is set.
const DEFAULT_TOTAL_SHARE: f64 = 0.75;

/// How much of the tasks the queue may keep resident while pressure is `High`.
pub const HIGH_PRESSURE_QUEUE_WINDOW: usize = 64;

/// How full the system is, in three steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Pressure {
    Ok,
    High,
    Critical,
}

impl Pressure {
    fn to_u8(self) -> u8 {
        match self {
            Pressure::Ok => 0,
            Pressure::High => 1,
            Pressure::Critical => 2,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => Pressure::Ok,
            1 => Pressure::High,
            _ => Pressure::Critical,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Pressure::Ok => "ok",
            Pressure::High => "high",
            Pressure::Critical => "critical",
        }
    }
}

/// One reading of everything the governor looks at.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemorySample {
    /// Anonymous plus shared memory the process holds: what counts against the budget.
    pub process_anon: u64,
    /// Resident set size including file-backed pages, for the peak report.
    pub process_rss: u64,
    pub host_total: u64,
    pub host_available: u64,
    /// The tightest cgroup limit on this process's path, if any.
    pub cgroup_limit: Option<u64>,
    /// Anonymous memory charged to that same cgroup, if readable.
    pub cgroup_anon: Option<u64>,
}

/// Where samples come from. Injected in tests.
pub trait MemoryReader: Send + Sync {
    fn sample(&self) -> Option<MemorySample>;
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// What `SEANCE_MEMORY_LIMIT` asked for.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LimitSpec {
    /// An absolute number of bytes.
    Bytes(u64),
    /// A fraction (0 to 1) of `MemAvailable` when the process starts.
    PercentOfAvailable(f64),
    /// No governor.
    Off,
}

/// Parse `12G`, `12GiB`, `512M`, `1.5G`, `1048576` (bytes), `80%`, `off`, `0`.
/// `K`, `M`, `G`, `T` are binary multiples, with or without `i` and `B`.
pub fn parse_limit(spec: &str) -> Result<LimitSpec, String> {
    let s = spec.trim();
    if s.is_empty() {
        return Err("empty value".into());
    }
    let lower = s.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "off" | "none" | "unlimited" | "disabled" | "0"
    ) {
        return Ok(LimitSpec::Off);
    }
    if let Some(p) = lower.strip_suffix('%') {
        let pct: f64 = p
            .trim()
            .parse()
            .map_err(|_| format!("{spec:?} is not a percentage"))?;
        if !(pct > 0.0 && pct <= 100.0) {
            return Err(format!("{spec:?}: a percentage must be in (0, 100]"));
        }
        return Ok(LimitSpec::PercentOfAvailable(pct / 100.0));
    }
    let split = lower
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(lower.len());
    let (num, unit) = lower.split_at(split);
    let value: f64 = num
        .parse()
        .map_err(|_| format!("{spec:?} does not start with a number"))?;
    let unit = unit.trim();
    let multiplier: f64 = match unit {
        "" | "b" => 1.0,
        "k" | "kb" | "kib" => 1024.0,
        "m" | "mb" | "mib" => 1024.0 * 1024.0,
        "g" | "gb" | "gib" => 1024.0 * 1024.0 * 1024.0,
        "t" | "tb" | "tib" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        other => return Err(format!("{spec:?}: unknown unit {other:?}")),
    };
    let bytes = value * multiplier;
    if !bytes.is_finite() || bytes < 1.0 {
        return Err(format!("{spec:?} is not a positive size"));
    }
    Ok(LimitSpec::Bytes(bytes as u64))
}

/// The grace period from `SEANCE_MEMORY_GRACE_SECS`: whole seconds.
fn parse_grace(raw: &str) -> Result<Duration, String> {
    raw.trim()
        .parse::<u64>()
        .map(Duration::from_secs)
        .map_err(|_| format!("{raw:?} is not a whole number of seconds"))
}

fn kb_field(text: &str, key: &str) -> Option<u64> {
    text.lines().find_map(|line| {
        let rest = line.strip_prefix(key)?.strip_prefix(':')?;
        let n: u64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
        Some(n.saturating_mul(1024))
    })
}

/// `(MemTotal, MemAvailable)` in bytes from `/proc/meminfo` text.
pub fn parse_meminfo(text: &str) -> Option<(u64, u64)> {
    let total = kb_field(text, "MemTotal")?;
    // A kernel too old to report MemAvailable (before 3.14): MemFree alone
    // excludes the page cache, so it UNDER-reports what is available and would
    // read as host shortage, which can stop a healthy run. Estimate with
    // MemFree + Buffers + Cached instead; it is still an estimate, but it errs
    // in the same direction as MemAvailable rather than far below it.
    let available = match kb_field(text, "MemAvailable") {
        Some(n) => n,
        None => kb_field(text, "MemFree")?
            .saturating_add(kb_field(text, "Buffers").unwrap_or(0))
            .saturating_add(kb_field(text, "Cached").unwrap_or(0))
            .min(total),
    };
    Some((total, available))
}

/// `(anonymous + shared, nothing else)` from `/proc/self/status` text.
pub fn parse_status_anon(text: &str) -> Option<u64> {
    let anon = kb_field(text, "RssAnon")?;
    Some(anon + kb_field(text, "RssShmem").unwrap_or(0))
}

/// Resident bytes from `/proc/self/statm` text (second field, in pages).
pub fn parse_statm_resident(text: &str, page_size: u64) -> Option<u64> {
    let pages: u64 = text.split_whitespace().nth(1)?.parse().ok()?;
    Some(pages.saturating_mul(page_size))
}

/// A cgroup limit file: a number, or `max` (v2) / a value near `i64::MAX` (v1)
/// meaning no limit.
pub fn parse_cgroup_limit(text: &str) -> Option<u64> {
    let t = text.trim();
    if t == "max" {
        return None;
    }
    let n: u64 = t.parse().ok()?;
    // v1 reports "unlimited" as the page-rounded i64::MAX. Anything above 2^60
    // (an exbibyte) is not a limit anyone set.
    if n >= (1u64 << 60) {
        None
    } else {
        Some(n)
    }
}

/// `anon` (v2) or `total_rss` / `rss` (v1) from a `memory.stat` file.
pub fn parse_cgroup_stat_anon(text: &str) -> Option<u64> {
    let find = |key: &str| {
        text.lines().find_map(|l| {
            let mut it = l.split_whitespace();
            (it.next()? == key).then(|| it.next()?.parse::<u64>().ok())?
        })
    };
    find("anon")
        .or_else(|| find("total_rss"))
        .or_else(|| find("rss"))
}

/// This process's cgroup path: the `0::` line (v2), else the `memory`
/// controller's line (v1). `None` when neither is present.
pub fn parse_proc_cgroup(text: &str) -> Option<(CgroupVersion, String)> {
    let mut v1 = None;
    for line in text.lines() {
        let mut parts = line.splitn(3, ':');
        let (id, controllers, path) = (parts.next()?, parts.next()?, parts.next()?);
        if id == "0" && controllers.is_empty() {
            return Some((CgroupVersion::V2, path.to_string()));
        }
        if controllers.split(',').any(|c| c == "memory") {
            v1 = Some((CgroupVersion::V1, path.to_string()));
        }
    }
    v1
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CgroupVersion {
    V1,
    V2,
}

// ---------------------------------------------------------------------------
// The real reader
// ---------------------------------------------------------------------------

/// Reads `/proc` and the cgroup filesystem. The roots are fields so a test can
/// point them at a directory it built.
pub struct ProcReader {
    proc_root: PathBuf,
    cgroup_root: PathBuf,
    /// The kernel's page size, resolved on first use (see [`Self::page_size`]).
    page_size: std::sync::OnceLock<u64>,
}

impl Default for ProcReader {
    fn default() -> Self {
        Self::new("/proc", "/sys/fs/cgroup")
    }
}

impl ProcReader {
    pub fn new(proc_root: impl Into<PathBuf>, cgroup_root: impl Into<PathBuf>) -> Self {
        Self {
            proc_root: proc_root.into(),
            cgroup_root: cgroup_root.into(),
            page_size: std::sync::OnceLock::new(),
        }
    }

    /// The page size `statm` counts in, from `KernelPageSize` in the first
    /// mapping of `/proc/self/smaps`. Kernels on aarch64 run 16 KiB and 64 KiB
    /// pages, and reading their `statm` as 4096-byte pages under-reports the
    /// resident set so the governor acts late. Read once; only the head of the
    /// file is read, as the first mapping carries the field. 4096 where it
    /// cannot be read (CR-047).
    fn page_size(&self) -> u64 {
        *self.page_size.get_or_init(|| {
            use std::io::Read;
            let mut head = [0u8; 4096];
            let n = std::fs::File::open(self.proc_root.join("self/smaps"))
                .and_then(|mut f| f.read(&mut head))
                .unwrap_or(0);
            let text = String::from_utf8_lossy(&head[..n]);
            kb_field(&text, "KernelPageSize")
                .filter(|&b| b >= 4096 && b.is_power_of_two())
                .unwrap_or(4096)
        })
    }

    fn read(&self, path: &Path) -> Option<String> {
        std::fs::read_to_string(path).ok()
    }

    /// The tightest limit on this process's cgroup or an ancestor, with the
    /// anonymous usage of the cgroup that carries it.
    fn cgroup(&self) -> (Option<u64>, Option<u64>) {
        let Some(text) = self.read(&self.proc_root.join("self/cgroup")) else {
            return (None, None);
        };
        let Some((version, path)) = parse_proc_cgroup(&text) else {
            return (None, None);
        };
        let (base, limit_file) = match version {
            CgroupVersion::V2 => (self.cgroup_root.clone(), "memory.max"),
            CgroupVersion::V1 => (self.cgroup_root.join("memory"), "memory.limit_in_bytes"),
        };
        let mut dir = base.join(path.trim_start_matches('/'));
        let mut best: Option<(u64, PathBuf)> = None;
        loop {
            if let Some(limit) = self
                .read(&dir.join(limit_file))
                .and_then(|t| parse_cgroup_limit(&t))
            {
                if best.as_ref().is_none_or(|(b, _)| limit < *b) {
                    best = Some((limit, dir.clone()));
                }
            }
            if dir == base || !dir.starts_with(&base) {
                break;
            }
            match dir.parent() {
                Some(p) => dir = p.to_path_buf(),
                None => break,
            }
        }
        match best {
            Some((limit, dir)) => {
                let anon = self
                    .read(&dir.join("memory.stat"))
                    .and_then(|t| parse_cgroup_stat_anon(&t))
                    .or_else(|| {
                        self.read(&dir.join("memory.current"))
                            .and_then(|t| t.trim().parse().ok())
                    });
                (Some(limit), anon)
            }
            None => (None, None),
        }
    }
}

impl MemoryReader for ProcReader {
    fn sample(&self) -> Option<MemorySample> {
        let (host_total, host_available) =
            parse_meminfo(&self.read(&self.proc_root.join("meminfo"))?)?;
        let process_rss = self
            .read(&self.proc_root.join("self/statm"))
            .and_then(|t| parse_statm_resident(&t, self.page_size()))
            .unwrap_or(0);
        let process_anon = self
            .read(&self.proc_root.join("self/status"))
            .and_then(|t| parse_status_anon(&t))
            .unwrap_or(process_rss);
        let (cgroup_limit, cgroup_anon) = self.cgroup();
        Some(MemorySample {
            process_anon,
            process_rss,
            host_total,
            host_available,
            cgroup_limit,
            cgroup_anon,
        })
    }
}

// ---------------------------------------------------------------------------
// Budget and state machine
// ---------------------------------------------------------------------------

/// Turn the configured spec and a first reading into a budget in bytes.
/// `None` means the governor is off.
///
/// An explicit size is also capped at the cgroup limit: a budget larger than
/// the cgroup that contains the process would never be reached before the
/// kernel's own limit fires.
pub fn resolve_budget(spec: Option<LimitSpec>, first: &MemorySample) -> Option<u64> {
    let raw = match spec {
        Some(LimitSpec::Off) => return None,
        Some(LimitSpec::Bytes(b)) => b,
        Some(LimitSpec::PercentOfAvailable(f)) => (first.host_available as f64 * f) as u64,
        None => (first.host_total as f64 * DEFAULT_TOTAL_SHARE) as u64,
    };
    Some(match first.cgroup_limit {
        Some(c) => raw.min(c),
        None => raw,
    })
    .map(|b| b.max(1))
}

/// Ratios at which each level is entered; the exit set is lower, so a reading
/// that hovers at a boundary does not flap.
#[derive(Clone, Copy, Debug)]
struct Thresholds {
    /// Fraction of the budget.
    own: (f64, f64),
    /// Fraction of the cgroup limit.
    cgroup: (f64, f64),
    /// `MemAvailable / MemTotal` below which the host is short.
    host_avail: (f64, f64),
}

const ENTER: Thresholds = Thresholds {
    own: (0.85, 0.95),
    cgroup: (0.90, 0.97),
    host_avail: (0.06, 0.03),
};

const EXIT: Thresholds = Thresholds {
    own: (0.75, 0.90),
    cgroup: (0.80, 0.93),
    host_avail: (0.09, 0.045),
};

fn level_for(s: &MemorySample, budget: u64, t: &Thresholds) -> Pressure {
    let own = s.process_anon as f64 / budget.max(1) as f64;
    let cg = match (s.cgroup_anon, s.cgroup_limit) {
        (Some(a), Some(l)) if l > 0 => a as f64 / l as f64,
        _ => 0.0,
    };
    let host_short = if s.process_anon >= MIN_OWN_FOOTPRINT && s.host_total > 0 {
        s.host_available as f64 / s.host_total as f64
    } else {
        1.0
    };
    if own >= t.own.1 || cg >= t.cgroup.1 || host_short < t.host_avail.1 {
        Pressure::Critical
    } else if own >= t.own.0 || cg >= t.cgroup.0 || host_short < t.host_avail.0 {
        Pressure::High
    } else {
        Pressure::Ok
    }
}

/// What the state machine concluded from one sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Observation {
    pub pressure: Pressure,
    pub changed_from: Option<Pressure>,
    /// `Critical` has lasted past the grace period.
    pub stop: bool,
}

/// The pure state machine: samples in, pressure out. No clocks, no I/O; the
/// caller supplies `now`.
#[derive(Debug)]
pub struct Governor {
    budget: u64,
    grace: Duration,
    level: Pressure,
    critical_since: Option<Instant>,
}

impl Governor {
    pub fn new(budget: u64, grace: Duration) -> Self {
        Self {
            budget,
            grace,
            level: Pressure::Ok,
            critical_since: None,
        }
    }

    pub fn level(&self) -> Pressure {
        self.level
    }

    pub fn observe(&mut self, s: &MemorySample, now: Instant) -> Observation {
        self.observe_with(s, now, true)
    }

    /// As [`Self::observe`], where `busy` says whether there is work to stop.
    /// The grace clock runs only while busy: an idle process at `Critical` has
    /// no run to end, and a stop recorded against nothing would be reported
    /// against the next run that started.
    pub fn observe_with(&mut self, s: &MemorySample, now: Instant, busy: bool) -> Observation {
        let before = self.level;
        let up = level_for(s, self.budget, &ENTER);
        let down = level_for(s, self.budget, &EXIT);
        if up > self.level {
            self.level = up;
        } else if down < self.level {
            self.level = down;
        }
        if self.level == Pressure::Critical && busy {
            self.critical_since.get_or_insert(now);
        } else {
            self.critical_since = None;
        }
        let stop = self
            .critical_since
            .is_some_and(|t| now.saturating_duration_since(t) >= self.grace);
        Observation {
            pressure: self.level,
            changed_from: (before != self.level).then_some(before),
            stop,
        }
    }
}

// ---------------------------------------------------------------------------
// The shared handle
// ---------------------------------------------------------------------------

/// Why a run was stopped, kept until the orchestrator reports the run's end.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemoryStop {
    pub process_anon: u64,
    pub budget: u64,
    pub host_available: u64,
    pub peak_anon: u64,
}

impl MemoryStop {
    /// The sentence written onto every source the stop left incomplete.
    /// `tasks_done` is how many artifacts the run had processed.
    pub fn message(&self, tasks_done: usize) -> String {
        format!(
            "stopped: memory limit reached at {} (budget {}, host available {}), {} tasks done. \
             Processing of this source ended early so the process would not be killed by the \
             operating system; what its walk had not reached is absent from this case, not from \
             the evidence. Re-ingest the source with a higher SEANCE_MEMORY_LIMIT or fewer \
             SEANCE_WORKERS",
            human_bytes(self.process_anon),
            human_bytes(self.budget),
            human_bytes(self.host_available),
            tasks_done
        )
    }
}

/// Counters for the run summary log line.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GovernorStats {
    pub budget: u64,
    pub peak_anon: u64,
    pub peak_rss: u64,
    pub transitions: u64,
    pub high_ms: u64,
    pub critical_ms: u64,
    pub stops: u64,
}

struct Shared {
    budget: u64,
    level: AtomicU8,
    running: AtomicUsize,
    peak_anon: AtomicU64,
    peak_rss: AtomicU64,
    transitions: AtomicU64,
    high_ms: AtomicU64,
    critical_ms: AtomicU64,
    stops: AtomicU64,
    stop: Mutex<Option<MemoryStop>>,
    /// Set from a stop until the orchestrator consumes it; while set, workers
    /// are waved through so cancelled work drains instead of queueing behind a
    /// pause that nothing will lift.
    stopped: std::sync::atomic::AtomicBool,
}

/// The handle every worker and the monitor share. Cheap to clone.
#[derive(Clone)]
pub struct MemoryGuard {
    shared: Option<Arc<Shared>>,
    grace: Duration,
}

impl MemoryGuard {
    /// A guard that never pushes back. What the orchestrator holds when the
    /// limit is off or the host cannot be read.
    pub fn disabled() -> Self {
        Self {
            shared: None,
            grace: DEFAULT_GRACE,
        }
    }

    /// A guard with an explicit budget, for tests and for embedders.
    pub fn with_budget(budget: u64, grace: Duration) -> Self {
        Self {
            shared: Some(Arc::new(Shared {
                budget: budget.max(1),
                level: AtomicU8::new(0),
                running: AtomicUsize::new(0),
                peak_anon: AtomicU64::new(0),
                peak_rss: AtomicU64::new(0),
                transitions: AtomicU64::new(0),
                high_ms: AtomicU64::new(0),
                critical_ms: AtomicU64::new(0),
                stops: AtomicU64::new(0),
                stop: Mutex::new(None),
                stopped: std::sync::atomic::AtomicBool::new(false),
            })),
            grace,
        }
    }

    /// Configure from `SEANCE_MEMORY_LIMIT` and `SEANCE_MEMORY_GRACE_SECS`,
    /// reading the first sample from `reader`.
    pub fn from_env(reader: &dyn MemoryReader) -> Self {
        let spec = match std::env::var("SEANCE_MEMORY_LIMIT") {
            Ok(v) => match parse_limit(&v) {
                Ok(s) => Some(s),
                Err(e) => {
                    warn!(
                        "SEANCE_MEMORY_LIMIT ignored ({e}); using the default budget. \
                         Accepted: 12G, 8192M, 80%, off"
                    );
                    None
                }
            },
            Err(_) => None,
        };
        let grace = match std::env::var("SEANCE_MEMORY_GRACE_SECS") {
            Ok(v) => parse_grace(&v).unwrap_or_else(|e| {
                warn!(
                    "SEANCE_MEMORY_GRACE_SECS ignored ({e}); using the default of {} s. \
                     Accepted: whole seconds",
                    DEFAULT_GRACE.as_secs()
                );
                DEFAULT_GRACE
            }),
            Err(_) => DEFAULT_GRACE,
        };
        Self::configure(spec, grace, reader)
    }

    /// As [`Self::from_env`] with the configuration already parsed.
    pub fn configure(spec: Option<LimitSpec>, grace: Duration, reader: &dyn MemoryReader) -> Self {
        let Some(first) = reader.sample() else {
            info!("Memory governor inactive: host memory could not be read on this platform");
            return Self::disabled();
        };
        match resolve_budget(spec, &first) {
            None => {
                info!("Memory governor disabled by SEANCE_MEMORY_LIMIT");
                Self::disabled()
            }
            Some(budget) => {
                info!(
                    "Memory governor: budget {} (host total {}, available {}, cgroup limit {}); \
                     High at 85%, Critical at 95%, stop after {}s at Critical",
                    human_bytes(budget),
                    human_bytes(first.host_total),
                    human_bytes(first.host_available),
                    first
                        .cgroup_limit
                        .map_or_else(|| "none".to_string(), human_bytes),
                    grace.as_secs()
                );
                Self::with_budget(budget, grace)
            }
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.shared.is_some()
    }

    pub fn budget(&self) -> Option<u64> {
        self.shared.as_ref().map(|s| s.budget)
    }

    /// The current state. One atomic load.
    pub fn pressure(&self) -> Pressure {
        self.shared.as_ref().map_or(Pressure::Ok, |s| {
            Pressure::from_u8(s.level.load(Ordering::Relaxed))
        })
    }

    pub fn stats(&self) -> GovernorStats {
        match &self.shared {
            None => GovernorStats::default(),
            Some(s) => GovernorStats {
                budget: s.budget,
                peak_anon: s.peak_anon.load(Ordering::Relaxed),
                peak_rss: s.peak_rss.load(Ordering::Relaxed),
                transitions: s.transitions.load(Ordering::Relaxed),
                high_ms: s.high_ms.load(Ordering::Relaxed),
                critical_ms: s.critical_ms.load(Ordering::Relaxed),
                stops: s.stops.load(Ordering::Relaxed),
            },
        }
    }

    /// Whether a stop is waiting to be reported.
    pub fn is_stopped(&self) -> bool {
        self.shared
            .as_ref()
            .is_some_and(|s| s.stopped.load(Ordering::SeqCst))
    }

    /// Consume the pending stop, re-arming the guard for the next run. Called
    /// by the orchestrator when it reports the run that was stopped.
    pub fn take_stop(&self) -> Option<MemoryStop> {
        let s = self.shared.as_ref()?;
        let stop = s.stop.lock().unwrap_or_else(|e| e.into_inner()).take();
        s.stopped.store(false, Ordering::SeqCst);
        stop
    }

    /// Ask permission to begin one task. Returns when the governor allows it;
    /// the returned guard must be held for the task's duration.
    ///
    /// `Ok`: immediately. `High`: only if no other task is running (so the
    /// process keeps moving, one task at a time, and never wedges with every
    /// worker waiting on a condition only a running task could clear).
    /// `Critical`: waits, until pressure falls or the run is stopped.
    pub async fn admit(&self) -> Admission {
        let Some(s) = self.shared.clone() else {
            return Admission { shared: None };
        };
        let mut backoff = Duration::from_millis(20);
        loop {
            let level = Pressure::from_u8(s.level.load(Ordering::Relaxed));
            let stopped = s.stopped.load(Ordering::SeqCst);
            let go = match level {
                Pressure::Ok => {
                    s.running.fetch_add(1, Ordering::SeqCst);
                    true
                }
                Pressure::High => s
                    .running
                    .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok(),
                Pressure::Critical => {
                    if stopped {
                        s.running.fetch_add(1, Ordering::SeqCst);
                        true
                    } else {
                        false
                    }
                }
            };
            if go {
                return Admission { shared: Some(s) };
            }
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(Duration::from_secs(1));
        }
    }

    /// Feed one sample through `governor`, publish the result and report what
    /// the orchestrator must do. Split from [`Self::run_monitor`] so a test can
    /// drive it without a clock.
    pub fn apply(
        &self,
        governor: &mut Governor,
        sample: &MemorySample,
        now: Instant,
        elapsed: Duration,
        busy: bool,
    ) -> Observation {
        let obs = governor.observe_with(sample, now, busy);
        let Some(s) = &self.shared else { return obs };
        s.peak_anon
            .fetch_max(sample.process_anon, Ordering::Relaxed);
        s.peak_rss.fetch_max(sample.process_rss, Ordering::Relaxed);
        s.level.store(obs.pressure.to_u8(), Ordering::Relaxed);
        match obs.pressure {
            Pressure::High => {
                s.high_ms
                    .fetch_add(elapsed.as_millis() as u64, Ordering::Relaxed);
            }
            Pressure::Critical => {
                s.critical_ms
                    .fetch_add(elapsed.as_millis() as u64, Ordering::Relaxed);
            }
            Pressure::Ok => {}
        }
        if let Some(from) = obs.changed_from {
            s.transitions.fetch_add(1, Ordering::Relaxed);
            let line = format!(
                "memory pressure {} -> {}: process {} of {} budget, host available {}",
                from.as_str(),
                obs.pressure.as_str(),
                human_bytes(sample.process_anon),
                human_bytes(s.budget),
                human_bytes(sample.host_available)
            );
            if obs.pressure > from {
                warn!("{line}");
            } else {
                info!("{line}");
            }
        }
        if obs.stop && !s.stopped.load(Ordering::SeqCst) {
            s.stops.fetch_add(1, Ordering::Relaxed);
            *s.stop.lock().unwrap_or_else(|e| e.into_inner()) = Some(MemoryStop {
                process_anon: sample.process_anon,
                budget: s.budget,
                host_available: sample.host_available,
                peak_anon: s.peak_anon.load(Ordering::Relaxed),
            });
            s.stopped.store(true, Ordering::SeqCst);
            warn!(
                "memory limit reached ({} in use, budget {}) and not recovering after {}s: \
                 stopping the run cleanly rather than waiting for the operating system to kill \
                 the process",
                human_bytes(sample.process_anon),
                human_bytes(s.budget),
                self.grace.as_secs()
            );
        }
        obs
    }

    /// Sample forever, publishing pressure. `on_change` is called with every
    /// observation that changed the level, and `on_stop` once per stop.
    /// Returns immediately when the guard is disabled.
    pub async fn run_monitor(
        self,
        reader: Arc<dyn MemoryReader>,
        is_busy: impl Fn() -> bool + Send + 'static,
        on_change: impl Fn(Pressure) + Send + 'static,
        on_stop: impl Fn(&MemoryStop) + Send + 'static,
    ) {
        let Some(budget) = self.budget() else { return };
        let mut governor = Governor::new(budget, self.grace);
        let mut last = Instant::now();
        let mut ticker = tokio::time::interval(POLL_INTERVAL);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let now = Instant::now();
            let Some(sample) = reader.sample() else {
                continue;
            };
            let was_stopped = self.is_stopped();
            let obs = self.apply(
                &mut governor,
                &sample,
                now,
                now.duration_since(last),
                is_busy(),
            );
            last = now;
            if obs.changed_from.is_some() {
                on_change(obs.pressure);
            }
            if !was_stopped && self.is_stopped() {
                let stop = self
                    .shared
                    .as_ref()
                    .and_then(|s| s.stop.lock().unwrap_or_else(|e| e.into_inner()).clone());
                if let Some(stop) = stop {
                    on_stop(&stop);
                }
            }
        }
    }
}

/// Held while a task runs; dropping it lets the next one in.
pub struct Admission {
    shared: Option<Arc<Shared>>,
}

impl Drop for Admission {
    fn drop(&mut self) {
        if let Some(s) = &self.shared {
            s.running.fetch_sub(1, Ordering::SeqCst);
        }
    }
}

/// Opt-in self-protection: raise `oom_score_adj` to `SEANCE_OOM_SCORE_ADJ` so
/// the kernel picks this process before the desktop session or `sshd`. Only
/// ever raises: a value at or below the current one is left alone, because
/// lowering needs a privilege this process should not have. Returns what was
/// written, if anything.
pub fn apply_oom_score_adj_from_env() -> Option<i32> {
    let wanted: i32 = std::env::var("SEANCE_OOM_SCORE_ADJ")
        .ok()?
        .trim()
        .parse()
        .map_err(|_| warn!("SEANCE_OOM_SCORE_ADJ ignored: not an integer in 0..=1000"))
        .ok()?;
    apply_oom_score_adj(Path::new("/proc/self/oom_score_adj"), wanted)
}

/// [`apply_oom_score_adj_from_env`] against an explicit file.
pub fn apply_oom_score_adj(path: &Path, wanted: i32) -> Option<i32> {
    if !(0..=1000).contains(&wanted) {
        warn!("SEANCE_OOM_SCORE_ADJ {wanted} ignored: must be in 0..=1000");
        return None;
    }
    let current: i32 = std::fs::read_to_string(path)
        .ok()
        .and_then(|t| t.trim().parse().ok())?;
    if wanted <= current {
        return None;
    }
    match std::fs::write(path, wanted.to_string()) {
        Ok(()) => {
            info!("oom_score_adj raised from {current} to {wanted}: the kernel will pick this process first");
            Some(wanted)
        }
        Err(e) => {
            warn!("could not raise oom_score_adj to {wanted}: {e}");
            None
        }
    }
}

/// `12.3 GiB`-style rendering for log lines and messages.
pub fn human_bytes(b: u64) -> String {
    const GIB: f64 = 1024.0 * 1024.0 * 1024.0;
    const MIB: f64 = 1024.0 * 1024.0;
    if b as f64 >= GIB {
        format!("{:.1} GiB", b as f64 / GIB)
    } else {
        format!("{:.0} MiB", b as f64 / MIB)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;

    fn sample(anon: u64) -> MemorySample {
        MemorySample {
            process_anon: anon,
            process_rss: anon,
            host_total: 32 * GIB,
            host_available: 20 * GIB,
            cgroup_limit: None,
            cgroup_anon: None,
        }
    }

    #[test]
    fn limits_parse_in_every_documented_form() {
        assert_eq!(parse_limit("12G").unwrap(), LimitSpec::Bytes(12 * GIB));
        assert_eq!(parse_limit("12GiB").unwrap(), LimitSpec::Bytes(12 * GIB));
        assert_eq!(parse_limit(" 8192m ").unwrap(), LimitSpec::Bytes(8 * GIB));
        assert_eq!(
            parse_limit("1.5G").unwrap(),
            LimitSpec::Bytes(GIB + GIB / 2)
        );
        assert_eq!(parse_limit("4096").unwrap(), LimitSpec::Bytes(4096));
        assert_eq!(
            parse_limit("80%").unwrap(),
            LimitSpec::PercentOfAvailable(0.8)
        );
        for off in ["off", "OFF", "0", "none"] {
            assert_eq!(parse_limit(off).unwrap(), LimitSpec::Off, "{off}");
        }
    }

    #[test]
    fn nonsense_limits_are_refused_not_guessed() {
        for bad in ["", "abc", "12X", "0%", "150%", "-5G", "G"] {
            assert!(parse_limit(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn meminfo_is_read_in_bytes() {
        let text = concat!(
            "MemTotal: 32000000 kB\n",
            "MemFree: 100000 kB\n",
            "MemAvailable: 20000000 kB\n",
            "Buffers: 5 kB\n",
        );
        assert_eq!(
            parse_meminfo(text),
            Some((32_000_000 * 1024, 20_000_000 * 1024))
        );
        assert_eq!(parse_meminfo("nothing here"), None);
    }

    #[test]
    fn without_memavailable_the_page_cache_is_counted_not_ignored() {
        let text = "MemTotal: 1000 kB\nMemFree: 100 kB\nBuffers: 50 kB\nCached: 450 kB\n";
        assert_eq!(parse_meminfo(text), Some((1000 * 1024, 600 * 1024)));
        // An estimate never exceeds the total.
        let text = "MemTotal: 100 kB\nMemFree: 100 kB\nCached: 100 kB\n";
        assert_eq!(parse_meminfo(text), Some((100 * 1024, 100 * 1024)));
    }

    #[test]
    fn the_grace_period_is_whole_seconds_and_anything_else_is_refused() {
        assert_eq!(parse_grace("30"), Ok(Duration::from_secs(30)));
        assert_eq!(parse_grace(" 5 "), Ok(Duration::from_secs(5)));
        for bad in ["5m", "", "-1"] {
            assert!(parse_grace(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn process_memory_counts_anonymous_and_shared_not_file_pages() {
        let status = "Name:\tseance\nVmRSS:\t 9000000 kB\nRssAnon:\t 1000 kB\n\
                      RssFile:\t 8000000 kB\nRssShmem:\t 24 kB\n";
        assert_eq!(parse_status_anon(status), Some(1024 * 1024));
        assert_eq!(
            parse_statm_resident("100 25 3 1 0 9 0", 4096),
            Some(25 * 4096)
        );
    }

    #[test]
    fn cgroup_limit_files_distinguish_a_limit_from_unlimited() {
        assert_eq!(parse_cgroup_limit("8589934592\n"), Some(8 * GIB));
        assert_eq!(parse_cgroup_limit("max\n"), None);
        // cgroup v1's "no limit".
        assert_eq!(parse_cgroup_limit("9223372036854771712"), None);
        assert_eq!(parse_cgroup_limit("garbage"), None);
    }

    #[test]
    fn cgroup_stat_reads_v2_anon_and_v1_rss() {
        assert_eq!(
            parse_cgroup_stat_anon("anon 123\nfile 456\nkernel 7\n"),
            Some(123)
        );
        assert_eq!(
            parse_cgroup_stat_anon("cache 5\nrss 99\ntotal_rss 77\n"),
            Some(77)
        );
        assert_eq!(parse_cgroup_stat_anon("file 1\n"), None);
    }

    #[test]
    fn proc_cgroup_finds_v2_and_v1_paths() {
        assert_eq!(
            parse_proc_cgroup("0::/user.slice/run-x.scope\n"),
            Some((CgroupVersion::V2, "/user.slice/run-x.scope".into()))
        );
        assert_eq!(
            parse_proc_cgroup("12:cpu,cpuacct:/a\n4:memory:/docker/abc\n"),
            Some((CgroupVersion::V1, "/docker/abc".into()))
        );
        assert_eq!(parse_proc_cgroup("5:cpu:/a\n"), None);
    }

    /// Build a fake /proc and /sys/fs/cgroup and read them back through the
    /// real reader.
    #[test]
    fn the_reader_takes_the_tightest_ancestor_limit_on_cgroup_v2() {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path().join("proc");
        let cg = dir.path().join("cg");
        std::fs::create_dir_all(proc.join("self")).unwrap();
        std::fs::write(
            proc.join("meminfo"),
            "MemTotal: 1000 kB\nMemAvailable: 500 kB\n",
        )
        .unwrap();
        std::fs::write(proc.join("self/statm"), "10 5 0 0 0 0 0").unwrap();
        std::fs::write(
            proc.join("self/status"),
            "RssAnon:\t 4 kB\nRssShmem:\t 0 kB\n",
        )
        .unwrap();
        std::fs::write(proc.join("self/cgroup"), "0::/a/b/leaf\n").unwrap();
        let leaf = cg.join("a/b/leaf");
        std::fs::create_dir_all(&leaf).unwrap();
        std::fs::write(leaf.join("memory.max"), "max\n").unwrap();
        // The parent carries the real limit, as a systemd-run scope's slice does.
        std::fs::write(cg.join("a/b/memory.max"), "1048576\n").unwrap();
        std::fs::write(cg.join("a/b/memory.stat"), "anon 2048\n").unwrap();
        std::fs::write(cg.join("a/memory.max"), "9999999\n").unwrap();

        let s = ProcReader::new(&proc, &cg).sample().unwrap();
        assert_eq!(s.host_total, 1000 * 1024);
        assert_eq!(s.host_available, 500 * 1024);
        assert_eq!(s.process_rss, 5 * 4096);
        assert_eq!(s.process_anon, 4 * 1024);
        assert_eq!(s.cgroup_limit, Some(1_048_576));
        assert_eq!(s.cgroup_anon, Some(2048));
    }

    /// CR-047. SYNTHETIC fake /proc: a 64 KiB-page kernel (aarch64). `statm`
    /// counts pages, so reading it with a fixed 4096 under-reports the
    /// process's resident memory sixteen-fold and the governor acts late.
    fn fake_proc_with_statm(smaps: Option<&str>) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let proc = dir.path().join("proc");
        std::fs::create_dir_all(proc.join("self")).unwrap();
        std::fs::write(
            proc.join("meminfo"),
            "MemTotal: 1000 kB\nMemAvailable: 500 kB\n",
        )
        .unwrap();
        std::fs::write(proc.join("self/statm"), "10 5 0 0 0 0 0").unwrap();
        if let Some(text) = smaps {
            std::fs::write(proc.join("self/smaps"), text).unwrap();
        }
        (dir, proc)
    }

    #[test]
    fn resident_bytes_use_the_kernels_page_size_not_a_fixed_4096() {
        // The smaps field names are space-padded by the kernel; each padded line is allowed.
        let smaps = concat!(
            "00400000-00401000 r-xp 00000000 08:01 1 /bin/x\n",
            "Size:                 64 kB\n", // forensic-lint: allow RAGGED-STRING
            "KernelPageSize:       64 kB\n", // forensic-lint: allow RAGGED-STRING
            "MMUPageSize:          64 kB\n", // forensic-lint: allow RAGGED-STRING
        );
        let (dir, proc) = fake_proc_with_statm(Some(smaps));
        let s = ProcReader::new(&proc, dir.path()).sample().unwrap();
        assert_eq!(s.process_rss, 5 * 65536);
    }

    #[test]
    fn resident_bytes_fall_back_to_4096_pages_where_smaps_is_unreadable() {
        let (dir, proc) = fake_proc_with_statm(None);
        let s = ProcReader::new(&proc, dir.path()).sample().unwrap();
        assert_eq!(s.process_rss, 5 * 4096);
        let (dir, proc) = fake_proc_with_statm(Some("not an smaps file\n"));
        let s = ProcReader::new(&proc, dir.path()).sample().unwrap();
        assert_eq!(s.process_rss, 5 * 4096);
    }

    #[test]
    fn the_reader_reports_nothing_where_proc_is_absent() {
        let dir = tempfile::tempdir().unwrap();
        assert!(ProcReader::new(dir.path(), dir.path()).sample().is_none());
    }

    #[test]
    fn default_budget_is_the_smaller_of_cgroup_and_three_quarters_of_ram() {
        let mut s = sample(0);
        assert_eq!(resolve_budget(None, &s), Some(24 * GIB));
        s.cgroup_limit = Some(8 * GIB);
        assert_eq!(resolve_budget(None, &s), Some(8 * GIB));
        // An explicit size cannot exceed the cgroup that contains it.
        assert_eq!(
            resolve_budget(Some(LimitSpec::Bytes(12 * GIB)), &s),
            Some(8 * GIB)
        );
        s.cgroup_limit = None;
        assert_eq!(
            resolve_budget(Some(LimitSpec::PercentOfAvailable(0.5)), &s),
            Some(10 * GIB)
        );
        assert_eq!(resolve_budget(Some(LimitSpec::Off), &s), None);
    }

    #[test]
    fn pressure_climbs_with_the_footprint_and_falls_with_hysteresis() {
        let mut g = Governor::new(10 * GIB, Duration::from_secs(30));
        let t = Instant::now();
        assert_eq!(g.observe(&sample(5 * GIB), t).pressure, Pressure::Ok);
        let o = g.observe(&sample(9 * GIB), t);
        assert_eq!(o.pressure, Pressure::High);
        assert_eq!(o.changed_from, Some(Pressure::Ok));
        assert_eq!(g.observe(&sample(10 * GIB), t).pressure, Pressure::Critical);
        // 9.2 GiB is below Critical's entry but above its exit: still Critical.
        assert_eq!(
            g.observe(&sample(9 * GIB + GIB / 5), t).pressure,
            Pressure::Critical
        );
        assert_eq!(g.observe(&sample(8 * GIB), t).pressure, Pressure::High);
        // 7.6 GiB: under High's entry (8.5) but over its exit (7.5): holds.
        assert_eq!(
            g.observe(&sample(7 * GIB + GIB * 6 / 10), t).pressure,
            Pressure::High
        );
        assert_eq!(g.observe(&sample(6 * GIB), t).pressure, Pressure::Ok);
    }

    #[test]
    fn a_cgroup_nearly_full_of_anon_memory_is_pressure_even_when_the_budget_is_not() {
        let mut g = Governor::new(100 * GIB, DEFAULT_GRACE);
        let mut s = sample(GIB);
        s.cgroup_limit = Some(10 * GIB);
        s.cgroup_anon = Some(9 * GIB + GIB / 5);
        assert_eq!(g.observe(&s, Instant::now()).pressure, Pressure::High);
        s.cgroup_anon = Some(9 * GIB + GIB * 8 / 10);
        assert_eq!(g.observe(&s, Instant::now()).pressure, Pressure::Critical);
    }

    #[test]
    fn a_neighbours_appetite_does_not_count_against_a_small_process() {
        let mut g = Governor::new(100 * GIB, DEFAULT_GRACE);
        let mut s = sample(200 * 1024 * 1024);
        s.host_available = GIB / 4; // the host is nearly out of memory
        assert_eq!(g.observe(&s, Instant::now()).pressure, Pressure::Ok);
        // The same shortage with a big footprint is this process's to answer.
        s.process_anon = 4 * GIB;
        assert_eq!(g.observe(&s, Instant::now()).pressure, Pressure::Critical);
    }

    #[test]
    fn critical_stops_the_run_only_after_the_grace_period_and_only_if_it_lasts() {
        let mut g = Governor::new(10 * GIB, Duration::from_secs(30));
        let t0 = Instant::now();
        let crit = sample(10 * GIB);
        assert!(!g.observe(&crit, t0).stop);
        assert!(!g.observe(&crit, t0 + Duration::from_secs(29)).stop);
        assert!(g.observe(&crit, t0 + Duration::from_secs(30)).stop);

        // Recovering resets the clock.
        let mut g = Governor::new(10 * GIB, Duration::from_secs(30));
        g.observe(&crit, t0);
        g.observe(&sample(GIB), t0 + Duration::from_secs(20));
        g.observe(&crit, t0 + Duration::from_secs(25));
        assert!(!g.observe(&crit, t0 + Duration::from_secs(50)).stop);
        assert!(g.observe(&crit, t0 + Duration::from_secs(56)).stop);
    }

    #[test]
    fn a_stop_is_recorded_once_with_the_numbers_and_consumed_once() {
        let guard = MemoryGuard::with_budget(10 * GIB, Duration::from_secs(1));
        let mut g = Governor::new(10 * GIB, Duration::from_secs(1));
        let t0 = Instant::now();
        let crit = sample(11 * GIB);
        guard.apply(&mut g, &crit, t0, Duration::ZERO, true);
        assert!(!guard.is_stopped());
        guard.apply(
            &mut g,
            &crit,
            t0 + Duration::from_secs(2),
            Duration::from_secs(2),
            true,
        );
        assert!(guard.is_stopped());
        assert_eq!(guard.stats().stops, 1);
        // A second critical sample must not record a second stop.
        guard.apply(
            &mut g,
            &crit,
            t0 + Duration::from_secs(3),
            Duration::from_secs(1),
            true,
        );
        assert_eq!(guard.stats().stops, 1);

        let stop = guard.take_stop().expect("the stop is waiting");
        assert_eq!(stop.budget, 10 * GIB);
        let msg = stop.message(42);
        assert!(
            msg.starts_with("stopped: memory limit reached at 11.0 GiB"),
            "{msg}"
        );
        assert!(msg.contains("42 tasks done"), "{msg}");
        assert!(msg.contains("SEANCE_MEMORY_LIMIT"), "{msg}");
        assert!(msg.contains("SEANCE_WORKERS"), "{msg}");
        assert!(msg.contains("not from the evidence"), "{msg}");
        assert!(guard.take_stop().is_none());
        assert!(!guard.is_stopped(), "taking the stop re-arms the guard");
        assert_eq!(guard.stats().peak_anon, 11 * GIB);
    }

    #[tokio::test]
    async fn admission_is_free_when_ok_single_file_when_high_and_blocked_when_critical() {
        let guard = MemoryGuard::with_budget(10 * GIB, Duration::from_secs(60));
        let mut g = Governor::new(10 * GIB, Duration::from_secs(60));
        let now = Instant::now();

        let a = guard.admit().await;
        let b = guard.admit().await;
        drop((a, b));

        guard.apply(&mut g, &sample(9 * GIB), now, Duration::ZERO, true);
        assert_eq!(guard.pressure(), Pressure::High);
        let first = guard.admit().await;
        let second = tokio::time::timeout(Duration::from_millis(100), guard.admit()).await;
        assert!(second.is_err(), "High lets one task run at a time");
        drop(first);
        let after = tokio::time::timeout(Duration::from_millis(500), guard.admit()).await;
        assert!(after.is_ok(), "the next task goes once the first is done");
        drop(after);

        guard.apply(&mut g, &sample(10 * GIB), now, Duration::ZERO, true);
        assert_eq!(guard.pressure(), Pressure::Critical);
        let blocked = tokio::time::timeout(Duration::from_millis(100), guard.admit()).await;
        assert!(blocked.is_err(), "Critical dispatches nothing");

        guard.apply(&mut g, &sample(GIB), now, Duration::ZERO, true);
        let freed = tokio::time::timeout(Duration::from_millis(500), guard.admit()).await;
        assert!(freed.is_ok(), "recovery lets work continue");
    }

    #[tokio::test]
    async fn a_disabled_guard_never_pushes_back() {
        let guard = MemoryGuard::disabled();
        assert!(!guard.is_enabled());
        assert_eq!(guard.pressure(), Pressure::Ok);
        let _a = guard.admit().await;
        let _b = guard.admit().await;
        assert!(guard.take_stop().is_none());
    }

    struct Fixed(MemorySample);
    impl MemoryReader for Fixed {
        fn sample(&self) -> Option<MemorySample> {
            Some(self.0)
        }
    }
    struct Nothing;
    impl MemoryReader for Nothing {
        fn sample(&self) -> Option<MemorySample> {
            None
        }
    }

    #[test]
    fn configure_honours_the_spec_and_disables_itself_when_blind() {
        let s = sample(0);
        let g = MemoryGuard::configure(Some(LimitSpec::Bytes(GIB)), DEFAULT_GRACE, &Fixed(s));
        assert_eq!(g.budget(), Some(GIB));
        assert!(
            !MemoryGuard::configure(Some(LimitSpec::Off), DEFAULT_GRACE, &Fixed(s)).is_enabled()
        );
        assert!(!MemoryGuard::configure(None, DEFAULT_GRACE, &Nothing).is_enabled());
    }

    #[test]
    fn oom_score_adj_is_only_ever_raised() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("oom_score_adj");
        std::fs::write(&f, "0\n").unwrap();
        assert_eq!(apply_oom_score_adj(&f, 500), Some(500));
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "500");
        // Lowering is refused, and so is an out-of-range value.
        assert_eq!(apply_oom_score_adj(&f, 200), None);
        assert_eq!(std::fs::read_to_string(&f).unwrap(), "500");
        assert_eq!(apply_oom_score_adj(&f, 5000), None);
        assert_eq!(apply_oom_score_adj(&dir.path().join("absent"), 100), None);
    }

    #[test]
    fn the_real_reader_reads_this_machine_on_linux() {
        if !Path::new("/proc/meminfo").exists() {
            return;
        }
        let s = ProcReader::default()
            .sample()
            .expect("a Linux host is readable");
        assert!(s.host_total > 0 && s.process_rss > 0);
    }
}
