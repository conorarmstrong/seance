//! An opt-in allocation profiler for memory profiles (HUNT-125).
//!
//! Set `SEANCE_ALLOC_TRACE_MB=<n>` and the process allocator does two things:
//!
//! * it logs a backtrace for any single allocation of `n` MiB or more, and
//! * it samples the heap (one allocation per `SEANCE_ALLOC_SAMPLE_KB`, default
//!   512 KiB, allocated), remembers which call site made each sampled
//!   allocation until it is freed, and every `SEANCE_ALLOC_DUMP_SECS` (default
//!   30) prints the call sites holding the most **live** bytes.
//!
//! The second is the one that finds a retention: the question is not who
//! allocates the most but who is still holding it. A sample stands for
//! `max(size, interval)` bytes, which is the usual estimate for a sampling heap
//! profiler; it is an estimate, and only the ordering of the top sites is to be
//! trusted, not the third digit.
//!
//! Unset, the cost is one relaxed load per allocation. It exists because a
//! memory defect that scales with the evidence is found by measuring which call
//! site holds the memory, and the last five such fixes were each derived that
//! way (`HUNT-114`); it is not a general-purpose profiler, and the table is
//! fixed-size, so a sample that finds no free slot is dropped, not stored.

use std::alloc::{GlobalAlloc, Layout};
use std::cell::Cell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering::Relaxed};
use std::sync::Mutex;

pub struct TracingAllocator<A: GlobalAlloc>(pub A);

/// Single-allocation threshold in bytes; 0 means tracing is off.
static SINGLE_BYTES: AtomicUsize = AtomicUsize::new(0);
static SAMPLE_BYTES: AtomicUsize = AtomicUsize::new(512 << 10);

const SLOTS: usize = 1 << 20;
const PROBES: usize = 16;
const EMPTY: usize = 0;

static PTRS: [AtomicUsize; SLOTS] = [const { AtomicUsize::new(EMPTY) }; SLOTS];
static WEIGHT: [AtomicU64; SLOTS] = [const { AtomicU64::new(0) }; SLOTS];
static SITE: [AtomicU32; SLOTS] = [const { AtomicU32::new(0) }; SLOTS];

struct Sites {
    by_key: HashMap<String, u32>,
    keys: Vec<String>,
}
static SITES: Mutex<Option<Sites>> = Mutex::new(None);

thread_local! {
    static IN_TRACE: Cell<bool> = const { Cell::new(false) };
    static UNTIL_SAMPLE: Cell<isize> = const { Cell::new(0) };
}

/// Read the environment once, at startup, after the allocator is usable.
pub fn configure_from_env() {
    let env = |k: &str| std::env::var(k).ok().and_then(|v| v.parse::<usize>().ok());
    let Some(mb) = env("SEANCE_ALLOC_TRACE_MB").filter(|&mb| mb > 0) else {
        return;
    };
    if let Some(kb) = env("SEANCE_ALLOC_SAMPLE_KB").filter(|&k| k > 0) {
        SAMPLE_BYTES.store(kb << 10, Relaxed);
    }
    *SITES.lock().unwrap() = Some(Sites {
        by_key: HashMap::new(),
        keys: vec![String::new()],
    });
    let secs = env("SEANCE_ALLOC_DUMP_SECS")
        .filter(|&s| s > 0)
        .unwrap_or(30);
    SINGLE_BYTES.store(mb << 20, Relaxed);
    let _ = std::thread::Builder::new()
        .name("alloc-trace-dump".into())
        .spawn(move || {
            IN_TRACE.with(|f| f.set(true));
            loop {
                std::thread::sleep(std::time::Duration::from_secs(secs as u64));
                dump();
            }
        });
}

/// The frames of the current stack that are worth naming: the first few that
/// are not the allocator's own or the runtime's.
fn site_key() -> String {
    let bt = std::backtrace::Backtrace::force_capture().to_string();
    let mut frames: Vec<&str> = Vec::new();
    for line in bt.lines() {
        let t = line.trim_start();
        let Some((n, name)) = t.split_once(": ") else {
            continue;
        };
        if !n.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        if name.contains("alloc_trace")
            || name.starts_with("alloc::")
            || name.starts_with("__rust")
            || name.starts_with("_rjem")
            || name.starts_with("mi_")
            || name.starts_with("core::")
            || name.starts_with("<alloc::")
            || name.starts_with("std::")
        {
            continue;
        }
        frames.push(name);
        if frames.len() == 7 {
            break;
        }
    }
    frames.join("\n      <- ")
}

fn intern(key: String) -> u32 {
    let mut guard = SITES.lock().unwrap();
    let sites = guard.as_mut().unwrap();
    if let Some(&id) = sites.by_key.get(&key) {
        return id;
    }
    let id = sites.keys.len() as u32;
    sites.keys.push(key.clone());
    sites.by_key.insert(key, id);
    id
}

fn slot(ptr: usize) -> usize {
    (ptr >> 4).wrapping_mul(0x9E37_79B9_7F4A_7C15) >> 40 & (SLOTS - 1)
}

fn remember(ptr: *mut u8, size: usize) {
    if ptr.is_null() || SINGLE_BYTES.load(Relaxed) == 0 {
        return;
    }
    let sample = SAMPLE_BYTES.load(Relaxed) as isize;
    let take = UNTIL_SAMPLE.with(|c| {
        let left = c.get() - size as isize;
        if left <= 0 {
            c.set(sample);
            true
        } else {
            c.set(left);
            false
        }
    });
    if !take {
        return;
    }
    IN_TRACE.with(|flag| {
        if flag.replace(true) {
            return;
        }
        let id = intern(site_key());
        let base = slot(ptr as usize);
        for i in 0..PROBES {
            let s = (base + i) & (SLOTS - 1);
            if PTRS[s]
                .compare_exchange(EMPTY, ptr as usize, Relaxed, Relaxed)
                .is_ok()
            {
                WEIGHT[s].store(size.max(sample as usize) as u64, Relaxed);
                SITE[s].store(id, Relaxed);
                break;
            }
        }
        flag.set(false);
    });
}

fn forget(ptr: *mut u8) {
    if SINGLE_BYTES.load(Relaxed) == 0 {
        return;
    }
    let base = slot(ptr as usize);
    for i in 0..PROBES {
        let s = (base + i) & (SLOTS - 1);
        if PTRS[s].load(Relaxed) == ptr as usize
            && PTRS[s]
                .compare_exchange(ptr as usize, EMPTY, Relaxed, Relaxed)
                .is_ok()
        {
            return;
        }
    }
}

fn dump() {
    let mut by_site: HashMap<u32, u64> = HashMap::new();
    let mut total = 0u64;
    for s in 0..SLOTS {
        if PTRS[s].load(Relaxed) != EMPTY {
            let w = WEIGHT[s].load(Relaxed);
            *by_site.entry(SITE[s].load(Relaxed)).or_default() += w;
            total += w;
        }
    }
    let mut rows: Vec<(u32, u64)> = by_site.into_iter().collect();
    rows.sort_by_key(|r| std::cmp::Reverse(r.1));
    let anon_kb = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find_map(|l| l.strip_prefix("RssAnon:").map(|v| v.trim().to_string()))
        })
        .unwrap_or_default();
    let guard = SITES.lock().unwrap();
    let keys = &guard.as_ref().unwrap().keys;
    let mut out = format!(
        "ALLOC_LIVE total_sampled_live_mb={} rss_anon={}\n",
        total >> 20,
        anon_kb
    );
    for (id, w) in rows.iter().take(10) {
        out.push_str(&format!(
            "ALLOC_LIVE_SITE {} MB\n      {}\n",
            w >> 20,
            keys[*id as usize]
        ));
    }
    eprintln!("{out}");
}

fn trace_single(size: usize) {
    IN_TRACE.with(|flag| {
        if flag.replace(true) {
            return;
        }
        eprintln!("ALLOC_SINGLE size={size} at\n      {}", site_key());
        flag.set(false);
    });
}

unsafe impl<A: GlobalAlloc> GlobalAlloc for TracingAllocator<A> {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let single = SINGLE_BYTES.load(Relaxed);
        let p = self.0.alloc(layout);
        if single != 0 {
            if layout.size() >= single {
                trace_single(layout.size());
            }
            remember(p, layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        forget(ptr);
        self.0.dealloc(ptr, layout)
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let single = SINGLE_BYTES.load(Relaxed);
        let p = self.0.alloc_zeroed(layout);
        if single != 0 {
            if layout.size() >= single {
                trace_single(layout.size());
            }
            remember(p, layout.size());
        }
        p
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        forget(ptr);
        let p = self.0.realloc(ptr, layout, new_size);
        if SINGLE_BYTES.load(Relaxed) != 0 {
            remember(p, new_size);
        }
        p
    }
}
