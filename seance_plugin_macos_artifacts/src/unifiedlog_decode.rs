//! Per-message decoding of an Apple unified log against its own tree.
//!
//! A `.tracev3` names each message's format string by reference into the
//! machine's catalogue — `uuidtext` entries and `dsc` shared caches — and
//! stamps it in continuous time, which the `timesync` database turns into a
//! wall clock. None of those live in the `.tracev3`: they are in the rest of
//! the tree it came from. This module reaches that tree through
//! [`DataSource::open_from_ancestor`], a bounded climb of at most three
//! directories, in one of two layouts:
//!
//! * a `.logarchive` — `Persist/x.tracev3` beside `<XX>/<rest>`, `dsc/<UUID>`
//!   and `timesync/`, one directory up;
//! * a live `/var/db/diagnostics` — `Persist/x.tracev3` with `timesync/` one
//!   directory up and `/var/db/uuidtext/<XX>/<rest>` and `uuidtext/dsc/<UUID>`
//!   two up.
//!
//! # Reach, stated honestly
//!
//! A loose file on disk and an entry in a ZIP can climb; a file inside a disk
//! image cannot yet, and says so — **"tree not reachable, not decoded"** —
//! rather than rendering a message with an empty format. A reference into a
//! catalogue file that is not in the tree is reported unresolved with its
//! reason, never as an empty message.
//!
//! Catalogue files are opened by name, so no directory listing is needed.
//! Timesync files have sequence names (`0000000000000002.timesync`). They are
//! found by **listing** `timesync/` where the source can list it (a loose file
//! or a ZIP entry), so a file far along the sequence after rotation is seen
//! (HUNT-272); a source that cannot list is **probed** by sequence name in
//! order, where a file far off the sequence is not seen. The record says which
//! was done. When no boot matches, the message is dated from the `.tracev3`
//! header's own clock anchor and labelled as such.
//!
//! Parsed catalogue files are held in a bounded process-wide cache keyed by
//! the file's own path, so the hundreds of `.tracev3` of one archive share one
//! reading of each 90 MB shared cache. A source with no path (a ZIP entry) is
//! read per file.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};

use seance_core::data_source::DataSource;

use crate::firehose::{
    FirehoseChunk, Item, ItemValue, Oversize, Tracepoint, ACTIVITY, LOG, LOSS, SIGNPOST, TRACE,
};
use crate::timesync;
use crate::unifiedlog_chunks::Catalog;
use crate::unifiedlog_dumps::{Simpledump, Statedump, StatedumpData};
use crate::unifiedlog_resolve::{
    parse_dsc, parse_uuidtext, render, resolve, CatalogueSet, Dsc, UuidText,
};
use serde_json::json;

/// Largest catalogue file read (a shared cache runs to ~90 MB).
const MAX_CATALOGUE_FILE: u64 = 512 * 1024 * 1024;
/// Largest timesync file read.
const MAX_TIMESYNC_FILE: u64 = 64 * 1024 * 1024;
/// How far below its tree's root a `.tracev3` may sit: one directory
/// (`Persist/`, `Special/`, `Signpost/`, `HighVolume/`) or none
/// (`logdata.LiveData.tracev3`). Tried in this order until one is found.
const LEVELS_UP: [usize; 2] = [1, 0];
/// Timesync sequence names probed, and the run of misses after the last hit
/// that ends the probe.
const TIMESYNC_PROBE_LIMIT: u64 = 256;
const TIMESYNC_PROBE_MISSES: u64 = 16;
/// Message records emitted per `.tracev3`; the counts stay whole past it.
pub(crate) const MAX_MESSAGE_RECORDS: usize = 150_000;
/// Bytes of an undecoded statedump's data shown as hex on its record.
const MAX_DUMP_HEX: usize = 4096;
/// Distinct unresolved reasons kept in words; the count stays whole.
const MAX_REASONS: usize = 16;
/// Bytes of parsed catalogue held process-wide before the cache is dropped.
const CACHE_BUDGET: usize = 1024 * 1024 * 1024;

/// Where the catalogue sits relative to the `.tracev3`'s directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Layout {
    LogArchive,
    Diagnostics,
}

impl Layout {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Layout::LogArchive => "logarchive",
            Layout::Diagnostics => "diagnostics",
        }
    }
    /// Where a `uuidtext` entry is, for a file `up` directories below the
    /// tree's root: `(levels to climb, relative path)`.
    fn uuidtext(self, uuid: &str, up: usize) -> (usize, String) {
        let (dir, rest) = uuid.split_at(2);
        match self {
            Layout::LogArchive => (up, format!("{dir}/{rest}")),
            Layout::Diagnostics => (up + 1, format!("uuidtext/{dir}/{rest}")),
        }
    }
    fn dsc(self, uuid: &str, up: usize) -> (usize, String) {
        match self {
            Layout::LogArchive => (up, format!("dsc/{uuid}")),
            Layout::Diagnostics => (up + 1, format!("uuidtext/dsc/{uuid}")),
        }
    }
}

/// A parsed catalogue file.
#[derive(Clone)]
enum Parsed {
    Uuid(Arc<UuidText>),
    Dsc(Arc<Dsc>),
}

/// Process-wide cache of parsed catalogue files, keyed by path.
fn cache() -> &'static Mutex<(HashMap<PathBuf, Parsed>, usize)> {
    static CACHE: OnceLock<Mutex<(HashMap<PathBuf, Parsed>, usize)>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new((HashMap::new(), 0)))
}

fn read_whole(ds: &dyn DataSource, cap: u64) -> Option<Vec<u8>> {
    if ds.size() > cap {
        return None;
    }
    let mut buf = vec![0u8; ds.size() as usize];
    let got = seance_core::io::read_full(ds, 0, &mut buf);
    (got == buf.len()).then_some(buf)
}

/// Render a message's format against the arguments of its oversize entry.
fn join_oversize(summary: &mut Summary, m: &mut Message, format: &str, items: &[Item]) {
    let text = render(format, items);
    summary.rendered_raw = summary.rendered_raw - m.rendered_raw + text.rendered_raw;
    m.rendered_raw = text.rendered_raw;
    m.missing_arguments = text.missing_arguments;
    m.private_arguments = items
        .iter()
        .filter(|i| i.value == ItemValue::Private)
        .count();
    m.text = Some(text.text);
    m.arguments_from_oversize = true;
}

/// Directories below a tree's root that hold `.tracev3` files; `""` is the
/// root itself (`logdata.LiveData.tracev3`).
const TRACEV3_DIRS: [&str; 5] = ["", "Persist", "Special", "Signpost", "HighVolume"];
/// Largest `.tracev3` read for its oversize entries.
const MAX_TRACEV3_FILE: u64 = 512 * 1024 * 1024;
/// Trees whose oversize entries are held at once.
const TREE_CACHE_ROOTS: usize = 4;

/// The oversize entries of every `.tracev3` of one tree, keyed by (boot
/// UUID, first process id, second process id, data reference): process ids
/// and references are only unique within a boot.
/// (boot, first proc id, second proc id, data ref) of an oversize entry.
type OversizeKey = (String, u64, u32, u32);

#[derive(Debug, Default)]
struct TreeOversize {
    /// At least one of the tree's directories could be listed.
    listed: bool,
    files_read: usize,
    /// Files that could not be opened, or were not read whole.
    files_unread: usize,
    entries: HashMap<OversizeKey, (String, Vec<Item>)>,
}

impl TreeOversize {
    fn read(src: &dyn DataSource, up: usize) -> Self {
        let mut t = TreeOversize::default();
        for dir in TRACEV3_DIRS {
            let Some(names) = src.list_from_ancestor(up, dir) else {
                continue;
            };
            t.listed = true;
            for name in names.iter().filter(|n| n.ends_with(".tracev3")) {
                let rel = if dir.is_empty() {
                    name.clone()
                } else {
                    format!("{dir}/{name}")
                };
                let bytes = src
                    .open_from_ancestor(up, &rel)
                    .and_then(|ds| read_whole(ds.as_ref(), MAX_TRACEV3_FILE));
                let Some(bytes) = bytes else {
                    t.files_unread += 1;
                    continue;
                };
                let (boot, entries, whole) = oversize_entries_of(&bytes);
                if whole {
                    t.files_read += 1;
                } else {
                    t.files_unread += 1;
                }
                let Some(boot) = boot else {
                    continue;
                };
                for o in entries {
                    t.entries
                        .entry((boot.clone(), o.first_proc_id, o.second_proc_id, o.data_ref))
                        .or_insert_with(|| (rel.clone(), o.items));
                }
            }
        }
        t
    }
}

/// Where a missing oversize entry was looked for, in words: a search that
/// could not be made is said as such, never as "not found".
fn oversize_missing_detail(r: u32, tree: Option<&TreeOversize>) -> String {
    let Some(t) = tree else {
        return format!("oversize entry {r} could not be looked in: the tree's root is not known");
    };
    if !t.listed {
        return format!(
            "oversize entry {r} could not be searched for: the tree could not be listed"
        );
    }
    let mut d = format!(
        "oversize entry {r} found in none of the {} other file(s) of the tree",
        t.files_read
    );
    if t.files_unread > 0 {
        d.push_str(&format!("; {} could not be read", t.files_unread));
    }
    d
}

fn tree_cache() -> &'static Mutex<HashMap<PathBuf, Arc<TreeOversize>>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Arc<TreeOversize>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// A `.tracev3`'s boot and its oversize entries, walking its chunks and
/// decompressing each chunkset; `false` when it was not read whole.
fn oversize_entries_of(file: &[u8]) -> (Option<String>, Vec<Oversize>, bool) {
    use crate::unifiedlog_chunks::{decompress_chunkset, walk_entries, TAG_OVERSIZE};
    let (mut boot, mut out, mut whole) = (None, Vec::new(), true);
    let mut off = 0usize;
    while off < file.len() {
        let Some(pre) = file.get(off..off + 16) else {
            whole = false;
            break;
        };
        let tag = u32::from_le_bytes([pre[0], pre[1], pre[2], pre[3]]);
        let size = u64::from_le_bytes(pre[8..16].try_into().unwrap_or([0; 8]));
        let Some(body) = usize::try_from(size)
            .ok()
            .and_then(|n| off.checked_add(16)?.checked_add(n))
            .and_then(|end| file.get(off + 16..end))
        else {
            whole = false;
            break;
        };
        match tag {
            0x1000 => boot = parse_header(body).and_then(|h| h.boot_uuid),
            0x600d => match decompress_chunkset(body) {
                Ok(bytes) => {
                    let walk = walk_entries(&bytes);
                    if walk.framing_broken {
                        whole = false;
                    }
                    for e in walk.entries.iter().filter(|e| e.tag == TAG_OVERSIZE) {
                        match crate::firehose::parse_oversize(e.payload) {
                            Some(o) => out.push(o),
                            None => whole = false,
                        }
                    }
                }
                Err(_) => whole = false,
            },
            _ => {}
        }
        off += 16 + body.len();
        off += (8 - off % 8) % 8;
    }
    (boot, out, whole)
}

/// The `.tracev3`'s own header: which boot wrote it, and one clock anchor.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Header {
    pub(crate) timebase_numerator: u32,
    pub(crate) timebase_denominator: u32,
    pub(crate) continuous_time: u64,
    pub(crate) wall_time_ns: i64,
    pub(crate) boot_uuid: Option<String>,
}

/// Read the Header chunk's payload (after its 16-byte preamble).
pub(crate) fn parse_header(p: &[u8]) -> Option<Header> {
    let u32_at = |at: usize| {
        p.get(at..at + 4)
            .map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
    };
    let u64_at = |at: usize| {
        p.get(at..at + 8).map(|s| {
            let mut b = [0u8; 8];
            b.copy_from_slice(s);
            u64::from_le_bytes(b)
        })
    };
    let secs = i64::try_from(u64_at(16)?).ok()?;
    let usecs = i64::from(u32_at(24)?);
    let mut h = Header {
        timebase_numerator: u32_at(0)?,
        timebase_denominator: u32_at(4)?,
        continuous_time: u64_at(8)?,
        wall_time_ns: secs
            .checked_mul(1_000_000_000)?
            .checked_add(usecs * 1_000)?,
        boot_uuid: None,
    };
    // Sub-chunks follow at 40: tag, size, data. 0x6102 carries the boot UUID.
    let mut off = 40usize;
    while let (Some(tag), Some(size)) = (u32_at(off), u32_at(off + 4)) {
        let data = off + 8;
        if tag == 0x6102 {
            h.boot_uuid = p
                .get(data..data + 16)
                .map(|b| b.iter().map(|x| format!("{x:02X}")).collect());
        }
        match data.checked_add(size as usize) {
            Some(next) if next > off && next <= p.len() => off = next,
            _ => break,
        }
    }
    Some(h)
}

/// Continuous time to wall-clock nanoseconds through one anchor.
pub(crate) fn to_wall_ns(
    ct: u64,
    anchor_ct: u64,
    anchor_wall_ns: i64,
    numer: u32,
    denom: u32,
) -> Option<i64> {
    if denom == 0 {
        return None;
    }
    let delta = i128::from(ct) - i128::from(anchor_ct);
    let ns = delta * i128::from(numer) / i128::from(denom);
    i64::try_from(i128::from(anchor_wall_ns) + ns).ok()
}

/// How a message was dated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TimeSource {
    Timesync,
    TraceHeader,
}

impl TimeSource {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            TimeSource::Timesync => "timesync",
            TimeSource::TraceHeader => "tracev3_header",
        }
    }
}

/// One decoded message.
#[derive(Debug, Clone, Default)]
pub(crate) struct Message {
    pub(crate) continuous_time: u64,
    pub(crate) wall_time_ns: Option<i64>,
    pub(crate) time_source: Option<TimeSource>,
    pub(crate) activity_type: u8,
    pub(crate) log_type: u8,
    pub(crate) thread_id: u64,
    pub(crate) pid: Option<u32>,
    pub(crate) euid: Option<u32>,
    pub(crate) process_path: Option<String>,
    pub(crate) process_uuid: Option<String>,
    pub(crate) image_path: Option<String>,
    pub(crate) image_uuid: Option<String>,
    pub(crate) subsystem: Option<String>,
    pub(crate) category: Option<String>,
    pub(crate) format: Option<String>,
    pub(crate) text: Option<String>,
    pub(crate) dynamic: bool,
    pub(crate) unresolved: Option<String>,
    pub(crate) rendered_raw: usize,
    pub(crate) missing_arguments: usize,
    pub(crate) private_arguments: usize,
    pub(crate) lost_entries: Option<u64>,
    pub(crate) flaw: Option<String>,
    /// The tracepoint's arguments are in an oversize entry with this
    /// reference.
    pub(crate) oversize_ref: Option<u32>,
    /// That oversize entry was found and its arguments rendered.
    pub(crate) arguments_from_oversize: bool,
    /// The oversize entry was in another `.tracev3` of the tree: its path
    /// below the tree's root (HUNT-271). `None` when it was in this file.
    pub(crate) oversize_from_file: Option<String>,
    /// The oversize entry was found nowhere: where it was looked for, and
    /// whether the other files of the tree could be looked in at all.
    pub(crate) oversize_missing: Option<String>,
    /// `statedump` or `simpledump` for those entries; empty for a tracepoint.
    pub(crate) dump_kind: &'static str,
    /// The entry's own fields for a statedump or simpledump.
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

/// What the decoding of one file came to.
#[derive(Debug, Clone, Default)]
pub(crate) struct Summary {
    pub(crate) tree_reachable: bool,
    pub(crate) layout: Option<Layout>,
    /// Directories climbed from the file's own to the tree's root (the
    /// `.logarchive`, or `/var/db/diagnostics`): 1 for `Persist/…`, 0 for a
    /// file at the root such as `logdata.LiveData.tracev3`.
    pub(crate) levels_up: Option<usize>,
    pub(crate) catalogue_files_loaded: usize,
    pub(crate) catalogue_files_unparsed: usize,
    pub(crate) catalogue_uuids_not_in_tree: usize,
    pub(crate) timesync_files: usize,
    /// How the timesync files were found: `listing` (the directory was
    /// listed) or `probing` (the source cannot list, so sequence names were
    /// tried in order).
    pub(crate) timesync_found_by: Option<&'static str>,
    pub(crate) boot_uuid: Option<String>,
    pub(crate) boot_in_timesync: bool,
    pub(crate) resolved: usize,
    pub(crate) dynamic: usize,
    pub(crate) unresolved: usize,
    pub(crate) loss_records: usize,
    pub(crate) rendered_raw: usize,
    pub(crate) messages_over_cap: usize,
    pub(crate) unresolved_reasons: BTreeMap<String, usize>,
    /// Oversize entries read, and those less than whole.
    pub(crate) oversize_entries: usize,
    pub(crate) oversize_entries_flawed: usize,
    /// Emitted messages whose arguments are in an oversize entry: joined to
    /// one in this file, or not found in it.
    pub(crate) oversize_joined: usize,
    pub(crate) oversize_not_in_file: usize,
    /// Of those not in this file: joined to an oversize entry in another
    /// `.tracev3` of the same tree and boot, and found in none (HUNT-271).
    pub(crate) oversize_joined_from_tree: usize,
    pub(crate) oversize_not_in_tree: usize,
    /// `.tracev3` files of the tree read for their oversize entries, and
    /// those that could not be read; `false` when the tree could not be
    /// listed, so no other file was looked in.
    pub(crate) oversize_tree_files_read: usize,
    pub(crate) oversize_tree_files_unread: usize,
    pub(crate) oversize_tree_listed: bool,
    /// Statedump and simpledump entries decoded, statedumps whose data this
    /// reader does not decode, and dump entries that were not read whole.
    pub(crate) statedumps: usize,
    pub(crate) simpledumps: usize,
    pub(crate) statedump_data_not_decoded: usize,
    pub(crate) dumps_not_read_whole: usize,
}

/// Decodes the firehose tracepoints of one `.tracev3` as the chunk walk
/// hands them over.
pub(crate) struct Decoder {
    src: Arc<dyn DataSource>,
    set: CatalogueSet,
    tried: HashSet<String>,
    catalog: Catalog,
    header: Option<Header>,
    boot: Option<timesync::Boot>,
    /// The depth below the tree's root the timesync database was found at.
    timesync_levels_up: Option<usize>,
    /// Oversize entries' arguments, by (first process id, second process id,
    /// data reference), held until [`Self::finish`].
    oversize: HashMap<(u64, u32, u32), Vec<Item>>,
    /// Emitted messages waiting on an oversize entry: (index, key, format).
    pending: Vec<(usize, (u64, u32, u32), String)>,
    pub(crate) summary: Summary,
    pub(crate) messages: Vec<Message>,
}

impl Decoder {
    /// A decoder for the file `src`, or `None` when this kind of source cannot
    /// reach its tree at all.
    pub(crate) fn new(src: Arc<dyn DataSource>) -> Option<Self> {
        if !src.supports_ancestors() {
            return None;
        }
        Some(Self {
            src,
            set: CatalogueSet::default(),
            tried: HashSet::new(),
            catalog: Catalog::default(),
            header: None,
            boot: None,
            timesync_levels_up: None,
            oversize: HashMap::new(),
            pending: Vec::new(),
            summary: Summary::default(),
            messages: Vec::new(),
        })
    }

    /// Read one catalogue file, through the process-wide cache when the
    /// source has a path. `None` when it does not read or parse.
    fn load(ds: Arc<dyn DataSource>, is_dsc: bool) -> Option<Parsed> {
        let key = ds.get_underlying_path();
        if let Some(k) = &key {
            let c = cache().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(p) = c.0.get(k) {
                return Some(p.clone());
            }
        }
        let bytes = read_whole(ds.as_ref(), MAX_CATALOGUE_FILE)?;
        let parsed = if is_dsc {
            Parsed::Dsc(Arc::new(parse_dsc(&bytes)?))
        } else {
            Parsed::Uuid(Arc::new(parse_uuidtext(&bytes)?))
        };
        if let Some(k) = key {
            let mut c = cache().lock().unwrap_or_else(|e| e.into_inner());
            if c.1 + bytes.len() > CACHE_BUDGET {
                c.0.clear();
                c.1 = 0;
            }
            c.1 += bytes.len();
            c.0.insert(k, parsed.clone());
        }
        Some(parsed)
    }

    /// The depths below the tree's root still worth trying: the one found,
    /// else the one the timesync database was found at first, else both.
    fn depths(&self) -> Vec<usize> {
        if let Some(up) = self.summary.levels_up {
            return vec![up];
        }
        let mut v = LEVELS_UP.to_vec();
        if let Some(t) = self.timesync_levels_up {
            v.sort_by_key(|&u| u != t);
        }
        v
    }

    /// The (layout, depth) places still worth trying: the one found, or all.
    fn places(&self) -> Vec<(Layout, usize)> {
        let layouts = match self.summary.layout {
            Some(l) => vec![l],
            None => vec![Layout::LogArchive, Layout::Diagnostics],
        };
        self.depths()
            .into_iter()
            .flat_map(|up| layouts.iter().map(move |&l| (l, up)))
            .collect()
    }

    /// Bring one UUID's catalogue file — a `uuidtext` entry or a shared
    /// cache — into the set, once.
    fn ensure(&mut self, uuid: &str) {
        if uuid.len() != 32 || !uuid.is_ascii() || !self.tried.insert(uuid.to_string()) {
            return;
        }
        for (layout, up) in self.places() {
            for is_dsc in [false, true] {
                let (levels, rel) = if is_dsc {
                    layout.dsc(uuid, up)
                } else {
                    layout.uuidtext(uuid, up)
                };
                let Some(ds) = self.src.open_from_ancestor(levels, &rel) else {
                    continue;
                };
                self.summary.layout = Some(layout);
                self.summary.levels_up = Some(up);
                self.summary.tree_reachable = true;
                match Self::load(ds, is_dsc) {
                    Some(Parsed::Uuid(u)) => {
                        self.set.uuidtext.insert(uuid.to_string(), u);
                        self.summary.catalogue_files_loaded += 1;
                    }
                    Some(Parsed::Dsc(d)) => {
                        self.set.dsc.insert(uuid.to_string(), d);
                        self.summary.catalogue_files_loaded += 1;
                    }
                    None => self.summary.catalogue_files_unparsed += 1,
                }
                return;
            }
        }
        self.summary.catalogue_uuids_not_in_tree += 1;
    }

    /// The Header chunk: the boot, and the timesync boot that dates it.
    pub(crate) fn header(&mut self, payload: &[u8]) {
        let Some(h) = parse_header(payload) else {
            return;
        };
        self.summary.boot_uuid = h.boot_uuid.clone();
        if let Some(boot_uuid) = &h.boot_uuid {
            // Timesync sits at the tree's root in both layouts. The directory
            // is listed where the source can list it: the files keep their
            // sequence names after the oldest are rotated away, so the first
            // present can be far along the sequence (HUNT-272). A source that
            // cannot list is probed by sequence name, in order, until a run
            // of misses. The first depth that holds any file is the one used.
            'depth: for up in self.depths() {
                let listed = self.src.list_from_ancestor(up, "timesync").map(|names| {
                    names
                        .into_iter()
                        .filter(|n| n.ends_with(".timesync"))
                        .collect::<Vec<_>>()
                });
                let (found_by, names): (&'static str, Box<dyn Iterator<Item = String>>) =
                    match listed {
                        Some(names) => ("listing", Box::new(names.into_iter())),
                        None => (
                            "probing",
                            Box::new(
                                (0..TIMESYNC_PROBE_LIMIT).map(|n| format!("{n:016x}.timesync")),
                            ),
                        ),
                    };
                let mut last_hit = 0u64;
                let mut found_any = false;
                for (n, name) in names.enumerate() {
                    if found_by == "probing" && n as u64 > last_hit + TIMESYNC_PROBE_MISSES {
                        break;
                    }
                    let Some(ds) = self.src.open_from_ancestor(up, &format!("timesync/{name}"))
                    else {
                        continue;
                    };
                    last_hit = n as u64;
                    found_any = true;
                    self.timesync_levels_up = Some(up);
                    self.summary.timesync_files += 1;
                    self.summary.timesync_found_by = Some(found_by);
                    let Some(ts) = read_whole(ds.as_ref(), MAX_TIMESYNC_FILE)
                        .as_deref()
                        .and_then(timesync::parse)
                    else {
                        continue;
                    };
                    if let Some(b) = ts.boots.into_iter().find(|b| &b.boot_uuid == boot_uuid) {
                        self.boot = Some(b);
                        self.summary.boot_in_timesync = true;
                        break 'depth;
                    }
                }
                if found_any {
                    break;
                }
            }
        }
        self.header = Some(h);
    }

    /// An oversize entry: held until the end of the file, because the
    /// tracepoint that refers to it may come before or after it.
    pub(crate) fn oversize(&mut self, o: &Oversize) {
        self.summary.oversize_entries += 1;
        if o.flaw.is_some() {
            self.summary.oversize_entries_flawed += 1;
        }
        self.oversize.insert(
            (o.first_proc_id, o.second_proc_id, o.data_ref),
            o.items.clone(),
        );
    }

    /// Join each message whose arguments are in an oversize entry to that
    /// entry, once every chunk of the file has been read. The log may write
    /// the entry to another `.tracev3` of the same boot (HUNT-271), so one
    /// that is not in this file is looked for in the other files of the tree
    /// — listed, never guessed — and the file it came from is named. One found
    /// nowhere leaves the message with its arguments missing, and it says so.
    pub(crate) fn finish(&mut self) {
        let mut missing = Vec::new();
        for (idx, key, format) in std::mem::take(&mut self.pending) {
            let Some(m) = self.messages.get_mut(idx) else {
                continue;
            };
            let Some(items) = self.oversize.get(&key) else {
                self.summary.oversize_not_in_file += 1;
                missing.push((idx, key, format));
                continue;
            };
            join_oversize(&mut self.summary, m, &format, items);
            self.summary.oversize_joined += 1;
        }
        self.oversize.clear();
        if missing.is_empty() {
            return;
        }
        let tree = self.tree_oversize();
        if let Some(t) = &tree {
            self.summary.oversize_tree_listed = t.listed;
            self.summary.oversize_tree_files_read = t.files_read;
            self.summary.oversize_tree_files_unread = t.files_unread;
        }
        let boot = self.summary.boot_uuid.clone();
        for (idx, (first, second, data_ref), format) in missing {
            let hit = match (&tree, &boot) {
                (Some(t), Some(b)) => t.entries.get(&(b.clone(), first, second, data_ref)),
                _ => None,
            };
            let Some(m) = self.messages.get_mut(idx) else {
                continue;
            };
            let Some((file, items)) = hit else {
                self.summary.oversize_not_in_tree += 1;
                m.oversize_missing = Some(oversize_missing_detail(data_ref, tree.as_deref()));
                continue;
            };
            join_oversize(&mut self.summary, m, &format, items);
            m.oversize_from_file = Some(file.clone());
            self.summary.oversize_joined_from_tree += 1;
        }
    }

    /// Every oversize entry of the other `.tracev3` files of this file's
    /// tree, through a process-wide cache keyed by the tree's root when the
    /// source has a path. `None` when the tree's root is not known.
    fn tree_oversize(&self) -> Option<Arc<TreeOversize>> {
        let up = self.summary.levels_up.or(self.timesync_levels_up)?;
        let root = self.src.get_underlying_path().and_then(|p| {
            let mut dir = p.parent()?.to_path_buf();
            for _ in 0..up {
                dir = dir.parent()?.to_path_buf();
            }
            Some(dir)
        });
        if let Some(r) = &root {
            let c = tree_cache().lock().unwrap_or_else(|e| e.into_inner());
            if let Some(t) = c.get(r) {
                return Some(t.clone());
            }
        }
        let built = Arc::new(TreeOversize::read(self.src.as_ref(), up));
        if let Some(r) = root {
            let mut c = tree_cache().lock().unwrap_or_else(|e| e.into_inner());
            if c.len() >= TREE_CACHE_ROOTS {
                c.clear();
            }
            c.insert(r, built.clone());
        }
        Some(built)
    }

    /// A statedump entry, as a message of its own.
    pub(crate) fn statedump(&mut self, d: &Statedump) {
        self.summary.statedumps += 1;
        let mut m = self.dump_message(
            "statedump",
            d.first_proc_id,
            d.second_proc_id,
            d.continuous_time,
        );
        let x = &mut m.extra;
        x.insert("title".into(), json!(d.title));
        x.insert("object_type".into(), json!(d.object_type));
        x.insert("decoder_library".into(), json!(d.decoder_library));
        x.insert("activity_id".into(), json!(d.activity_id));
        x.insert("statedump_uuid".into(), json!(d.uuid));
        x.insert("data_type".into(), json!(d.data_type));
        let data = match &d.data {
            StatedumpData::Plist(v) => {
                x.insert("data".into(), v.clone());
                x.insert("data_decoded".into(), json!(true));
                v.to_string()
            }
            StatedumpData::Empty => {
                x.insert("data_size".into(), json!(0));
                "none".to_string()
            }
            StatedumpData::Undecoded { kind, bytes } => {
                self.summary.statedump_data_not_decoded += 1;
                x.insert("data_decoded".into(), json!(false));
                x.insert("data_kind".into(), json!(kind));
                x.insert("data_size".into(), json!(bytes.len()));
                let shown = &bytes[..bytes.len().min(MAX_DUMP_HEX)];
                x.insert(
                    "data_hex".into(),
                    json!(shown.iter().map(|b| format!("{b:02x}")).collect::<String>()),
                );
                if bytes.len() > MAX_DUMP_HEX {
                    x.insert("data_hex_truncated_at".into(), json!(MAX_DUMP_HEX));
                }
                format!("{} bytes of {kind} data, not decoded", bytes.len())
            }
        };
        m.text = Some(format!(
            "title: {}, object type: {}, library: {}, data: {data}",
            d.title, d.object_type, d.decoder_library
        ));
        if let Some(f) = &d.flaw {
            self.summary.dumps_not_read_whole += 1;
            m.flaw = Some(f.clone());
        }
        self.push_dump(m);
    }

    /// A simpledump entry, as a message of its own.
    pub(crate) fn simpledump(&mut self, d: &Simpledump) {
        self.summary.simpledumps += 1;
        let mut m = self.dump_message(
            "simpledump",
            d.first_proc_id,
            d.second_proc_id,
            d.continuous_time,
        );
        m.thread_id = d.thread_id;
        m.subsystem = Some(d.subsystem.clone());
        m.text = Some(d.message.clone());
        m.extra.insert("sender_uuid".into(), json!(d.sender_uuid));
        m.extra.insert("dsc_uuid".into(), json!(d.dsc_uuid));
        if let Some(f) = &d.flaw {
            self.summary.dumps_not_read_whole += 1;
            m.flaw = Some(f.clone());
        }
        self.push_dump(m);
    }

    /// A dump entry's common fields: when, and which process.
    fn dump_message(&self, kind: &'static str, first: u64, second: u32, ct: u64) -> Message {
        let (wall_time_ns, time_source) = self.date(ct);
        let mut m = Message {
            continuous_time: ct,
            wall_time_ns,
            time_source,
            dump_kind: kind,
            ..Message::default()
        };
        if let Some(p) = self.catalog.process(first, second) {
            m.pid = Some(p.pid);
            m.euid = Some(p.euid);
            let main = self.catalog.uuid(p.main_uuid_index).map(str::to_string);
            m.process_path = main
                .as_deref()
                .and_then(|u| self.set.uuidtext.get(u))
                .and_then(|u| u.path.clone());
            m.process_uuid = main;
        }
        m
    }

    fn push_dump(&mut self, m: Message) {
        if self.messages.len() < MAX_MESSAGE_RECORDS {
            self.messages.push(m);
        } else {
            self.summary.messages_over_cap += 1;
        }
    }

    /// A Catalog chunk: the processes the following chunksets refer to.
    pub(crate) fn catalog(&mut self, catalog: &Catalog) {
        self.catalog = catalog.clone();
        for uuid in &catalog.uuids {
            self.ensure(uuid);
        }
    }

    /// A continuous time on this file's boot, as a wall clock.
    fn date(&self, ct: u64) -> (Option<i64>, Option<TimeSource>) {
        if let Some(b) = &self.boot {
            // The last anchor at or before the time; before the first anchor,
            // the boot itself (continuous time zero).
            let (a_ct, a_wall) = b
                .anchors
                .iter()
                .rev()
                .find(|a| a.continuous_time <= ct)
                .map_or((0, b.boot_time_ns), |a| (a.continuous_time, a.wall_time_ns));
            if let Some(ns) = to_wall_ns(
                ct,
                a_ct,
                a_wall,
                b.timebase_numerator,
                b.timebase_denominator,
            ) {
                return (Some(ns), Some(TimeSource::Timesync));
            }
        }
        if let Some(h) = &self.header {
            if let Some(ns) = to_wall_ns(
                ct,
                h.continuous_time,
                h.wall_time_ns,
                h.timebase_numerator,
                h.timebase_denominator,
            ) {
                return (Some(ns), Some(TimeSource::TraceHeader));
            }
        }
        (None, None)
    }

    fn note_unresolved(&mut self, reason: &str) {
        self.summary.unresolved += 1;
        let r = &mut self.summary.unresolved_reasons;
        if let Some(n) = r.get_mut(reason) {
            *n += 1;
        } else if r.len() < MAX_REASONS {
            r.insert(reason.to_string(), 1);
        } else {
            *r.entry("(further reasons not listed)".into()).or_default() += 1;
        }
    }

    /// One firehose entry's tracepoints.
    pub(crate) fn firehose(&mut self, chunk: &FirehoseChunk) {
        for t in &chunk.tracepoints {
            let m = self.message(chunk, t);
            if self.messages.len() < MAX_MESSAGE_RECORDS {
                if let (Some(r), Some(f)) = (t.oversize_ref, &m.format) {
                    self.pending.push((
                        self.messages.len(),
                        (chunk.first_proc_id, chunk.second_proc_id, r),
                        f.clone(),
                    ));
                }
                self.messages.push(m);
            } else {
                self.summary.messages_over_cap += 1;
            }
        }
    }

    fn message(&mut self, chunk: &FirehoseChunk, t: &Tracepoint) -> Message {
        let (wall_time_ns, time_source) = self.date(t.continuous_time);
        let mut m = Message {
            continuous_time: t.continuous_time,
            wall_time_ns,
            time_source,
            activity_type: t.activity_type,
            log_type: t.log_type,
            thread_id: t.thread_id,
            flaw: t.flaw.clone(),
            oversize_ref: t.oversize_ref,
            private_arguments: t
                .items
                .iter()
                .filter(|i| i.value == ItemValue::Private)
                .count(),
            ..Message::default()
        };
        if t.activity_type == LOSS {
            self.summary.loss_records += 1;
            m.lost_entries = t.loss.as_ref().map(|l| l.count);
            return m;
        }
        let r = resolve(
            t,
            chunk.first_proc_id,
            chunk.second_proc_id,
            &self.catalog,
            &self.set,
        );
        m.pid = r.pid;
        m.euid = r.euid;
        m.process_path = r.process_path;
        m.process_uuid = r.process_uuid;
        m.image_path = r.image_path;
        m.image_uuid = r.image_uuid;
        m.subsystem = r.subsystem;
        m.category = r.category;
        m.dynamic = r.dynamic;
        match r.format {
            Some(f) => {
                if r.dynamic {
                    self.summary.dynamic += 1;
                } else {
                    self.summary.resolved += 1;
                }
                let text = render(&f, &t.items);
                self.summary.rendered_raw += text.rendered_raw;
                m.rendered_raw = text.rendered_raw;
                m.missing_arguments = text.missing_arguments;
                m.text = Some(text.text);
                m.format = Some(f);
            }
            None => {
                let reason = if self.summary.tree_reachable {
                    r.unresolved
                        .unwrap_or_else(|| "the reference was not followed".into())
                } else {
                    "the catalogue tree (uuidtext and dsc) was not found beside this file, so \
                     no format string could be looked up"
                        .into()
                };
                self.note_unresolved(&reason);
                m.unresolved = Some(reason);
            }
        }
        m
    }
}

/// The name Apple gives an activity type.
pub(crate) fn activity_type_name(t: u8) -> &'static str {
    match t {
        ACTIVITY => "activity",
        TRACE => "trace",
        LOG => "log",
        SIGNPOST => "signpost",
        LOSS => "loss",
        _ => "unknown",
    }
}

/// The name Apple gives a log message's level, for log entries.
pub(crate) fn log_level_name(activity_type: u8, log_type: u8) -> Option<&'static str> {
    if activity_type != LOG {
        return None;
    }
    Some(match log_type {
        0x00 => "default",
        0x01 => "info",
        0x02 => "debug",
        0x10 => "error",
        0x11 => "fault",
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firehose::parse_firehose;
    use crate::unifiedlog_chunks::{
        decompress_chunkset, parse_catalog, walk_entries, TAG_FIREHOSE, TAG_OVERSIZE,
        TAG_SIMPLEDUMP, TAG_STATEDUMP,
    };
    use crate::unifiedlog_dumps::{parse_simpledump, parse_statedump};
    use seance_core::data_source::{ByteSliceDataSource, FileDataSource};
    use std::path::Path;

    fn corpus() -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default())
            .join("forensic_corpora/mandiant_unifiedlogs/test_data")
    }

    /// Walk a file's chunks through a decoder, as the module does.
    fn drive(file: &[u8], d: &mut Decoder) {
        let mut off = 0usize;
        while off + 16 <= file.len() {
            let tag = u32::from_le_bytes(file[off..off + 4].try_into().unwrap());
            let size = u64::from_le_bytes(file[off + 8..off + 16].try_into().unwrap()) as usize;
            let body = &file[off + 16..off + 16 + size];
            match tag {
                0x1000 => d.header(body),
                0x600b => d.catalog(&parse_catalog(body).unwrap()),
                0x600d => {
                    let bytes = decompress_chunkset(body).unwrap();
                    for e in walk_entries(&bytes).entries {
                        if e.tag == TAG_FIREHOSE {
                            d.firehose(&parse_firehose(e.payload).unwrap());
                        } else if e.tag == TAG_OVERSIZE {
                            d.oversize(&crate::firehose::parse_oversize(e.payload).unwrap());
                        } else if e.tag == TAG_STATEDUMP {
                            d.statedump(&parse_statedump(e.payload).unwrap());
                        } else if e.tag == TAG_SIMPLEDUMP {
                            d.simpledump(&parse_simpledump(e.payload).unwrap());
                        }
                    }
                }
                _ => {}
            }
            off += 16 + size;
            off += (8 - off % 8) % 8;
        }
    }

    fn decode_path(path: &Path) -> Option<Decoder> {
        let file = std::fs::read(path).ok()?;
        let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path.to_path_buf()).ok()?);
        let mut d = Decoder::new(src).expect("a file can climb");
        drive(&file, &mut d);
        Some(d)
    }

    #[test]
    fn a_header_chunk_names_its_boot_and_its_clock() {
        // Built to the layout: timebase, continuous time, seconds, microseconds,
        // four u32 fields, then sub-chunks 0x6100 and 0x6102.
        let mut p = Vec::new();
        p.extend_from_slice(&125u32.to_le_bytes());
        p.extend_from_slice(&3u32.to_le_bytes());
        p.extend_from_slice(&1_000u64.to_le_bytes());
        p.extend_from_slice(&1_600_000_000u64.to_le_bytes());
        p.extend_from_slice(&250_000u32.to_le_bytes());
        p.extend_from_slice(&[0u8; 12]);
        p.extend_from_slice(&0x6100u32.to_le_bytes());
        p.extend_from_slice(&8u32.to_le_bytes());
        p.extend_from_slice(&[0u8; 8]);
        p.extend_from_slice(&0x6102u32.to_le_bytes());
        p.extend_from_slice(&24u32.to_le_bytes());
        p.extend_from_slice(&[0xAB; 16]);
        p.extend_from_slice(&[0u8; 8]);
        let h = parse_header(&p).expect("a header");
        assert_eq!((h.timebase_numerator, h.timebase_denominator), (125, 3));
        assert_eq!(h.wall_time_ns, 1_600_000_000_250_000_000);
        assert_eq!(
            h.boot_uuid.as_deref(),
            Some("ABABABABABABABABABABABABABABABAB")
        );
        // 3,000 ticks past the anchor at 125/3 ns per tick is 125,000 ns.
        assert_eq!(
            to_wall_ns(4_000, h.continuous_time, h.wall_time_ns, 125, 3),
            Some(1_600_000_000_250_125_000)
        );
    }

    #[test]
    fn a_source_that_cannot_climb_is_not_given_a_decoder() {
        let bytes: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0; 16]));
        assert!(Decoder::new(bytes).is_none());
    }

    /// The Big Sur archive's Persist/4 decoded against its own tree, reached
    /// one directory up. The counts are Mandiant's reading of the same file,
    /// a comparison and not ground truth; the time is checked against the
    /// file's own header clock, a second, independent anchor.
    #[test]
    fn a_logarchive_file_decodes_against_the_tree_one_directory_up() {
        let root = corpus().join("system_logs_big_sur.logarchive");
        let Some(d) = decode_path(&root.join("Persist/0000000000000004.tracev3")) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let s = &d.summary;
        assert!(s.tree_reachable);
        assert_eq!(s.layout, Some(Layout::LogArchive));
        assert_eq!(s.catalogue_files_unparsed, 0);
        assert!(
            s.boot_in_timesync,
            "the header's boot is in the archive's timesync"
        );
        assert_eq!(
            (s.resolved, s.dynamic, s.unresolved, s.loss_records),
            (110_836, 108, 8, 1)
        );
        assert_eq!(d.messages.len(), 110_953);
        let first = d
            .messages
            .iter()
            .find(|m| m.text.is_some())
            .expect("a rendered message");
        assert_eq!(
            first.text.as_deref(),
            Some("opendirectoryd (build 796.100) launched...")
        );
        assert_eq!(first.pid, Some(105));
        assert_eq!(first.subsystem.as_deref(), Some("com.apple.opendirectoryd"));
        assert_eq!(first.time_source, Some(TimeSource::Timesync));
        let header = d.header.clone().expect("a header");
        let by_header = to_wall_ns(
            first.continuous_time,
            header.continuous_time,
            header.wall_time_ns,
            header.timebase_numerator,
            header.timebase_denominator,
        )
        .unwrap();
        let by_timesync = first.wall_time_ns.expect("dated");
        assert!(
            (by_header - by_timesync).abs() < 2_000_000_000,
            "the timesync date {by_timesync} and the header's {by_header} agree within 2 s"
        );
        assert_eq!(
            crate::to_rfc3339_nanos(
                by_timesync.div_euclid(1_000_000_000),
                by_timesync.rem_euclid(1_000_000_000) as u32
            )
            .as_deref(),
            Some(FIRST_MESSAGE_TIME)
        );
        // Every message is dated, and every unresolved one says why.
        assert!(d.messages.iter().all(|m| m.wall_time_ns.is_some()));
        assert!(d
            .messages
            .iter()
            .all(|m| m.text.is_some() || m.unresolved.is_some() || m.lost_entries.is_some()));
    }

    /// Read through the archive's timesync, and checked against the file's
    /// header clock above; not an answer key from another tool.
    const FIRST_MESSAGE_TIME: &str = "2022-01-16T03:32:13.964503310+00:00";

    /// The same evidence laid out as a live system — `diagnostics/Persist/…`
    /// with `uuidtext/` beside `diagnostics/` — decodes the same, through the
    /// two-level climb.
    #[test]
    fn a_diagnostics_layout_reaches_uuidtext_two_directories_up() {
        let root = corpus().join("system_logs_big_sur.logarchive");
        if !root.is_dir() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let db = tmp.path().join("db");
        std::fs::create_dir_all(db.join("diagnostics/Persist")).unwrap();
        std::os::unix::fs::symlink(&root, db.join("uuidtext")).unwrap();
        std::os::unix::fs::symlink(root.join("timesync"), db.join("diagnostics/timesync")).unwrap();
        let log = db.join("diagnostics/Persist/0000000000000004.tracev3");
        std::os::unix::fs::symlink(root.join("Persist/0000000000000004.tracev3"), &log).unwrap();
        let d = decode_path(&log).unwrap();
        assert_eq!(d.summary.layout, Some(Layout::Diagnostics));
        assert!(d.summary.boot_in_timesync);
        assert_eq!(
            (d.summary.resolved, d.summary.dynamic, d.summary.unresolved),
            (110_836, 108, 8)
        );
    }

    /// `logdata.LiveData.tracev3` sits at the archive's root, beside the
    /// catalogue rather than one directory below it: it reaches the tree with
    /// no climb, and its boot in `timesync/` beside it.
    #[test]
    fn a_file_at_the_archive_root_reaches_the_tree_beside_it() {
        let live = corpus().join("system_logs_big_sur.logarchive/logdata.LiveData.tracev3");
        let Some(d) = decode_path(&live) else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        assert!(d.summary.tree_reachable);
        assert_eq!(d.summary.layout, Some(Layout::LogArchive));
        assert_eq!(d.summary.levels_up, Some(0));
        assert!(d.summary.boot_in_timesync);
        assert!(d.summary.resolved > 0);
        assert!(d.messages.iter().all(|m| m.wall_time_ns.is_some()));
    }

    /// The Big Sur archive rebuilt with every entry but `timesync/` linked in,
    /// and its one timesync file given the sequence name `timesync_name`.
    fn archive_with_timesync_named(timesync_name: &str) -> Option<tempfile::TempDir> {
        let root = corpus().join("system_logs_big_sur.logarchive");
        if !root.is_dir() {
            return None;
        }
        let tmp = tempfile::tempdir().unwrap();
        let arch = tmp.path().join("copy.logarchive");
        std::fs::create_dir_all(arch.join("timesync")).unwrap();
        for e in std::fs::read_dir(&root).unwrap().flatten() {
            if e.file_name() != "timesync" {
                std::os::unix::fs::symlink(e.path(), arch.join(e.file_name())).unwrap();
            }
        }
        std::os::unix::fs::symlink(
            root.join("timesync/0000000000000002.timesync"),
            arch.join("timesync").join(timesync_name),
        )
        .unwrap();
        Some(tmp)
    }

    /// A long-lived Mac rotates its timesync files: the oldest are deleted
    /// and the survivors keep their sequence names, so the first file present
    /// can be far along the sequence. The directory is listed, not probed
    /// from zero (HUNT-272), so a file at 0x1f4 — past any fixed run of misses
    /// and past the old 256-name probe — is still found. The file is the
    /// archive's own timesync under another name; what is pinned is the reach,
    /// not the reading.
    #[test]
    fn a_timesync_file_far_along_its_sequence_is_found_by_listing() {
        let Some(tmp) = archive_with_timesync_named("00000000000001f4.timesync") else {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        };
        let log = tmp
            .path()
            .join("copy.logarchive/Persist/0000000000000004.tracev3");
        let d = decode_path(&log).unwrap();
        assert!(
            d.summary.boot_in_timesync,
            "the boot is in 00000000000001f4.timesync"
        );
        assert_eq!(d.summary.timesync_files, 1);
        assert_eq!(d.summary.timesync_found_by, Some("listing"));
        assert!(d
            .messages
            .iter()
            .all(|m| m.time_source == Some(TimeSource::Timesync)));
    }

    /// A tracepoint too large for its firehose entry keeps its arguments in
    /// an oversize entry; across the Big Sur archive those are joined back
    /// within each file, and the ones whose entry is in another file say so.
    #[test]
    fn oversize_arguments_are_joined_to_their_messages() {
        let root = corpus().join("system_logs_big_sur.logarchive");
        if !root.is_dir() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let mut stack = vec![root];
        let (mut entries, mut flawed, mut joined, mut absent) = (0, 0, 0, 0);
        let mut example = None;
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "tracev3") {
                    continue;
                }
                let mut d = decode_path(&p).unwrap();
                d.finish();
                entries += d.summary.oversize_entries;
                flawed += d.summary.oversize_entries_flawed;
                joined += d.summary.oversize_joined;
                absent += d.summary.oversize_not_in_file;
                let with = d
                    .messages
                    .iter()
                    .filter(|m| m.arguments_from_oversize)
                    .count();
                assert_eq!(
                    with,
                    d.summary.oversize_joined + d.summary.oversize_joined_from_tree,
                    "{p:?}"
                );
                if example.is_none() {
                    example = d
                        .messages
                        .iter()
                        .find(|m| m.arguments_from_oversize && m.missing_arguments == 0)
                        .and_then(|m| m.text.clone());
                }
            }
        }
        assert_eq!((entries, flawed, joined, absent), BIG_SUR_OVERSIZE);
        assert!(
            example.is_some(),
            "a message rendered from its oversize entry"
        );
    }

    /// HUNT-271: the log may write a tracepoint's oversize entry to another
    /// `.tracev3` of the same boot. Across the Big Sur archive, the messages
    /// whose entry is not in their own file are looked for in every other
    /// `.tracev3` of the tree (listed, not guessed), keyed by boot as well as
    /// by process and reference; each one joined names the file it came
    /// from, and the ones found nowhere say so.
    #[test]
    fn an_oversize_entry_in_another_file_of_the_tree_is_joined() {
        let root = corpus().join("system_logs_big_sur.logarchive");
        if !root.is_dir() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let mut stack = vec![root.clone()];
        let (mut not_in_file, mut from_tree, mut not_in_tree, mut named) = (0, 0, 0, 0);
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "tracev3") {
                    continue;
                }
                let mut d = decode_path(&p).unwrap();
                d.finish();
                let s = &d.summary;
                not_in_file += s.oversize_not_in_file;
                from_tree += s.oversize_joined_from_tree;
                not_in_tree += s.oversize_not_in_tree;
                assert_eq!(
                    s.oversize_joined_from_tree + s.oversize_not_in_tree,
                    s.oversize_not_in_file,
                    "{p:?}"
                );
                if s.oversize_not_in_file > 0 {
                    assert!(s.oversize_tree_listed, "{p:?}");
                    assert_eq!(s.oversize_tree_files_unread, 0, "{p:?}");
                }
                let own = p
                    .strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned();
                for m in &d.messages {
                    if let Some(f) = &m.oversize_from_file {
                        assert_ne!(f, &own, "joined from another file");
                        assert!(m.arguments_from_oversize);
                        named += 1;
                    }
                }
            }
        }
        assert_eq!(named, from_tree);
        assert_eq!((not_in_file, from_tree, not_in_tree), BIG_SUR_CROSS_FILE);
    }

    /// Big Sur archive, as read: (messages whose oversize entry is not in
    /// their file, of them joined from another file of the tree, found in
    /// none).
    const BIG_SUR_CROSS_FILE: (usize, usize, usize) = (23, 23, 0);

    /// A missing oversize entry says where it was looked for. When the
    /// tree's root is not known, or its directories could not be listed, or
    /// some of its files could not be read, the record says it could not
    /// look (or could not look everywhere) rather than "not found".
    #[test]
    fn a_missing_oversize_entry_says_whether_the_tree_could_be_searched() {
        let none = oversize_missing_detail(7, None);
        assert!(none.contains("oversize entry 7"), "{none}");
        assert!(none.contains("could not be looked in"), "{none}");

        let unlisted = TreeOversize::default();
        let d = oversize_missing_detail(7, Some(&unlisted));
        assert!(d.contains("could not be listed"), "{d}");
        assert!(!d.contains("found in none"), "{d}");

        let searched = TreeOversize {
            listed: true,
            files_read: 12,
            ..TreeOversize::default()
        };
        let d = oversize_missing_detail(7, Some(&searched));
        assert!(d.contains("found in none of the 12"), "{d}");
        assert!(!d.contains("could not"), "{d}");

        let partly = TreeOversize {
            listed: true,
            files_read: 12,
            files_unread: 2,
            ..TreeOversize::default()
        };
        let d = oversize_missing_detail(7, Some(&partly));
        assert!(d.contains("found in none of the 12"), "{d}");
        assert!(d.contains("2 could not be read"), "{d}");
    }

    /// A loss record whose body is cut short never gave its count: the
    /// message carries no count rather than a zero it did not read.
    #[test]
    fn a_loss_record_whose_count_was_not_read_states_no_count() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("Persist");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("0000000000000001.tracev3");
        std::fs::write(&path, [0u8; 16]).unwrap();
        let src: Arc<dyn DataSource> = Arc::new(FileDataSource::new(path).unwrap());
        let mut d = Decoder::new(src).expect("a file can climb");
        let t = Tracepoint {
            activity_type: LOSS,
            log_type: 0,
            flags: 0,
            format_offset: 0,
            thread_id: 0,
            continuous_time: 0,
            pc_id: None,
            location: crate::firehose::FormatLocation::NotApplicable,
            subsystem_id: None,
            activity_id: None,
            unique_pid: None,
            signpost_id: None,
            signpost_name: None,
            oversize_ref: None,
            items: Vec::new(),
            backtrace_frames: 0,
            loss: None,
            flaw: Some("the loss record ends before its count".into()),
        };
        d.firehose(&FirehoseChunk {
            tracepoints: vec![t],
            ..FirehoseChunk::default()
        });
        assert_eq!(d.messages.len(), 1);
        assert_eq!(d.messages[0].lost_entries, None);
        assert_eq!(d.summary.loss_records, 1);
    }

    /// Statedump and simpledump entries are messages of their own: across
    /// the Big Sur archive each is decoded, dated and attributed to its
    /// process, and tracepoints plus dumps equal the archive's total that
    /// Mandiant's tests pin (747,616) — a comparison, not ground truth.
    #[test]
    fn statedumps_and_simpledumps_are_messages_of_their_own() {
        let root = corpus().join("system_logs_big_sur.logarchive");
        if !root.is_dir() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let mut stack = vec![root];
        let (mut tracepoints, mut states, mut simples, mut undecoded, mut flawed) = (0, 0, 0, 0, 0);
        let mut titled = 0;
        while let Some(dir) = stack.pop() {
            for e in std::fs::read_dir(&dir).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "tracev3") {
                    continue;
                }
                let d = decode_path(&p).unwrap();
                let s = &d.summary;
                tracepoints += s.resolved + s.dynamic + s.unresolved + s.loss_records;
                states += s.statedumps;
                simples += s.simpledumps;
                undecoded += s.statedump_data_not_decoded;
                flawed += s.dumps_not_read_whole;
                for m in d.messages.iter().filter(|m| !m.dump_kind.is_empty()) {
                    assert!(m.wall_time_ns.is_some());
                    assert!(m.text.as_deref().is_some_and(|t| !t.is_empty()));
                    if m.dump_kind == "statedump" && m.extra["title"].is_string() {
                        titled += 1;
                    }
                }
            }
        }
        assert_eq!(tracepoints + states + simples, 747_616);
        assert_eq!((states, simples, undecoded, flawed), BIG_SUR_DUMPS);
        assert!(titled > 0);
    }

    /// Big Sur archive, as read: (statedumps, simpledumps, statedumps whose
    /// data is not decoded, dumps not read whole).
    const BIG_SUR_DUMPS: (usize, usize, usize, usize) = (322, 0, 66, 0);

    /// Big Sur archive, as read: (oversize entries, of them less than whole,
    /// messages joined to one, messages whose one is not in their file).
    const BIG_SUR_OVERSIZE: (usize, usize, usize, usize) = (1_300, 0, 1_259, 23);

    /// A lone `.tracev3` whose tree is not beside it: every message is
    /// unresolved with the reason, none is rendered empty, and the dates come
    /// from the header, labelled so.
    #[test]
    fn a_file_without_its_tree_says_unresolved_and_dates_by_its_header() {
        let src = corpus().join("system_logs_big_sur.logarchive/Persist/0000000000000004.tracev3");
        if !src.is_file() {
            eprintln!("skipping: the Mandiant unified-log corpus is not present");
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(tmp.path().join("x/Persist")).unwrap();
        let lone = tmp.path().join("x/Persist/lone.tracev3");
        std::fs::copy(&src, &lone).unwrap();
        let d = decode_path(&lone).unwrap();
        assert!(!d.summary.tree_reachable);
        assert_eq!(d.summary.resolved + d.summary.dynamic, 0);
        assert!(d.summary.unresolved > 0);
        assert!(d.messages.iter().all(|m| m.text.is_none()));
        assert!(d
            .messages
            .iter()
            .filter(|m| m.lost_entries.is_none())
            .all(|m| m.unresolved.as_deref().is_some_and(|r| !r.is_empty())));
        assert!(d
            .messages
            .iter()
            .all(|m| m.time_source == Some(TimeSource::TraceHeader)));
    }
}
