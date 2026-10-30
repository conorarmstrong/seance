//! EWF logical evidence files (`.L01`): walking the file-entry tree libewf
//! reads, and serving one entry's bytes (HUNT-144).
//!
//! A logical evidence file holds files and their metadata, not an image of a
//! device. libewf parses the L01's entry table (the `ltree` section) itself and
//! exposes it as a tree of `libewf_file_entry_t`; this module walks that tree
//! and describes every entry, and reads an entry's bytes through
//! `libewf_file_entry_read_random`, so the bytes an examiner is handed are the
//! ones libewf attributes to that entry — never a guess at an offset into the
//! media stream made on this side.
//!
//! # Shape
//!
//! The walk is written once, generically, over [`EntryNode`], and driven by the
//! libewf-backed node in [`E01DataSource::walk_logical`](crate::E01DataSource)
//! — in the isolated helper by default, in process when isolation is off. The
//! generic form is what lets the caps be tested without a C library or an L01.
//!
//! # Bounds
//!
//! The entry table is attacker-controlled, and a hostile one can claim any
//! number of entries at any depth. The walk is iterative (an explicit stack, so
//! depth cannot overflow the thread stack), holds at most one libewf entry per
//! level of the current path, and stops at [`MAX_L01_ENTRIES`] entries and
//! [`MAX_L01_DEPTH`] levels. Reaching either is **stated on the record**
//! ([`LogicalWalk::entry_cap_reached`], [`LogicalWalk::depth_cap_reached`], and
//! how many entries libewf listed that were not visited), never silent.

use serde::{Deserialize, Serialize};

/// The most entries one walk describes. A targeted logical collection is
/// usually thousands of entries (the NGDC 2012 phone L01s hold 9,952 to 14,804);
/// a million leaves room for whole-profile collections while bounding what a
/// hostile entry table can make either process hold.
pub const MAX_L01_ENTRIES: usize = 1_000_000;

/// The deepest level the walk descends to, the root being level 0. Real
/// collections are a few dozen levels deep at most (the NGDC phone L01s reach
/// 13); anything deeper is described down to this level and the entries below
/// it are counted as not walked.
pub const MAX_L01_DEPTH: usize = 256;

/// The two ceilings a walk runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WalkLimits {
    pub max_entries: usize,
    pub max_depth: usize,
}

impl Default for WalkLimits {
    fn default() -> Self {
        Self {
            max_entries: MAX_L01_ENTRIES,
            max_depth: MAX_L01_DEPTH,
        }
    }
}

/// libewf's `LIBEWF_FILE_ENTRY_TYPE_DIRECTORY` (`'d'`), from
/// `/usr/include/libewf/definitions.h`. The enum has no `libewf_`-prefixed
/// typedef, so this build's bindgen allowlist does not surface it (the same
/// caveat as `ewf_format_name`).
pub const ENTRY_TYPE_DIRECTORY: u8 = b'd';
/// libewf's `LIBEWF_FILE_ENTRY_TYPE_FILE` (`'f'`).
pub const ENTRY_TYPE_FILE: u8 = b'f';
/// libewf's `LIBEWF_FILE_ENTRY_FLAG_SPARSE_DATA`: the entry's data was not
/// stored in the L01 (EnCase records the entry without its content).
pub const ENTRY_FLAG_SPARSE_DATA: u32 = 0x0400_0000;

/// What libewf says about one entry. Every field libewf was asked for and
/// would not answer is `None`, with libewf's own words in `errors`: a value
/// that could not be read is not a value of zero.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFacts {
    /// The recorded name, `None` when libewf would not give one.
    pub name: Option<String>,
    /// `true` when the name libewf returned was not valid UTF-8 and was
    /// converted lossily.
    pub name_lossy: bool,
    /// libewf's entry type byte: `'d'` directory, `'f'` file.
    pub entry_type: Option<u8>,
    pub flags: Option<u32>,
    /// The logical size libewf reports for the entry.
    pub size: Option<u64>,
    pub media_data_offset: Option<i64>,
    pub media_data_size: Option<u64>,
    pub duplicate_media_data_offset: Option<i64>,
    /// The four times an L01 records, each a POSIX timestamp as libewf returns
    /// it, under libewf's own names.
    pub creation_time: Option<u32>,
    pub modification_time: Option<u32>,
    pub access_time: Option<u32>,
    pub entry_modification_time: Option<u32>,
    /// The MD5 the L01 stores for this entry, when it stores one.
    pub md5: Option<String>,
    /// HUNT-250: for an entry recording size 0 and storing one byte (the
    /// form EnCase writes for 609-745 directories per NGDC file), that byte
    /// as read from the media stream at `media_data_offset`. `None` when the
    /// entry is not of that form or the read failed (the failure is in
    /// `errors` as `placeholder_byte: ...`). What the byte means is not
    /// established; it is recorded, never presented as content.
    #[serde(default)]
    pub placeholder_byte: Option<u8>,
    /// Field-level failures, `"<field>: <libewf message>"`.
    pub errors: Vec<String>,
}

/// One entry as the walk found it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalEntry {
    /// The child index at each level from the root to this entry; the root is
    /// `[]`. This, not the name, is the entry's identity: sibling names are
    /// not guaranteed unique, and it is how a read finds the entry again.
    pub index_path: Vec<u32>,
    /// The position of the parent in [`LogicalWalk::entries`]; `None` for the
    /// root. Entries are in pre-order, so a parent always precedes its children.
    pub parent: Option<u32>,
    pub depth: u32,
    pub facts: EntryFacts,
    /// How many sub-entries libewf reports, `None` if it would not say.
    pub sub_entries: Option<u32>,
    /// Sub-entries libewf listed that the walk did not visit because a cap was
    /// reached at or below this entry.
    pub sub_entries_not_walked: u32,
}

/// The result of one walk.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogicalWalk {
    /// `false` when libewf reported no root entry at all (an L01 with an empty
    /// entry table), which is a different answer from a root with no children.
    pub root_present: bool,
    pub entries: Vec<LogicalEntry>,
    pub limits: Option<WalkLimits>,
    pub entry_cap_reached: bool,
    pub depth_cap_reached: bool,
    /// Entries libewf listed that were not visited because a cap was reached.
    /// A lower bound when the entry cap fired: sub-trees below an unvisited
    /// entry are not counted, because counting them would mean walking them.
    pub entries_not_walked: u64,
    /// Failures that cost the walk entries: a sub-entry libewf listed and then
    /// would not hand over, or a count it would not give.
    pub errors: Vec<String>,
}

impl LogicalWalk {
    /// `true` when anything libewf listed is missing from [`Self::entries`].
    pub fn is_incomplete(&self) -> bool {
        self.entry_cap_reached
            || self.depth_cap_reached
            || self.entries_not_walked > 0
            || !self.errors.is_empty()
    }
}

impl EntryFacts {
    /// `true` for the one-byte placeholder form: a recorded size of 0 with
    /// exactly one byte stored at a known media offset.
    pub fn is_placeholder_form(&self) -> bool {
        self.size == Some(0)
            && self.media_data_size == Some(1)
            && self.media_data_offset.is_some_and(|o| o >= 0)
    }
}

/// HUNT-250: read the one stored byte of every placeholder-form entry through
/// `read_byte(media_offset)`, recording it in `placeholder_byte`, or the
/// reader's failure in the entry's `errors` as `placeholder_byte: <msg>`.
pub fn record_placeholder_bytes(
    walk: &mut LogicalWalk,
    mut read_byte: impl FnMut(i64) -> Result<u8, String>,
) {
    for entry in &mut walk.entries {
        let facts = &mut entry.facts;
        if !facts.is_placeholder_form() {
            continue;
        }
        let Some(offset) = facts.media_data_offset else {
            continue;
        };
        match read_byte(offset) {
            Ok(byte) => facts.placeholder_byte = Some(byte),
            Err(e) => facts.errors.push(format!("placeholder_byte: {e}")),
        }
    }
}

/// HUNT-250: what a walk's stored spans establish about each entry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredSpans {
    /// Per walked entry, in walk order: whether its stored span shares a byte
    /// with another known span (see [`stored_spans`]).
    pub shares: Vec<bool>,
    /// Walked entries whose span is not known: libewf would not give its
    /// media offset or size (or, for a sparse entry, its duplicate offset), or
    /// it stores data at no usable offset. While this is non-zero, no entry
    /// can be said to share no byte with another: the unknown span could
    /// cover it. `false` in `shares` then means "not found", not "none".
    pub unknown: usize,
}

/// HUNT-250: for each walked entry, in walk order, whether a span of its
/// shares any byte with another walked entry's span; and how many walked
/// entries have a span that is not known.
///
/// An entry's spans are what libewf reads for it from the media stream: its
/// stored data (`media_data_offset .. + media_data_size`) and, for an entry
/// flagged sparse that names a duplicate data offset, the read there of as
/// many bytes as its recorded size. Spans that merely abut share nothing.
/// An entry that stores nothing and reads nothing has no span to share.
///
/// Only the walked entries are compared, so on an incomplete walk the answer
/// covers what was walked; and while [`StoredSpans::unknown`] is non-zero no
/// entry can be said to share nothing. The caller must not state either as a
/// fact about the file.
pub fn stored_spans(walk: &LogicalWalk) -> StoredSpans {
    let mut shares = vec![false; walk.entries.len()];
    let mut unknown = 0usize;
    // (start, end, ordinal) of every known span, sorted by start.
    let mut spans: Vec<(u64, u64, usize)> = Vec::new();
    for (i, e) in walk.entries.iter().enumerate() {
        match entry_spans(&e.facts) {
            Some(found) => spans.extend(found.into_iter().map(|(s, end)| (s, end, i))),
            None => unknown += 1,
        }
    }
    spans.sort_unstable();
    // Sorted by start, a span shares bytes with an earlier-starting one iff
    // the furthest end seen so far passes its start, and with a later one iff
    // the next span starts before it ends.
    let mut furthest_end = 0u64;
    for k in 0..spans.len() {
        let (start, end, ordinal) = spans[k];
        let with_earlier = k > 0 && furthest_end > start;
        let with_later = spans.get(k + 1).is_some_and(|next| next.0 < end);
        if with_earlier || with_later {
            shares[ordinal] = true;
        }
        furthest_end = furthest_end.max(end);
    }
    StoredSpans { shares, unknown }
}

/// The media-stream spans libewf reads for one entry, `None` when they are
/// not known (see [`stored_spans`]).
fn entry_spans(facts: &EntryFacts) -> Option<Vec<(u64, u64)>> {
    let failed = |field: &str| {
        let prefix = format!("{field}:");
        facts.errors.iter().any(|e| e.starts_with(&prefix))
    };
    if failed("media_data_offset") || failed("media_data_size") {
        return None;
    }
    let known_offset = |o: Option<i64>| o.and_then(|o| u64::try_from(o).ok());
    let span = |start: u64, len: u64| (start, start.saturating_add(len));
    let mut found = Vec::new();
    match (facts.media_data_offset, facts.media_data_size) {
        (_, Some(0)) | (None, None) => {}
        (off, Some(len)) => found.push(span(known_offset(off)?, len)),
        // An offset with no size stored says nothing of where the data ends.
        (Some(_), None) => return None,
    }
    // A sparse entry naming a duplicate data offset is read there. Flags
    // libewf would not give leave open whether the entry is sparse.
    let sparse = match facts.flags {
        Some(f) => f & ENTRY_FLAG_SPARSE_DATA != 0,
        None => {
            facts.duplicate_media_data_offset.is_some() || failed("duplicate_media_data_offset")
        }
    };
    if sparse {
        if facts.flags.is_none() || failed("duplicate_media_data_offset") {
            return None;
        }
        // A negative or absent duplicate offset is not read: libewf serves
        // the one stored byte repeated instead.
        if let Some(du) = known_offset(facts.duplicate_media_data_offset) {
            match facts.size {
                Some(0) => {}
                Some(n) => found.push(span(du, n)),
                None => return None,
            }
        }
    }
    Some(found)
}

/// An entry the walk can describe and descend into.
pub trait EntryNode: Sized {
    fn facts(&self) -> EntryFacts;
    fn sub_entry_count(&self) -> Result<u32, String>;
    fn sub_entry(&self, index: u32) -> Result<Self, String>;
}

struct Frame<N> {
    node: N,
    /// Position of this node's entry in `walk.entries`.
    entry: usize,
    index_path: Vec<u32>,
    depth: usize,
    next: u32,
    count: u32,
}

/// Walk the tree below `root` in pre-order, within `limits`.
///
/// Iterative: the only state per level is one [`Frame`], and a frame's node is
/// dropped (for libewf, freed) as soon as its sub-entries are done.
pub fn walk<N: EntryNode>(root: Option<N>, limits: WalkLimits) -> LogicalWalk {
    let mut walk = LogicalWalk {
        limits: Some(limits),
        ..LogicalWalk::default()
    };
    let Some(root) = root else {
        return walk;
    };
    walk.root_present = true;
    if limits.max_entries == 0 {
        walk.entry_cap_reached = true;
        walk.entries_not_walked = 1;
        return walk;
    }

    let mut stack: Vec<Frame<N>> = Vec::new();
    let root_entry = push_entry(&mut walk, &root, Vec::new(), None, 0);
    let count = open_sub_entries(&mut walk, &root, root_entry, 0, limits);
    stack.push(Frame {
        node: root,
        entry: root_entry,
        index_path: Vec::new(),
        depth: 0,
        next: 0,
        count,
    });

    while let Some(top) = stack.last_mut() {
        if top.next >= top.count {
            stack.pop();
            continue;
        }
        if walk.entries.len() >= limits.max_entries {
            // Everything still listed on the stack is unvisited.
            walk.entry_cap_reached = true;
            for frame in &stack {
                let remaining = frame.count - frame.next;
                walk.entries_not_walked += u64::from(remaining);
                walk.entries[frame.entry].sub_entries_not_walked += remaining;
            }
            break;
        }
        let index = top.next;
        top.next += 1;
        let parent_entry = top.entry;
        let depth = top.depth + 1;
        let mut index_path = top.index_path.clone();
        index_path.push(index);
        let child = match top.node.sub_entry(index) {
            Ok(child) => child,
            Err(e) => {
                walk.errors.push(format!(
                    "sub-entry {index} of entry {:?}: libewf listed it and would not hand it over: {e}",
                    top.index_path
                ));
                walk.entries_not_walked += 1;
                walk.entries[parent_entry].sub_entries_not_walked += 1;
                continue;
            }
        };
        let entry = push_entry(
            &mut walk,
            &child,
            index_path.clone(),
            Some(parent_entry),
            depth,
        );
        let count = open_sub_entries(&mut walk, &child, entry, depth, limits);
        if count > 0 {
            stack.push(Frame {
                node: child,
                entry,
                index_path,
                depth,
                next: 0,
                count,
            });
        }
    }
    walk
}

fn push_entry<N: EntryNode>(
    walk: &mut LogicalWalk,
    node: &N,
    index_path: Vec<u32>,
    parent: Option<usize>,
    depth: usize,
) -> usize {
    walk.entries.push(LogicalEntry {
        index_path,
        parent: parent.map(|p| p as u32),
        depth: depth as u32,
        facts: node.facts(),
        sub_entries: None,
        sub_entries_not_walked: 0,
    });
    walk.entries.len() - 1
}

/// Ask for `node`'s sub-entry count, record it, and return how many of them
/// the walk will visit — none past the depth cap.
fn open_sub_entries<N: EntryNode>(
    walk: &mut LogicalWalk,
    node: &N,
    entry: usize,
    depth: usize,
    limits: WalkLimits,
) -> u32 {
    let count = match node.sub_entry_count() {
        Ok(c) => c,
        Err(e) => {
            walk.errors.push(format!(
                "entry {:?}: libewf would not give its sub-entry count, so none were walked: {e}",
                walk.entries[entry].index_path
            ));
            return 0;
        }
    };
    walk.entries[entry].sub_entries = Some(count);
    if count > 0 && depth + 1 > limits.max_depth {
        walk.depth_cap_reached = true;
        walk.entries_not_walked += u64::from(count);
        walk.entries[entry].sub_entries_not_walked += count;
        return 0;
    }
    count
}

/// Something that can read a walked entry's bytes, by the entry's position in
/// the walk: the isolated helper, or libewf in this process.
pub trait LogicalBackend: std::fmt::Debug + Send + Sync {
    fn read_entry(&self, ordinal: u32, offset: u64, buf: &mut [u8]) -> std::io::Result<usize>;
    /// Whether libewf runs in the helper subprocess for this backend.
    fn isolated(&self) -> bool;
}

/// libewf in this process: the fallback when isolation is off or the helper
/// binary is absent, exactly as for a physical image.
#[derive(Debug)]
pub struct InProcessLogicalBackend {
    source: crate::E01DataSource,
    index_paths: Vec<Vec<u32>>,
}

impl InProcessLogicalBackend {
    pub fn new(source: crate::E01DataSource, walk: &LogicalWalk) -> Self {
        Self {
            source,
            index_paths: walk.entries.iter().map(|e| e.index_path.clone()).collect(),
        }
    }
}

impl LogicalBackend for InProcessLogicalBackend {
    fn read_entry(&self, ordinal: u32, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        let path = self.index_paths.get(ordinal as usize).ok_or_else(|| {
            std::io::Error::other(format!(
                "no entry {ordinal}: the walk holds {}",
                self.index_paths.len()
            ))
        })?;
        self.source.read_logical_entry(path, offset, buf)
    }

    fn isolated(&self) -> bool {
        false
    }
}

/// One entry's bytes, as a [`DataSource`](seance_core::data_source::DataSource)
/// of the size the L01 records for it. Reads past that size end the stream;
/// a read libewf cannot serve is an error, never zeroes.
#[derive(Debug)]
pub struct LogicalEntrySource {
    backend: std::sync::Arc<dyn LogicalBackend>,
    ordinal: u32,
    size: u64,
}

impl LogicalEntrySource {
    pub fn new(backend: std::sync::Arc<dyn LogicalBackend>, ordinal: u32, size: u64) -> Self {
        Self {
            backend,
            ordinal,
            size,
        }
    }
}

impl seance_core::data_source::DataSource for LogicalEntrySource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
        if offset >= self.size || buf.is_empty() {
            return Ok(0);
        }
        let want = usize::try_from(self.size - offset)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        self.backend
            .read_entry(self.ordinal, offset, &mut buf[..want])
    }

    fn size(&self) -> u64 {
        self.size
    }
}

/// Render a POSIX timestamp as RFC 3339 UTC; `None` for 0, which is how an L01
/// says a time was not recorded rather than a claim of 1970-01-01.
pub fn posix_to_rfc3339(ts: u32) -> Option<String> {
    if ts == 0 {
        return None;
    }
    chrono::DateTime::<chrono::Utc>::from_timestamp(i64::from(ts), 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic tree: each node's children are generated from its path, so
    /// a tree of any breadth or depth costs nothing until it is walked.
    #[derive(Clone)]
    struct Fake {
        path: Vec<u32>,
        fanout: fn(&[u32]) -> Result<u32, String>,
        refuse_child: Option<Vec<u32>>,
    }

    impl EntryNode for Fake {
        fn facts(&self) -> EntryFacts {
            EntryFacts {
                name: Some(format!("n{:?}", self.path)),
                ..EntryFacts::default()
            }
        }
        fn sub_entry_count(&self) -> Result<u32, String> {
            (self.fanout)(&self.path)
        }
        fn sub_entry(&self, index: u32) -> Result<Self, String> {
            let mut path = self.path.clone();
            path.push(index);
            if self.refuse_child.as_ref() == Some(&path) {
                return Err("synthetic refusal".into());
            }
            Ok(Fake {
                path,
                fanout: self.fanout,
                refuse_child: self.refuse_child.clone(),
            })
        }
    }

    fn root(fanout: fn(&[u32]) -> Result<u32, String>) -> Option<Fake> {
        Some(Fake {
            path: vec![],
            fanout,
            refuse_child: None,
        })
    }

    /// Three levels of three: 1 + 3 + 9 + 27 = 40 entries, pre-order.
    fn three_by_three(p: &[u32]) -> Result<u32, String> {
        Ok(if p.len() < 3 { 3 } else { 0 })
    }

    /// A chain one entry wide and a million deep: a recursive walk would
    /// overflow the stack here, and an unbounded one would never stop.
    fn endless_chain(_: &[u32]) -> Result<u32, String> {
        Ok(1)
    }

    /// A root claiming four billion children — the count is attacker data.
    fn huge_fanout(p: &[u32]) -> Result<u32, String> {
        Ok(if p.is_empty() { u32::MAX } else { 0 })
    }

    #[test]
    fn an_uncapped_walk_visits_every_entry_in_pre_order_with_parents_first() {
        let w = walk(root(three_by_three), WalkLimits::default());
        assert_eq!(w.entries.len(), 40);
        assert!(!w.is_incomplete());
        assert_eq!(w.entries[0].index_path, Vec::<u32>::new());
        assert_eq!(w.entries[1].index_path, vec![0]);
        assert_eq!(w.entries[2].index_path, vec![0, 0]);
        assert_eq!(w.entries[3].index_path, vec![0, 0, 0]);
        for (i, e) in w.entries.iter().enumerate().skip(1) {
            let p = e.parent.expect("non-root has a parent") as usize;
            assert!(p < i, "a parent must precede its child");
            assert_eq!(
                w.entries[p].index_path[..],
                e.index_path[..e.index_path.len() - 1]
            );
            assert_eq!(e.depth as usize, e.index_path.len());
        }
    }

    #[test]
    fn the_depth_cap_stops_descent_and_counts_what_it_did_not_walk() {
        let w = walk(
            root(endless_chain),
            WalkLimits {
                max_entries: 10_000,
                max_depth: 5,
            },
        );
        // Levels 0..=5 are described; level 6 is listed and not visited.
        assert_eq!(w.entries.len(), 6);
        assert!(w.depth_cap_reached);
        assert!(!w.entry_cap_reached);
        assert_eq!(w.entries_not_walked, 1);
        assert_eq!(w.entries[5].sub_entries, Some(1));
        assert_eq!(w.entries[5].sub_entries_not_walked, 1);
        assert!(w.is_incomplete());
    }

    #[test]
    fn a_million_deep_chain_ends_at_the_default_depth_cap_without_recursion() {
        let w = walk(root(endless_chain), WalkLimits::default());
        assert_eq!(w.entries.len(), MAX_L01_DEPTH + 1);
        assert!(w.depth_cap_reached);
    }

    #[test]
    fn the_entry_cap_stops_the_walk_and_says_how_many_listed_entries_were_left() {
        let w = walk(
            root(three_by_three),
            WalkLimits {
                max_entries: 5,
                max_depth: 100,
            },
        );
        assert_eq!(w.entries.len(), 5);
        assert!(w.entry_cap_reached);
        // Pre-order: root, [0], [0,0], [0,0,0], [0,0,1]. Still listed and
        // unvisited: [0,0,2] (1), [0,1],[0,2] (2), [1],[2] (2) = 5.
        assert_eq!(w.entries_not_walked, 5);
        assert_eq!(w.entries[0].sub_entries_not_walked, 2);
        assert!(w.is_incomplete());
    }

    #[test]
    fn a_hostile_fanout_is_bounded_by_the_entry_cap_not_by_its_claim() {
        let w = walk(
            root(huge_fanout),
            WalkLimits {
                max_entries: 1000,
                max_depth: 10,
            },
        );
        assert_eq!(w.entries.len(), 1000);
        assert!(w.entry_cap_reached);
        assert_eq!(w.entries_not_walked, u64::from(u32::MAX) - 999);
    }

    #[test]
    fn an_empty_entry_table_is_not_a_root_with_no_children() {
        let w = walk::<Fake>(None, WalkLimits::default());
        assert!(!w.root_present);
        assert!(w.entries.is_empty());
        let w = walk(root(|_| Ok(0)), WalkLimits::default());
        assert!(w.root_present);
        assert_eq!(w.entries.len(), 1);
    }

    #[test]
    fn a_sub_entry_libewf_will_not_hand_over_is_an_error_not_a_silence() {
        let mut r = root(three_by_three).unwrap();
        r.refuse_child = Some(vec![1]);
        let w = walk(Some(r), WalkLimits::default());
        // The refused entry and the twelve below it are gone; only it is
        // known to be missing, and the error says which.
        assert_eq!(w.entries.len(), 27);
        assert_eq!(w.entries_not_walked, 1);
        assert_eq!(w.errors.len(), 1);
        assert!(w.errors[0].contains("sub-entry 1"), "{}", w.errors[0]);
        assert!(w.is_incomplete());
    }

    #[test]
    fn a_count_libewf_will_not_give_is_recorded() {
        let w = walk(
            root(|p| {
                if p.is_empty() {
                    Err("no count".into())
                } else {
                    Ok(0)
                }
            }),
            WalkLimits::default(),
        );
        assert_eq!(w.entries.len(), 1);
        assert_eq!(w.entries[0].sub_entries, None);
        assert!(w.is_incomplete());
    }

    #[test]
    fn a_zero_time_is_unrecorded_not_the_epoch() {
        assert_eq!(posix_to_rfc3339(0), None);
        assert_eq!(
            posix_to_rfc3339(1_342_372_560).as_deref(),
            Some("2012-07-15T17:16:00Z")
        );
    }

    fn placeholder_entry(offset: i64) -> LogicalEntry {
        LogicalEntry {
            index_path: vec![0],
            parent: Some(0),
            depth: 1,
            facts: EntryFacts {
                name: Some("Parsed".into()),
                entry_type: Some(ENTRY_TYPE_DIRECTORY),
                size: Some(0),
                media_data_size: Some(1),
                media_data_offset: Some(offset),
                ..EntryFacts::default()
            },
            sub_entries: Some(0),
            sub_entries_not_walked: 0,
        }
    }

    /// HUNT-250: only the size-0, one-byte-stored form is read, at its own
    /// media offset; a failed read is an error on the entry, not a value.
    #[test]
    fn a_placeholder_s_one_byte_is_read_at_its_offset_and_a_failure_is_recorded() {
        let mut other = placeholder_entry(10);
        other.facts.size = Some(192);
        other.facts.media_data_size = Some(192);
        let mut walk = LogicalWalk {
            root_present: true,
            entries: vec![placeholder_entry(7), other, placeholder_entry(99)],
            ..LogicalWalk::default()
        };
        let mut asked = Vec::new();
        record_placeholder_bytes(&mut walk, |off| {
            asked.push(off);
            if off == 99 {
                Err("read failed".into())
            } else {
                Ok(0xE5)
            }
        });
        assert_eq!(asked, vec![7, 99], "only placeholder-form entries are read");
        assert_eq!(walk.entries[0].facts.placeholder_byte, Some(0xE5));
        assert_eq!(walk.entries[1].facts.placeholder_byte, None);
        assert_eq!(walk.entries[2].facts.placeholder_byte, None);
        assert_eq!(
            walk.entries[2].facts.errors,
            vec!["placeholder_byte: read failed".to_string()]
        );
    }

    /// HUNT-250: a span shares bytes when any other walked span covers any
    /// of its bytes (same start, containment or partial overlap); spans that
    /// merely abut do not, and an entry with no usable span never does.
    #[test]
    fn stored_spans_that_overlap_are_found_and_abutting_spans_are_not() {
        let span = |off: Option<i64>, len: Option<u64>| {
            let mut e = placeholder_entry(0);
            e.facts.media_data_offset = off;
            e.facts.media_data_size = len;
            e
        };
        let walk = LogicalWalk {
            root_present: true,
            entries: vec![
                span(Some(0), Some(10)), // 0: abuts 1 only
                span(Some(10), Some(1)), // 1: placeholder, alone
                span(Some(11), Some(5)), // 2: contains 3
                span(Some(13), Some(1)), // 3: placeholder inside 2
                span(Some(16), Some(4)), // 4: overlaps 5 partly
                span(Some(18), Some(4)), // 5
                span(Some(30), Some(1)), // 6: same start as 7
                span(Some(30), Some(1)), // 7
                span(None, Some(1)),     // 8: no offset
                span(Some(-1), Some(1)), // 9: negative offset
                span(Some(5), Some(0)),  // 10: nothing stored
                span(Some(40), Some(1)), // 11: last, alone
            ],
            ..LogicalWalk::default()
        };
        let spans = stored_spans(&walk);
        assert_eq!(
            spans.shares,
            vec![false, false, true, true, true, true, true, true, false, false, false, false]
        );
        // 8 and 9 store a byte at no usable offset: their spans are unknown.
        assert_eq!(spans.unknown, 2);
    }

    /// HUNT-250: a span libewf would not give is unknown, never "no span";
    /// and a sparse entry's read at its duplicate data offset (as many bytes
    /// as its recorded size) is a span too, so it can cover a placeholder.
    #[test]
    fn a_span_libewf_would_not_give_is_unknown_and_a_sparse_read_is_a_span() {
        let span = |off: Option<i64>, len: Option<u64>| {
            let mut e = placeholder_entry(0);
            e.facts.entry_type = Some(ENTRY_TYPE_FILE);
            e.facts.flags = Some(0);
            e.facts.media_data_offset = off;
            e.facts.media_data_size = len;
            e.facts.size = len;
            e
        };
        // A sparse read that runs past its target's span, over a placeholder.
        let mut sparse = span(Some(11), Some(1));
        sparse.facts.flags = Some(ENTRY_FLAG_SPARSE_DATA);
        sparse.facts.size = Some(12);
        sparse.facts.duplicate_media_data_offset = Some(0);
        let mut du_failed_not_sparse = span(Some(21), Some(3));
        du_failed_not_sparse
            .facts
            .errors
            .push("duplicate_media_data_offset: failed".into());
        let walk = LogicalWalk {
            root_present: true,
            entries: vec![
                span(Some(0), Some(10)), // 0: covered by the sparse read
                placeholder_entry(10),   // 1: inside the sparse read 0..12
                sparse,                  // 2: stores 11..12, reads 0..12
                placeholder_entry(20),   // 3: alone
                du_failed_not_sparse,    // 4: not sparse, so the du is not read
            ],
            ..LogicalWalk::default()
        };
        let spans = stored_spans(&walk);
        assert_eq!(spans.unknown, 0);
        assert_eq!(spans.shares, vec![true, true, true, false, false]);

        let failed = |field: &str| {
            let mut e = span(None, None);
            e.facts.errors.push(format!("{field}: libewf said no"));
            e
        };
        let mut offset_without_size = span(Some(50), None);
        offset_without_size.facts.size = Some(4);
        let mut sparse_du_failed = failed("duplicate_media_data_offset");
        sparse_du_failed.facts.media_data_offset = Some(60);
        sparse_du_failed.facts.media_data_size = Some(1);
        sparse_du_failed.facts.flags = Some(ENTRY_FLAG_SPARSE_DATA);
        let mut sparse_flags_failed = failed("flags");
        sparse_flags_failed.facts.flags = None;
        sparse_flags_failed.facts.media_data_offset = Some(70);
        sparse_flags_failed.facts.media_data_size = Some(1);
        sparse_flags_failed.facts.size = Some(9);
        sparse_flags_failed.facts.duplicate_media_data_offset = Some(0);
        let walk = LogicalWalk {
            root_present: true,
            entries: vec![
                placeholder_entry(40),
                failed("media_data_offset"),
                failed("media_data_size"),
                offset_without_size,
                sparse_du_failed,
                sparse_flags_failed,
            ],
            ..LogicalWalk::default()
        };
        assert_eq!(stored_spans(&walk).unknown, 5);
    }

    /// The recorded byte survives the helper's JSON frame, and a frame from
    /// before the field existed still parses.
    #[test]
    fn a_placeholder_byte_survives_the_helper_frame_and_old_frames_still_parse() {
        let mut facts = placeholder_entry(7).facts;
        facts.placeholder_byte = Some(0xE5);
        let json = serde_json::to_string(&facts).unwrap();
        let back: EntryFacts = serde_json::from_str(&json).unwrap();
        assert_eq!(back.placeholder_byte, Some(0xE5));
        let mut old = serde_json::to_value(&facts).unwrap();
        old.as_object_mut().unwrap().remove("placeholder_byte");
        let back: EntryFacts = serde_json::from_value(old).unwrap();
        assert_eq!(back.placeholder_byte, None);
    }
}
