//! [`TableCache`]: the bounded, shared memo of page-table entries a walk reads.
//!
//! # Why this is load-bearing rather than an optimisation
//!
//! Every typed field a plugin reads is a fresh walk, and every walk re-reads
//! the same three or four tables. Listing 400 processes and reading 30 fields
//! from each is 12,000 walks over an almost completely overlapping set of
//! tables; without a memo the same page-directory entry is fetched from the
//! acquisition file thousands of times, which on an E01 or a snappy-framed AVML
//! means thousands of decompressions.
//!
//! # Why it is keyed on the entry's *physical* address
//!
//! A page-table entry lives at a physical address and means the same thing no
//! matter which address space is walking it. That makes this cache
//! **DTB-independent**, and therefore safe to share between every address space
//! in a case: one bounded allocation instead of one per process. A cache keyed
//! on a virtual address could not be shared, and giving 400 processes their own
//! copy is how a memory tool ends up using gigabytes of RAM to save time.
//!
//! Sharding on the table's own address, rather than one lock over everything,
//! keeps parallel scan workers from serialising on a single mutex. All entries
//! of one 4 KiB table land in the same shard, so a walk that reads several
//! entries from one table touches one lock.
//!
//! # It never changes an answer
//!
//! A memo may only return what a read already returned. Nothing here
//! synthesises an entry, and a lock this crate finds poisoned is recovered
//! rather than treated as a value: a cache is not evidence, and its failure
//! must degrade performance, never truth.

use lru::LruCache;
use std::fmt;
use std::num::NonZeroUsize;
use std::sync::Mutex;

/// How many independently locked shards the entry memo is split across.
///
/// Sixteen is the plan's figure: enough to keep the rayon-bounded scan workers
/// off each other's locks, few enough that the total bound stays obvious.
pub const TABLE_CACHE_SHARDS: usize = 16;

/// Entries memoised per shard. Sixteen shards of 4096 eight-byte entries is
/// 65,536 memoised entries, roughly 1 MiB of keys and values — a fixed ceiling
/// that does not grow with the number of processes examined.
pub const ENTRIES_PER_SHARD: usize = 4096;

/// Table shapes memoised. Establishing one costs a whole 4 KiB read, so
/// remembering it matters more than remembering a single entry; there are far
/// fewer tables than entries, hence the smaller number.
pub const TABLE_SHAPES: usize = 1024;

/// What a probe of a page-sized paging table found.
///
/// Deliberately a *fact about the bytes* rather than a verdict about them. The
/// verdict — "this table is Windows' unused-address filler and may be treated
/// as absent" — depends on which OS conventions are in force, so deriving it
/// here would make this memo unshareable between address spaces read under
/// different conventions, and would silently give one of them the other's
/// answer. Storing the observation and leaving the judgement to the caller
/// keeps the memo what it claims to be: a record of bytes already read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableShape {
    /// The table holds at least two entries that differ.
    Mixed,
    /// Every entry in the table is this value, byte for byte.
    Repeated(u64),
}

const fn non_zero(value: usize) -> NonZeroUsize {
    // A constant-folded `NonZeroUsize` with no panicking path. The `None` arm
    // is unreachable for the constants above and exists only so this function
    // cannot abort a case.
    match NonZeroUsize::new(value) {
        Some(n) => n,
        None => NonZeroUsize::MIN,
    }
}

/// A bounded memo of page-table entries, shareable across address spaces.
///
/// Hold it in an `Arc` and hand the same one to every [`crate::translate::VirtualLayer`]
/// built over the same physical layer; the contents are physical-address keyed
/// and therefore correct for all of them.
pub struct TableCache {
    entries: [Mutex<LruCache<u64, u64>>; TABLE_CACHE_SHARDS],
    shapes: Mutex<LruCache<u64, TableShape>>,
}

impl TableCache {
    /// A cache bounded by [`TABLE_CACHE_SHARDS`] x [`ENTRIES_PER_SHARD`].
    pub fn new() -> Self {
        Self {
            entries: std::array::from_fn(|_| {
                Mutex::new(LruCache::new(non_zero(ENTRIES_PER_SHARD)))
            }),
            shapes: Mutex::new(LruCache::new(non_zero(TABLE_SHAPES))),
        }
    }

    /// Which shard owns `physical_address`.
    ///
    /// Shifting by the page size first means every entry of one table shares a
    /// shard, so a walk that reads two entries from the same table takes one
    /// lock twice rather than two different locks.
    pub fn shard_of(physical_address: u64) -> usize {
        ((physical_address >> 12) as usize) % TABLE_CACHE_SHARDS
    }

    /// The memoised value of the entry at `entry_pa`, if it has been read
    /// recently.
    pub fn entry(&self, entry_pa: u64) -> Option<u64> {
        let shard = &self.entries[Self::shard_of(entry_pa)];
        let mut guard = shard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.get(&entry_pa).copied()
    }

    /// Remember the value read from `entry_pa`.
    pub fn store_entry(&self, entry_pa: u64, value: u64) {
        let shard = &self.entries[Self::shard_of(entry_pa)];
        let mut guard = shard
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.put(entry_pa, value);
    }

    /// What a previous probe found in the page-sized table at `table_pa`.
    pub fn table_shape(&self, table_pa: u64) -> Option<TableShape> {
        let mut guard = self
            .shapes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.get(&table_pa).copied()
    }

    /// Remember what a probe found.
    ///
    /// Only ever called with a shape actually established by reading the table;
    /// a probe that could not be read stores nothing, so a transient I/O
    /// failure cannot make a table look absent for the rest of the case.
    pub fn store_table_shape(&self, table_pa: u64, shape: TableShape) {
        let mut guard = self
            .shapes
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.put(table_pa, shape);
    }

    /// How many entries are memoised right now, across every shard. Diagnostic
    /// only; it says nothing about the evidence.
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .map(|shard| {
                shard
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .len()
            })
            .sum()
    }

    /// Whether anything has been memoised yet.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for TableCache {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TableCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately does not dump contents: an entry value is evidence-
        // derived and a debug line is not the place for it.
        f.debug_struct("TableCache")
            .field("shards", &TABLE_CACHE_SHARDS)
            .field("entries_per_shard", &ENTRIES_PER_SHARD)
            .field("memoised", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_entry_survives_a_round_trip_and_a_miss_stays_a_miss() {
        let cache = TableCache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.entry(0x1000), None);
        cache.store_entry(0x1000, 0xDEAD_BEEF);
        assert_eq!(cache.entry(0x1000), Some(0xDEAD_BEEF));
        // A neighbouring entry is a different key, not the same one rounded.
        assert_eq!(cache.entry(0x1008), None);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn a_zero_valued_entry_is_remembered_as_a_value_not_as_a_miss() {
        // A page-table entry of zero is a real, meaningful read: the region is
        // absent. Confusing it with "not cached" would re-read it forever, and
        // confusing it the other way would be worse.
        let cache = TableCache::new();
        cache.store_entry(0x2000, 0);
        assert_eq!(cache.entry(0x2000), Some(0));
    }

    #[test]
    fn every_entry_of_one_table_lands_in_one_shard() {
        let table = 0x1_A000u64;
        let shard = TableCache::shard_of(table);
        for index in 0..512u64 {
            assert_eq!(TableCache::shard_of(table + index * 8), shard);
        }
        // And consecutive tables do not all pile into the same shard.
        let shards: Vec<usize> = (0..TABLE_CACHE_SHARDS as u64)
            .map(|i| TableCache::shard_of(table + i * 0x1000))
            .collect();
        let distinct: std::collections::BTreeSet<usize> = shards.iter().copied().collect();
        assert_eq!(distinct.len(), TABLE_CACHE_SHARDS);
    }

    #[test]
    fn the_memo_is_bounded_and_evicts_the_least_recently_used() {
        let cache = TableCache::new();
        // Fill one shard past its capacity: every address here shares a shard
        // because they share a page.
        let base = 0x10_0000u64;
        for index in 0..(ENTRIES_PER_SHARD as u64 + 16) {
            // Stay inside one page so the shard is fixed, by folding the index
            // into the high bits above the shard selector.
            cache.store_entry(base + index * (1 << 12) * TABLE_CACHE_SHARDS as u64, index);
        }
        assert!(
            cache.len() <= TABLE_CACHE_SHARDS * ENTRIES_PER_SHARD,
            "the memo must never grow without bound"
        );
        // The most recent write is still there; the very first is gone.
        let last = ENTRIES_PER_SHARD as u64 + 15;
        assert_eq!(
            cache.entry(base + last * (1 << 12) * TABLE_CACHE_SHARDS as u64),
            Some(last)
        );
        assert_eq!(cache.entry(base), None);
    }

    #[test]
    fn table_shapes_are_remembered_separately_from_entries() {
        let cache = TableCache::new();
        assert_eq!(cache.table_shape(0x3000), None);
        cache.store_table_shape(0x3000, TableShape::Repeated(0x9001));
        cache.store_entry(0x3000, 0x42);
        assert_eq!(
            cache.table_shape(0x3000),
            Some(TableShape::Repeated(0x9001))
        );
        assert_eq!(cache.entry(0x3000), Some(0x42));
    }

    #[test]
    fn a_shape_records_the_bytes_and_leaves_the_verdict_to_the_caller() {
        // The memo is shared between address spaces that may be read under
        // different OS conventions. Storing "unused, suppress it" instead of
        // "every entry is this value" would hand one address space the other's
        // judgement.
        let cache = TableCache::new();
        cache.store_table_shape(0x6000, TableShape::Mixed);
        assert_eq!(cache.table_shape(0x6000), Some(TableShape::Mixed));
        assert_ne!(
            cache.table_shape(0x6000),
            Some(TableShape::Repeated(0)),
            "an all-zero table and a mixed table are different observations"
        );
    }

    #[test]
    fn a_poisoned_shard_still_serves_reads() {
        use std::sync::Arc;
        let cache = Arc::new(TableCache::new());
        cache.store_entry(0x4000, 7);
        let poisoner = Arc::clone(&cache);
        // Panicking inside a closure that holds no lock cannot poison, so the
        // lock is poisoned deliberately through the public API's own mutex.
        let _ = std::thread::spawn(move || {
            let _guard = poisoner.entries[TableCache::shard_of(0x4000)]
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            panic!("deliberate poison");
        })
        .join();
        // A poisoned memo degrades performance, never truth.
        assert_eq!(cache.entry(0x4000), Some(7));
        cache.store_entry(0x4008, 9);
        assert_eq!(cache.entry(0x4008), Some(9));
    }

    #[test]
    fn the_debug_view_reports_bounds_without_dumping_evidence() {
        let cache = TableCache::new();
        cache.store_entry(0x5000, 0xABCD);
        let rendered = format!("{cache:?}");
        assert!(rendered.contains("shards"));
        assert!(!rendered.contains("abcd"), "{rendered}");
        assert!(!rendered.contains("ABCD"), "{rendered}");
    }
}
