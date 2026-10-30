//! Streaming page reader over a [`DataSource`].
//!
//! Reads pages on demand via `read_at` rather than loading the whole file into
//! RAM or spilling to a temp file. This keeps evidence handling clean and bounds
//! memory to a page at a time (plus whatever the caller retains).

use seance_core::data_source::DataSource;
use std::collections::HashMap;
use std::sync::Mutex;

/// The most page bytes a [`PageReader`] keeps. The cache was a map with no
/// bound, so reading a database through (the forensic pass visits every page)
/// held the whole file in memory for as long as the reader lived, twice over
/// counting the copy handed back: 1.5 GB at one sample of one real ingest
/// (HUNT-125). The pages worth keeping are the few interior b-tree pages a
/// lookup revisits, and those fit in this.
const PAGE_CACHE_BYTES: usize = 16 * 1024 * 1024;

/// A page cache that holds at most [`PAGE_CACHE_BYTES`], evicting the page that
/// was cached longest ago.
struct PageCache {
    max_pages: usize,
    pages: HashMap<usize, Vec<u8>>,
    order: std::collections::VecDeque<usize>,
}

impl PageCache {
    fn new(page_size: usize) -> Self {
        Self {
            max_pages: (PAGE_CACHE_BYTES / page_size.max(1)).max(16),
            pages: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    fn get(&self, index: usize) -> Option<&Vec<u8>> {
        self.pages.get(&index)
    }

    fn insert(&mut self, index: usize, page: Vec<u8>) {
        if self.pages.insert(index, page).is_some() {
            return;
        }
        self.order.push_back(index);
        while self.pages.len() > self.max_pages {
            match self.order.pop_front() {
                Some(oldest) => {
                    self.pages.remove(&oldest);
                }
                None => break,
            }
        }
    }
}

/// Reads SQLite pages from a data source with a small page cache.
pub struct PageReader<'a> {
    src: &'a dyn DataSource,
    /// Byte offset within the source where the SQLite database begins. Non-zero
    /// when the magic was found at an offset (embedded database / carved region).
    base_offset: u64,
    /// Total bytes of the database region (from `base_offset` to end of source).
    db_len: u64,
    page_size: usize,
    usable_size: usize,
    max_leaf_payload: usize,
    min_leaf_payload: usize,
    cache: Mutex<PageCache>,
}

impl<'a> PageReader<'a> {
    pub fn new(
        src: &'a dyn DataSource,
        base_offset: u64,
        page_size: usize,
        reserved: usize,
    ) -> Self {
        let total = src.size();
        let db_len = total.saturating_sub(base_offset);
        let reserved = if reserved >= page_size { 0 } else { reserved };
        let usable = page_size - reserved;
        let max_leaf = usable.saturating_sub(35);
        let min_leaf = ((usable.saturating_sub(12)) * 32 / 255).saturating_sub(23);
        Self {
            src,
            base_offset,
            db_len,
            page_size,
            usable_size: usable,
            max_leaf_payload: max_leaf,
            min_leaf_payload: min_leaf,
            cache: Mutex::new(PageCache::new(page_size)),
        }
    }

    pub fn page_size(&self) -> usize {
        self.page_size
    }

    pub fn usable_size(&self) -> usize {
        self.usable_size
    }

    pub fn max_leaf_payload(&self) -> usize {
        self.max_leaf_payload
    }

    pub fn min_leaf_payload(&self) -> usize {
        self.min_leaf_payload
    }

    /// Number of whole pages in the database region. A trailing partial page is
    /// still readable via [`read_page`] but not counted here.
    pub fn total_pages(&self) -> usize {
        if self.page_size == 0 {
            return 0;
        }
        (self.db_len / self.page_size as u64) as usize
    }

    /// Number of pages including a trailing partial page (used when scanning a
    /// truncated database so the last partial page is still carved).
    pub fn page_count_including_partial(&self) -> usize {
        if self.page_size == 0 {
            return 0;
        }
        self.db_len.div_ceil(self.page_size as u64) as usize
    }

    /// Content offset within a page: 100 for page 1 (index 0), else 0.
    pub fn content_offset(&self, page_index: usize) -> usize {
        if page_index == 0 {
            100
        } else {
            0
        }
    }

    /// Reads a bounded raw range from the source relative to `base_offset`.
    pub fn read_range(&self, rel_offset: u64, len: usize) -> Vec<u8> {
        if len == 0 {
            return Vec::new();
        }
        let mut buf = vec![0u8; len];
        let abs = self.base_offset + rel_offset;
        let mut filled = 0usize;
        // read_at may return short reads; loop until EOF or full.
        while filled < len {
            match self.src.read_at(abs + filled as u64, &mut buf[filled..]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(_) => break,
            }
        }
        buf.truncate(filled);
        buf
    }

    /// Reads page at 0-based `index`. Returns the page bytes (possibly short at
    /// end of file), or empty if out of range. Cached.
    pub fn read_page(&self, index: usize) -> Vec<u8> {
        let start = index as u64 * self.page_size as u64;
        if start >= self.db_len {
            return Vec::new();
        }
        if let Some(cached) = self
            .cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(index)
        {
            return cached.clone();
        }
        let remaining = self.db_len - start;
        let len = (self.page_size as u64).min(remaining) as usize;
        let page = self.read_range(start, len);
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(index, page.clone());
        page
    }

    /// Reads and reassembles an overflow chain starting at 1-based `first_page`,
    /// pulling up to `bytes_needed` bytes. Cycle-guarded and bounds-checked.
    /// Ported from the reference `readOverflowChain`.
    pub fn read_overflow_chain(&self, first_page: i64, bytes_needed: usize) -> Vec<u8> {
        let mut result = Vec::with_capacity(bytes_needed.min(1 << 20));
        let mut visited = std::collections::HashSet::new();
        let mut page_number = first_page;
        let mut remaining = bytes_needed;
        while page_number != 0 && remaining > 0 {
            if page_number < 0 || !visited.insert(page_number) {
                break;
            }
            let page_index = (page_number - 1) as usize;
            let page = self.read_page(page_index);
            if page.len() < 4 {
                break;
            }
            let next = i64::from(u32::from_be_bytes([page[0], page[1], page[2], page[3]]));
            let chunk_limit = self.usable_size.saturating_sub(4);
            let mut chunk = remaining.min(chunk_limit);
            let available = page.len().saturating_sub(4);
            if chunk > available {
                chunk = available;
            }
            if chunk == 0 {
                page_number = next;
                continue;
            }
            result.extend_from_slice(&page[4..4 + chunk]);
            remaining = remaining.saturating_sub(chunk);
            page_number = next;
        }
        result
    }
}

#[cfg(test)]
mod page_cache_tests {
    use super::*;

    /// HUNT-125: the cache held every page ever read, so reading a database
    /// through held the whole file. It is bounded, and keeps the recent pages.
    #[test]
    fn the_page_cache_is_bounded_and_keeps_the_most_recent_pages() {
        let page_size = 4096;
        let mut cache = PageCache::new(page_size);
        let cap = PAGE_CACHE_BYTES / page_size;
        for i in 0..cap * 3 {
            cache.insert(i, vec![0u8; page_size]);
        }
        assert_eq!(cache.pages.len(), cap, "held at the bound, not the file");
        assert!(cache.get(0).is_none(), "the oldest page was evicted");
        assert!(cache.get(cap * 3 - 1).is_some(), "the newest page is kept");
        // Re-inserting a held page neither grows nor reorders the cache.
        cache.insert(cap * 3 - 1, vec![1u8; page_size]);
        assert_eq!(cache.pages.len(), cap);
        assert_eq!(cache.order.len(), cap);
    }

    #[test]
    fn a_huge_page_size_still_caches_a_few_pages() {
        let mut cache = PageCache::new(65536);
        for i in 0..100 {
            cache.insert(i, vec![0u8; 8]);
        }
        assert!(cache.pages.len() >= 16);
        assert!(cache.pages.len() <= PAGE_CACHE_BYTES / 65536);
    }
}
