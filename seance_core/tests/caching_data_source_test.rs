//! CachingDataSource must return byte-identical results to its inner source for
//! any read (within a chunk, spanning chunks, at/after EOF) while collapsing
//! repeated and localized reads into a small number of inner reads, and evicting
//! correctly when the working set exceeds the cache.

use seance_core::data_source::{CachingDataSource, DataSource};
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// Inner source with deterministic content (`byte[i] == i as u8`) that counts
/// how many times `read_at` reaches it.
#[derive(Debug)]
struct Counting {
    data: Vec<u8>,
    reads: Arc<AtomicUsize>,
}

impl Counting {
    fn new(len: usize) -> (Arc<Self>, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let data = (0..len).map(|i| i as u8).collect();
        (
            Arc::new(Self {
                data,
                reads: reads.clone(),
            }),
            reads,
        )
    }
}

impl DataSource for Counting {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::Relaxed);
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.data.len() - off);
        buf[..n].copy_from_slice(&self.data[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

fn read_vec(src: &dyn DataSource, offset: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let n = src.read_at(offset, &mut buf).unwrap();
    buf.truncate(n);
    buf
}

#[test]
fn reads_are_byte_identical_to_inner() {
    let len = 10_000usize;
    let (inner, _reads) = Counting::new(len);
    let reference: Vec<u8> = (0..len).map(|i| i as u8).collect();
    // Small chunk so most reads cross chunk boundaries.
    let cache = CachingDataSource::new(inner, 1024, 1024 * 1024);

    assert_eq!(cache.size(), len as u64);

    // Within one chunk, spanning two, spanning several, ending exactly at EOF,
    // and a read longer than what remains (must clamp).
    for &(off, req) in &[
        (0u64, 10usize),
        (500, 100),
        (1000, 1),
        (1023, 5),        // straddles chunk 0/1 boundary
        (2040, 200),      // spans chunks 1..3
        (0, len),         // whole thing
        (9990, 10),       // ends at EOF
        (9990, 50),       // over-reads past EOF -> clamps to 10
        (len as u64, 16), // offset at EOF -> 0 bytes
    ] {
        let got = read_vec(&cache, off, req);
        let want_end = (off as usize + req).min(len);
        let want = if off as usize >= len {
            Vec::new()
        } else {
            reference[off as usize..want_end].to_vec()
        };
        assert_eq!(got, want, "mismatch at offset {off} len {req}");
    }
}

#[test]
fn repeated_and_localized_reads_hit_the_cache() {
    let (inner, reads) = Counting::new(64 * 1024);
    let cache = CachingDataSource::new(inner, 1024, 1024 * 1024);

    // Read the same 100 bytes (all within chunk 0) 50 times.
    for _ in 0..50 {
        let _ = read_vec(&cache, 100, 100);
    }
    assert_eq!(
        reads.load(Ordering::Relaxed),
        1,
        "a hot chunk must be read from the inner source exactly once"
    );

    // Touch each of the 64 chunks once, sequentially: 63 further inner reads
    // (chunk 0 already cached).
    for c in 0..64u64 {
        let _ = read_vec(&cache, c * 1024, 16);
    }
    assert_eq!(
        reads.load(Ordering::Relaxed),
        64,
        "each distinct chunk read from inner exactly once"
    );
}

#[test]
fn evicts_least_recently_used_chunk() {
    let (inner, reads) = Counting::new(16 * 1024);
    // Cache holds only 2 chunks of 1 KiB.
    let cache = CachingDataSource::new(inner, 1024, 2 * 1024);

    let _ = read_vec(&cache, 0, 16); // load chunk 0
    let _ = read_vec(&cache, 1024, 16); // load chunk 1
    let _ = read_vec(&cache, 2048, 16); // load chunk 2, evicts chunk 0
    assert_eq!(reads.load(Ordering::Relaxed), 3);

    // Chunk 0 was evicted -> another inner read; the data is still correct.
    let got = read_vec(&cache, 0, 16);
    assert_eq!(got, (0..16u8).collect::<Vec<_>>());
    assert_eq!(
        reads.load(Ordering::Relaxed),
        4,
        "re-reading an evicted chunk hits the inner source again"
    );
}

/// Fails to deliver its declared bytes on the first fill attempt, then recovers.
/// Models a container/IPC round-trip that returns early once: the first call
/// serves a 100-byte prefix, the second returns 0 (ending the fill loop short),
/// and every call after that serves in full.
#[derive(Debug)]
struct FlakyShortSource {
    data: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl DataSource for FlakyShortSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let n = buf.len().min(self.data.len() - off);
        let n = match self.calls.fetch_add(1, Ordering::Relaxed) {
            0 => n.min(100),
            1 => 0,
            _ => n,
        };
        buf[..n].copy_from_slice(&self.data[off..off + n]);
        Ok(n)
    }
    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// B5-009: the chunk fill loop stops on `Ok(0)` and then cached whatever it had.
/// A momentary shortfall from the inner source therefore became the PERMANENT
/// view of that range — every later read, hash and preview was served a short
/// prefix as though it were the full content, with nothing saying the rest was
/// never obtained.
#[test]
fn a_short_chunk_fill_is_not_cached_as_the_whole_chunk() {
    let len = 4096usize;
    let reference: Vec<u8> = (0..len).map(|i| i as u8).collect();
    let calls = Arc::new(AtomicUsize::new(0));
    let inner = Arc::new(FlakyShortSource {
        data: reference.clone(),
        calls: calls.clone(),
    });
    let cache = CachingDataSource::new(inner, 1024, 1024 * 1024);

    // The first fill of chunk 0 is short. Because the short prefix is not
    // memoized, the read re-fills the chunk and returns the real 1024 bytes.
    // Cached, it would have returned only the 100-byte prefix — a truncated
    // region presented as the content at that offset.
    let got = read_vec(&cache, 0, 1024);
    assert_eq!(
        got,
        reference[..1024].to_vec(),
        "a short fill must not become the permanent view of the chunk"
    );

    // The chunk that did fill completely IS cached: no further inner reads.
    let before = calls.load(Ordering::Relaxed);
    let again = read_vec(&cache, 0, 1024);
    assert_eq!(again, reference[..1024].to_vec());
    assert_eq!(
        calls.load(Ordering::Relaxed),
        before,
        "a complete chunk must still be served from the cache"
    );
}
