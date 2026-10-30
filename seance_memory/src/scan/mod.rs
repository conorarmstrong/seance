//! Scanning: finding byte patterns in a memory address space without ever
//! reading, stitching or fabricating a byte the acquisition did not capture.
//!
//! Scanning is how memory forensics finds the things list-walking cannot see. A
//! terminated process, a closed handle, an unlinked driver and a wiped kernel
//! banner are all gone from every list the kernel maintains, but the allocation
//! that held them is usually still sitting in RAM. Pool-tag scanning — thousands
//! of four-byte needles in one pass — is carving applied to kernel objects, and
//! it is the single most productive detection primitive an examiner has.
//!
//! Because it is a *detection* primitive, being quietly wrong matters more here
//! than anywhere else in the crate: a scan that silently found nothing and a
//! scan that silently could not read look identical in a report, and a hit
//! reported at an address that does not hold it is testimony about evidence that
//! does not exist. Three rules follow, and all three are correctness rather than
//! tuning.
//!
//! # 1. Sections come from `mapping()`, and the overlap never crosses one
//!
//! The driver asks the layer which regions are backed ([`derive_sections`]) and
//! walks only those. That is mandatory, not an optimisation: it is the
//! difference between scanning the 8 GiB that was acquired and walking a 256 TiB
//! virtual address space a page at a time.
//!
//! More importantly, a chunk's overlap **must never span a hole**. A chunk that
//! reached across an unmapped gap and glued the two sides together would create
//! byte adjacency that never existed on the suspect's machine, and a needle
//! matching across that seam is a *fabricated hit* — the same class of error as
//! zero-padding an unmapped read, and one nothing downstream can catch, because
//! both sides of the seam are genuine bytes. So a chunk lives strictly inside one
//! mapped section, and the last chunk of a section is clipped at the section end
//! rather than extended past it.
//!
//! # 2. A hit is reported exactly once, and a straddling hit is not lost
//!
//! Chunks are read with an overlap and *accepted* by start address: a chunk owns
//! hits starting in `[address, accept_end)` and discards whatever it found in
//! the overlap tail, which the next chunk owns. A needle lying across a chunk
//! boundary is therefore found once — by the chunk that owns its first byte,
//! which read far enough past the boundary to see all of it. Both failure modes
//! are courtroom problems: duplicates inflate a count, and a missed straddling
//! hit is a missed artifact.
//!
//! The overlap is the longest possible match minus one, capped by
//! [`ScanConfig::max_overlap`]. When a scanner can match something longer than
//! the overlap allows — any regex with an unbounded quantifier, or a needle above
//! the cap — the outcome says so through
//! [`ScanOutcome::pattern_may_exceed_overlap`], with the reliable length in
//! [`ScanOutcome::max_reliable_pattern_len`]. The limitation is published, never
//! silently absorbed.
//!
//! # 3. Failure is recorded, and hit offsets never shift
//!
//! [`ScanOutcome::unread`] carries every range that could not be examined and
//! why: unmapped holes the layer skipped, the tail of a truncated acquisition
//! file, and whatever lay above a cap that fired. A scan of an image with gaps
//! can therefore never be mistaken for a scan of complete memory.
//!
//! Hit addresses always come from the chunk descriptor plus the match offset
//! within the bytes actually read. A short read shortens the scanned slice and
//! produces an `unread` entry; it never rebases the offsets of the bytes that
//! *were* read.
//!
//! # Parallelism
//!
//! The driver is single-threaded, deliberately: this crate carries no
//! work-stealing dependency and adding one is not part of this change. The loop
//! is factored so that adding it later is mechanical — [`ChunkPlan`]s come from
//! an iterator ([`chunk_plans`]) that borrows nothing from the scan state, and
//! [`scan_one_chunk`] is a function of `(layer, scanner, plan)` plus its own
//! scratch buffer. Dropping in a bounded pool of `min(num_cpus, 8)` workers means
//! giving each worker its own buffer and hit vector and merging results by
//! address; nothing else here changes. `DataSource::read_at` is stateless and
//! `Send + Sync` by contract, so there is no seek contention to design around.

use seance_core::data_source::DataSource;
use seance_core::io::IncompleteReason;
use std::io;
use std::ops::Range;

use crate::layer::{backed_len, LayerError, MemoryLayer};

/// Bytes of a mapped section handed to the scanner per chunk.
///
/// 16 MiB keeps the read count low over a multi-gigabyte image while staying far
/// below any plausible memory budget: the driver holds one buffer of
/// `chunk_size + overlap` whatever the image size.
pub const DEFAULT_CHUNK_SIZE: u64 = 16 * 1024 * 1024;

/// Ceiling on the chunk overlap, and therefore on the longest pattern findable
/// across a chunk boundary.
///
/// A page of overlap covers every fixed needle memory forensics actually uses —
/// pool tags are four bytes, kernel banners a few hundred — while bounding what
/// an unbounded regex can force the driver to re-read.
pub const DEFAULT_MAX_OVERLAP: u64 = 4096;

/// Hard cap on hits returned by one scan.
///
/// Sized for a pool-tag sweep of a 64 GiB image. When it fires the outcome is
/// marked [`ScanOutcome::truncated`] and the unscanned remainder is recorded in
/// [`ScanOutcome::unread`], so "five million hits" can never be read as "all the
/// hits".
pub const MAX_SCAN_HITS: usize = 5_000_000;

/// Hard cap on mapped sections enumerated for one scan.
///
/// Mirrors [`crate::layer::MAX_SEGMENTS`]: a hostile or corrupt acquisition
/// header can claim millions of runs, and enumerating them is an allocation the
/// examiner never asked for.
pub const MAX_SCAN_SECTIONS: usize = 1_048_576;

/// Hard cap on individually recorded unread ranges.
///
/// Mirrors the existing metadata-run discipline. When it fires,
/// [`ScanOutcome::unread_bytes`] stays exact and
/// [`ScanOutcome::unread_truncated`] is set; only the per-range detail is lost.
pub const MAX_UNREAD_RANGES: usize = 4096;

/// Hard cap on the number of [`MemoryLayer::mapping`] probes one section
/// derivation issues.
///
/// [`ScanConfig::max_sections`] does not bound that walk on its own, and the two
/// gaps are exactly the ones a hostile image would aim for: a probe that comes
/// back as a hole pushes no section at all, and a probe that comes back adjacent
/// to the previous one is *merged* into it rather than counted. A layer
/// answering in one-byte holes — or in one-byte mapped runs — therefore drives
/// the loop once per address for as long as the address space lasts, which on a
/// 256 TiB virtual space is a hung ingest rather than a wrong answer.
///
/// Exhausting the budget is reported exactly as the section cap is: the address
/// enumeration stopped at lands in [`SectionPlan::truncated_at`], and everything
/// above it becomes [`IncompleteReason::CapReached`] on the outcome. It is never
/// the end of the mapped memory.
///
/// At the default probe window this is 4 PiB of address space, so no real
/// acquisition can reach it.
pub const MAX_SECTION_PROBES: usize = 16_777_216;

/// How much address space one [`MemoryLayer::mapping`] probe covers while
/// deriving sections.
///
/// Bounds the transient run list a single probe can build on an image with a
/// million tiny segments. Probe boundaries are invisible in the result: adjacent
/// mapped windows are merged back into one section, which is a correctness
/// requirement rather than tidiness — see [`derive_sections`].
pub const DEFAULT_PROBE_WINDOW: u64 = 256 * 1024 * 1024;

/// How many `ErrorKind::Interrupted` results one chunk read tolerates before
/// giving up and recording the remainder as unread. Bounds a pathological source
/// that can only ever return `Interrupted`.
const MAX_INTERRUPTED_RETRIES: u32 = 16;

/// Ceiling on a compiled regex program, in bytes.
const REGEX_SIZE_LIMIT: usize = 16 * 1024 * 1024;

/// Ceiling on the lazy-DFA cache of a compiled regex, in bytes.
const REGEX_DFA_SIZE_LIMIT: usize = 8 * 1024 * 1024;

/// Everything that can stop a scan before it starts, or make its result
/// untrustworthy enough that returning a number would be worse than returning
/// nothing.
///
/// Note what is *not* here: an unreadable region mid-scan. That is a fact about
/// the image, not a failure of the scan, and it belongs in
/// [`ScanOutcome::unread`] where an examiner can see it.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// The layer could not project part of its own address space, for a reason
    /// other than an ordinary hole.
    #[error("the memory layer could not be projected: {0}")]
    Layer(#[from] LayerError),

    /// A scanner could not be built from the supplied patterns.
    #[error("scanner pattern is unusable: {detail}")]
    Pattern { detail: String },

    /// The scan configuration cannot produce a correct walk.
    #[error("invalid scan configuration: {detail}")]
    Config { detail: String },

    /// The layer reported neither progress nor a hole while being enumerated.
    ///
    /// Fail closed rather than loop: a layer answering "no bytes here, and not a
    /// hole either" is inconsistent, and a driver that kept asking would hang an
    /// ingest instead of reporting the defect.
    #[error(
        "the memory layer made no progress at address {address:#x} while deriving scan sections"
    )]
    NoProgress { address: u64 },

    /// The layer's bounds are inverted, so it has no address space to walk.
    #[error("the layer's minimum address {min:#x} is above its maximum address {max:#x}")]
    EmptyAddressSpace { min: u64, max: u64 },
}

/// One pattern match, located in the *layer's* address space.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Hit {
    /// Address of the match's first byte. Derived from the chunk descriptor plus
    /// the offset inside the bytes actually read — never from a buffer length,
    /// which is how a partial read silently shifts every offset in a scan.
    pub address: u64,
    /// Which pattern matched, as an index into the scanner's pattern list. A
    /// pool sweep over four thousand tags has to know *which* tag hit without
    /// re-reading the bytes.
    pub pattern_id: u32,
    /// Length of the match, in bytes.
    pub length: u32,
}

/// What the driver wants a scanner to do after a hit.
///
/// Exists so a hit cap can stop a scanner mid-chunk rather than let it
/// materialise sixteen million matches into a vector that is about to be
/// truncated anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanControl {
    /// Keep scanning this chunk.
    Continue,
    /// Stop scanning this chunk now.
    Stop,
}

/// A pattern-matching strategy the chunked driver can drive.
///
/// Object safe: the driver holds `&dyn Scanner`, and a plugin can supply its own
/// without this module knowing about it.
///
/// Implementors report matches in terms of the chunk they were given and nothing
/// else. In particular they must not assume a chunk is a whole section, a whole
/// page, or aligned to anything.
pub trait Scanner: Send + Sync + std::fmt::Debug {
    /// Short identifier recorded on the outcome, so a report can say which scan
    /// produced a count and which scan hit a limitation.
    fn name(&self) -> &str;

    /// The longest byte sequence a match can span, when that is knowable.
    ///
    /// `None` means unbounded — a regex with `*`, `+` or `{n,}` can match an
    /// arbitrarily long run of bytes. The driver cannot then guarantee a match
    /// spanning a chunk boundary is found, so it publishes the limitation on the
    /// outcome instead of quietly missing matches.
    fn max_match_len(&self) -> Option<u64>;

    /// Scan `chunk`, whose first byte lives at layer address `base`, reporting
    /// each match to `sink` as an absolute layer address.
    ///
    /// `chunk` holds only bytes that were genuinely read: the driver never passes
    /// the untouched tail of a buffer, so an implementor may treat every byte it
    /// sees as acquired evidence.
    ///
    /// Stop as soon as `sink` returns [`ScanControl::Stop`].
    fn scan_chunk(&self, chunk: &[u8], base: u64, sink: &mut dyn FnMut(Hit) -> ScanControl);
}

/// One chunk a scanner's engine would not scan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefusedChunk {
    /// Address of the chunk's first byte.
    pub address: u64,
    /// Bytes that were offered.
    pub bytes: usize,
    /// What the engine said.
    pub detail: String,
}

/// What a scanner has to say that its hits cannot.
///
/// [`Scanner::scan_chunk`] cannot fail. The driver offers a chunk and takes
/// hits, so an engine that **refused** a chunk has no way to say so through the
/// trait — and a refused chunk that reads as a clean one is the false absence
/// this crate is written against. An engine that can match without producing an
/// address (a YARA rule whose condition is true with none of its strings found)
/// has the same problem in reverse: it fired and no row can carry it.
///
/// A scanner with either property implements this alongside [`Scanner`], and
/// the stage driving it publishes what it says beside the hit count. Both
/// methods return an empty vector for a scan in which nothing of the kind
/// happened, which is why neither is optional: an implementor states both, so a
/// caller never has to guess whether silence means "none" or "not asked".
pub trait ScannerDiagnostics: Send + Sync + std::fmt::Debug {
    /// Chunks the engine refused since this was last called, **and clears
    /// them**.
    ///
    /// **Read this before reading an empty hit list as a clean address space.**
    ///
    /// Draining rather than reading, because one scanner drives several scans:
    /// the same compiled rule set searches every process of one image, that
    /// image's own space, and then the next image in the case. Faults that
    /// accumulated would be published again on every record after the one they
    /// happened in — a refusal in process 4 reported against process 900, and
    /// against the next capture — which puts a fault on a record whose scan
    /// did not have it. What each record must carry is what *its* scan met.
    fn take_refused_chunks(&self) -> Vec<RefusedChunk>;

    /// Patterns that matched with no address to report since this was last
    /// called, **and clears them**. Draining for the reason above.
    fn take_matched_without_address(&self) -> Vec<String>;
}

// ── Scanners ────────────────────────────────────────────────────────────────

/// Thousands of fixed needles in a single pass, over Aho-Corasick.
///
/// The workhorse of memory forensics. Pool-tag scanning submits the whole
/// constraint table at once (`Proc`/`Pro\xe3`, `File`/`Fil\xe5`, `Driv`/`Dri\xf6`,
/// `MmLd`, `CM10`, …) and kernel-banner identification submits thousands of
/// candidate version strings; both become one pass over the image instead of one
/// pass per needle, which is the difference between a scan an examiner waits for
/// and a scan an examiner abandons.
///
/// Matches are **leftmost-longest and non-overlapping**, the right semantic for a
/// tag table: where two needles could match in the same place the longer one is
/// the answer, and the shorter one is not additionally reported as if it were a
/// separate allocation.
#[derive(Debug)]
pub struct MultiStringScanner {
    name: String,
    automaton: aho_corasick::AhoCorasick,
    needles: Vec<Vec<u8>>,
    max_len: u64,
}

impl MultiStringScanner {
    /// Build a scanner over `needles`.
    ///
    /// # Errors
    ///
    /// [`ScanError::Pattern`] if the needle list is empty, if any needle is empty
    /// (an empty needle matches at every offset, which would report the whole
    /// image as evidence), or if the automaton cannot be built.
    pub fn new<I, P>(name: impl Into<String>, needles: I) -> Result<Self, ScanError>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<[u8]>,
    {
        let needles: Vec<Vec<u8>> = needles.into_iter().map(|n| n.as_ref().to_vec()).collect();
        if needles.is_empty() {
            return Err(ScanError::Pattern {
                detail: "no needles supplied".to_string(),
            });
        }
        if let Some(index) = needles.iter().position(|n| n.is_empty()) {
            return Err(ScanError::Pattern {
                detail: format!("needle {index} is empty, and an empty needle matches everywhere"),
            });
        }
        let max_len = needles.iter().map(|n| n.len() as u64).max().unwrap_or(0);
        let automaton = aho_corasick::AhoCorasick::builder()
            .match_kind(aho_corasick::MatchKind::LeftmostLongest)
            .build(&needles)
            .map_err(|e| ScanError::Pattern {
                detail: e.to_string(),
            })?;
        Ok(Self {
            name: name.into(),
            automaton,
            needles,
            max_len,
        })
    }

    /// The needle behind a [`Hit::pattern_id`], so a record can name the pool tag
    /// or banner it matched without re-reading the image.
    pub fn needle(&self, pattern_id: u32) -> Option<&[u8]> {
        self.needles.get(pattern_id as usize).map(|n| n.as_slice())
    }

    /// How many needles this scanner carries.
    pub fn needle_count(&self) -> usize {
        self.needles.len()
    }
}

impl Scanner for MultiStringScanner {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_match_len(&self) -> Option<u64> {
        Some(self.max_len)
    }

    fn scan_chunk(&self, chunk: &[u8], base: u64, sink: &mut dyn FnMut(Hit) -> ScanControl) {
        for m in self.automaton.find_iter(chunk) {
            // A match offset cannot exceed the chunk length, and chunk lengths
            // are bounded by the configuration, so this only fails on an address
            // space ending at the very top of `u64`. Stopping is honest;
            // reporting a wrapped address is not.
            let Some(address) = base.checked_add(m.start() as u64) else {
                return;
            };
            let hit = Hit {
                address,
                pattern_id: m.pattern().as_u32(),
                length: m.len() as u32,
            };
            if sink(hit) == ScanControl::Stop {
                return;
            }
        }
    }
}

/// One fixed needle, over `memchr`'s substring searcher.
///
/// The single-pattern case of [`MultiStringScanner`], kept separate because the
/// SIMD substring search is materially faster than a one-pattern automaton, and
/// because a caller looking for one magic value should not have to build a
/// vector to say so. Matches are non-overlapping.
#[derive(Debug)]
pub struct SingleStringScanner {
    name: String,
    finder: memchr::memmem::Finder<'static>,
    needle_len: u64,
}

impl SingleStringScanner {
    /// Build a scanner for `needle`.
    ///
    /// # Errors
    ///
    /// [`ScanError::Pattern`] if `needle` is empty: an empty needle matches at
    /// every offset, which would report the whole image as evidence.
    pub fn new(name: impl Into<String>, needle: &[u8]) -> Result<Self, ScanError> {
        if needle.is_empty() {
            return Err(ScanError::Pattern {
                detail: "the needle is empty, and an empty needle matches everywhere".to_string(),
            });
        }
        Ok(Self {
            name: name.into(),
            finder: memchr::memmem::Finder::new(needle).into_owned(),
            needle_len: needle.len() as u64,
        })
    }
}

impl Scanner for SingleStringScanner {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_match_len(&self) -> Option<u64> {
        Some(self.needle_len)
    }

    fn scan_chunk(&self, chunk: &[u8], base: u64, sink: &mut dyn FnMut(Hit) -> ScanControl) {
        for start in self.finder.find_iter(chunk) {
            let Some(address) = base.checked_add(start as u64) else {
                return;
            };
            let hit = Hit {
                address,
                pattern_id: 0,
                length: self.needle_len as u32,
            };
            if sink(hit) == ScanControl::Stop {
                return;
            }
        }
    }
}

/// A regular expression over raw bytes, compiled for binary evidence.
///
/// Two settings are not the defaults, and both matter when the haystack is
/// memory rather than text:
///
/// - **DOTALL (`(?s)`)** — `.` matches `0x0a` like any other byte. Memory is not
///   line-oriented, and a pattern that stopped at a newline would miss a
///   structure purely because one of its bytes happened to be `0x0a`.
/// - **Unicode off** — `.` and the character classes match *bytes*, not UTF-8
///   code points. With Unicode on, `.` cannot match `0xff`, so patterns silently
///   fail over exactly the non-textual regions memory forensics cares about most.
///
/// Compilation is bounded, because a pattern may come from an examiner's search
/// box: a pathological one fails to compile rather than exhausting memory
/// mid-ingest.
///
/// A regex has no knowable maximum match length, so [`Scanner::max_match_len`]
/// is `None` and every outcome using one carries the boundary limitation.
#[derive(Debug)]
pub struct RegexScanner {
    name: String,
    regex: regex::bytes::Regex,
}

impl RegexScanner {
    /// Compile `pattern` for byte-oriented scanning.
    ///
    /// # Errors
    ///
    /// [`ScanError::Pattern`] if the pattern is invalid or exceeds the
    /// compilation budget.
    pub fn new(name: impl Into<String>, pattern: &str) -> Result<Self, ScanError> {
        let regex = regex::bytes::RegexBuilder::new(pattern)
            .dot_matches_new_line(true)
            .unicode(false)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .map_err(|e| ScanError::Pattern {
                detail: e.to_string(),
            })?;
        Ok(Self {
            name: name.into(),
            regex,
        })
    }
}

impl Scanner for RegexScanner {
    fn name(&self) -> &str {
        &self.name
    }

    fn max_match_len(&self) -> Option<u64> {
        // `regex` publishes no maximum match length, and for any pattern with an
        // unbounded quantifier there is none. A number here would claim a
        // boundary guarantee the driver cannot honour.
        None
    }

    fn scan_chunk(&self, chunk: &[u8], base: u64, sink: &mut dyn FnMut(Hit) -> ScanControl) {
        for m in self.regex.find_iter(chunk) {
            // A zero-length match is not evidence of anything, and one per offset
            // would bury real hits under the cap.
            if m.start() == m.end() {
                continue;
            }
            let Some(address) = base.checked_add(m.start() as u64) else {
                return;
            };
            let hit = Hit {
                address,
                pattern_id: 0,
                length: (m.end() - m.start()) as u32,
            };
            if sink(hit) == ScanControl::Stop {
                return;
            }
        }
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Chunking geometry and the caps that bound one scan.
#[derive(Debug, Clone, Copy)]
pub struct ScanConfig {
    /// Bytes of a section each chunk owns. A chunk *reads*
    /// `chunk_size + overlap` but accepts hits only in its own `chunk_size`.
    pub chunk_size: u64,
    /// Ceiling on the overlap. The effective overlap is the scanner's longest
    /// possible match minus one, clamped to this and to `chunk_size - 1`.
    pub max_overlap: u64,
    /// Ceiling on hits returned. Reaching it sets [`ScanOutcome::truncated`].
    pub max_hits: usize,
    /// Ceiling on enumerated mapped sections.
    pub max_sections: usize,
    /// Ceiling on individually recorded unread ranges. The byte total stays exact
    /// past this point; only per-range detail is dropped.
    pub max_unread_ranges: usize,
    /// How much address space one `mapping()` probe covers while enumerating
    /// sections. Invisible in the result — adjacent windows are merged.
    pub probe_window: u64,
    /// Ceiling on the number of `mapping()` probes one section derivation
    /// issues. Bounds a layer whose holes or runs are one byte long, which
    /// neither `max_sections` nor `probe_window` bounds on its own. Reaching it
    /// sets [`SectionPlan::truncated_at`].
    pub max_probes: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            max_overlap: DEFAULT_MAX_OVERLAP,
            max_hits: MAX_SCAN_HITS,
            max_sections: MAX_SCAN_SECTIONS,
            max_unread_ranges: MAX_UNREAD_RANGES,
            probe_window: DEFAULT_PROBE_WINDOW,
            max_probes: MAX_SECTION_PROBES,
        }
    }
}

impl ScanConfig {
    /// Reject a geometry that cannot produce a correct walk.
    ///
    /// Each of these would otherwise surface as a wrong answer rather than an
    /// error: a zero chunk size never advances, a zero hit cap reports an empty
    /// scan, and a buffer larger than `usize` cannot be allocated on the target.
    pub fn validate(&self) -> Result<(), ScanError> {
        if self.chunk_size == 0 {
            return Err(ScanError::Config {
                detail: "chunk_size must be at least 1 byte".to_string(),
            });
        }
        if self.max_hits == 0 {
            return Err(ScanError::Config {
                detail: "max_hits must be at least 1".to_string(),
            });
        }
        if self.max_sections == 0 {
            return Err(ScanError::Config {
                detail: "max_sections must be at least 1".to_string(),
            });
        }
        if self.probe_window == 0 {
            return Err(ScanError::Config {
                detail: "probe_window must be at least 1 byte".to_string(),
            });
        }
        if self.max_probes == 0 {
            return Err(ScanError::Config {
                detail: "max_probes must be at least 1".to_string(),
            });
        }
        let buffer = self
            .chunk_size
            .checked_add(self.max_overlap)
            .ok_or_else(|| ScanError::Config {
                detail: "chunk_size + max_overlap overflows".to_string(),
            })?;
        usize::try_from(buffer).map_err(|_| ScanError::Config {
            detail: format!("a chunk buffer of {buffer} bytes does not fit in usize"),
        })?;
        // A match cannot be longer than the chunk it was found in, and
        // [`Hit::length`] is a `u32`. Refusing a chunk that could hold a longer
        // match is the difference between an error and a hit whose recorded
        // length silently wrapped — a number in the case record that no match
        // ever had.
        if buffer > u64::from(u32::MAX) {
            return Err(ScanError::Config {
                detail: format!(
                    "a chunk buffer of {buffer} bytes could hold a match longer than a hit's \
                     recorded length can express ({} bytes)",
                    u32::MAX
                ),
            });
        }
        Ok(())
    }

    /// The overlap this configuration gives `scanner`, and the longest pattern
    /// that overlap can reliably find across a chunk boundary.
    fn geometry(&self, scanner: &dyn Scanner) -> Geometry {
        // `chunk_size >= 1` by validation, so this cannot underflow.
        let cap = self.max_overlap.min(self.chunk_size - 1);
        let (overlap, reliable) = match scanner.max_match_len() {
            Some(len) => {
                let wanted = len.saturating_sub(1);
                (wanted.min(cap), wanted <= cap)
            }
            // Unbounded: give it the whole cap, and admit the guarantee is absent.
            None => (cap, false),
        };
        Geometry {
            overlap,
            max_reliable_pattern_len: overlap.saturating_add(1),
            reliable,
        }
    }
}

/// Resolved chunk geometry for one scanner.
#[derive(Debug, Clone, Copy)]
struct Geometry {
    overlap: u64,
    max_reliable_pattern_len: u64,
    reliable: bool,
}

// ── Sections ────────────────────────────────────────────────────────────────

/// The mapped regions of a layer, in ascending address order.
///
/// Produced by [`derive_sections`]. Sections never overlap, are never empty and
/// are never adjacent — two adjacent mapped windows are always merged, because a
/// section boundary suppresses the chunk overlap and an *artificial* boundary
/// would drop a hit straddling it.
#[derive(Debug, Clone, Default)]
pub struct SectionPlan {
    /// Ascending, disjoint, non-adjacent mapped ranges.
    pub sections: Vec<Range<u64>>,
    /// Address from which nothing was enumerated because
    /// [`ScanConfig::max_sections`] fired. `None` means the whole requested range
    /// was enumerated.
    pub truncated_at: Option<u64>,
    /// First address enumeration started from.
    start: u64,
    /// Exclusive top of the enumerated range. Held as `u128` because an address
    /// space whose last byte is `u64::MAX` has an exclusive top of 2^64.
    top: u128,
}

impl SectionPlan {
    /// A plan over sections the caller already knows.
    ///
    /// [`derive_sections`] answers "what is mapped in this layer", which is the
    /// right question for a sweep. It is the wrong question when the regions
    /// *are* the forensic structure: a scan of one process's virtual address
    /// descriptors looks in the allocations the kernel recorded, so that a hit
    /// can be attributed to the allocation that held it, and a hit outside
    /// every allocation is not a thing this scan can produce.
    ///
    /// The ranges are sorted, empty ones dropped, and overlapping or touching
    /// ones **merged**. The merge is correctness and not tidiness, for the same
    /// reason it is in [`derive_sections`]: the chunk overlap is suppressed at a
    /// section end, so two sections that touch would silently lose a match
    /// lying across the boundary between them. A caller attributing hits back
    /// to its own regions must therefore attribute by address — the region a
    /// hit's first byte falls in — rather than by which section produced it.
    ///
    /// Unmapped address space **inside** a section is read and reported as a
    /// short read, exactly as it would be in a derived plan, so a caller whose
    /// regions include reserved memory should probe with
    /// [`derive_sections_in`] per region and pass the results here rather than
    /// passing the regions themselves.
    pub fn over(ranges: impl IntoIterator<Item = Range<u64>>) -> Self {
        let mut ranges: Vec<Range<u64>> = ranges.into_iter().filter(|r| r.start < r.end).collect();
        ranges.sort_by_key(|r| (r.start, r.end));

        let mut sections: Vec<Range<u64>> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match sections.last_mut() {
                // Touching counts as overlapping: `end == start` means no byte
                // lies between them, and a boundary there is invented.
                Some(last) if range.start <= last.end => {
                    if range.end > last.end {
                        last.end = range.end;
                    }
                }
                _ => sections.push(range),
            }
        }

        let start = sections.first().map(|s| s.start).unwrap_or(0);
        let top = sections.last().map(|s| s.end as u128).unwrap_or(0);
        Self {
            sections,
            truncated_at: None,
            start,
            top,
        }
    }

    /// First address the enumeration covered.
    pub fn start(&self) -> u64 {
        self.start
    }

    /// Exclusive top of the enumerated range, clamped into `u64`.
    ///
    /// `Range<u64>` cannot express an exclusive end of 2^64, so a layer whose
    /// last addressable byte is `u64::MAX` has that single byte excluded. No
    /// acquisition has a 16-exabyte address space; the clamp exists so a
    /// synthetic one cannot overflow or hang the walk.
    pub fn top(&self) -> u64 {
        clamp_top(self.top)
    }

    /// Total bytes covered by the sections: how much of the space is backed and
    /// will actually be scanned.
    pub fn mapped_len(&self) -> u64 {
        self.sections
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.end - s.start))
    }
}

fn clamp_top(top: u128) -> u64 {
    top.min(u64::MAX as u128) as u64
}

/// Enumerate every mapped region of `layer`, in ascending order.
///
/// This is what makes scanning tractable and honest at once. Tractable, because
/// the driver walks the bytes that exist rather than the address space they sit
/// in — the difference between 8 GiB and 256 TiB. Honest, because a region that
/// is not in a section is never read, so no hit can be reported out of memory the
/// acquisition did not capture.
///
/// The walk probes with [`MemoryLayer::mapping`] in windows of
/// [`ScanConfig::probe_window`]. A window that comes back as a hole advances the
/// cursor past it; a window that comes back mapped becomes a section, merged with
/// the previous one when they touch. **The merge is correctness, not tidiness:**
/// the chunk overlap is suppressed at section ends, so a boundary invented by the
/// probe geometry would silently lose any hit lying across it.
///
/// # Errors
///
/// - [`ScanError::EmptyAddressSpace`] if the layer's bounds are inverted.
/// - [`ScanError::NoProgress`] if the layer reports neither mapped bytes nor a
///   hole. Failing closed beats looping forever inside an ingest.
/// - [`ScanError::Layer`] for any other projection failure.
///
/// A layer that *does* advance, but only by a byte at a time, is bounded by
/// [`ScanConfig::max_probes`] rather than by [`ScanConfig::max_sections`]: holes
/// push no section and adjacent windows merge into one, so neither would ever
/// count such a walk. Exhausting the probe budget stops the enumeration at
/// [`SectionPlan::truncated_at`], which the driver reports as a cap.
pub fn derive_sections(
    layer: &dyn MemoryLayer,
    config: &ScanConfig,
) -> Result<SectionPlan, ScanError> {
    let min = layer.min_address();
    let max = layer.max_address();
    if min > max {
        return Err(ScanError::EmptyAddressSpace { min, max });
    }
    derive_sections_inner(layer, min, max as u128 + 1, config)
}

/// Enumerate the mapped regions of `layer` that fall inside `range`.
///
/// The targeted form of [`derive_sections`], for a scan that already knows where
/// to look — a pool sweep restricted to the kernel's non-paged pool, say. Hole
/// semantics are identical: a requested range partly outside the acquired memory
/// yields sections for the acquired part only.
pub fn derive_sections_in(
    layer: &dyn MemoryLayer,
    range: Range<u64>,
    config: &ScanConfig,
) -> Result<SectionPlan, ScanError> {
    let min = layer.min_address();
    let max = layer.max_address();
    if min > max {
        return Err(ScanError::EmptyAddressSpace { min, max });
    }
    let start = range.start.max(min);
    let top = (range.end as u128).min(max as u128 + 1);
    if (start as u128) >= top {
        // The request lies entirely above the address space. That is an empty
        // question, not an unread region: there are no addresses there to miss.
        return Ok(SectionPlan {
            sections: Vec::new(),
            truncated_at: None,
            start,
            top: start as u128,
        });
    }
    derive_sections_inner(layer, start, top, config)
}

fn derive_sections_inner(
    layer: &dyn MemoryLayer,
    start: u64,
    top: u128,
    config: &ScanConfig,
) -> Result<SectionPlan, ScanError> {
    let mut plan = SectionPlan {
        sections: Vec::new(),
        truncated_at: None,
        start,
        top,
    };
    let mut cursor = start;
    let mut probes = 0usize;

    loop {
        let here = cursor as u128;
        if here >= top {
            break;
        }
        // Bound the walk itself, not just what it produces: a layer answering in
        // one-byte holes pushes no section and merges no run, so `max_sections`
        // would never fire and the loop would run once per address.
        probes += 1;
        if probes > config.max_probes {
            plan.truncated_at = Some(cursor);
            return Ok(plan);
        }
        let want = (top - here).min(config.probe_window as u128) as u64;

        match layer.mapping(cursor, want) {
            Ok(runs) => {
                // How much of *this request* the runs back, not how much
                // address space they describe. A layer over a compressed
                // acquisition returns whole-frame runs that can begin below the
                // cursor and end above the window, and summing them would
                // advance the cursor past bytes that were never scanned while
                // recording them inside a scanned section.
                let covered = backed_len(&runs, cursor, want);
                if covered == 0 {
                    // `Ok` and nothing covered. Two different things again: a
                    // layer that cannot describe itself, or one that reports a
                    // window inside a hole this way rather than refusing —
                    // which `PhysicalLayer` over a declared geometry
                    // deliberately does. Ask it where the next acquired byte
                    // is; only a layer that cannot answer is a contradiction.
                    //
                    // Failing closed on both ended a scan of every sparse image
                    // at its first hole: a hibernation reconstruction whose
                    // first page is at 0x1000 produced "the layer made no
                    // progress at address 0x0" and no sections at all.
                    match layer.next_backed(cursor) {
                        Some(next) if next > cursor => {
                            cursor = next;
                            continue;
                        }
                        _ => return Err(ScanError::NoProgress { address: cursor }),
                    }
                }
                let Some(end) = cursor.checked_add(covered) else {
                    // The section runs to the very top of `u64`, which
                    // `Range<u64>` cannot express as an exclusive end.
                    push_section(&mut plan.sections, cursor..u64::MAX, config.max_sections);
                    plan.truncated_at = Some(u64::MAX);
                    return Ok(plan);
                };
                if !push_section(&mut plan.sections, cursor..end, config.max_sections) {
                    plan.truncated_at = Some(cursor);
                    return Ok(plan);
                }
                cursor = end;
            }
            Err(LayerError::Hole(hole)) => {
                if hole.address > cursor {
                    // The hole starts above the cursor, so the prefix below it
                    // should be mapped — but ask rather than assume. A prefix we
                    // cannot confirm is left out of the sections entirely, and so
                    // is recorded as unread rather than scanned.
                    let prefix = hole.address - cursor;
                    if let Ok(runs) = layer.mapping(cursor, prefix) {
                        let covered = backed_len(&runs, cursor, prefix);
                        if covered > 0 {
                            let end = cursor.saturating_add(covered);
                            if !push_section(&mut plan.sections, cursor..end, config.max_sections) {
                                plan.truncated_at = Some(cursor);
                                return Ok(plan);
                            }
                        }
                    }
                }
                let Some(next) = hole.address.checked_add(hole.length) else {
                    // The hole runs to the top of the address space.
                    break;
                };
                if next <= cursor {
                    return Err(ScanError::NoProgress { address: cursor });
                }
                cursor = next;
            }
            // Two different things arrive here and they are not the same
            // fact: the cursor is past the top of the space, or it is in the
            // **non-addressable middle** of a sign-extending 64-bit one. The
            // second has the kernel's whole half of the address space above it,
            // so breaking on both enumerated the lower canonical half and
            // called it the space -- a sweep of a Windows kernel space
            // reported 11 mapped regions totalling 156 KiB that way, with the
            // plan claiming it had enumerated everything.
            Err(LayerError::OutOfRange { .. }) => match layer.next_addressable(cursor) {
                Some(next) if next > cursor => cursor = next,
                // Nothing above this is addressable, which is the end.
                _ => break,
            },
            Err(other) => return Err(ScanError::Layer(other)),
        }
    }

    Ok(plan)
}

/// Append `range`, merging it into the previous section when they touch.
/// Returns `false` when the section cap would be exceeded.
fn push_section(sections: &mut Vec<Range<u64>>, range: Range<u64>, cap: usize) -> bool {
    if range.start >= range.end {
        return true;
    }
    if let Some(last) = sections.last_mut() {
        if last.end == range.start {
            last.end = range.end;
            return true;
        }
    }
    if sections.len() >= cap {
        return false;
    }
    sections.push(range);
    true
}

// ── Chunk planning ──────────────────────────────────────────────────────────

/// One unit of work: the bytes to read, and the addresses whose hits belong to
/// this chunk.
///
/// Separating `read_len` from `accept_end` is the whole boundary contract. A
/// chunk reads past its own end by the overlap so a match beginning just before
/// the boundary is visible in full, but it only *claims* hits beginning below
/// `accept_end`; anything beyond belongs to the next chunk, which will see it in
/// its own right. That is why a straddling hit is reported once rather than
/// twice, and once rather than never.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkPlan {
    /// Layer address of the chunk's first byte.
    pub address: u64,
    /// Bytes to read from `address`, including the overlap. Never extends past
    /// the end of the section: reading across a hole would fabricate byte
    /// adjacency.
    pub read_len: u64,
    /// Exclusive address bound for hits this chunk owns.
    pub accept_end: u64,
}

impl ChunkPlan {
    /// Exclusive end of the bytes this chunk reads.
    pub fn read_end(&self) -> u64 {
        self.address.saturating_add(self.read_len)
    }
}

/// Iterator over the chunks of one mapped section.
///
/// Borrows nothing from the scan state, so a future parallel driver can hand
/// descriptors to a worker pool without restructuring anything.
#[derive(Debug, Clone)]
pub struct ChunkPlans {
    cursor: u64,
    end: u64,
    chunk_size: u64,
    overlap: u64,
}

impl Iterator for ChunkPlans {
    type Item = ChunkPlan;

    fn next(&mut self) -> Option<ChunkPlan> {
        if self.chunk_size == 0 || self.cursor >= self.end {
            return None;
        }
        let accept_end = self.cursor.saturating_add(self.chunk_size).min(self.end);
        let read_end = self
            .cursor
            .saturating_add(self.chunk_size)
            .saturating_add(self.overlap)
            .min(self.end);
        let plan = ChunkPlan {
            address: self.cursor,
            read_len: read_end - self.cursor,
            accept_end,
        };
        // `chunk_size >= 1` and `cursor < end`, so `accept_end > cursor`: the walk
        // always advances.
        self.cursor = accept_end;
        Some(plan)
    }
}

/// Plan the chunks covering one mapped section.
///
/// The last chunk of a section is clipped at the section end and never extended
/// past it — that clip is what keeps the overlap from reaching across a hole.
pub fn chunk_plans(section: Range<u64>, chunk_size: u64, overlap: u64) -> ChunkPlans {
    ChunkPlans {
        cursor: section.start,
        end: section.end,
        chunk_size,
        overlap,
    }
}

// ── Outcome ─────────────────────────────────────────────────────────────────

/// The result of one scan, including everything it could not do.
///
/// Upstream's scanner swallows every exception, so a scan that failed and a scan
/// that found nothing produce the same empty list. Here the two are structurally
/// different: a failure leaves an entry in [`ScanOutcome::unread`], and
/// [`ScanOutcome::is_complete`] is the single question a report must ask before
/// writing "no hits".
#[derive(Debug, Clone, Default)]
pub struct ScanOutcome {
    /// Matches, in ascending address order, each reported exactly once.
    pub hits: Vec<Hit>,
    /// Distinct addressable bytes examined. Overlap is counted once, so this is
    /// the size of the evidence actually looked at, comparable against the
    /// layer's mapped length.
    pub bytes_scanned: u64,
    /// Ranges that were not examined, and why: unmapped holes the layer skipped,
    /// the tail of a truncated acquisition, and whatever lay above a cap that
    /// fired. Ascending and disjoint.
    pub unread: Vec<(Range<u64>, IncompleteReason)>,
    /// Total bytes in `unread`, exact even when the range list itself was capped.
    pub unread_bytes: u64,
    /// How many of `unread_bytes` were never mapped at all.
    ///
    /// A subset of `unread_bytes`, not a separate quantity: subtract it to get
    /// the bytes that were mapped and could not be read, which is the only part
    /// that represents evidence possibly missed. Nothing could have been in the
    /// rest.
    ///
    /// The distinction matters because the two differ by orders of magnitude. A
    /// sweep of a large reserved region in a 64-bit process reported
    /// "2199081095168 byte(s) … were not examined, so a service record among
    /// them would not have been found" — 2.2 TB of address space that never
    /// held a page — on the same record as a genuine 217 KB gap, which the
    /// bigger number rendered invisible.
    pub unmapped_bytes: u64,
    /// How many of `unread_bytes` lie above a ceiling that fired: planned and
    /// never asked for, mapped or not. A subset of `unread_bytes`, disjoint
    /// from `unmapped_bytes`; the bytes that were mapped and would not read are
    /// `unread_bytes - unmapped_bytes - not_searched_bytes` (MEM-041).
    pub not_searched_bytes: u64,
    /// Whether the `unread` *list* was capped. The byte total above stays exact.
    pub unread_truncated: bool,
    /// Whether the scan stopped early: the hit cap or the section cap fired. The
    /// unscanned remainder is in `unread` with [`IncompleteReason::CapReached`].
    pub truncated: bool,
    /// Longest pattern this scan could reliably find across a chunk boundary,
    /// i.e. the overlap plus one.
    pub max_reliable_pattern_len: u64,
    /// Whether the scanner can match something longer than
    /// `max_reliable_pattern_len` — any unbounded regex, or a needle above the
    /// overlap cap. Such a match is still found when it lies inside a chunk; it
    /// is unreliable only across a boundary. Published so it is a stated
    /// limitation rather than a silent miss.
    pub pattern_may_exceed_overlap: bool,
    /// Which scanner produced this outcome.
    pub scanner: String,
}

impl ScanOutcome {
    /// Whether every mapped byte of the requested range was examined and every
    /// hit returned.
    ///
    /// The question a report must ask before writing "no hits found": an
    /// incomplete scan that found nothing says nothing about the evidence.
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.unread.is_empty() && self.unread_bytes == 0
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let unread: Vec<serde_json::Value> = self
            .unread
            .iter()
            .map(|(range, reason)| {
                serde_json::json!({
                    "start": range.start,
                    "end": range.end,
                    "reason": reason.as_str(),
                })
            })
            .collect();
        serde_json::json!({
            "scanner": self.scanner,
            "hits": self.hits.len(),
            "bytes_scanned": self.bytes_scanned,
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "max_reliable_pattern_len": self.max_reliable_pattern_len,
            "pattern_may_exceed_overlap": self.pattern_may_exceed_overlap,
            "unread_bytes": self.unread_bytes,
            "unmapped_bytes": self.unmapped_bytes,
            "not_searched_bytes": self.not_searched_bytes,
            "unread_truncated": self.unread_truncated,
            "unread": unread,
        })
    }
}

/// Accumulator for unread ranges that keeps the byte total exact even after the
/// range list is capped.
#[derive(Debug)]
struct UnreadLog {
    ranges: Vec<(Range<u64>, IncompleteReason)>,
    bytes: u64,
    /// How many of `bytes` were never mapped, as opposed to mapped and
    /// unreadable. Counted alongside, never instead: every existing reader of
    /// `bytes` sees exactly what it saw before.
    unmapped_bytes: u64,
    /// How many of `bytes` lie above a ceiling that fired.
    not_searched_bytes: u64,
    /// Highest exclusive end recorded so far, so overlapping reports from
    /// adjacent chunks cannot double-count.
    high_water: u64,
    truncated: bool,
    cap: usize,
}

impl UnreadLog {
    fn new(cap: usize) -> Self {
        Self {
            ranges: Vec::new(),
            bytes: 0,
            unmapped_bytes: 0,
            not_searched_bytes: 0,
            high_water: 0,
            truncated: false,
            cap,
        }
    }

    /// Record `range` as address space that was never mapped.
    ///
    /// A hole between two mapped sections, or the space above the last one.
    /// Nothing was there to read, so calling it "not examined" — which is what
    /// `bytes` alone says — invites the reader to think evidence might have
    /// been missed there. It could not have been.
    ///
    /// Still recorded in `bytes` and `ranges`, because changing what those mean
    /// would change every completeness claim built on them at once. This only
    /// makes the split *available* to a caller that wants to describe the two
    /// honestly.
    fn record_unmapped(&mut self, range: Range<u64>) {
        let before = self.bytes;
        self.record(range, IncompleteReason::Unmapped);
        self.unmapped_bytes = self
            .unmapped_bytes
            .saturating_add(self.bytes.saturating_sub(before));
    }

    /// Record `range` as address space above a ceiling that fired: never asked
    /// for, so neither "unmapped" nor "would not read" describes it.
    fn record_not_searched(&mut self, range: Range<u64>) {
        let before = self.bytes;
        self.record(range, IncompleteReason::CapReached);
        self.not_searched_bytes = self
            .not_searched_bytes
            .saturating_add(self.bytes.saturating_sub(before));
    }

    /// Record `range` as unexamined. Ranges arrive in ascending order, which the
    /// driver guarantees by walking sections ascending.
    fn record(&mut self, range: Range<u64>, reason: IncompleteReason) {
        if range.start >= range.end {
            return;
        }
        // Count only bytes an earlier, overlapping entry has not already counted.
        let counted_from = range.start.max(self.high_water);
        if range.end > counted_from {
            self.bytes = self.bytes.saturating_add(range.end - counted_from);
        }
        self.high_water = self.high_water.max(range.end);

        if let Some((last, last_reason)) = self.ranges.last_mut() {
            if *last_reason == reason && range.start <= last.end {
                if range.end > last.end {
                    last.end = range.end;
                }
                return;
            }
        }
        if self.ranges.len() >= self.cap {
            self.truncated = true;
            return;
        }
        self.ranges.push((range, reason));
    }
}

// ── Driver ──────────────────────────────────────────────────────────────────

/// Scan every mapped byte of `layer` for `scanner`'s patterns.
///
/// # Errors
///
/// Only for failures that make the whole scan meaningless — an inconsistent
/// layer, or a configuration that cannot produce a correct walk. A region that
/// could not be read is *not* an error: it lands in [`ScanOutcome::unread`],
/// where an examiner can see exactly what was missed.
pub fn scan_layer(
    layer: &dyn MemoryLayer,
    scanner: &dyn Scanner,
    config: &ScanConfig,
) -> Result<ScanOutcome, ScanError> {
    config.validate()?;
    let plan = derive_sections(layer, config)?;
    scan_planned(layer, scanner, &plan, config)
}

/// Scan the mapped bytes of `layer` that fall inside `range`.
///
/// For scans that already know where to look: a pool sweep bounded to the
/// kernel's non-paged pool, a banner sweep bounded to low physical memory. Holes
/// inside `range` are skipped and recorded exactly as in [`scan_layer`].
pub fn scan_range(
    layer: &dyn MemoryLayer,
    scanner: &dyn Scanner,
    range: Range<u64>,
    config: &ScanConfig,
) -> Result<ScanOutcome, ScanError> {
    config.validate()?;
    let plan = derive_sections_in(layer, range, config)?;
    scan_planned(layer, scanner, &plan, config)
}

/// Scan a section plan that was already derived.
///
/// Split out so a caller that wants to inspect, report or reuse the section list
/// — "the scan covered these 41 regions totalling 7.7 GiB of an 8 GiB address
/// space" — does not have to derive it twice.
pub fn scan_planned(
    layer: &dyn MemoryLayer,
    scanner: &dyn Scanner,
    plan: &SectionPlan,
    config: &ScanConfig,
) -> Result<ScanOutcome, ScanError> {
    config.validate()?;
    let geometry = config.geometry(scanner);

    let mut outcome = ScanOutcome {
        max_reliable_pattern_len: geometry.max_reliable_pattern_len,
        pattern_may_exceed_overlap: !geometry.reliable,
        scanner: scanner.name().to_string(),
        ..ScanOutcome::default()
    };
    let mut unread = UnreadLog::new(config.max_unread_ranges);

    // One buffer for the whole scan; `validate` proved the length fits `usize`.
    // A parallel driver would give each worker one of these.
    let buffer_len =
        usize::try_from(config.chunk_size.saturating_add(geometry.overlap)).map_err(|_| {
            ScanError::Config {
                detail: "the chunk buffer does not fit in usize".to_string(),
            }
        })?;
    let mut buffer = vec![0u8; buffer_len];

    let top = plan.top();
    let mut prev_end = plan.start;
    let mut stopped_at: Option<u64> = None;

    'sections: for section in &plan.sections {
        // Anything between the previous section and this one is memory the
        // acquisition did not capture. Skipped, never read through, and never
        // dropped from the record.
        if section.start > prev_end {
            unread.record_unmapped(prev_end..section.start);
        }

        for chunk in chunk_plans(section.clone(), config.chunk_size, geometry.overlap) {
            let len = usize::try_from(chunk.read_len).map_err(|_| ScanError::Config {
                detail: "the chunk read length does not fit in usize".to_string(),
            })?;
            let slice = buffer.get_mut(..len).ok_or_else(|| ScanError::Config {
                detail: "the chunk read length exceeds the scan buffer".to_string(),
            })?;

            let report = scan_one_chunk(
                layer,
                scanner,
                &chunk,
                slice,
                config.max_hits,
                &mut outcome.hits,
            );
            outcome.bytes_scanned = outcome.bytes_scanned.saturating_add(report.bytes_scanned);
            if let Some(range) = report.unread {
                unread.record(range, IncompleteReason::ShortRead);
            }
            if let Some(address) = report.stopped_at {
                stopped_at = Some(address);
                break 'sections;
            }
        }

        prev_end = section.end;
    }

    if let Some(address) = stopped_at {
        // The hit cap fired. Everything from just past the last reported hit
        // upward went unexamined, holes included — one honest range rather than a
        // claim about which parts of it were mapped.
        outcome.truncated = true;
        unread.record_not_searched(address..top);
    } else {
        if prev_end < top {
            let tail_end = plan.truncated_at.unwrap_or(top).min(top);
            unread.record_unmapped(prev_end..tail_end);
        }
        if let Some(address) = plan.truncated_at {
            outcome.truncated = true;
            unread.record_not_searched(address..top);
        }
    }

    outcome.unread = unread.ranges;
    outcome.unread_bytes = unread.bytes;
    outcome.unmapped_bytes = unread.unmapped_bytes;
    outcome.not_searched_bytes = unread.not_searched_bytes;
    outcome.unread_truncated = unread.truncated;
    Ok(outcome)
}

/// What one chunk contributed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ChunkReport {
    /// Distinct addressable bytes examined by this chunk, overlap excluded.
    bytes_scanned: u64,
    /// The part of this chunk that could not be read.
    unread: Option<Range<u64>>,
    /// Set when the hit cap fired inside this chunk, giving the address from
    /// which nothing more was examined.
    stopped_at: Option<u64>,
}

/// Read and scan one chunk.
///
/// The unit a parallel driver would hand to a worker: it depends on nothing but
/// its arguments, and `DataSource::read_at` is stateless and `Send + Sync` by
/// contract, so several of these could run at once with no locking. Kept single
/// threaded here because this crate carries no work-stealing dependency.
///
/// Three invariants live in this function:
///
/// - only `buf[..n]` is ever scanned, where `n` is what the layer actually
///   returned, so the zeroed tail of the buffer can never be matched as if it
///   were acquired memory;
/// - hit addresses are `chunk.address + match_offset`, never derived from a
///   buffer length, so a short read cannot shift every offset in the scan;
/// - only hits starting below `chunk.accept_end` are kept, so a match visible
///   both in this chunk's overlap and in the next chunk's body is reported once.
fn scan_one_chunk(
    layer: &dyn MemoryLayer,
    scanner: &dyn Scanner,
    chunk: &ChunkPlan,
    buf: &mut [u8],
    max_hits: usize,
    hits: &mut Vec<Hit>,
) -> ChunkReport {
    let n = read_into(layer.as_data_source(), chunk.address, buf);

    let unread = if (n as u64) < chunk.read_len {
        let from = chunk.address.saturating_add(n as u64);
        Some(from..chunk.read_end())
    } else {
        None
    };

    let accept_len = chunk.accept_end.saturating_sub(chunk.address);
    let mut stopped_at: Option<u64> = None;
    {
        let start = chunk.address;
        let accept_end = chunk.accept_end;
        let mut sink = |hit: Hit| -> ScanControl {
            if hit.address < start || hit.address >= accept_end {
                // Found in the overlap: it belongs to the next chunk, which owns
                // those addresses and will report it there.
                return ScanControl::Continue;
            }
            hits.push(hit);
            if hits.len() >= max_hits {
                stopped_at = Some(hit.address.saturating_add(1));
                ScanControl::Stop
            } else {
                ScanControl::Continue
            }
        };
        scanner.scan_chunk(&buf[..n], start, &mut sink);
    }

    let mut bytes_scanned = (n as u64).min(accept_len);
    if let Some(address) = stopped_at {
        bytes_scanned = bytes_scanned.min(address.saturating_sub(chunk.address));
    }

    ChunkReport {
        bytes_scanned,
        unread,
        stopped_at,
    }
}

/// Fill `buf` from `source` at `address`, returning how many bytes were really
/// read.
///
/// Deliberately best-effort, and deliberately honest about it: the caller scans
/// only the prefix this returns and records the rest as unread. A hole, a
/// truncated acquisition file and an I/O failure all shorten the result rather
/// than producing bytes, which is the only behaviour compatible with never
/// fabricating evidence.
fn read_into(source: &dyn DataSource, address: u64, buf: &mut [u8]) -> usize {
    let mut done = 0usize;
    let mut interrupted = 0u32;
    while done < buf.len() {
        let Some(at) = address.checked_add(done as u64) else {
            break;
        };
        match source.read_at(at, &mut buf[done..]) {
            Ok(0) => break,
            // `min` guards a source reporting more bytes than it was given room
            // for; indexing past the buffer would panic on hostile evidence.
            Ok(got) => done += got.min(buf.len() - done),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {
                interrupted += 1;
                if interrupted > MAX_INTERRUPTED_RETRIES {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    done
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::MemoryImageFormat;
    use crate::layer::{MappedRange, MemoryHole};
    use crate::meta::LayerMeta;
    use crate::physical::PhysicalLayer;
    use crate::segmented::{Segment, SegmentedLayer};
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;

    const FILLER: u8 = 0xCC;

    fn source(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes))
    }

    fn flat(bytes: Vec<u8>) -> PhysicalLayer {
        PhysicalLayer::raw(source(bytes)).expect("non-empty image")
    }

    fn meta() -> LayerMeta {
        LayerMeta::new(MemoryImageFormat::Lime)
    }

    /// Small chunks, so a test can exercise boundary behaviour without building a
    /// 16 MiB fixture.
    fn tight(chunk_size: u64) -> ScanConfig {
        ScanConfig {
            chunk_size,
            ..ScanConfig::default()
        }
    }

    /// A layer that reports whole frames, as one over a compressed acquisition
    /// does: every run starts on a frame boundary and runs a full frame.
    #[derive(Debug)]
    struct FramedLayer {
        inner: Arc<dyn MemoryLayer>,
        frame: u64,
    }

    impl DataSource for FramedLayer {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            self.inner.as_data_source().read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.inner.as_data_source().size()
        }
    }

    impl MemoryLayer for FramedLayer {
        fn min_address(&self) -> u64 {
            self.inner.min_address()
        }
        fn max_address(&self) -> u64 {
            self.inner.max_address()
        }
        fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
            let runs = self.inner.mapping(offset, length)?;
            if runs.is_empty() {
                return Ok(runs);
            }
            let first = runs[0].offset - (runs[0].offset % self.frame);
            let end = runs[runs.len() - 1].end().div_ceil(self.frame) * self.frame;
            let mut widened = Vec::new();
            let mut at = first;
            while at < end {
                widened.push(MappedRange::identity(at, self.frame, at));
                at += self.frame;
            }
            Ok(widened)
        }
        fn layer_meta(&self) -> &LayerMeta {
            self.inner.layer_meta()
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    /// A layer shaped like a sign-extending 64-bit virtual space: bytes low,
    /// bytes high, and **nothing addressable in between** — the region a
    /// 64-bit CPU faults on, which `mapping` reports the same way as the top of
    /// the space.
    ///
    /// `addressable_middle` chooses whether it answers
    /// [`MemoryLayer::next_addressable`] the way a real virtual layer does. With
    /// it off the layer takes the trait's default, which is what every
    /// contiguous layer wants and is exactly what made a kernel-space sweep
    /// stop at the gap.
    #[derive(Debug)]
    struct SignExtendingLayer {
        inner: Arc<dyn MemoryLayer>,
        /// Where the upper half's bytes are in `inner`.
        upper_at: u64,
        answers_next_addressable: bool,
    }

    /// Base of the upper canonical half of a 48-bit x86-64 space.
    const UPPER_HALF: u64 = 0xFFFF_8000_0000_0000;
    /// First address of the unusable middle.
    const GAP_START: u64 = 0x0000_8000_0000_0000;

    impl SignExtendingLayer {
        /// `inner` holds the low bytes at 0 and the high half's bytes at
        /// `upper_at`.
        fn new(inner: Arc<dyn MemoryLayer>, upper_at: u64, answers: bool) -> Self {
            Self {
                inner,
                upper_at,
                answers_next_addressable: answers,
            }
        }

        /// Where an address's bytes live in the backing image, if anywhere.
        fn backing(&self, address: u64) -> Option<u64> {
            if address < 0x100 {
                Some(address)
            } else if (UPPER_HALF..UPPER_HALF + 0x100).contains(&address) {
                Some(self.upper_at + (address - UPPER_HALF))
            } else {
                None
            }
        }
    }

    impl DataSource for SignExtendingLayer {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            match self.backing(offset) {
                Some(at) => self.inner.as_data_source().read_at(at, buf),
                None => Ok(0),
            }
        }
        fn size(&self) -> u64 {
            u64::MAX
        }
    }

    impl MemoryLayer for SignExtendingLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            u64::MAX
        }
        fn next_addressable(&self, address: u64) -> Option<u64> {
            if !self.answers_next_addressable {
                return (address <= self.max_address()).then_some(address);
            }
            if (GAP_START..UPPER_HALF).contains(&address) {
                Some(UPPER_HALF)
            } else {
                Some(address)
            }
        }
        fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
            if length == 0 {
                return Ok(Vec::new());
            }
            // The gap is not addressable at all, and a real layer reports that
            // the same way it reports the top of the space.
            if (GAP_START..UPPER_HALF).contains(&offset) {
                return Err(LayerError::OutOfRange {
                    address: offset,
                    max_address: self.max_address(),
                });
            }
            match self.backing(offset) {
                Some(at) => {
                    let end = if offset < 0x100 {
                        0x100
                    } else {
                        UPPER_HALF + 0x100
                    };
                    let len = length.min(end - offset);
                    Ok(vec![MappedRange::identity(offset, len, at)])
                }
                // One hole per region a table entry would govern, as a real
                // layer reports: to the end of this half of the space. A double
                // that answered in 256-byte holes would exhaust the probe
                // budget long before the gap and test nothing.
                None if offset < GAP_START => Err(LayerError::Hole(MemoryHole::unmapped(
                    offset,
                    GAP_START - offset,
                ))),
                None => Err(LayerError::Hole(MemoryHole::unmapped(offset, u64::MAX))),
            }
        }
        fn layer_meta(&self) -> &LayerMeta {
            self.inner.layer_meta()
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    /// **The kernel's half of a 64-bit space is enumerated**, because the walk
    /// asks the layer where the next addressable byte is instead of reading the
    /// unusable middle as the end of the space.
    ///
    /// The failure this closes: a sweep of a real Windows kernel space returned
    /// **11 sections totalling 156 KiB** — the System process's low half — and
    /// reported the plan as complete, with the entire kernel above the gap
    /// never probed.
    #[test]
    fn a_sign_extending_space_is_enumerated_above_its_unusable_middle() {
        let mut bytes = vec![FILLER; 0x400];
        bytes[0x200..0x204].copy_from_slice(b"Proc");
        let layer = SignExtendingLayer::new(Arc::new(flat(bytes)), 0x200, true);

        let plan = derive_sections(&layer, &ScanConfig::default()).expect("a walkable layer");
        assert_eq!(
            plan.sections,
            vec![0..0x100, UPPER_HALF..UPPER_HALF + 0x100],
            "both halves, and nothing in the gap"
        );
        assert!(
            plan.truncated_at.is_none(),
            "the walk reached the top of the space"
        );

        // And a scan of it finds the needle that only exists above the gap.
        let scanner = SingleStringScanner::new("one", b"Proc").expect("valid needle");
        let outcome =
            scan_planned(&layer, &scanner, &plan, &tight(64)).expect("a well-formed scan");
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, UPPER_HALF);
        assert_eq!(outcome.bytes_scanned, 0x200);
    }

    /// The default answer — every contiguous layer's — stops at the gap, which
    /// is why a sign-extending layer has to override it.
    #[test]
    fn without_the_layers_own_answer_the_walk_stops_at_the_middle() {
        let mut bytes = vec![FILLER; 0x400];
        bytes[0x200..0x204].copy_from_slice(b"Proc");
        let layer = SignExtendingLayer::new(Arc::new(flat(bytes)), 0x200, false);

        let plan = derive_sections(&layer, &ScanConfig::default()).expect("a walkable layer");
        assert_eq!(plan.sections, vec![0..0x100], "the lower half only");
    }

    /// **A sparse image is enumerated across its holes**, because the layer is
    /// asked where the next acquired byte is instead of its `Ok`-with-no-runs
    /// being read as a layer that cannot describe itself.
    ///
    /// The failure this closes: a hibernation reconstruction whose first page
    /// is at `0x1000` produced *"the memory layer made no progress at address
    /// 0x0"* and no sections at all — so an examiner's patterns were searched
    /// for in none of it. Every sparse format has this shape: LiME starting
    /// above zero, a crash dump that skips page zero, any acquisition with an
    /// MMIO window in the middle.
    #[test]
    fn a_sparse_physical_layer_is_enumerated_across_its_holes() {
        // Acquired at 0x100..0x200 and 0x300..0x400 of a 0x400-byte space, with
        // the needle in the second run — the run a walk that stopped at the
        // first hole would never reach.
        let mut bytes = vec![FILLER; 0x400];
        bytes[0x310..0x314].copy_from_slice(b"Proc");
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        let layer = PhysicalLayer::raw(source)
            .expect("non-empty")
            .with_backed(vec![(0x100, 0x100), (0x300, 0x100)]);

        let plan = derive_sections(&layer, &ScanConfig::default()).expect("a walkable layer");
        assert_eq!(plan.sections, vec![0x100..0x200, 0x300..0x400]);
        assert!(plan.truncated_at.is_none());

        let scanner = SingleStringScanner::new("one", b"Proc").expect("valid needle");
        let outcome =
            scan_planned(&layer, &scanner, &plan, &tight(64)).expect("a well-formed scan");
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 0x310);
        assert_eq!(outcome.bytes_scanned, 0x200, "the two acquired runs");
        assert_eq!(
            outcome.unread_bytes, outcome.unmapped_bytes,
            "the hole between them was never acquired, so nothing could have been in it"
        );
    }

    /// A layer that answers `Ok` with no runs **and** cannot say where the next
    /// acquired byte is contradicts itself, and that is still refused. The
    /// default `next_backed` answers with the address itself, which is what a
    /// flat layer means — so a layer with no geometry that reports no runs is
    /// broken, not sparse.
    #[test]
    fn a_layer_that_reports_nothing_and_cannot_say_where_to_resume_is_refused() {
        #[derive(Debug)]
        struct SaysNothing(Arc<dyn MemoryLayer>);
        impl DataSource for SaysNothing {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                self.0.as_data_source().read_at(offset, buf)
            }
            fn size(&self) -> u64 {
                self.0.as_data_source().size()
            }
        }
        impl MemoryLayer for SaysNothing {
            fn min_address(&self) -> u64 {
                self.0.min_address()
            }
            fn max_address(&self) -> u64 {
                self.0.max_address()
            }
            fn mapping(&self, _offset: u64, _length: u64) -> Result<Vec<MappedRange>, LayerError> {
                Ok(Vec::new())
            }
            fn layer_meta(&self) -> &LayerMeta {
                self.0.layer_meta()
            }
            fn as_data_source(&self) -> &dyn DataSource {
                self
            }
        }

        let layer = SaysNothing(Arc::new(flat(vec![FILLER; 0x200])));
        let err = derive_sections(&layer, &ScanConfig::default())
            .expect_err("a layer that describes nothing is a refusal");
        assert!(
            matches!(err, ScanError::NoProgress { address: 0 }),
            "{err:?}"
        );
    }

    /// Section planning must not credit coverage the request never asked for.
    ///
    /// A layer whose runs are wider than the request — every layer over a
    /// compressed acquisition — makes the sum of run lengths exceed the probe
    /// window. Advancing the cursor by that sum walks past addresses that were
    /// never probed *and* records them inside a section, so the plan reports as
    /// scanned a range nothing looked at. For a tool whose sweep decides
    /// "this image holds no Linux kernel", that is the difference between a
    /// negative finding and an unexamined gap.
    #[test]
    fn a_section_plan_over_whole_frame_runs_does_not_run_past_the_request() {
        // Deliberately NOT a whole number of frames: the last frame is
        // partial, so widening the final run pushes it past the top of the
        // address space. An image that tiles the frame size exactly would hide
        // the defect, because every over-reported byte would happen to be
        // backed anyway.
        let bytes = vec![FILLER; 0x3800];
        let layer = FramedLayer {
            inner: Arc::new(flat(bytes)),
            frame: 0x1000,
        };
        // A probe window that is not a whole number of frames, so summing the
        // returned runs necessarily over-reports.
        let config = ScanConfig {
            probe_window: 0x600,
            ..ScanConfig::default()
        };
        let plan = derive_sections(&layer, &config).expect("sections");

        for section in &plan.sections {
            assert!(
                section.end <= layer.max_address() + 1,
                "section {section:?} runs past the top of the address space"
            );
        }
        let total: u64 = plan.sections.iter().map(|s| s.end - s.start).sum();
        assert!(
            total <= 0x3800,
            "the plan claims {total:#x} bytes of a 0x3800-byte space"
        );
        // Ascending and disjoint, which over-advancing would also break.
        for pair in plan.sections.windows(2) {
            assert!(
                pair[0].end <= pair[1].start,
                "sections overlap: {:?} then {:?}",
                pair[0],
                pair[1]
            );
        }
    }

    fn needle_at(len: usize, offset: usize, needle: &[u8]) -> Vec<u8> {
        let mut bytes = vec![FILLER; len];
        bytes[offset..offset + needle.len()].copy_from_slice(needle);
        bytes
    }

    fn scan(layer: &dyn MemoryLayer, scanner: &dyn Scanner, config: &ScanConfig) -> ScanOutcome {
        scan_layer(layer, scanner, config).expect("a well-formed scan")
    }

    // ── Chunk geometry ──────────────────────────────────────────────────────

    #[test]
    fn the_last_chunk_of_a_section_never_reads_past_the_section_end() {
        // Reading past the end is how an overlap window reaches across a hole and
        // fabricates byte adjacency, so the clip is checked directly.
        let plans: Vec<ChunkPlan> = chunk_plans(0..100, 64, 7).collect();
        assert_eq!(
            plans,
            vec![
                ChunkPlan {
                    address: 0,
                    read_len: 71,
                    accept_end: 64
                },
                ChunkPlan {
                    address: 64,
                    read_len: 36,
                    accept_end: 100
                },
            ]
        );
        assert_eq!(plans[1].read_end(), 100, "clipped at the section end");
    }

    #[test]
    fn chunk_plans_tile_a_section_exactly_once() {
        let plans: Vec<ChunkPlan> = chunk_plans(0x1000..0x1500, 0x200, 0x10).collect();
        let mut expected = 0x1000u64;
        for plan in &plans {
            assert_eq!(plan.address, expected, "no gap and no overlap in ownership");
            expected = plan.accept_end;
        }
        assert_eq!(expected, 0x1500);
    }

    #[test]
    fn a_section_at_the_very_top_of_the_address_space_terminates() {
        let plans: Vec<ChunkPlan> = chunk_plans(u64::MAX - 10..u64::MAX, 4, 3)
            .take(20)
            .collect();
        assert_eq!(plans.len(), 3);
        assert_eq!(plans.last().expect("chunks").accept_end, u64::MAX);
    }

    // ── The straddling hit ──────────────────────────────────────────────────

    #[test]
    fn a_needle_straddling_a_chunk_boundary_is_found_exactly_once() {
        // Chunk 0 owns [0,64) and reads [0,71); the needle runs 60..68, so only
        // chunk 0 can see all of it, and only chunk 0 owns it.
        let scanner = SingleStringScanner::new("straddle", b"SEANCE!!").expect("valid needle");
        let layer = flat(needle_at(0x100, 60, b"SEANCE!!"));
        let outcome = scan(&layer, &scanner, &tight(64));

        assert_eq!(
            outcome.hits,
            vec![Hit {
                address: 60,
                pattern_id: 0,
                length: 8
            }]
        );
        assert!(outcome.is_complete());
    }

    #[test]
    fn a_needle_at_every_offset_across_a_boundary_is_found_exactly_once() {
        // The whole boundary window, not just the interesting-looking case: a
        // needle wholly before the boundary, straddling it at every alignment,
        // and wholly inside the next chunk.
        let scanner = SingleStringScanner::new("sweep", b"SEANCE!!").expect("valid needle");
        for offset in 50..=80usize {
            let layer = flat(needle_at(0x100, offset, b"SEANCE!!"));
            let outcome = scan(&layer, &scanner, &tight(64));
            assert_eq!(
                outcome.hits.len(),
                1,
                "offset {offset} must be reported exactly once, not {:?}",
                outcome.hits
            );
            assert_eq!(outcome.hits[0].address, offset as u64);
        }
    }

    #[test]
    fn a_hit_visible_in_the_overlap_is_reported_by_the_next_chunk_only() {
        // The overlap is sized by the LONGEST needle, so a shorter one can be
        // fully visible inside it. "Proc" at 66 is complete within chunk 0's read
        // of [0,71) and complete within chunk 1's body: chunk 0 must discard it.
        let scanner =
            MultiStringScanner::new("mixed", [b"SEANCE!!".as_slice(), b"Proc".as_slice()])
                .expect("valid needles");
        let layer = flat(needle_at(0x100, 66, b"Proc"));
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.hits.len(), 1, "{:?}", outcome.hits);
        assert_eq!(outcome.hits[0].address, 66);
    }

    #[test]
    fn a_pattern_of_exactly_the_declared_reliable_length_is_found_at_the_worst_offset() {
        // `max_reliable_pattern_len` is a promise made in the outcome, and the
        // offset that tests it is the last one a chunk owns: a needle starting
        // at `accept_end - 1` must still be visible in full inside that chunk's
        // read. One byte less overlap and this is a silent miss.
        let config = ScanConfig {
            chunk_size: 64,
            max_overlap: 4,
            ..ScanConfig::default()
        };
        let scanner = SingleStringScanner::new("exact", b"ABCDE").expect("valid needle");
        let layer = flat(needle_at(0x100, 63, b"ABCDE"));
        let outcome = scan(&layer, &scanner, &config);

        assert_eq!(outcome.max_reliable_pattern_len, 5);
        assert!(
            !outcome.pattern_may_exceed_overlap,
            "5 <= 5, so it is a promise"
        );
        assert_eq!(
            outcome.hits,
            vec![Hit {
                address: 63,
                pattern_id: 0,
                length: 5
            }],
            "the last offset the chunk owns, found exactly once"
        );
    }

    #[test]
    fn a_pattern_longer_than_the_declared_reliable_length_is_missed_but_declared() {
        // The honest half of the same promise. Six bytes across a boundary a
        // five-byte overlap cannot span is genuinely unfindable here, so the
        // outcome must not read as a clean scan that found nothing.
        let config = ScanConfig {
            chunk_size: 64,
            max_overlap: 4,
            ..ScanConfig::default()
        };
        let scanner = SingleStringScanner::new("toolong", b"ABCDEF").expect("valid needle");
        let layer = flat(needle_at(0x100, 63, b"ABCDEF"));
        let outcome = scan(&layer, &scanner, &config);

        assert!(outcome.hits.is_empty(), "{:?}", outcome.hits);
        assert_eq!(outcome.max_reliable_pattern_len, 5);
        assert!(
            outcome.pattern_may_exceed_overlap,
            "an empty hit list here must carry the reason it may be empty"
        );

        // And the same needle wholly inside one chunk is still found, so the
        // limitation is about boundaries and nothing else.
        let layer = flat(needle_at(0x100, 20, b"ABCDEF"));
        let outcome = scan(&layer, &scanner, &config);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 20);
    }

    #[test]
    fn hits_are_reported_in_ascending_address_order() {
        let mut bytes = vec![FILLER; 0x200];
        for offset in [10usize, 63, 130, 200, 400] {
            bytes[offset..offset + 4].copy_from_slice(b"Proc");
        }
        let scanner = MultiStringScanner::new("tags", [b"Proc".as_slice()]).expect("valid needles");
        let layer = flat(bytes);
        let outcome = scan(&layer, &scanner, &tight(64));
        let addresses: Vec<u64> = outcome.hits.iter().map(|h| h.address).collect();
        assert_eq!(addresses, vec![10, 63, 130, 200, 400]);
    }

    #[test]
    fn bytes_scanned_counts_each_address_once_despite_the_overlap() {
        let scanner = SingleStringScanner::new("count", b"SEANCE!!").expect("valid needle");
        let layer = flat(vec![FILLER; 0x1000]);
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.bytes_scanned, 0x1000);
        assert!(outcome.hits.is_empty());
        assert!(outcome.is_complete());
    }

    // ── Holes ───────────────────────────────────────────────────────────────

    /// Backing bytes with a needle laid across file offsets `0x0FE..0x102`, so
    /// two segments can be built from it that are file-adjacent but, in one case,
    /// memory-disjoint.
    fn seam_image() -> Vec<u8> {
        let mut bytes = vec![FILLER; 0x400];
        bytes[0x0FE..0x102].copy_from_slice(b"ABCD");
        bytes
    }

    /// The needle's halves land either side of an unmapped 0x100-byte gap: "AB"
    /// ends the first segment, "CD" starts the second. The bytes are adjacent in
    /// the acquisition *file* and were never adjacent in *memory*.
    fn holed_layer() -> SegmentedLayer {
        SegmentedLayer::new(
            source(seam_image()),
            vec![
                Segment::new(0x000, 0x000, 0x100),
                Segment::new(0x100, 0x200, 0x100),
            ],
            meta(),
        )
        .expect("a valid segment list")
    }

    /// The same bytes with the gap removed, so the needle really is contiguous in
    /// memory.
    fn seamless_layer() -> SegmentedLayer {
        SegmentedLayer::new(
            source(seam_image()),
            vec![
                Segment::new(0x000, 0x000, 0x100),
                Segment::new(0x100, 0x100, 0x100),
            ],
            meta(),
        )
        .expect("a valid segment list")
    }

    #[test]
    fn a_needle_is_found_when_the_bytes_really_are_adjacent_in_memory() {
        // The control for the test below: same file, same needle, no hole. Without
        // this, the negative result there would prove nothing.
        let scanner = SingleStringScanner::new("seam", b"ABCD").expect("valid needle");
        let layer = seamless_layer();
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 0x0FE);
        assert!(outcome.is_complete());
    }

    #[test]
    fn a_hit_is_never_fabricated_by_stitching_across_a_hole() {
        // Reporting "ABCD" here would be testimony about an adjacency that never
        // existed on the suspect's machine.
        let scanner = SingleStringScanner::new("seam", b"ABCD").expect("valid needle");
        let layer = holed_layer();
        let outcome = scan(&layer, &scanner, &tight(64));

        assert!(
            outcome.hits.is_empty(),
            "a hole must not be stitched shut: {:?}",
            outcome.hits
        );
        assert_eq!(outcome.bytes_scanned, 0x200, "both segments were scanned");
        assert_eq!(
            outcome.unread,
            vec![(0x100..0x200, IncompleteReason::Unmapped)]
        );
        assert_eq!(outcome.unread_bytes, 0x100);
        assert!(
            !outcome.is_complete(),
            "an image with a gap is not complete"
        );
    }

    #[test]
    fn no_hit_can_land_inside_an_unmapped_region() {
        // Every hole byte would read as 0x00 if it were fabricated, so a needle of
        // zeros is the direct probe: the filler is 0xCC and the mapped segments
        // hold no zero run at all.
        let scanner = SingleStringScanner::new("zeros", &[0u8; 8]).expect("valid needle");
        let layer = holed_layer();
        let outcome = scan(&layer, &scanner, &tight(64));
        assert!(
            outcome.hits.is_empty(),
            "unmapped memory must not read as zeros: {:?}",
            outcome.hits
        );
        assert_eq!(outcome.unread_bytes, 0x100);
    }

    #[test]
    fn sections_skip_the_hole_and_report_what_was_mapped() {
        let layer = holed_layer();
        let plan = derive_sections(&layer, &ScanConfig::default()).expect("sections");
        assert_eq!(plan.sections, vec![0x000..0x100, 0x200..0x300]);
        assert_eq!(plan.mapped_len(), 0x200);
        assert_eq!(plan.start(), 0);
        assert_eq!(plan.top(), 0x300);
        assert!(plan.truncated_at.is_none());
    }

    #[test]
    fn probe_window_boundaries_do_not_split_a_contiguous_section() {
        // An artificial section boundary suppresses the overlap and would lose a
        // hit lying across it, so probing must merge adjacent windows.
        let config = ScanConfig {
            chunk_size: 64,
            probe_window: 16,
            ..ScanConfig::default()
        };
        let layer = flat(needle_at(0x100, 60, b"SEANCE!!"));
        let plan = derive_sections(&layer, &config).expect("sections");
        assert_eq!(
            plan.sections,
            vec![0..0x100],
            "sixteen probe windows, one section"
        );

        let scanner = SingleStringScanner::new("straddle", b"SEANCE!!").expect("valid needle");
        let outcome = scan(&layer, &scanner, &config);
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 60);
    }

    #[test]
    fn a_truncated_acquisition_file_shortens_the_scan_instead_of_padding_it() {
        // The segment list claims 0x200 bytes; the file holds 0x100. The missing
        // half must be recorded, and must not be scanned as zeros.
        let layer = SegmentedLayer::new(
            source(vec![FILLER; 0x100]),
            vec![Segment::new(0, 0, 0x200)],
            meta(),
        )
        .expect("a valid segment list");
        let scanner = SingleStringScanner::new("zeros", &[0u8; 8]).expect("valid needle");
        let outcome = scan(&layer, &scanner, &tight(64));

        assert!(outcome.hits.is_empty(), "the missing tail is not zeros");
        assert_eq!(outcome.bytes_scanned, 0x100);
        assert_eq!(
            outcome.unread,
            vec![(0x100..0x200, IncompleteReason::ShortRead)]
        );
        assert_eq!(outcome.unread_bytes, 0x100);
        assert!(!outcome.is_complete());
    }

    // ── Caps ────────────────────────────────────────────────────────────────

    fn tagged_image() -> Vec<u8> {
        let mut bytes = vec![FILLER; 0x200];
        for offset in (0..0x200 - 4).step_by(0x20) {
            bytes[offset..offset + 4].copy_from_slice(b"Proc");
        }
        bytes
    }

    #[test]
    fn the_hit_cap_reports_truncation_rather_than_dropping_hits_silently() {
        let scanner = MultiStringScanner::new("tags", [b"Proc".as_slice()]).expect("valid needles");
        let layer = flat(tagged_image());
        let config = ScanConfig {
            chunk_size: 64,
            max_hits: 3,
            ..ScanConfig::default()
        };
        let outcome = scan(&layer, &scanner, &config);

        assert_eq!(outcome.hits.len(), 3, "the cap is honoured exactly");
        assert!(outcome.truncated, "and it is declared");
        assert!(!outcome.is_complete());
        let last = outcome.hits[2].address;
        assert_eq!(
            outcome.unread,
            vec![(last + 1..0x200, IncompleteReason::CapReached)],
            "everything above the last reported hit is named as unexamined"
        );
        assert_eq!(outcome.unread_bytes, 0x200 - (last + 1));
    }

    #[test]
    fn an_uncapped_scan_of_the_same_image_finds_every_hit() {
        // Proves the cap test above measures the cap, and not a scan that could
        // only ever have found three.
        let scanner = MultiStringScanner::new("tags", [b"Proc".as_slice()]).expect("valid needles");
        let layer = flat(tagged_image());
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.hits.len(), 16);
        assert!(!outcome.truncated);
        assert!(outcome.is_complete());
    }

    #[test]
    fn the_section_cap_names_the_address_it_stopped_enumerating_at() {
        // Four one-page segments with a page-sized hole between each; a cap of two
        // must stop, say so, and mark everything above as unexamined.
        let layer = SegmentedLayer::new(
            source(vec![FILLER; 0x4000]),
            (0..4)
                .map(|i| Segment::new(i * 0x1000, i * 0x2000, 0x1000))
                .collect(),
            meta(),
        )
        .expect("a valid segment list");
        let config = ScanConfig {
            chunk_size: 0x400,
            max_sections: 2,
            ..ScanConfig::default()
        };

        let plan = derive_sections(&layer, &config).expect("sections");
        assert_eq!(plan.sections, vec![0x0000..0x1000, 0x2000..0x3000]);
        assert_eq!(plan.truncated_at, Some(0x4000));

        let scanner = SingleStringScanner::new("zeros", &[0u8; 8]).expect("valid needle");
        let outcome = scan(&layer, &scanner, &config);
        assert!(outcome.truncated);
        assert!(outcome
            .unread
            .contains(&(0x4000..0x7000, IncompleteReason::CapReached)));
        assert_eq!(outcome.bytes_scanned, 0x2000);
    }

    #[test]
    fn the_unread_range_cap_keeps_the_byte_total_exact() {
        // Sixteen segments with fifteen holes between them, room to record two of
        // the holes: the detail is capped and declared, the arithmetic is not.
        let layer = SegmentedLayer::new(
            source(vec![FILLER; 0x10000]),
            (0..16)
                .map(|i| Segment::new(i * 0x1000, i * 0x2000, 0x1000))
                .collect(),
            meta(),
        )
        .expect("a valid segment list");
        let config = ScanConfig {
            chunk_size: 0x400,
            max_unread_ranges: 2,
            ..ScanConfig::default()
        };
        let scanner = SingleStringScanner::new("zeros", &[0u8; 8]).expect("valid needle");
        let outcome = scan(&layer, &scanner, &config);

        assert_eq!(outcome.unread.len(), 2);
        assert!(outcome.unread_truncated);
        assert_eq!(outcome.unread_bytes, 15 * 0x1000, "fifteen holes, exactly");
        assert!(!outcome.is_complete());
    }

    /// Holes are unread *and* unmapped; a failed read is unread and not.
    ///
    /// The two were one number, and the difference is the difference between
    /// "evidence may have been missed here" and "there was never anything
    /// here". A large reserved region in a 64-bit process made the first claim
    /// about 2.2 TB of address space that never held a page, on the same record
    /// as a real 217 KB gap the big number then hid.
    #[test]
    fn an_unmapped_hole_is_counted_apart_from_a_byte_that_could_not_be_read() {
        // Four segments, three one-page holes between them. Every byte that is
        // mapped is readable, so the whole shortfall is unmapped.
        let layer = SegmentedLayer::new(
            source(vec![FILLER; 0x8000]),
            (0..4)
                .map(|i| Segment::new(i * 0x1000, i * 0x2000, 0x1000))
                .collect(),
            meta(),
        )
        .expect("a valid segment list");
        let scanner = SingleStringScanner::new("zeros", &[0u8; 8]).expect("valid needle");
        let outcome = scan(&layer, &scanner, &ScanConfig::default());

        assert_eq!(outcome.unread_bytes, 3 * 0x1000, "three holes");
        assert_eq!(
            outcome.unmapped_bytes, outcome.unread_bytes,
            "every missing byte here is address space that was never mapped, so \
             none of it is a byte that could not be read"
        );
        assert_eq!(
            outcome.unread_bytes - outcome.unmapped_bytes,
            0,
            "the subtraction a caller performs to describe the real gap"
        );

        // The split is additive: `unread_bytes` still means what it always did,
        // so nothing built on it changes.
        assert!(!outcome.is_complete());
    }

    // ── Pattern-length limitations ──────────────────────────────────────────

    #[test]
    fn a_needle_within_the_overlap_cap_is_declared_reliable() {
        let scanner = SingleStringScanner::new("short", b"Proc").expect("valid needle");
        let layer = flat(vec![FILLER; 0x100]);
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.max_reliable_pattern_len, 4);
        assert!(!outcome.pattern_may_exceed_overlap);
        assert_eq!(outcome.scanner, "short");
    }

    #[test]
    fn a_needle_longer_than_the_overlap_cap_is_declared_a_limitation() {
        // The overlap is clamped, so a match across a chunk boundary is no longer
        // guaranteed. That is stated, not silently absorbed.
        let scanner = SingleStringScanner::new("long", b"SEANCE!!").expect("valid needle");
        let layer = flat(vec![FILLER; 0x100]);
        let config = ScanConfig {
            chunk_size: 64,
            max_overlap: 4,
            ..ScanConfig::default()
        };
        let outcome = scan(&layer, &scanner, &config);
        assert_eq!(outcome.max_reliable_pattern_len, 5);
        assert!(outcome.pattern_may_exceed_overlap);
    }

    #[test]
    fn an_unbounded_regex_is_always_declared_a_boundary_limitation() {
        let scanner = RegexScanner::new("unbounded", "Proc.*End").expect("valid pattern");
        assert_eq!(scanner.max_match_len(), None);
        let layer = flat(vec![FILLER; 0x100]);
        let outcome = scan(&layer, &scanner, &tight(64));
        assert!(outcome.pattern_may_exceed_overlap);
        assert_eq!(outcome.max_reliable_pattern_len, 64);
    }

    // ── Scanners ────────────────────────────────────────────────────────────

    #[test]
    fn a_regex_matches_across_a_newline_because_dotall_is_set() {
        // Memory is not line-oriented. A pattern that stopped at 0x0a would miss a
        // structure purely because one of its bytes happened to be a newline.
        let scanner = RegexScanner::new("dotall", "foo.bar").expect("valid pattern");
        let layer = flat(b"....foo\nbar....".to_vec());
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 4);
        assert_eq!(outcome.hits[0].length, 7);
    }

    #[test]
    fn a_regex_dot_matches_a_byte_that_is_not_valid_utf8() {
        // With Unicode matching left on, `.` cannot match 0xff, and patterns
        // silently fail over exactly the binary regions that matter most.
        let scanner = RegexScanner::new("binary", "a.c").expect("valid pattern");
        let layer = flat(vec![FILLER, b'a', 0xFF, b'c', FILLER]);
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 1);
        assert_eq!(outcome.hits[0].length, 3);
    }

    #[test]
    fn a_regex_that_can_match_nothing_reports_no_hits() {
        // A zero-length match at every offset would bury real hits under the cap
        // and assert evidence where there is none.
        let scanner = RegexScanner::new("empty", "Q*").expect("valid pattern");
        let layer = flat(vec![FILLER; 0x40]);
        let outcome = scan(&layer, &scanner, &tight(64));
        assert!(outcome.hits.is_empty());
    }

    #[test]
    fn a_multi_string_scan_names_which_needle_matched() {
        // The pool-tag case: one pass, many needles, and the record has to say
        // which allocation type was found.
        let tags: Vec<&[u8]> = vec![
            b"Proc".as_slice(),
            b"Thre".as_slice(),
            b"File".as_slice(),
            b"Driv".as_slice(),
        ];
        let scanner = MultiStringScanner::new("pool", tags).expect("valid needles");
        assert_eq!(scanner.needle_count(), 4);

        let mut bytes = vec![FILLER; 0x80];
        bytes[0x10..0x14].copy_from_slice(b"File");
        bytes[0x40..0x44].copy_from_slice(b"Proc");
        let layer = flat(bytes);
        let outcome = scan(&layer, &scanner, &tight(64));

        assert_eq!(outcome.hits.len(), 2);
        assert_eq!(outcome.hits[0].address, 0x10);
        assert_eq!(
            scanner.needle(outcome.hits[0].pattern_id),
            Some(b"File".as_slice())
        );
        assert_eq!(outcome.hits[1].address, 0x40);
        assert_eq!(
            scanner.needle(outcome.hits[1].pattern_id),
            Some(b"Proc".as_slice())
        );
        assert_eq!(scanner.needle(99), None);
    }

    #[test]
    fn a_multi_string_scan_finds_the_high_bit_pre_win8_tag_variants() {
        // The constraint table pairs each Windows 8+ tag with its pre-Win8 form,
        // which sets the high bit on the last byte. Both must survive the
        // automaton unchanged; a UTF-8 assumption anywhere would corrupt them.
        let tags: Vec<&[u8]> = vec![
            b"Proc".as_slice(),
            b"Pro\xe3".as_slice(),
            b"File".as_slice(),
            b"Fil\xe5".as_slice(),
        ];
        let scanner = MultiStringScanner::new("pool", tags).expect("valid needles");
        let mut bytes = vec![FILLER; 0x40];
        bytes[0x08..0x0C].copy_from_slice(b"Pro\xe3");
        bytes[0x20..0x24].copy_from_slice(b"Fil\xe5");
        let layer = flat(bytes);
        let outcome = scan(&layer, &scanner, &tight(64));

        assert_eq!(outcome.hits.len(), 2);
        assert_eq!(
            scanner.needle(outcome.hits[0].pattern_id),
            Some(b"Pro\xe3".as_slice())
        );
        assert_eq!(
            scanner.needle(outcome.hits[1].pattern_id),
            Some(b"Fil\xe5".as_slice())
        );
    }

    #[test]
    fn a_multi_string_scan_prefers_the_longer_needle_at_the_same_offset() {
        let scanner =
            MultiStringScanner::new("nested", [b"Proc".as_slice(), b"ProcessX".as_slice()])
                .expect("valid needles");
        let layer = flat(needle_at(0x40, 0x10, b"ProcessX"));
        let outcome = scan(&layer, &scanner, &tight(64));
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].length, 8);
    }

    #[test]
    fn an_empty_needle_is_refused_rather_than_matching_everywhere() {
        let err = SingleStringScanner::new("bad", b"").expect_err("an empty needle is unusable");
        assert!(matches!(err, ScanError::Pattern { .. }), "{err}");

        let err = MultiStringScanner::new("bad", [b"Proc".as_slice(), b"".as_slice()])
            .expect_err("an empty needle is unusable");
        assert!(matches!(err, ScanError::Pattern { .. }), "{err}");

        let empty: Vec<&[u8]> = Vec::new();
        let err = MultiStringScanner::new("bad", empty).expect_err("no needles is unusable");
        assert!(matches!(err, ScanError::Pattern { .. }), "{err}");
    }

    #[test]
    fn an_invalid_regex_fails_to_build_rather_than_matching_nothing() {
        let err = RegexScanner::new("bad", "(unclosed").expect_err("invalid pattern");
        assert!(matches!(err, ScanError::Pattern { .. }), "{err}");
    }

    // ── Configuration ───────────────────────────────────────────────────────

    #[test]
    fn a_configuration_that_cannot_walk_is_refused() {
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = flat(vec![FILLER; 0x40]);

        for config in [
            ScanConfig {
                chunk_size: 0,
                ..ScanConfig::default()
            },
            ScanConfig {
                max_hits: 0,
                ..ScanConfig::default()
            },
            ScanConfig {
                max_sections: 0,
                ..ScanConfig::default()
            },
            ScanConfig {
                probe_window: 0,
                ..ScanConfig::default()
            },
            ScanConfig {
                max_probes: 0,
                ..ScanConfig::default()
            },
            ScanConfig {
                chunk_size: u64::MAX,
                max_overlap: u64::MAX,
                ..ScanConfig::default()
            },
        ] {
            let err = scan_layer(&layer, &scanner, &config).expect_err("must be refused");
            assert!(matches!(err, ScanError::Config { .. }), "{err}");
        }
    }

    #[test]
    fn a_chunk_too_large_for_a_hit_length_to_express_is_refused() {
        // `Hit::length` is a `u32`. A chunk that could hold a longer match would
        // report a wrapped length: a number in the case record that no match
        // ever had. The refusal happens before a single byte is read.
        let config = ScanConfig {
            chunk_size: u64::from(u32::MAX),
            max_overlap: 1,
            ..ScanConfig::default()
        };
        let err = config.validate().expect_err("must be refused");
        assert!(matches!(err, ScanError::Config { .. }), "{err}");

        // And the boundary itself is usable, so the guard is a cap and not an
        // arbitrary shrinking of the geometry.
        ScanConfig {
            chunk_size: u64::from(u32::MAX) - 4096,
            max_overlap: 4096,
            ..ScanConfig::default()
        }
        .validate()
        .expect("exactly u32::MAX bytes of buffer is representable");
    }

    #[test]
    fn a_single_byte_chunk_still_walks_and_declares_what_it_cannot_find() {
        // Degenerate geometry: the overlap clamps to zero, so no needle longer
        // than one byte can be found across a boundary — and the outcome says so
        // instead of reporting a clean empty scan.
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = flat(needle_at(0x40, 0x10, b"Proc"));
        let outcome = scan(&layer, &scanner, &tight(1));
        assert_eq!(outcome.max_reliable_pattern_len, 1);
        assert!(outcome.pattern_may_exceed_overlap);
        assert!(
            outcome.hits.is_empty(),
            "a 4-byte needle cannot fit a 1-byte chunk"
        );
        assert_eq!(outcome.bytes_scanned, 0x40);
    }

    // ── Targeted ranges ─────────────────────────────────────────────────────

    #[test]
    fn a_targeted_scan_looks_only_inside_the_requested_range() {
        let mut bytes = vec![FILLER; 0x200];
        bytes[0x010..0x014].copy_from_slice(b"Proc");
        bytes[0x120..0x124].copy_from_slice(b"Proc");
        let scanner = MultiStringScanner::new("pool", [b"Proc".as_slice()]).expect("valid needles");
        let layer = flat(bytes);

        let outcome = scan_range(&layer, &scanner, 0x100..0x200, &tight(64)).expect("a scan");
        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 0x120);
        assert_eq!(outcome.bytes_scanned, 0x100);
        assert!(outcome.is_complete());
    }

    #[test]
    fn a_targeted_scan_of_a_hole_reports_no_hits_and_names_the_gap() {
        let scanner = SingleStringScanner::new("zeros", &[0u8; 8]).expect("valid needle");
        let layer = holed_layer();
        let outcome = scan_range(&layer, &scanner, 0x100..0x200, &tight(64)).expect("a scan");
        assert!(outcome.hits.is_empty());
        assert_eq!(outcome.bytes_scanned, 0);
        assert_eq!(
            outcome.unread,
            vec![(0x100..0x200, IncompleteReason::Unmapped)]
        );
    }

    #[test]
    fn a_targeted_scan_above_the_address_space_is_empty_not_incomplete() {
        // There are no addresses up there to have missed, so nothing is unread.
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = flat(vec![FILLER; 0x40]);
        let outcome = scan_range(&layer, &scanner, 0x1000..0x2000, &tight(64)).expect("a scan");
        assert!(outcome.hits.is_empty());
        assert_eq!(outcome.bytes_scanned, 0);
        assert!(outcome.unread.is_empty());
        assert!(outcome.is_complete());
    }

    // ── Hostile and inconsistent layers ─────────────────────────────────────

    /// A layer whose `read_at` claims to have written more bytes than the buffer
    /// holds. A correct implementation cannot do this, which is precisely why a
    /// driver that trusts the number indexes past the end and panics.
    #[derive(Debug)]
    struct OverclaimingLayer {
        meta: LayerMeta,
    }

    impl DataSource for OverclaimingLayer {
        fn read_at(&self, _offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            Ok(buf.len() + 4096)
        }
        fn size(&self) -> u64 {
            0x1000
        }
    }

    impl MemoryLayer for OverclaimingLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            0x0FFF
        }
        fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
            let available = 0x1000u64.saturating_sub(offset);
            Ok(vec![MappedRange::identity(
                offset,
                length.min(available),
                offset,
            )])
        }
        fn layer_meta(&self) -> &LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_layer_that_overclaims_a_read_cannot_drive_the_scanner_off_the_buffer() {
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = OverclaimingLayer {
            meta: LayerMeta::default(),
        };
        let outcome = scan(&layer, &scanner, &tight(64));
        assert!(outcome.hits.is_empty());
        assert_eq!(outcome.bytes_scanned, 0x1000);
    }

    /// A layer that answers every projection with a zero-length hole: neither
    /// bytes to scan nor a gap to step over.
    #[derive(Debug)]
    struct StalledLayer {
        meta: LayerMeta,
    }

    impl DataSource for StalledLayer {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            0x1000
        }
    }

    impl MemoryLayer for StalledLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            0x0FFF
        }
        fn mapping(&self, offset: u64, _length: u64) -> Result<Vec<MappedRange>, LayerError> {
            Err(LayerError::Hole(MemoryHole::unmapped(offset, 0)))
        }
        fn layer_meta(&self) -> &LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_layer_that_never_advances_fails_closed_instead_of_hanging_the_ingest() {
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = StalledLayer {
            meta: LayerMeta::default(),
        };
        let err = scan_layer(&layer, &scanner, &tight(64)).expect_err("must fail closed");
        assert!(matches!(err, ScanError::NoProgress { address: 0 }), "{err}");
    }

    /// A layer that advances, but only ever by a single byte, and never maps
    /// anything. Every probe is a legal answer; the sequence of them is not
    /// something a driver can afford to follow to the end of a 64-bit space.
    #[derive(Debug)]
    struct CrumblingLayer {
        meta: LayerMeta,
    }

    impl DataSource for CrumblingLayer {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            u64::MAX
        }
    }

    impl MemoryLayer for CrumblingLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            u64::MAX - 1
        }
        fn mapping(&self, offset: u64, _length: u64) -> Result<Vec<MappedRange>, LayerError> {
            Err(LayerError::Hole(MemoryHole::unmapped(offset, 1)))
        }
        fn layer_meta(&self) -> &LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_layer_that_advances_one_byte_at_a_time_is_stopped_by_the_probe_budget() {
        // `max_sections` cannot bound this walk: a hole pushes no section, so the
        // section list stays empty however long the loop runs. Without a probe
        // budget the derivation runs once per address over a 64-bit space, which
        // is a hung ingest rather than a wrong answer.
        let config = ScanConfig {
            chunk_size: 64,
            max_probes: 32,
            ..ScanConfig::default()
        };
        let layer = CrumblingLayer {
            meta: LayerMeta::default(),
        };

        let plan = derive_sections(&layer, &config).expect("the walk must terminate");
        assert!(plan.sections.is_empty(), "nothing was ever mapped");
        assert_eq!(
            plan.truncated_at,
            Some(32),
            "one byte skipped per probe, and the budget names where it stopped"
        );

        // And the driver turns that into a declared cap, never into a clean scan
        // of an image that simply had nothing in it.
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let outcome = scan_layer(&layer, &scanner, &config).expect("a scan");
        assert!(outcome.truncated, "the budget firing is declared");
        assert!(!outcome.is_complete());
        assert!(outcome.hits.is_empty());
        assert_eq!(outcome.bytes_scanned, 0);
        assert!(
            outcome
                .unread
                .iter()
                .any(|(_, reason)| *reason == IncompleteReason::CapReached),
            "the unexamined remainder is named: {:?}",
            outcome.unread
        );
    }

    #[test]
    fn the_probe_budget_does_not_fire_on_an_image_it_can_actually_enumerate() {
        // The control for the test above: the same budget, a real layer, and a
        // probe window small enough to need many probes. A cap that fired here
        // would silently truncate ordinary evidence.
        let config = ScanConfig {
            chunk_size: 64,
            probe_window: 16,
            max_probes: 32,
            ..ScanConfig::default()
        };
        let layer = flat(vec![FILLER; 0x100]);
        let plan = derive_sections(&layer, &config).expect("sections");
        assert_eq!(plan.sections, vec![0..0x100]);
        assert!(plan.truncated_at.is_none(), "sixteen probes, budget of 32");
    }

    /// A layer that claims a successful projection but projects no bytes.
    #[derive(Debug)]
    struct EmptyMappingLayer {
        meta: LayerMeta,
    }

    impl DataSource for EmptyMappingLayer {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            0x1000
        }
    }

    impl MemoryLayer for EmptyMappingLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            0x0FFF
        }
        fn mapping(&self, _offset: u64, _length: u64) -> Result<Vec<MappedRange>, LayerError> {
            Ok(Vec::new())
        }
        fn layer_meta(&self) -> &LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_layer_that_maps_nothing_without_declaring_a_hole_is_an_error() {
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = EmptyMappingLayer {
            meta: LayerMeta::default(),
        };
        let err = scan_layer(&layer, &scanner, &tight(64)).expect_err("must fail closed");
        assert!(matches!(err, ScanError::NoProgress { address: 0 }), "{err}");
    }

    /// A layer whose bounds are inverted.
    #[derive(Debug)]
    struct InvertedLayer {
        meta: LayerMeta,
    }

    impl DataSource for InvertedLayer {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Ok(0)
        }
        fn size(&self) -> u64 {
            0x1000
        }
    }

    impl MemoryLayer for InvertedLayer {
        fn min_address(&self) -> u64 {
            0x2000
        }
        fn max_address(&self) -> u64 {
            0x1000
        }
        fn mapping(&self, _offset: u64, _length: u64) -> Result<Vec<MappedRange>, LayerError> {
            Ok(Vec::new())
        }
        fn layer_meta(&self) -> &LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_layer_with_inverted_bounds_has_no_address_space_to_scan() {
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = InvertedLayer {
            meta: LayerMeta::default(),
        };
        let err = scan_layer(&layer, &scanner, &tight(64)).expect_err("must fail closed");
        assert!(
            matches!(
                err,
                ScanError::EmptyAddressSpace {
                    min: 0x2000,
                    max: 0x1000
                }
            ),
            "{err}"
        );
    }

    /// A layer whose reads always fail with an ordinary I/O error.
    #[derive(Debug)]
    struct FailingLayer {
        meta: LayerMeta,
    }

    impl DataSource for FailingLayer {
        fn read_at(&self, _offset: u64, _buf: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("the evidence drive went away"))
        }
        fn size(&self) -> u64 {
            0x200
        }
    }

    impl MemoryLayer for FailingLayer {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            0x1FF
        }
        fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
            let available = 0x200u64.saturating_sub(offset);
            Ok(vec![MappedRange::identity(
                offset,
                length.min(available),
                offset,
            )])
        }
        fn layer_meta(&self) -> &LayerMeta {
            &self.meta
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_scan_that_could_read_nothing_is_not_a_scan_that_found_nothing() {
        // The defect this whole outcome type exists to prevent: an empty hit list
        // that looks identical to a clean image.
        let scanner = SingleStringScanner::new("x", b"Proc").expect("valid needle");
        let layer = FailingLayer {
            meta: LayerMeta::default(),
        };
        let outcome = scan(&layer, &scanner, &tight(64));
        assert!(outcome.hits.is_empty());
        assert_eq!(outcome.bytes_scanned, 0);
        assert_eq!(outcome.unread_bytes, 0x200);
        assert!(!outcome.is_complete(), "silence here is not evidence");
    }

    // ── Reporting ───────────────────────────────────────────────────────────

    #[test]
    fn the_json_view_cannot_present_an_incomplete_scan_as_a_clean_one() {
        let scanner = SingleStringScanner::new("zeros", &[0u8; 8]).expect("valid needle");
        let layer = holed_layer();
        let outcome = scan(&layer, &scanner, &tight(64));
        let json = outcome.to_json();

        assert_eq!(json["scanner"], "zeros");
        assert_eq!(json["hits"], 0);
        assert_eq!(json["complete"], false);
        assert_eq!(json["bytes_scanned"], 0x200);
        assert_eq!(json["unread_bytes"], 0x100);
        assert_eq!(json["unread"][0]["start"], 0x100);
        assert_eq!(json["unread"][0]["end"], 0x200);
        // A hole between two mapped segments: never mapped, so `unmapped`
        // rather than `short_read`. A truncated acquisition still reports
        // `short_read` — see
        // `a_truncated_acquisition_file_shortens_the_scan_instead_of_padding_it`
        // — and the two must not look alike to a reader deciding whether
        // evidence might have been missed.
        assert_eq!(json["unread"][0]["reason"], "unmapped");
        assert_eq!(json["unmapped_bytes"], 0x100, "all of it was a hole");
    }

    // ── A plan the caller brought ───────────────────────────────────────────

    #[test]
    fn a_plan_over_known_sections_covers_exactly_them() {
        let plan = SectionPlan::over([0x1000..0x2000, 0x5000..0x6000]);
        assert_eq!(plan.sections, vec![0x1000..0x2000, 0x5000..0x6000]);
        assert_eq!(plan.start(), 0x1000);
        assert_eq!(
            plan.top(),
            0x6000,
            "nothing above the last section is claimed"
        );
        assert_eq!(plan.mapped_len(), 0x2000);
        assert!(plan.truncated_at.is_none());
    }

    #[test]
    fn a_plan_over_known_sections_sorts_merges_and_drops_the_empty() {
        // Unsorted, touching, overlapping and empty, all at once. The touching
        // pair MUST merge: the overlap is suppressed at a section end, so a
        // boundary at 0x2000 would lose a match lying across it.
        let plan = SectionPlan::over([
            0x5000..0x6000,
            0x2000..0x3000,
            0x1000..0x2000,
            0x2800..0x2900,
            0x7000..0x7000,
        ]);
        assert_eq!(plan.sections, vec![0x1000..0x3000, 0x5000..0x6000]);
        assert_eq!(plan.mapped_len(), 0x3000);
    }

    #[test]
    fn a_plan_over_nothing_scans_nothing_and_says_so() {
        let plan = SectionPlan::over(std::iter::empty());
        assert!(plan.sections.is_empty());
        assert_eq!(plan.mapped_len(), 0);
        let layer = flat(needle_at(0x200, 0x10, b"Proc"));
        let scanner = SingleStringScanner::new("one", b"Proc").expect("valid needle");
        let outcome =
            scan_planned(&layer, &scanner, &plan, &tight(64)).expect("a well-formed scan");
        assert!(outcome.hits.is_empty());
        assert_eq!(outcome.bytes_scanned, 0);
        // Nothing was looked at, and nothing is claimed unread either: the plan
        // asked for no address at all.
        assert_eq!(outcome.unread_bytes, 0);
    }

    #[test]
    fn a_hit_in_a_brought_plan_is_found_and_the_gap_between_sections_is_unmapped() {
        // The shape of a VAD scan: two allocations, a hole between them, and a
        // match in the second. The hole is memory nothing could have been in,
        // so it is counted as unmapped rather than as evidence possibly missed.
        let layer = flat(needle_at(0x400, 0x210, b"Proc"));
        let scanner = SingleStringScanner::new("one", b"Proc").expect("valid needle");
        let plan = SectionPlan::over([0x0..0x100, 0x200..0x300]);
        let outcome =
            scan_planned(&layer, &scanner, &plan, &tight(64)).expect("a well-formed scan");

        assert_eq!(outcome.hits.len(), 1);
        assert_eq!(outcome.hits[0].address, 0x210);
        assert_eq!(
            outcome.bytes_scanned, 0x200,
            "both sections, and nothing else"
        );
        assert_eq!(outcome.unread_bytes, 0x100, "the gap");
        assert_eq!(
            outcome.unmapped_bytes, 0x100,
            "all of the gap was address space the plan never asked for, not evidence missed"
        );
        assert_eq!(outcome.unread_bytes - outcome.unmapped_bytes, 0);
    }

    #[test]
    fn the_scanner_trait_is_object_safe() {
        // The driver holds `&dyn Scanner`, and a plugin supplies its own.
        let scanners: Vec<Box<dyn Scanner>> = vec![
            Box::new(SingleStringScanner::new("one", b"Proc").expect("valid needle")),
            Box::new(MultiStringScanner::new("many", [b"Proc".as_slice()]).expect("valid needles")),
            Box::new(RegexScanner::new("re", "Proc").expect("valid pattern")),
        ];
        let layer = flat(needle_at(0x100, 0x20, b"Proc"));
        for scanner in &scanners {
            let outcome = scan(&layer, scanner.as_ref(), &tight(64));
            assert_eq!(outcome.hits.len(), 1, "{}", scanner.name());
            assert_eq!(outcome.hits[0].address, 0x20);
        }
    }
}
