// the counter is a document budget, compared against a cap inside the loop and
// reported afterwards as how much of the index was actually scanned.
#![allow(clippy::explicit_counter_loop)]
#![forbid(unsafe_code)]
pub mod scope;
pub mod sweep;

pub use scope::{
    search_universe, search_universe_for, IndexTextExtractor, IndexTextProvenance, MatchMode,
    SearchUniverse, TEXT_EXTRACTOR_VERSION,
};

use anyhow::{Context, Result};
use regex::{Regex, RegexBuilder};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender as CmdSender, SyncSender};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};
use tantivy::{
    collector::{Count, DocSetCollector, TopDocs},
    directory::MmapDirectory,
    doc,
    query::{Query, QueryParser},
    schema::{Field, Schema, Value, STORED, STRING, TEXT},
    Index, IndexWriter, TantivyDocument,
};
use tracing::{error, info, warn};
use uuid::Uuid;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::{ForensicsModule, InputCapability, ModuleError},
};

/// Most bytes of a single file read into the index. Bounds per-artifact cost;
/// keyword hits beyond this offset in a very large file are not indexed.
const CONTENT_INDEX_CAP: usize = 16 * 1024 * 1024;

/// Marker token appended to the indexed text of any artifact whose content was
/// NOT indexed in full.
///
/// Searching for it lists every artifact whose keyword coverage is partial. A
/// query that misses is otherwise identical whether the word is absent from the
/// file or merely past the cap / past a short read, and an examiner who
/// searches a case and finds nothing is entitled to know which of the two they
/// are looking at. Two variants follow it: `cap_reached` (file larger than
/// [`CONTENT_INDEX_CAP`]) and `short_read` (the source stopped early).
pub const INDEX_INCOMPLETE_TOKEN: &str = "seance_index_incomplete";

/// The file, inside the index directory, that records which text extractor
/// version built each case's file documents ([`IndexTextProvenance`]).
///
/// It lives inside the index directory on purpose: when a schema mismatch
/// rebuilds the index from empty, the record goes with the documents it
/// describes. Tantivy only garbage-collects files it manages, so it leaves
/// this one alone.
pub const TEXT_EXTRACTOR_RECORD_FILE: &str = "seance_text_extractor.json";

/// Minimum printable-run length kept when extracting strings from content.
const MIN_STRING_LEN: usize = 4;

/// Pull text runs from raw file bytes (a `strings`-style pass) so keyword
/// search matches content in both text and binary artifacts.
///
/// Three passes: UTF-8 (which subsumes ASCII), UTF-16LE and UTF-16BE. Bytes
/// that decode to nothing act as separators, and a run shorter than
/// [`MIN_STRING_LEN`] characters is discarded — that bound is what keeps a
/// binary file from filling the index with two-character noise.
///
/// # What it used to miss, and why that was a false absence
///
/// A search that returns nothing is read as "the term is absent from the
/// evidence". Until 2026-09-15 this function made three whole classes of text
/// unfindable, measured by running it:
///
/// | bytes | indexed as |
/// |---|---|
/// | ASCII `SecretKey` | `SecretKey` |
/// | UTF-16LE `SecretKey` | `SecretKey` |
/// | UTF-16BE `SecretKey` | `SecretKe` — **minus its last character** |
/// | UTF-8 `cañón` | nothing at all |
/// | UTF-16LE `cañón` | `n` |
///
/// All five are indexed whole today; the UTF-16 `cañón` case since 2026-09-26
/// (`SEARCH-002`), within the limits set out on `utf16_runs`.
///
/// The big-endian case came of sniffing for a zero byte *after* a printable
/// one: in big-endian order that lands on the byte before each character's own
/// null, so every run lost its final character and the full term missed while
/// the term-minus-one-character hit. The other two came of a byte-wise
/// printable test that treats every byte above `0x7e` as a separator, so an
/// accented or non-Latin word was shredded into fragments below the minimum run
/// length and discarded entirely.
///
/// None of that was theoretical: NIST CFTT's Forensic String Search key asks
/// for 220 hits in UTF-16BE, 217 in UTF-16LE, and terms including `cañón`.
///
/// # Which characters count as text
///
/// ASCII printable, tab, newline and carriage return, as before — plus any
/// **alphabetic or numeric** character outside ASCII. Deliberately not "any
/// non-control character": most bytes above `0x7e` in a binary file decode to
/// punctuation and symbols in some script or other, and admitting those would
/// trade a false absence for an index full of noise. A test pins that a
/// megabyte of pseudo-random bytes still yields almost nothing.
///
/// In the UTF-8 pass a **combining mark** (Unicode category M, e.g. U+0303)
/// is also kept when it follows a character of a run already in progress, so
/// decomposed (NFD) text such as `man` + U+0303 + `ana` is indexed whole
/// rather than as `man ana` (`VAL-001`). A mark does not count toward the
/// minimum run length, and a mark with nothing before it is a separator. The
/// UTF-16 passes apply the same rule to the marks they accept; which UTF-16
/// characters they accept at all is narrower, and is set out on `utf16_runs`
/// (`SEARCH-002`).
///
/// No Unicode normalisation is applied, here or to the query: matching is
/// exact-form. A decomposed term finds decomposed text and a precomposed (NFC)
/// term finds precomposed text; NFC `mañana` does not find NFD `mañana`.
fn extract_searchable_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() / 2);
    utf8_runs(bytes, &mut out);
    out.push(' ');
    utf16_runs(bytes, Endian::Little, &mut out);
    out.push(' ');
    utf16_runs(bytes, Endian::Big, &mut out);
    out
}

/// The text the content indexer's two UTF-16 passes (little- then big-endian)
/// take from `bytes`, runs separated by spaces, exactly as
/// `extract_searchable_text` indexes it but without the UTF-8 pass.
///
/// Public so that a tool which predicts what the index can reach — the CFTT
/// grader's `utf16_index_reaches` — can be tested against the indexer itself
/// rather than against a copy of its rule (`SEARCH-002`).
pub fn utf16_indexed_text(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() / 2);
    utf16_runs(bytes, Endian::Little, &mut out);
    out.push(' ');
    utf16_runs(bytes, Endian::Big, &mut out);
    out
}

/// Whether a decoded character is text worth indexing.
///
/// ASCII printable and the three whitespace controls, plus alphabetic and
/// numeric characters in any script. See `extract_searchable_text` for why this
/// is not simply "not a control character".
fn is_text_char(c: char) -> bool {
    if c.is_ascii() {
        return c == '\t' || c == '\n' || c == '\r' || ('\u{20}'..='\u{7e}').contains(&c);
    }
    c.is_alphabetic() || c.is_numeric()
}

/// Close a run: drop it when it is too short, and separate it when it is kept.
///
/// `chars` is a character count and `bytes_pushed` the UTF-8 length of what was
/// appended, because a non-ASCII character is more than one byte and truncating
/// by the count would cut one in half.
fn close_run(out: &mut String, chars: usize, bytes_pushed: usize) {
    if chars > 0 && chars < MIN_STRING_LEN {
        out.truncate(out.len() - bytes_pushed);
    } else if chars >= MIN_STRING_LEN {
        out.push(' ');
    }
}

/// Whether a character is a Unicode combining mark (general category M).
fn is_combining_mark(c: char) -> bool {
    unicode_normalization::char::is_combining_mark(c)
}

/// UTF-8 runs, which subsume ASCII.
fn utf8_runs(bytes: &[u8], out: &mut String) {
    let mut chars = 0usize;
    let mut pushed = 0usize;
    let mut i = 0usize;
    while i < bytes.len() {
        // Decode one UTF-8 sequence. An invalid one is a separator and costs
        // exactly one byte, so the valid text after it is not lost.
        // An ASCII byte is itself. A multi-byte sequence must VALIDATE --
        // `from_utf8` rejects an over-long or truncated one -- and anything
        // else is a separator costing one byte, so the valid text after it is
        // not lost.
        //
        // A byte that is not a valid sequence must NOT fall through to
        // Latin-1: `0xFF as char` is 'ÿ', which `is_alphabetic` accepts, so
        // padding bytes either side of a short string joined it into one long
        // enough run and made `cat` findable through the minimum-length bound.
        let (c, step) = if bytes[i] < 0x80 {
            (Some(bytes[i] as char), 1)
        } else {
            let len = utf8_len(bytes[i]);
            match (len > 1 && i + len <= bytes.len())
                .then(|| std::str::from_utf8(&bytes[i..i + len]).ok())
                .flatten()
                .and_then(|s| s.chars().next())
            {
                Some(c) => (Some(c), len),
                None => (None, 1),
            }
        };
        // A combining mark (U+0303 in decomposed `man\u{303}ana`) is neither
        // alphabetic nor numeric, but it is part of the character it follows:
        // treating it as a separator indexed NFD text as `man ana` and made it
        // unfindable (`VAL-001`). So a mark is kept when it follows a run
        // already in progress -- and does not count toward `MIN_STRING_LEN`,
        // since it adds no character of its own. A mark with no base before
        // it is still a separator, so bare marks in binary data stay noise.
        let attached_mark = c.filter(|c| chars > 0 && is_combining_mark(*c));
        if let Some(c) = attached_mark {
            out.push(c);
            pushed += c.len_utf8();
            i += step;
            continue;
        }
        match c.filter(|c| is_text_char(*c)) {
            Some(c) => {
                out.push(c);
                chars += 1;
                pushed += c.len_utf8();
                i += step;
            }
            None => {
                close_run(out, chars, pushed);
                chars = 0;
                pushed = 0;
                i += 1;
            }
        }
    }
    close_run(out, chars, pushed);
}

/// How many bytes a UTF-8 sequence beginning with this byte claims.
fn utf8_len(b: u8) -> usize {
    match b {
        0x00..=0x7F => 1,
        0xC2..=0xDF => 2,
        0xE0..=0xEF => 3,
        0xF0..=0xF4 => 4,
        // A continuation byte or an over-long lead: not a sequence start.
        _ => 1,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Endian {
    Little,
    Big,
}

/// UTF-16 runs in one byte order, **restricted to the code units a structural
/// test can vouch for**.
///
/// Every two-byte alignment is tried, because a run in a binary file does not
/// begin on an even offset: the scan advances by two inside a run and by one
/// when it breaks, which is what the previous byte-pair sniff did and is the
/// reason it worked on little-endian text at all.
///
/// # Why not every script, when the UTF-8 pass takes any
///
/// Because of what each pass can VALIDATE. A multi-byte UTF-8 sequence is
/// self-describing and `from_utf8` rejects an invalid one, so random bytes
/// almost never decode as text and the UTF-8 pass can afford to accept any
/// script. A UTF-16 code unit is two arbitrary bytes with no check digit: a
/// pass that accepted any alphabetic character from them filled the index with
/// CJK noise, measured — a megabyte of pseudo-random bytes produced runs like
/// `懿戀㴀Ø揞搀`, which are not text and are indistinguishable from text by any
/// cheap local test.
///
/// So each unit must carry a structural signal (`SEARCH-002`):
///
/// * **a zero high byte** — ASCII printable and whitespace, and the Latin-1
///   letters U+00C0–U+00FE less `×` and `÷` ([`utf16_text_unit`]);
/// * **or one high byte for the whole run**, from a short list of alphabetic
///   blocks that each fit in one: [`UTF16_SCRIPT_BLOCKS`] (Greek, Cyrillic,
///   Armenian/Hebrew, Arabic, kana). The first such unit locks the run to its
///   block; a unit from another block ends the run and starts a new one.
///   ASCII and Latin-1 units may sit anywhere inside a locked run, so
///   `==> Россия 1063` is one run. On uniform random bytes a four-unit run
///   passes these tests, by estimate, less than once in 10^8 alignments; the
///   fixed megabyte the tests measure yields none. Structured binary (a table
///   of `u16` values that happen to fall in one block) is not measured.
///
/// A combining mark attaches to a run in progress — one from U+0300–U+036F in
/// any run, or one from the run's own locked block — as the UTF-8 pass lets
/// one attach (`VAL-001`).
///
/// **The cost is recorded rather than hidden.** CJK ideographs and Hangul span
/// dozens of high bytes, so no single-block test can guard them, and admitting
/// them would put roughly one junk run per hundred alignments into the index.
/// They are excluded by owner decision (2026-09-26): UTF-16 CJK or Korean text
/// is not findable through the index, which is a false absence in a search.
/// The search universe statement ([`scope::search_universe`]) says so on every
/// search, and points at the byte sweep, which does search them. `SEARCH-002`
/// in `BUGS.md` holds the measurements.
fn utf16_runs(bytes: &[u8], endian: Endian, out: &mut String) {
    let unit = |at: usize| -> Option<u16> {
        let pair: [u8; 2] = bytes.get(at..at + 2)?.try_into().ok()?;
        Some(match endian {
            Endian::Little => u16::from_le_bytes(pair),
            Endian::Big => u16::from_be_bytes(pair),
        })
    };
    let mut chars = 0usize;
    let mut pushed = 0usize;
    // The script block this run is locked to, once a unit outside the zero
    // high byte has been taken.
    let mut lock: Option<u8> = None;
    let mut i = 0usize;
    while i + 1 < bytes.len() {
        let Some(u) = unit(i) else { break };
        // A surrogate is in no accepted block, so a pair is a separator and a
        // lone surrogate costs one byte rather than swallowing the run after it.
        let step = 2;
        let high = (u >> 8) as u8;
        // A combining mark attached to a run in progress (NFD text) is kept,
        // exactly as the UTF-8 pass keeps one (`VAL-001`): it does not count
        // toward the minimum length, and a bare mark is still a separator.
        if chars > 0 && utf16_attached_mark(u, lock) {
            let c = char::from_u32(u32::from(u)).unwrap_or(' ');
            out.push(c);
            pushed += c.len_utf8();
            i += step;
            continue;
        }
        let taken = match utf16_text_unit(u) {
            Some(c) => Some(c),
            None => match utf16_script_unit(u) {
                // Same block as the run, or the first block the run meets.
                Some(c) if lock.is_none_or(|l| l == high) => {
                    lock = Some(high);
                    Some(c)
                }
                // A letter from ANOTHER block: the run ends here and a new
                // one starts at this unit, which is not consumed.
                Some(_) => {
                    close_run(out, chars, pushed);
                    chars = 0;
                    pushed = 0;
                    lock = None;
                    continue;
                }
                None => None,
            },
        };
        match taken {
            Some(c) => {
                out.push(c);
                chars += 1;
                pushed += c.len_utf8();
                i += step;
            }
            None => {
                close_run(out, chars, pushed);
                chars = 0;
                pushed = 0;
                lock = None;
                i += 1;
            }
        }
    }
    close_run(out, chars, pushed);
}

/// The high bytes a UTF-16 run may be locked to, with what each block holds.
///
/// Each is an alphabet that fits inside one 256-unit block, which is what
/// makes the single-high-byte coherence test possible. CJK ideographs
/// (U+4E00–U+9FFF) and Hangul (U+AC00–U+D7A3) are absent by owner decision,
/// 2026-09-26 (`SEARCH-002`). The search-universe statement is built from this
/// list, so the screen names exactly what the indexer takes.
pub(crate) const UTF16_SCRIPT_BLOCKS: &[(u8, &str)] = &[
    (0x03, "Greek (U+0370–U+03FF)"),
    (0x04, "Cyrillic (U+0400–U+04FF)"),
    (
        0x05,
        "Cyrillic Supplement, Armenian and Hebrew (U+0500–U+05FF)",
    ),
    (0x06, "Arabic (U+0600–U+06FF)"),
    (0x30, "Japanese kana (U+3041–U+30FF)"),
];

/// The first code unit taken from the kana block. U+3000–U+3040 (CJK
/// symbols: `々`, `〆`, the iteration marks `〱`–`〵`, the Hangzhou numerals)
/// are not kana, and their units are ASCII `0` followed by a space, a digit
/// or punctuation, so taking them read 8-bit digit text such as
/// `01020304` as `〱〲〳〴` (`SEARCH-002`).
const KANA_FIRST: u16 = 0x3041;

/// A letter or digit from one of [`UTF16_SCRIPT_BLOCKS`].
fn utf16_script_unit(u: u16) -> Option<char> {
    let high = (u >> 8) as u8;
    if !UTF16_SCRIPT_BLOCKS.iter().any(|(b, _)| *b == high) || (high == 0x30 && u < KANA_FIRST) {
        return None;
    }
    char::from_u32(u32::from(u)).filter(|c| is_text_char(*c))
}

/// Whether one UTF-16 code unit is text the UTF-16 passes accept.
///
/// ASCII printable and whitespace as before, plus the Latin-1 letters
/// U+00C0–U+00FE less `×` (U+00D7) and `÷` (U+00F7). All have a zero high
/// byte, which is the structural signal that keeps random bytes out.
///
/// `ÿ` (U+00FF) is deliberately NOT accepted: its units are `ff 00` / `00 ff`,
/// and `0xFF` beside `0x00` is the commonest padding in a binary file. Taking
/// it joined a three-letter UTF-16 fragment to the padding after it and made
/// `cat` findable through the minimum-length bound — the same trap the UTF-8
/// pass fell into with a lone `0xFF` byte. A UTF-16 word containing `ÿ` is
/// split there, which is the stated cost.
fn utf16_text_unit(u: u16) -> Option<char> {
    let latin1_letter = (0xC0..=0xFE).contains(&u) && u != 0xD7 && u != 0xF7;
    if u < 0x80 {
        let c = u as u8 as char;
        return is_text_char(c).then_some(c);
    }
    latin1_letter
        .then(|| char::from_u32(u32::from(u)))
        .flatten()
}

/// Whether a UTF-16 unit is a combining mark that may attach to the run in
/// progress: a generic diacritic (U+0300–U+036F) in any run, or a mark from
/// the block the run is locked to (Arabic harakat, Hebrew points, the kana
/// voicing marks).
fn utf16_attached_mark(u: u16, lock: Option<u8>) -> bool {
    if (0x0300..=0x036F).contains(&u) {
        return true;
    }
    lock == Some((u >> 8) as u8) && char::from_u32(u32::from(u)).is_some_and(is_combining_mark)
}

/// Characters kept on each side of the first match in an excerpt.
const EXCERPT_RADIUS: usize = 120;

/// Maximum highlight ranges returned per result.
const MAX_HIGHLIGHTS: usize = 8;

/// Upper bound on the number of stored documents a single blocking scan (plain
/// substring or regex) will retrieve and examine before stopping early and
/// reporting the result set as `truncated`. Together with [`SCAN_DEADLINE`] this
/// bounds the worst-case cost of one search so a pathological query on a very
/// large case cannot pin a blocking-pool thread indefinitely (availability/DoS).
/// Set an order of magnitude above any realistic case so normal searches are
/// never truncated by it.
const MAX_SCAN_DOCS: usize = 5_000_000;

/// Wall-clock ceiling for a single blocking scan. A generous backstop for the
/// case where per-document work (very large content, a complex regex) makes even
/// a sub-budget scan expensive. Checked every [`SCAN_DEADLINE_CHECK_EVERY`]
/// documents so the clock read stays off the hot path.
const SCAN_DEADLINE: Duration = Duration::from_secs(30);

/// How often, in documents scanned, the [`SCAN_DEADLINE`] clock is polled.
const SCAN_DEADLINE_CHECK_EVERY: usize = 4096;

/// Ceiling on the candidate window the ranked full-text path will retrieve when
/// an extension post-filter is active.
///
/// That path filters by extension AFTER retrieval, so it over-fetches five
/// candidates per wanted row. Without a ceiling, paging deep into an
/// extension-filtered ranked search would ask tantivy to retrieve and decode
/// `(offset + limit) * 5` stored documents in one request. The ceiling bounds
/// that; when it binds, the existing `count_is_lower_bound` flag already says
/// the count is a floor, so nothing is hidden by it.
///
/// # What it also bounds, and how that is disclosed (SHIP-034)
///
/// A post-filter can only skip rows it retrieved. So on this routing an OFFSET
/// can only reach as deep as the number of candidates in the window that
/// survive the filter — and that is not this constant, and is not any constant:
/// it is a property of the data. On the ordinary forensic shape, a rare
/// extension thinly spread through a large case, it is small.
/// `seance_search/tests/search_paging_cost_test.rs` measures a 6,000-match case
/// holding 100 `.txt` files where a jump to OFFSET 200 already cannot be
/// served, and a 60,000-match case where offset 30,000 cannot be either.
///
/// Such a jump used to come back as an empty page with `count_is_lower_bound`
/// set, `truncated` set and no cursor: disclosed rather than false, but shaped
/// exactly like "you have paged past the end of the result set", and an
/// examiner who read it that way concluded there was nothing further to
/// review. It is now refused with [`OffsetUnreachable`], the way `seance_api`'s
/// `SEARCH_MAX_OFFSET` refuses a jump past ITS ceiling: the refusal states how
/// many candidates were examined, how deep a jump can reach, that the match set
/// does not end there, and the two routes that do reach past the window (the
/// cursor, and the export). The first page is never refused — with no
/// survivors it is served empty with a cursor past the window, so the walk can
/// begin. `a_deep_offset_under_an_extension_filter_is_refused_not_served_empty`
/// pins both halves so they cannot drift unnoticed, and the decision at
/// `SEARCH_MAX_OFFSET` is read against this bound rather than the advertised
/// one.
const MAX_EXTENSION_CANDIDATES: usize = 25_000;

/// Compiled-program size ceiling for a user-supplied search regex, and the
/// lazy-DFA cache ceiling used while matching. A pattern whose compiled form
/// would exceed these fails to build (fail closed) rather than consume unbounded
/// memory. Both are generous relative to any realistic forensic pattern.
const REGEX_SIZE_LIMIT: usize = 4 * 1024 * 1024;
const REGEX_DFA_SIZE_LIMIT: usize = 2 * 1024 * 1024;

/// Stop condition for a bounded document scan: true once the per-search document
/// budget or the wall-clock deadline is reached. `scanned` is the number of
/// documents already examined this scan.
fn scan_budget_exhausted(scanned: usize, max_scan_docs: usize, start_time: Instant) -> bool {
    scanned >= max_scan_docs
        || (scanned.is_multiple_of(SCAN_DEADLINE_CHECK_EVERY)
            && start_time.elapsed() >= SCAN_DEADLINE)
}

/// A lazy, ordered, resumable walk of the documents matching `query`.
///
/// ORDER. The enumeration is (segment ordinal, document id) ascending — the
/// index's own physical layout — and that is load-bearing rather than
/// incidental. The scans used to enumerate by iterating the `HashSet<DocAddress>`
/// that tantivy's `DocSetCollector` returns, and Rust seeds a `HashSet`'s hasher
/// per instance: two identical searches in one process walked the case in two
/// different orders and, once a result limit bit, returned two different subsets
/// of the same match set. That is invisible while the only thing a caller can
/// ask for is the first page — it just looks like an arbitrary sample, which the
/// first page of an unranked scan legitimately is — but it makes paging
/// impossible: page 2 of a re-rolled enumeration repeats some matches and skips
/// others while looking like a continuation. Walking the segments in order and
/// each segment's postings in doc-id order fixes the order to something the
/// index itself decides, so two requests against one snapshot enumerate
/// identically. `seance_search/tests/search_paging_test.rs` pins this.
///
/// COST. It also removes the materialisation. `DocSetCollector` builds the whole
/// matching set before anything can be sliced out of it, so every page of every
/// scan allocated one `DocAddress` per document in the case and sorted them,
/// however few rows the page wanted. Walking the postings lazily costs nothing
/// until a document is asked for.
///
/// RESUME. `resume` names a position to continue strictly AFTER, which is what
/// makes a cursor page cost what the page is worth rather than what everything
/// before it was worth. Segments before it are skipped whole; the segment
/// holding it is sought into. Because the order is the index's physical layout,
/// the position is only meaningful against the exact index snapshot it was taken
/// from — see [`SearchCursor`], which refuses rather than re-bases.
struct OrderedDocs<'a> {
    searcher: &'a tantivy::Searcher,
    weight: Box<dyn tantivy::query::Weight>,
    /// Index into `searcher.segment_readers()` of the segment being walked.
    segment_ord: usize,
    /// The postings of the current segment, or `None` before one is opened.
    scorer: Option<Box<dyn tantivy::query::Scorer>>,
    /// Position to resume strictly after, as (segment ordinal, document id).
    resume: Option<(u32, u32)>,
}

impl<'a> OrderedDocs<'a> {
    fn new(
        searcher: &'a tantivy::Searcher,
        query: &dyn Query,
        resume: Option<(u32, u32)>,
    ) -> Result<Self> {
        // Scoring disabled: these are the unranked scan paths, which order by
        // position in the index and score every match 1.0.
        let weight = query.weight(tantivy::query::EnableScoring::disabled_from_searcher(
            searcher,
        ))?;
        Ok(Self {
            searcher,
            weight,
            segment_ord: 0,
            scorer: None,
            resume,
        })
    }

    /// The next matching document, or `None` once the walk is finished.
    fn next(&mut self) -> Result<Option<tantivy::DocAddress>> {
        use tantivy::DocSet;
        let searcher = self.searcher;
        let readers = searcher.segment_readers();
        loop {
            if self.scorer.is_none() {
                // Segments before the resume position hold only documents this
                // walk has already accounted for.
                if let Some((resume_segment, _)) = self.resume {
                    while self.segment_ord < readers.len()
                        && (self.segment_ord as u32) < resume_segment
                    {
                        self.segment_ord += 1;
                    }
                }
                let Some(reader) = readers.get(self.segment_ord) else {
                    return Ok(None);
                };
                let mut scorer = self.weight.scorer(reader, 1.0)?;
                if let Some((resume_segment, resume_doc)) = self.resume {
                    if resume_segment == self.segment_ord as u32 {
                        // Strictly after: the document the cursor names was
                        // already delivered or already skipped.
                        scorer.seek(resume_doc.saturating_add(1).min(tantivy::TERMINATED));
                    }
                }
                self.scorer = Some(scorer);
            }

            let segment_ord = self.segment_ord as u32;
            // Deleted documents are still in the postings; the alive bitset is
            // what keeps a purged artifact out of a result set.
            let alive = readers[self.segment_ord].alive_bitset();
            let scorer = self.scorer.as_mut().expect("opened above");
            while scorer.doc() != tantivy::TERMINATED {
                let doc_id = scorer.doc();
                scorer.advance();
                if alive.is_none_or(|bitset| bitset.is_alive(doc_id)) {
                    return Ok(Some(tantivy::DocAddress::new(segment_ord, doc_id)));
                }
            }
            self.scorer = None;
            self.segment_ord += 1;
        }
    }
}

/// A fingerprint of the exact index snapshot a search was served from.
///
/// Paging rests on a stable enumeration order, and the order below — segment
/// ordinal then document id, or relevance then document address — is stable
/// only against a FIXED index. Ingest committing new documents, or the
/// display-name repair rewriting existing ones, re-segments the index and moves
/// the enumeration under an examiner who is part-way through paging it. There
/// is no way to prevent that (this product's whole premise is working on a case
/// while it is still being ingested), so the honest move is to make it VISIBLE:
/// a caller that keeps the fingerprint it was given with one page and compares
/// it against the next can tell its enumeration shifted, and say so, instead of
/// presenting two pages of two different index states as one walk of one result
/// set.
///
/// Built from each live segment's identity and document counts rather than a
/// clock, so it changes when and only when the searchable content does. The
/// per-segment fingerprints are sorted before hashing so the value does not
/// depend on the order the reader happens to list segments in.
fn index_snapshot(searcher: &tantivy::Searcher) -> String {
    let mut segments: Vec<(String, u32, u32)> = searcher
        .segment_readers()
        .iter()
        .map(|reader| {
            (
                reader.segment_id().uuid_string(),
                reader.max_doc(),
                reader.num_deleted_docs(),
            )
        })
        .collect();
    segments.sort();
    let mut hasher = DefaultHasher::new();
    segments.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// How long a pinned snapshot may go UNREAD before it is revoked.
///
/// A pin lives as long as the response body it was moved into, and nothing else
/// in the server bounds that: `tower_http`'s `TimeoutLayer` bounds the response
/// FUTURE, not the streaming of its body, and `ResponseBodyTimeoutLayer` is not
/// in use. So a client that reads the headers and then stops — a tab left open,
/// a half-open TCP connection, a slow-loris — would hold a whole index
/// snapshot's segment files open indefinitely, and there is deliberately no cap
/// on concurrent exports. A handful of stalled downloads on a large case is an
/// evidence volume filling up.
///
/// Measured from the LAST READ rather than from the pin, because the thing being
/// bounded is abandonment, not size. An export of a very large case is minutes
/// of legitimate work and a total deadline would cut off exactly the exhibit the
/// pin was introduced to make whole; a walk that is still being read renews its
/// own lease with every page it serves. Five minutes is far longer than the gap
/// between two pages of any download that is still moving — a page is 1,000 rows
/// and a few hundred kilobytes — and far shorter than "for ever".
const PIN_IDLE_LIMIT: Duration = Duration::from_secs(300);

/// How often the reaper looks at the live pins.
///
/// It is a poll rather than a timer per pin because the conditions it checks are
/// not only clock-driven: a purge landing has to release the segment files
/// holding the purged documents promptly, and no timer knows when that happens.
/// The sweep is a lock and a walk of a list that is empty on almost every
/// server, and the reaper waits indefinitely instead of polling when it is.
const PIN_REAP_INTERVAL: Duration = Duration::from_millis(250);

/// Why a [`PinnedSearcher`] stopped being readable.
///
/// Two causes, kept apart because they call for opposite responses. A purge
/// means the walk MUST stop and the file must say a purge stopped it; an idle
/// timeout means nobody was listening and the walk is being reclaimed. Reporting
/// either as a generic failure would leave the reader of an exhibit unable to
/// tell "this stopped because evidence was destroyed" from "this stopped
/// because the download stalled".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PinRevoked {
    /// Documents were REMOVED from the index after the pin was taken.
    ///
    /// The snapshot this pin holds still contains them — stored fields and all
    /// — so continuing the walk would write purged evidence into the exhibit.
    /// See [`PinnedSearcher`].
    Purged,
    /// The pin went unread for longer than its idle bound, so it was reclaimed.
    Idle,
}

impl std::fmt::Display for PinRevoked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Purged => write!(
                f,
                "documents were purged from the index after this walk pinned its snapshot. The \
                 pinned snapshot still holds those documents, so the walk was stopped rather \
                 than allowed to read destroyed evidence out of it"
            ),
            Self::Idle => write!(
                f,
                "this walk went unread for longer than the server holds a pinned index snapshot \
                 open, so the snapshot was released"
            ),
        }
    }
}

impl std::error::Error for PinRevoked {}

/// A pin's readable state. Revoking replaces the searcher with the reason it
/// went, which is what releases the segment files — refusing to READ a held
/// searcher would leave the disk held.
enum PinState {
    Live(tantivy::Searcher),
    Revoked(PinRevoked),
}

/// The shared body of a pin, reachable from the reaper as well as from the walk.
struct PinnedInner {
    state: std::sync::Mutex<PinState>,
    /// Fingerprint of the pinned snapshot, computed once at pin time. Kept
    /// outside the mutex so a revoked pin can still say which snapshot the rows
    /// already written came from.
    snapshot: String,
    /// When a page was last served from this pin.
    last_used: std::sync::Mutex<Instant>,
    idle_limit: Duration,
    /// The service's purge counter as it stood when the pin was taken, and the
    /// counter itself. Any movement means documents were removed from the index
    /// since, which is the one kind of index movement a pin must not absorb.
    purges_at_pin: u64,
    purges: Arc<AtomicU64>,
}

impl PinnedInner {
    /// The one rule for when a pin is dead: a purge has landed, or it has gone
    /// unread past the idle limit. Marks the state revoked and returns the cause.
    /// Does nothing and returns `None` for a state that is already revoked.
    ///
    /// Purge first. It is the graver of the two and the one whose wording an
    /// exhibit has to carry. Both the walk and the reaper go through here, so
    /// they cannot disagree about when a pin is dead.
    fn revoke_if_due(&self, state: &mut PinState) -> Option<PinRevoked> {
        if matches!(state, PinState::Revoked(_)) {
            return None;
        }
        let cause = if self.purges.load(Ordering::SeqCst) != self.purges_at_pin {
            PinRevoked::Purged
        } else {
            let last = self.last_used.lock().unwrap_or_else(|e| e.into_inner());
            if last.elapsed() > self.idle_limit {
                PinRevoked::Idle
            } else {
                return None;
            }
        };
        *state = PinState::Revoked(cause);
        Some(cause)
    }

    /// Revoke if a purge has landed or the pin has gone unread too long, and
    /// otherwise return the held searcher, renewing the idle lease.
    ///
    /// The walk calls it so a purge is caught at the page boundary rather than
    /// up to a reaper tick later; the reaper calls [`Self::reap`] so a pin nobody
    /// is reading is released even though nothing will ever ask it for a page
    /// again.
    fn take_searcher(&self) -> std::result::Result<tantivy::Searcher, PinRevoked> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if let PinState::Revoked(why) = &*state {
            return Err(*why);
        }
        if let Some(cause) = self.revoke_if_due(&mut state) {
            return Err(cause);
        }
        let PinState::Live(searcher) = &*state else {
            unreachable!("revoked states returned above")
        };
        let searcher = searcher.clone();
        *self.last_used.lock().unwrap_or_else(|e| e.into_inner()) = Instant::now();
        Ok(searcher)
    }

    /// The reaper's half: apply the same rules without renewing the lease and
    /// without wanting the searcher.
    fn reap(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        self.revoke_if_due(&mut state);
    }

    fn segment_readers<T>(&self, f: impl Fn(&tantivy::Searcher) -> T, revoked: T) -> T {
        let state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match &*state {
            PinState::Live(searcher) => f(searcher),
            PinState::Revoked(_) => revoked,
        }
    }
}

/// The registry the reaper walks, plus its wakeup.
///
/// `Weak`, so a pin dropped by its export is gone from here the moment it is
/// gone from the stream: the reaper never keeps a snapshot alive.
struct PinRegistry {
    pins: Vec<std::sync::Weak<PinnedInner>>,
    shutdown: bool,
}

/// One index snapshot, held open for the life of one whole-result-set walk.
///
/// # What it is for, and what it is NOT for
///
/// Interactive paging deliberately does not use this. A page served to a
/// browser reads whatever the index has committed at that moment, so the cursor
/// it hands back is a position in a snapshot that may be gone by the time the
/// examiner clicks "next" — minutes, or a lunch break, later — and it is then
/// REFUSED (see [`SearchCursor`]). That refusal is a forensic property: it is
/// how an examiner learns their walk was interrupted rather than being handed a
/// silent splice of two different result sets.
///
/// An EXPORT is a different shape of the same walk. It runs start-to-finish
/// inside one request, and it is the exhibit — so being cut off part-way is not
/// a message to a user who can click again, it is a short file. Before this
/// existed the export inherited the refusal, and the index moves for background
/// segment MERGES as well as for ingest commits: measured, exporting 20,000
/// matches immediately after indexing them stopped at row 18,000 and completed
/// in full only once the merges had settled. On a case still being ingested —
/// triage, and much of a working day — a large export routinely ended short.
///
/// Pinning removes the condition rather than hiding it. Every page of a pinned
/// walk reads the SAME segment readers, so the snapshot fingerprint every page
/// computes is identical, so no cursor in that walk can be refused for a moved
/// index. Nothing is re-based onto a newer enumeration: documents committed
/// after the pin are simply not in the snapshot being read, which is what keeps
/// the exhibit one result set.
///
/// # The line a pin must not cross: a PURGE
///
/// A pin absorbs index movement that ADDS or REORGANISES, because neither can
/// make the exhibit wrong. Documents that arrive after the pin belong to a later
/// index state, the file names the state it holds, and every row in it is true
/// of that state.
///
/// Movement that REMOVES is not like that, and it is not a performance detail.
/// A purge in this product is normally someone ruling material privileged, out
/// of scope, or outside a warrant, and the point of the ruling is that the
/// material stops leaving the building. A held searcher owns its store readers,
/// so `searcher.doc()` goes on returning the stored name and content of a purged
/// artifact for as long as the pin lives — so an export running while an admin
/// purges would write the destroyed evidence into a file the examiner then
/// holds, and disclosing that in the preamble would not un-write it.
///
/// So a pin is REVOKED the moment the service's purge counter moves
/// ([`PinRevoked::Purged`]): the walk is refused its next page, and the searcher
/// is dropped so the segment files holding the purged documents are released
/// too. Before the pin existed, the purge's own commit moved the snapshot and
/// the walk stopped; that posture is restored here deliberately and narrowly.
/// The completeness guarantee loses in exactly the case where it should lose,
/// and the caller is told which case it was so the file can name the cause.
///
/// The counter is global rather than per case (see [`writer_loop`]), so a purge
/// in another case revokes this pin too. That direction is the safe one: the
/// cost is a re-run of an export, and the cost of guessing wrong the other way
/// is destroyed evidence in an exhibit.
///
/// # What it costs
///
/// A held searcher holds SEGMENT FILES. Tantivy's `Searcher` owns its segment
/// readers and "guarantees that the `Segment` will not be removed before the
/// destruction of the `Searcher`" (tantivy's own words on `SearcherInner`), and
/// the mapped files behind them stay readable even once a merge has superseded
/// them and the collector has unlinked their directory entries. So the disk
/// those files occupy cannot be reclaimed while the pin lives.
///
/// That the READS stay valid is not luck, and it is the thing to re-check if
/// tantivy is ever upgraded: a `SegmentReader` opens every file slice it needs
/// when it is built — term dictionary, postings, positions, fast fields,
/// fieldnorms, alive bitset — and the `Searcher` builds its store readers at
/// the same moment. Nothing in a page of this walk opens a path lazily, so
/// nothing can go looking for a file a merge has since removed.
///
/// The bound is exact, and it is worth stating precisely rather than as "some
/// extra disk":
///
/// * what is held is the segment set NAMED BY THIS PIN, and nothing else. A pin
///   never grows: segments written after it — by ingest, or by the merges
///   themselves — are not in it and are collected on the normal schedule.
///   [`Self::pinned_segments`] and [`Self::pinned_documents`] report what it
///   holds, and `tests/search_export_pin_test.rs` pins that they do not move.
/// * so the worst case for ONE export is the on-disk size of the index as it
///   stood when that export began, held for the export's duration — reached
///   only if every one of those segments is merged away while it runs. On a
///   4,000,000-artifact case that is a real figure, not a rounding error, and
///   an operator sizing an evidence volume has to know it.
/// * the whole-server figure is that sum over the live pins. There is no cap on
///   how many exports may run at once — a cap would be a new way to refuse an
///   examiner an exhibit — so what bounds the sum is TIME rather than count:
///   every pin is released when its export finishes, when its download is
///   abandoned, or, if neither ever happens, when it has gone unread for
///   [`PIN_IDLE_LIMIT`]. A stalled client cannot hold a snapshot for ever.
/// * [`SearchService::live_pinned_searchers`] reports the current figure. It is
///   not a metrics endpoint — this server has none — so the way an operator
///   actually watches it is the log line the export handler emits when a pin is
///   taken and released, which carries the count.
///
/// The alternative bound — an export that ends early — costs an incomplete
/// exhibit on a case under time pressure. Disk is the cheaper of the two, and
/// it is bounded, observable and self-releasing.
pub struct PinnedSearcher {
    inner: Arc<PinnedInner>,
    /// Shared with the service so a live pin can be counted. Decremented by
    /// `Drop`, which is what makes an abandoned export release its hold.
    live: Arc<std::sync::atomic::AtomicUsize>,
}

impl PinnedSearcher {
    /// Fingerprint of the snapshot this pin holds. Constant for its life; it is
    /// what an export states in its preamble as the index state its rows came
    /// from. Still readable after the pin is revoked, because the rows already
    /// written did come from it.
    pub fn snapshot(&self) -> &str {
        &self.inner.snapshot
    }

    /// How many segments this pin is holding open, or zero once it has been
    /// revoked.
    ///
    /// Reported because it is the disk cost made visible: these are the exact
    /// segment files a merge cannot reclaim until the pin drops. Zero after
    /// revocation is the observable fact that revoking RELEASES rather than
    /// merely refuses — a pin that went on holding the files while declining to
    /// read them would leave the disk held for nothing.
    pub fn pinned_segments(&self) -> usize {
        self.inner.segment_readers(|s| s.segment_readers().len(), 0)
    }

    /// How many documents live in the pinned segments, deleted ones included,
    /// or zero once the pin has been revoked.
    ///
    /// Deleted documents are counted deliberately: they still occupy the
    /// segment files this pin is holding, so the figure describes what is held
    /// on disk rather than what a search would return.
    pub fn pinned_documents(&self) -> u64 {
        self.inner.segment_readers(
            |s| {
                s.segment_readers()
                    .iter()
                    .map(|reader| u64::from(reader.max_doc()))
                    .sum()
            },
            0,
        )
    }

    /// Why this pin stopped being readable, or `None` while it still is.
    pub fn revoked(&self) -> Option<PinRevoked> {
        let state = self.inner.state.lock().unwrap_or_else(|e| e.into_inner());
        match &*state {
            PinState::Revoked(why) => Some(*why),
            PinState::Live(_) => None,
        }
    }
}

impl Drop for PinnedSearcher {
    /// Releasing the count is not bookkeeping: an export abandoned mid-download
    /// drops its stream, which drops this, and a pin that survived that would
    /// hold segment files open for the life of the process with nothing left to
    /// read them.
    ///
    /// The registry entry is a `Weak` and needs no cleanup here — the reaper
    /// prunes what it can no longer upgrade.
    fn drop(&mut self) {
        self.live.fetch_sub(1, Ordering::Relaxed);
    }
}

/// Why a cursor cannot be honoured.
///
/// Named separately rather than folded into one "bad cursor", because the three
/// mean different things to the examiner holding it and only one of them is
/// their fault. A cursor whose index moved is a walk that was interrupted by
/// ingest doing exactly what ingest is for; a cursor for another query is a
/// client bug or a mangled link; a malformed one is a typo. The API turns each
/// into a different sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorRefusal {
    /// Not a cursor this build minted: unreadable, truncated, or mangled.
    Malformed,
    /// A cursor for a different case, query, or filter set. A position in one
    /// result set says nothing about another.
    QueryChanged,
    /// The index has changed since the cursor was minted, so the enumeration it
    /// names a position in no longer exists.
    IndexMoved,
}

/// A cursor this engine declines to serve, and the reason.
///
/// Carried through `anyhow` so no signature has to change; callers that need to
/// distinguish the cases (the HTTP layer does — it turns them into different
/// status codes and different sentences) recover it with
/// `err.downcast_ref::<CursorRefused>()`.
#[derive(Debug, Clone)]
pub struct CursorRefused {
    pub refusal: CursorRefusal,
    message: String,
}

impl CursorRefused {
    fn new(refusal: CursorRefusal, message: impl Into<String>) -> Self {
        Self {
            refusal,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for CursorRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for CursorRefused {}

/// Why a jump could not be reached. The refusal names it, because the two
/// causes call for different reading and the sentence for one is FALSE of the
/// other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OffsetUnreachableCause {
    /// The ranked routing under an extension filter: a bounded window of
    /// candidates was retrieved by relevance and the non-matching extensions
    /// were discarded after retrieval.
    ExtensionPostFilter,
    /// A substring or regex scan that ran out of its walk budget before it
    /// reached the requested offset. No extension filter need be involved, and
    /// nothing here is ranked.
    ScanBudget,
}

/// A jump to an offset the ranked routing cannot reach under an extension
/// filter (SHIP-034).
///
/// On the ranked routing an extension filter is a post-filter: the engine
/// retrieves a bounded window of candidates and discards the ones whose
/// extension does not match. A post-filter can only skip rows it retrieved, so
/// the number of positions a jump can reach is however many candidates in the
/// window survived — a property of the data, not a constant, and on the
/// ordinary forensic shape (a rare extension thinly spread through a large
/// case) a small one.
///
/// Until this type existed the answer to such a jump was an empty page with a
/// floored count and no cursor: disclosed, but shaped exactly like "you have
/// paged past the end of the result set", which is a false absence on a
/// court-facing surface. It is now a refusal that says what was examined, how
/// deep a jump can reach, that the match set does NOT end there, and which two
/// routes do reach past the window. Carried through `anyhow` like
/// [`CursorRefused`]; the HTTP layer recovers it with `downcast_ref`.
///
/// A jump to offset 0 is never refused: it is the first page, and when the
/// window holds no survivors that page is served empty with a cursor that
/// continues past the window, so the walk can begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OffsetUnreachable {
    /// The offset the caller asked to jump to.
    pub offset: usize,
    /// How many rows a jump on this search can reach. A COUNT, not a position:
    /// the refusal fires at `offset >= reachable`, so the reachable offsets are
    /// `0` to `reachable - 1`.
    pub reachable: usize,
    /// How many documents were retrieved or walked before the search gave up
    /// reaching further.
    pub examined: usize,
    /// Which of the two limits stopped it. See [`OffsetUnreachableCause`].
    pub cause: OffsetUnreachableCause,
}

impl std::fmt::Display for OffsetUnreachable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Two things this sentence gets right that it once did not.
        //
        // THE REACH IS STATED AS AN OFFSET. `reachable` is a COUNT of rows and
        // the refusal fires at `offset >= reachable`, so the deepest offset
        // actually served is one less. Naming `reachable` itself handed the
        // examiner back the offset just refused: at `offset == reachable` it
        // read "'offset' 12 cannot be reached ... the deepest position a jump
        // can reach on this search is 12" — self-contradictory in one sentence,
        // and refused again if acted on.
        //
        // THE CAUSE IS THE ONE THAT ACTUALLY APPLIED. Both routings raise this
        // refusal, and the extension-post-filter sentence is false of the scan
        // one: it asserts an extension filter discarded rows where there may be
        // no extension filter at all, calls an unranked scan "ranked by
        // relevance", and reports documents walked as candidates retrieved. A
        // refusal has to name its reason, and naming the wrong one is worse than
        // naming none.
        let deepest = self.reachable.saturating_sub(1);
        match self.cause {
            OffsetUnreachableCause::ExtensionPostFilter => write!(
                f,
                "'offset' {} cannot be reached by a jump on this search. The extension filter \
                 runs after retrieval: the server retrieved a window of {} candidates ranked by \
                 relevance and only {} of them carried a matching extension, so a jump on this \
                 search reaches only those {} rows and the deepest 'offset' it can be given is \
                 {}. This is not the end of the match set — the window was exhausted before the \
                 match set was, and further matches with this extension may lie past it. To \
                 reach them, follow the 'next_cursor' each page carries, which continues past \
                 the window instead of jumping into it, or use the search export \
                 (/search/export/csv or /search/export/json with the same query and filters), \
                 which walks the whole match set to the end in one request and states in the \
                 file whether it got there",
                self.offset, self.examined, self.reachable, self.reachable, deepest
            ),
            OffsetUnreachableCause::ScanBudget => write!(
                f,
                "'offset' {} cannot be reached by a jump on this search. This query is answered \
                 by scanning rather than by the ranked index, and the scan stopped at its budget \
                 after walking {} documents: it had found {} matches by then, so a jump on this \
                 search reaches only those {} rows and the deepest 'offset' it can be given is \
                 {}. This is not the end of the match set — the budget was exhausted before the \
                 match set was, and further matches may lie past it. To reach them, follow the \
                 'next_cursor' each page carries, which resumes the scan where it stopped \
                 instead of jumping into it, or use the search export (/search/export/csv or \
                 /search/export/json with the same query and filters), which walks the whole \
                 match set to the end in one request and states in the file whether it got there",
                self.offset, self.examined, self.reachable, self.reachable, deepest
            ),
        }
    }
}

impl std::error::Error for OffsetUnreachable {}

/// Where in an enumeration a cursor points.
///
/// Two orderings exist in this engine and they are not interchangeable, so the
/// position carries which one it belongs to rather than being a bare pair of
/// numbers that both shapes could misread.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CursorPosition {
    /// A position in a scan's (segment ordinal, document id) walk.
    Scan { segment_ord: u32, doc_id: u32 },
    /// A position in the ranked order: relevance descending, then document
    /// address ascending. The score is carried as its bit pattern so the
    /// comparison that resumes the walk is the same comparison that produced
    /// it, with no decimal rounding in between.
    Ranked {
        score_bits: u32,
        segment_ord: u32,
        doc_id: u32,
    },
}

/// An opaque promise about a position in one enumeration of one result set.
///
/// # Why this is not an offset
///
/// An offset is an instruction to walk from the beginning and throw away what
/// you pass. The scan paths obey it literally: reaching match 4,000,000 with a
/// page size of 100 means 40,000 walks of every document in the case, and the
/// paging ceiling existed to cap that bill by declaring the matches past it
/// unreachable. A cursor names where the last page stopped, so the walk of a
/// whole result set costs one pass rather than one pass per page, and no ceiling
/// has to stand in for the cost.
///
/// # Why it can be refused
///
/// A position is only meaningful against the enumeration it was taken from, and
/// both of this engine's orderings move when the index does. The scan order is
/// the index's physical layout, which ingest re-segments and the display-name
/// repair rewrites. The ranked order is BM25, whose scores are computed from
/// corpus-wide term statistics — so a single commit can reorder a result set
/// even where no document in it changed. There is no resume key that survives
/// that: an ingest ordinal stored as a fast field would keep the SCAN order
/// stable across a commit, but it cannot make a ranked order stable, and adding
/// a field to the schema rebuilds every case's index from empty.
///
/// So the cursor carries the [`index_snapshot`] it was minted against and is
/// REFUSED when the index no longer matches it. Refusing is the honest move and
/// the only honest one: re-basing the position onto a different enumeration
/// would hand back rows that look like a continuation, over a set that gained
/// and lost members at the seam, and the examiner would have no way to tell.
/// The refusal says which promise was broken; the caller starts the walk again.
///
/// # Shape
///
/// `shape` fingerprints the case, the query, and every filter that decides which
/// documents match — but NOT the page size, which is a property of the request
/// rather than of the result set. An examiner who changes the page size
/// mid-walk keeps their place.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SearchCursor {
    /// Fingerprint of the case + query + filters this position belongs to.
    shape: u64,
    /// The index snapshot the position was taken against.
    snapshot: String,
    position: CursorPosition,
    /// How many matches the walk has already delivered, i.e. where the page
    /// this cursor opens starts in the match set. Reported as the response's
    /// `offset` so a cursor page can state its position as plainly as an offset
    /// page does.
    consumed: usize,
    /// The size of the match set, established when the walk began. Exact for
    /// the snapshot the cursor is pinned to, which is why carrying it forward
    /// is sound: the count over a fixed index is a fixed number, and a cursor
    /// whose index moved is refused before this figure can be quoted.
    total: usize,
    /// Whether `total` is a floor rather than an exact count.
    total_is_floor: bool,
}

/// Version tag on the wire format, so a cursor minted by an older build is
/// refused as malformed instead of being misread field by field.
const CURSOR_VERSION: &str = "v1";

impl SearchCursor {
    /// Render as the opaque token a client holds and hands back.
    ///
    /// Hex over an ASCII record: opaque enough that nobody is tempted to
    /// hand-edit the numbers inside it (a hand-edited position is a claim about
    /// where rows sit in a result set), cheap enough to need no dependency, and
    /// safe in a URL and a shared link without further escaping.
    fn encode(&self) -> String {
        let (kind, a, b, c) = match self.position {
            CursorPosition::Scan {
                segment_ord,
                doc_id,
            } => ("s", segment_ord, doc_id, 0),
            CursorPosition::Ranked {
                score_bits,
                segment_ord,
                doc_id,
            } => ("r", score_bits, segment_ord, doc_id),
        };
        let payload = format!(
            "{CURSOR_VERSION}|{:016x}|{}|{kind}|{a}|{b}|{c}|{}|{}|{}",
            self.shape,
            self.snapshot,
            self.consumed,
            self.total,
            u8::from(self.total_is_floor),
        );
        payload
            .as_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Read a token back, refusing anything this build did not mint.
    ///
    /// Refused rather than defaulted: a cursor that cannot be read is not a
    /// request for the first page. A client that believes it asked for the
    /// continuation of a walk and is handed the top of the result set has been
    /// told a falsehood about which matches it is looking at, and that
    /// falsehood ends up under a screenshot.
    fn decode(token: &str) -> std::result::Result<Self, CursorRefused> {
        let malformed = || {
            CursorRefused::new(
                CursorRefusal::Malformed,
                "the paging cursor could not be read; it is not a cursor this server issued. \
                 Start the search again from the first page",
            )
        };
        if token.is_empty() || !token.len().is_multiple_of(2) {
            return Err(malformed());
        }
        let bytes: std::result::Result<Vec<u8>, _> = (0..token.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&token[i..i + 2], 16))
            .collect();
        let payload =
            String::from_utf8(bytes.map_err(|_| malformed())?).map_err(|_| malformed())?;

        let fields: Vec<&str> = payload.split('|').collect();
        if fields.len() != 10 || fields[0] != CURSOR_VERSION {
            return Err(malformed());
        }
        let shape = u64::from_str_radix(fields[1], 16).map_err(|_| malformed())?;
        let snapshot = fields[2].to_string();
        let a: u32 = fields[4].parse().map_err(|_| malformed())?;
        let b: u32 = fields[5].parse().map_err(|_| malformed())?;
        let c: u32 = fields[6].parse().map_err(|_| malformed())?;
        let position = match fields[3] {
            "s" => CursorPosition::Scan {
                segment_ord: a,
                doc_id: b,
            },
            "r" => CursorPosition::Ranked {
                score_bits: a,
                segment_ord: b,
                doc_id: c,
            },
            _ => return Err(malformed()),
        };
        let consumed: usize = fields[7].parse().map_err(|_| malformed())?;
        let total: usize = fields[8].parse().map_err(|_| malformed())?;
        let total_is_floor = match fields[9] {
            "0" => false,
            "1" => true,
            _ => return Err(malformed()),
        };
        if snapshot.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            shape,
            snapshot,
            position,
            consumed,
            total,
            total_is_floor,
        })
    }

    /// Check the cursor against the request it arrived with and the index it
    /// would be served from.
    fn validate(
        &self,
        expected_shape: u64,
        snapshot: &str,
    ) -> std::result::Result<(), CursorRefused> {
        if self.shape != expected_shape {
            return Err(CursorRefused::new(
                CursorRefusal::QueryChanged,
                "this paging cursor belongs to a different search. A position in one result \
                 set says nothing about another, so it cannot be applied to this query, case \
                 or filters. Run the search and page it from the first page",
            ));
        }
        if self.snapshot != snapshot {
            return Err(CursorRefused::new(
                CursorRefusal::IndexMoved,
                format!(
                    "the search index changed after this page of results was fetched \
                     (snapshot {} is now {snapshot}), so the position this cursor names no \
                     longer exists: evidence has been indexed, or the index has been \
                     repaired, and the result set has been re-ordered around it. Continuing \
                     from here would present rows from two different states of the index as \
                     one list, which is why it is refused rather than approximated. Start the \
                     walk again from the first page to walk one consistent set",
                    self.snapshot
                ),
            ));
        }
        Ok(())
    }
}

/// Fingerprint of everything that decides WHICH documents a search matches and
/// in what order — the identity of the result set a cursor is a position in.
///
/// Deliberately excludes `limit`: the page size shapes the request, not the
/// result set, so a cursor stays valid across a change of it.
///
/// Filter values are normalised first so that two spellings of one filter
/// (`.txt` and `txt`, two orderings of the same type list) are one result set
/// rather than two, and an examiner is not thrown back to the top of a walk by
/// a client that re-serialised its own request.
fn result_set_shape(case_id: Uuid, options: &SearchOptions) -> u64 {
    let mut types: Vec<String> = options
        .artifact_types
        .clone()
        .unwrap_or_default()
        .into_iter()
        .filter(|t| !t.is_empty())
        .collect();
    types.sort();
    types.dedup();
    let mut extensions = options
        .file_extensions
        .as_deref()
        .map(normalize_extensions)
        .unwrap_or_default();
    extensions.sort();
    extensions.dedup();

    let mut hasher = DefaultHasher::new();
    case_id.hash(&mut hasher);
    options.query.hash(&mut hasher);
    options.use_regex.hash(&mut hasher);
    options.fuzzy.map(|d| d.clamp(1, 2)).hash(&mut hasher);
    types.hash(&mut hasher);
    extensions.hash(&mut hasher);
    hasher.finish()
}

/// One document's place in the ranked order: relevance descending, then
/// document address ascending.
///
/// The tie-break is not decoration. Scores tie constantly — every document
/// holding a term once at the same length scores identically — so relevance
/// ALONE is not a total order, and a cursor over a partial order skips and
/// repeats rows at every tie boundary. Address-ascending is the same tie-break
/// tantivy's own `TopDocs` applies, which is what lets a cursor page and an
/// offset page be two views of one enumeration.
///
/// `Ordering::Greater` means BETTER, i.e. earlier in the result set.
#[derive(Debug, Clone, Copy)]
struct RankedKey {
    score: f32,
    segment_ord: u32,
    doc_id: u32,
}

impl RankedKey {
    fn address(&self) -> tantivy::DocAddress {
        tantivy::DocAddress::new(self.segment_ord, self.doc_id)
    }
}

impl Ord for RankedKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // `total_cmp` rather than `partial_cmp`, so a NaN score — which no BM25
        // computation should produce, but which would silently collapse the
        // order into "everything is equal" if one ever appeared — still yields
        // a total order rather than a set of incomparable rows.
        self.score.total_cmp(&other.score).then_with(|| {
            // Lower address sorts EARLIER, so it must compare as greater here.
            (other.segment_ord, other.doc_id).cmp(&(self.segment_ord, self.doc_id))
        })
    }
}

impl PartialOrd for RankedKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for RankedKey {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == std::cmp::Ordering::Equal
    }
}

impl Eq for RankedKey {}

/// The ranked window that begins immediately after a given position.
///
/// Tantivy 0.22 has no `search_after`, and `TopDocs::with_limit(n).and_offset(k)`
/// is not one: it keeps a heap of `n + k` entries and throws the first `k` away,
/// so the heap grows with depth and every deep page re-derives the rows in front
/// of it. This keeps a heap of `n` entries whatever the depth, because the
/// predicate — "strictly worse than the position the cursor names" — decides
/// membership per document instead of by counting.
struct RankedAfter {
    limit: usize,
    /// Position to resume strictly after; `None` collects from the top.
    after: Option<RankedKey>,
}

impl tantivy::collector::Collector for RankedAfter {
    type Fruit = Vec<(f32, tantivy::DocAddress)>;
    type Child = RankedAfterSegment;

    fn for_segment(
        &self,
        segment_ord: tantivy::SegmentOrdinal,
        _segment: &tantivy::SegmentReader,
    ) -> tantivy::Result<Self::Child> {
        Ok(RankedAfterSegment {
            segment_ord,
            limit: self.limit,
            after: self.after,
            // A min-heap of the best `limit` seen so far: `Reverse` puts the
            // WORST kept row at the top, which is the one a better row evicts.
            best: std::collections::BinaryHeap::new(),
        })
    }

    fn requires_scoring(&self) -> bool {
        true
    }

    fn merge_fruits(
        &self,
        segment_fruits: Vec<Vec<RankedKey>>,
    ) -> tantivy::Result<Vec<(f32, tantivy::DocAddress)>> {
        let mut all: Vec<RankedKey> = segment_fruits.into_iter().flatten().collect();
        // Best first, by the same total order the segments filtered against.
        all.sort_unstable_by(|a, b| b.cmp(a));
        all.truncate(self.limit);
        Ok(all.into_iter().map(|k| (k.score, k.address())).collect())
    }
}

struct RankedAfterSegment {
    segment_ord: u32,
    limit: usize,
    after: Option<RankedKey>,
    best: std::collections::BinaryHeap<std::cmp::Reverse<RankedKey>>,
}

impl tantivy::collector::SegmentCollector for RankedAfterSegment {
    type Fruit = Vec<RankedKey>;

    fn collect(&mut self, doc_id: tantivy::DocId, score: tantivy::Score) {
        let key = RankedKey {
            score,
            segment_ord: self.segment_ord,
            doc_id,
        };
        // Strictly after: a row equal to the cursor's position is the row the
        // previous page ended on, and handing it out again would put one match
        // on two pages.
        if let Some(after) = self.after {
            if key >= after {
                return;
            }
        }
        if self.limit == 0 {
            return;
        }
        self.best.push(std::cmp::Reverse(key));
        if self.best.len() > self.limit {
            self.best.pop();
        }
    }

    fn harvest(self) -> Vec<RankedKey> {
        self.best
            .into_iter()
            .map(|std::cmp::Reverse(key)| key)
            .collect()
    }
}

/// Split a query string into plain highlightable terms, dropping query-syntax
/// punctuation and boolean operators.
fn query_terms(query: &str) -> Vec<String> {
    query
        .split(|c: char| c.is_whitespace() || "\"'+-^~*():[]{}".contains(c))
        .filter(|t| !t.is_empty())
        .filter(|t| !matches!(t.to_ascii_uppercase().as_str(), "AND" | "OR" | "NOT" | "TO"))
        .map(|t| t.to_string())
        .collect()
}

/// Whether a query is a plain keyword search (no Tantivy query-language syntax),
/// and so should be matched as a case-insensitive substring rather than parsed
/// into a structured term query. Phrases (`"..."`), grouping (`( )`), wildcards
/// (`*` / `?`), and the boolean operator words route to the tokenized parser;
/// everything else — including hyphens, dots, colons and `+`/`-` inside a word —
/// is treated as literal text to search for. An empty/whitespace query is not
/// plain (it has nothing to match).
fn is_plain_query(query: &str) -> bool {
    let q = query.trim();
    if q.is_empty() {
        return false;
    }
    if q.contains('"') || q.contains('(') || q.contains(')') || q.contains('*') || q.contains('?') {
        return false;
    }
    if q.split_whitespace()
        .any(|w| matches!(w, "AND" | "OR" | "NOT"))
    {
        return false;
    }
    true
}

/// Build a case-insensitive regex matching any of the given literal terms
/// (longest first so overlapping terms prefer the longer match).
fn terms_regex(terms: &[String]) -> Option<Regex> {
    if terms.is_empty() {
        return None;
    }
    let mut sorted: Vec<&String> = terms.iter().collect();
    sorted.sort_by_key(|t| std::cmp::Reverse(t.len()));
    let pattern = sorted
        .iter()
        .map(|t| regex::escape(t))
        .collect::<Vec<_>>()
        .join("|");
    RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .build()
        .ok()
}

/// Build a plain-text excerpt of `content` centered on the first match of
/// `re`: up to [`EXCERPT_RADIUS`] chars on each side, cut at word boundaries,
/// with leading/trailing ellipses when truncated. Returns the snippet plus
/// byte-offset highlight ranges INTO THE SNIPPET (max [`MAX_HIGHLIGHTS`]).
fn build_excerpt(content: &str, re: &Regex) -> Option<(String, Vec<(usize, usize)>)> {
    let first = re.find(content)?;

    // Window centered on the first match, snapped to char boundaries.
    let mut start = first.start().saturating_sub(EXCERPT_RADIUS);
    while !content.is_char_boundary(start) {
        start -= 1;
    }
    let mut end = (first.end() + EXCERPT_RADIUS).min(content.len());
    while end < content.len() && !content.is_char_boundary(end) {
        end += 1;
    }

    // Cut at word boundaries: skip the partial word at the window start and
    // drop the partial word at the window end (only when actually truncated).
    if start > 0 {
        if let Some((i, c)) = content[start..first.start()]
            .char_indices()
            .find(|(_, c)| c.is_whitespace())
        {
            start += i + c.len_utf8();
        }
    }
    if end < content.len() {
        if let Some(i) = content[first.end()..end].rfind(char::is_whitespace) {
            end = first.end() + i;
        }
    }

    let prefix = if start > 0 { "..." } else { "" };
    let suffix = if end < content.len() { "..." } else { "" };
    let body = &content[start..end];
    let snippet = format!("{}{}{}", prefix, body, suffix);

    let mut highlights = Vec::new();
    for m in re.find_iter(body) {
        if highlights.len() >= MAX_HIGHLIGHTS {
            break;
        }
        highlights.push((m.start() + prefix.len(), m.end() + prefix.len()));
    }

    Some((snippet, highlights))
}

/// The edit distance a fuzzy search will actually use.
///
/// Tantivy's Levenshtein automaton is built for 1 or 2; anything else is
/// clamped. Exported because the clamp has to be applied in **two** places and
/// they must not disagree: the search applies it, and the export preamble
/// states it. When only the search clamped, `?fuzzy=9` produced a court-facing
/// file whose preamble read `# filter.fuzzy_edit_distance,9` over an
/// edit-distance-2 match set — a filter the exhibit claimed and the engine
/// never applied.
pub fn clamp_fuzzy_distance(distance: u8) -> u8 {
    distance.clamp(1, 2)
}

/// Turn a metadata key into something a person reads: `target_path` ->
/// `Target path`. Deliberately mechanical — it renames nothing and drops
/// nothing, so the field an examiner sees in the snippet is still the field
/// that is in the record.
fn humanise_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len());
    for (i, part) in key.split(['_', '-']).filter(|p| !p.is_empty()).enumerate() {
        if i > 0 {
            out.push(' ');
        }
        let mut chars = part.chars();
        if let Some(first) = chars.next() {
            if i == 0 {
                out.extend(first.to_uppercase());
            } else {
                out.push(first);
            }
            out.push_str(chars.as_str());
        }
    }
    if out.is_empty() {
        key.to_string()
    } else {
        out
    }
}

/// A metadata object rendered as `Key: value · Key: value`.
///
/// Used when the query matched the record's metadata somewhere the field-level
/// pass could not place — a key name, or a term spanning JSON punctuation. It
/// is the same information the raw JSON carried, minus the braces, quotes and
/// escapes that made it unreadable.
fn humanise_metadata(
    object: &serde_json::Map<String, serde_json::Value>,
    redacted: &[&str],
) -> String {
    object
        .iter()
        .filter(|(key, _)| !redacted.contains(&&key[..]))
        .filter_map(|(key, value)| {
            let rendered = match value {
                serde_json::Value::String(v) if !v.is_empty() => v.clone(),
                serde_json::Value::Number(v) => v.to_string(),
                serde_json::Value::Bool(v) => v.to_string(),
                _ => return None,
            };
            Some(format!("{}: {}", humanise_key(key), rendered))
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The excerpt for a result whose indexed content begins with the record's
/// serialised metadata (UI-008).
///
/// `build_doc` indexes the metadata JSON as the first value of the multi-valued
/// `content` field, and `serde_json::to_string` escapes newlines, so that value
/// is exactly the first line of the joined content. When the match landed in it,
/// excerpting the raw text produced snippets like
/// `{"type":"FileSignatureAnalysis","analysis_type":"file_analysis",...}` on a
/// court-facing screen: correct, since the term really is in that text, and
/// unreadable — and readable as if it were the *file's* content rather than a
/// description of the record.
///
/// So the match is placed instead:
///
/// 1. In a **field value** — the snippet is that value, excerpted as usual and
///    prefixed with the field's own name, so the examiner sees
///    `Detected type: PNG image` rather than a fragment of JSON.
/// 2. Anywhere else in the metadata — a key name, or a term straddling the
///    punctuation — the snippet is the whole record rendered as
///    `Key: value · Key: value`. Nothing is hidden and nothing is invented; the
///    braces and quotes are gone.
///
/// Returns `None` when the first line is not a JSON object, or when the match is
/// not in it at all, so the caller falls through to the ordinary text excerpt
/// over the file's own bytes — which is content, and should look like it.
///
/// Where more than one field matches, the first in `serde_json::Map` order wins.
/// That is alphabetical rather than the order the parser wrote, which is not the
/// most *interesting* field but is a stable one: the same record and the same
/// query always produce the same snippet, so two examiners reading the same
/// result see the same sentence.
fn metadata_excerpt(content: &str, re: &Regex) -> Option<(String, Vec<(usize, usize)>)> {
    let first_line = content.split('\n').next()?;
    if !first_line.starts_with('{') {
        return None;
    }
    let object = match serde_json::from_str::<serde_json::Value>(first_line).ok()? {
        serde_json::Value::Object(o) => o,
        _ => return None,
    };

    let redacted = redacted_keys(&object);
    let is_redacted = |key: &str| redacted.contains(&key);

    // 1. The match inside a single field's value.
    for (key, value) in &object {
        if is_redacted(key) {
            continue;
        }
        let rendered = match value {
            serde_json::Value::String(v) => v.clone(),
            serde_json::Value::Number(v) => v.to_string(),
            _ => continue,
        };
        if let Some((excerpt, highlights)) = build_excerpt(&rendered, re) {
            let prefix = format!("{}: ", humanise_key(key));
            let shift = prefix.len();
            let shifted = highlights
                .into_iter()
                .map(|(a, b)| (a + shift, b + shift))
                .collect();
            // A withheld field is *said*, never merely omitted. An examiner
            // reading a credential record's snippet has to know a value exists
            // and where to get it, or the screen reads as a record that holds
            // nothing.
            let notice = if redacted.is_empty() {
                String::new()
            } else {
                format!(" · {REDACTED_SNIPPET}")
            };
            return Some((format!("{prefix}{excerpt}{notice}"), shifted));
        }
    }

    // 2. The match is in the metadata but not in one field's value: a key name,
    //    or a term straddling the JSON punctuation. Render the record readably
    //    and excerpt that. If the term survives the rendering it is highlighted;
    //    if it does not — it was in the punctuation the rendering removed — the
    //    readable record is still a better snippet than the raw JSON, and it is
    //    returned with no highlight rather than with a wrong one.
    // The readable record, with the withheld field replaced by a sentence
    // saying it was withheld rather than simply dropped.
    let readable = {
        let body = humanise_metadata(&object, &redacted);
        match (body.is_empty(), redacted.is_empty()) {
            (_, true) => body,
            (true, false) => REDACTED_SNIPPET.to_string(),
            (false, false) => format!("{body} · {REDACTED_SNIPPET}"),
        }
    };

    if re.is_match(first_line) {
        if readable.is_empty() {
            return None;
        }
        return Some(
            build_excerpt(&readable, re)
                .unwrap_or_else(|| (truncate_for_snippet(&readable), Vec::new())),
        );
    }

    // A record carrying a redacted value never falls through to the raw-text
    // excerpt, whether or not the query matched anything renderable: that path
    // reads the serialised metadata, and the value is in it.
    if !redacted.is_empty() {
        return Some((truncate_for_snippet(&readable), Vec::new()));
    }

    None
}

/// What a snippet says in place of a value it will not print.
const REDACTED_SNIPPET: &str =
    "(recovered credential — the value is released only through the audited reveal)";

/// Metadata keys this record type carries that a snippet must never print.
///
/// `MemoryCredential` records hold a **decrypted** NT hash or LSA secret in
/// `value`, and `seance_api`'s `reveal_memory_credential` is the audited path
/// such a value travels by: it writes an audit entry naming the examiner who
/// asked for it. A search snippet that printed the same bytes would release it
/// with nothing in the custody trail recording that anyone saw it — the reveal
/// endpoint's whole purpose, defeated one column over.
///
/// This is the presentation half only. The value is still **in the index**,
/// because `build_doc` indexes every artifact's whole metadata JSON, so a search
/// for a known hash still finds the record — it just no longer echoes the hash
/// back. Whether the index should carry it at all is a separate decision, and is
/// recorded as its own defect rather than settled here: removing it would also
/// remove an examiner's ability to search for a hash they already hold, which is
/// a legitimate thing to want.
fn redacted_keys(object: &serde_json::Map<String, serde_json::Value>) -> Vec<&'static str> {
    let record_type = ["type", "subtype"]
        .iter()
        .find_map(|k| object.get(*k).and_then(|v| v.as_str()))
        .unwrap_or_default();

    match record_type {
        "MemoryCredential" => vec!["value"],
        _ => Vec::new(),
    }
}

/// A readable record with no match in it, cut to snippet length.
///
/// Never cuts mid-character, and marks the cut with an ellipsis so a truncated
/// snippet is not read as a whole one.
fn truncate_for_snippet(text: &str) -> String {
    const LIMIT: usize = EXCERPT_RADIUS * 2;
    if text.len() <= LIMIT {
        return text.to_string();
    }
    let mut end = LIMIT;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &text[..end])
}

/// Snippet + highlights for a result: a content excerpt when the pattern
/// matches the content, else a name excerpt, else the bare name.
///
/// The content excerpt is metadata-aware — see [`metadata_excerpt`] — because
/// the first value of the indexed content is the record's serialised metadata,
/// and excerpting that raw put JSON on the screen where a readable line
/// belonged (UI-008).
fn snippet_for(
    name: &str,
    content: &str,
    re: Option<&Regex>,
) -> (Option<String>, Vec<(usize, usize)>) {
    if let Some(re) = re {
        if let Some((snippet, highlights)) = metadata_excerpt(content, re) {
            return (Some(snippet), highlights);
        }
        if let Some((snippet, highlights)) = build_excerpt(content, re) {
            return (Some(snippet), highlights);
        }
        if let Some((snippet, highlights)) = build_excerpt(name, re) {
            return (Some(snippet), highlights);
        }
    }
    (Some(name.to_string()), Vec::new())
}

/// Join every value of the multi-valued `content` field of a retrieved document.
///
/// `content` is genuinely multi-valued: `build_doc` adds the artifact metadata
/// JSON and then, for file artifacts, the strings extracted from the file's own
/// bytes. The tokenized index matches across *all* values, so any code that
/// match-tests or excerpts a retrieved document must see all of them too.
/// Reading only the first value (`get_first`) makes a keyword that exists in the
/// file body present as "not in evidence" — and makes plain and regex search
/// disagree about the same case.
fn joined_content(doc: &TantivyDocument, field: Field) -> String {
    doc.get_all(field)
        .filter_map(|v| v.as_str())
        .collect::<Vec<_>>()
        .join("\n")
}

/// The schema fields needed to turn an artifact into a Tantivy document. `Field`
/// is `Copy`, so this is cheap to hand to the writer thread.
#[derive(Clone, Copy)]
struct DocFields {
    id: Field,
    case_id: Field,
    artifact_type: Field,
    name: Field,
    content: Field,
    record_kind: Field,
}

/// Work items for the dedicated index-writer thread. Adds carry an already-built
/// document so document building (metadata serialization + bounded content read)
/// stays parallel across ingest workers, and only the writer mutation (add +
/// commit) is serialized here. Commit/delete carry a responder so the caller can
/// wait for durability when it needs to.
enum IndexCommand {
    Add(Box<TantivyDocument>),
    /// Add a document after deleting any document already carrying that
    /// artifact id, in that order, on the writer thread.
    ///
    /// `Add` appends. That is right for ingest, where the id is new by
    /// construction, and wrong for the backfill (`LIVE-028`), which decides
    /// what to add from a *committed* view of the index: an artifact an ingest
    /// has enqueued but not yet committed reads as missing and would be added a
    /// second time, leaving one artifact with two documents — the file twice in
    /// every result and in every total, clearable only by a full rebuild.
    ///
    /// Tantivy applies a delete to documents whose opstamp precedes it, so
    /// deleting the term and then adding inside the same command keeps the new
    /// document and removes any older twin.
    AddReplacing(Box<TantivyDocument>, String),
    Commit(CmdSender<Result<()>>),
    DeleteArtifact(Uuid, CmdSender<Result<()>>),
    DeleteArtifacts(Vec<Uuid>, CmdSender<Result<()>>),
    DeleteCase(Uuid, CmdSender<Result<()>>),
    DeleteAll(CmdSender<Result<()>>),
    /// Swap a batch of documents for rebuilt versions of themselves, keyed by
    /// artifact id. Delete and re-add happen inside a single commit, so the
    /// documents are never absent from the index at any point another thread
    /// could observe. See [`replace_documents`].
    ///
    /// The `u64` is the value of the writer's purge counter when the repair
    /// that built this batch took its snapshot of the index. The writer refuses
    /// the batch if the counter has moved on, because a document this batch
    /// would re-add may be one a delete has since purged. See
    /// [`purge_overtook_repair`].
    ReplaceDocuments(Vec<(Uuid, TantivyDocument)>, u64, CmdSender<Result<()>>),
}

/// Metadata keys whose value is the PRODUCT's own prose about the artifact,
/// not anything read out of the evidence.
///
/// A keyword search has to answer "is this term in the evidence". These keys
/// answer "what did Séance conclude", in sentences written here — and once they
/// are in the indexed text, an ordinary word inside one of them matches every
/// artifact that carries it. Measured on the NIST CFReDS image: the MFT
/// parser's timestamp explanations put `"preserves the source"` on 4,026
/// artifacts and made a search for `rename` return 1,386 hits, none of them
/// because the word was in a file.
///
/// The values stay in the artifact's metadata — the API serves them, the UI
/// renders them, and they are part of the record. They are simply not treated
/// as words the evidence contains.
const NOT_EVIDENCE_TEXT: &[&str] = &["timestamp_indicators", "timestomp_reasons"];

/// `metadata` with [`NOT_EVIDENCE_TEXT`] removed, for the indexed text only.
///
/// Borrows when there is nothing to strip, which is the overwhelming majority
/// of artifacts, so the common path allocates nothing extra.
fn indexable_metadata(metadata: &serde_json::Value) -> std::borrow::Cow<'_, serde_json::Value> {
    let Some(map) = metadata.as_object() else {
        return std::borrow::Cow::Borrowed(metadata);
    };
    if !NOT_EVIDENCE_TEXT.iter().any(|k| map.contains_key(*k)) {
        return std::borrow::Cow::Borrowed(metadata);
    }
    let mut trimmed = map.clone();
    for key in NOT_EVIDENCE_TEXT {
        trimmed.remove(*key);
    }
    std::borrow::Cow::Owned(serde_json::Value::Object(trimmed))
}

/// The record-kind discriminator for a document: the metadata `type` when it
/// has one, else the artifact type.
///
/// The same discriminator the database computes as
/// `COALESCE(json_extract(metadata_json,'$.type'), artifact_type)`, written
/// into the index so the pivot can group by kind from the index alone (§1.0).
/// The two must agree: a kind shown beside a count has to be the kind the record
/// viewers key on.
fn record_kind_of(metadata: &serde_json::Value, artifact_type: &str) -> String {
    metadata
        .get("type")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(artifact_type)
        .to_string()
}

/// Build a Tantivy document from an artifact. Runs on the ingest worker (in
/// parallel), so only the writer mutation is serialized on the writer thread.
fn build_doc(artifact: &Artifact, fields: &DocFields) -> Result<TantivyDocument> {
    let mut doc = doc!(
        fields.id => artifact.id.to_string(),
        fields.case_id => artifact.case_id.to_string(),
        fields.artifact_type => artifact.artifact_type.to_string(),
    );

    let artifact_type_str = artifact.artifact_type.to_string();
    let record_kind = record_kind_of(&artifact.metadata, &artifact_type_str);
    doc.add_text(fields.record_kind, &record_kind);
    // A ParsedRecord almost never carries a `name`, so indexing that key alone
    // put the literal word "ParsedRecord" in the name column of every result
    // row for the largest artifact class in the case (LIVE-022).
    let name = seance_core::artifact::display_name(&artifact_type_str, &artifact.metadata);
    doc.add_text(fields.name, &name);

    let content_string = serde_json::to_string(&indexable_metadata(&artifact.metadata))
        .context("Failed to serialize artifact metadata for indexing")?;
    doc.add_text(fields.content, &content_string);

    // Index the file's own bytes (bounded) so keyword search covers content,
    // not just metadata. Only for file-shaped artifacts; printable runs are
    // extracted so binary files are searchable too.
    // The type list is `scope::CONTENT_INDEXED_TYPES`, which is also what the
    // search-universe statement names, so the two cannot disagree.
    if scope::CONTENT_INDEXED_TYPES.contains(&artifact.artifact_type) {
        if let Some(data) = &artifact.data {
            let declared = data.size();
            let cap = declared.min(CONTENT_INDEX_CAP as u64) as usize;
            if cap > 0 {
                let mut buf = vec![0u8; cap];
                let mut off = 0usize;
                let mut read_failed = false;
                while off < cap {
                    match data.read_at(off as u64, &mut buf[off..]) {
                        Ok(0) => break,
                        Ok(n) => off += n,
                        Err(e) => {
                            warn!(
                                "search index: read error {} bytes into artifact {}: {}",
                                off, artifact.id, e
                            );
                            read_failed = true;
                            break;
                        }
                    }
                }
                buf.truncate(off);
                let mut text = extract_searchable_text(&buf);
                // Say so when the indexed text is only part of the file. The
                // cap is deliberate; a short read is broken evidence. Either
                // way the keywords past that point are unsearchable, and the
                // marker is what stops "no hits" from being read as "not
                // present in this file".
                let incomplete = if off < cap || read_failed {
                    Some("short_read")
                } else if (cap as u64) < declared {
                    Some("cap_reached")
                } else {
                    None
                };
                if let Some(reason) = incomplete {
                    warn!(
                        "search index: artifact {} indexed {} of {} declared bytes ({})",
                        artifact.id, off, declared, reason
                    );
                    text.push(' ');
                    text.push_str(INDEX_INCOMPLETE_TOKEN);
                    text.push(' ');
                    text.push_str(reason);
                }
                if !text.is_empty() {
                    doc.add_text(fields.content, &text);
                }
            }
        }
    }

    Ok(doc)
}

/// What a per-case display-name repair did, so the caller can report it instead
/// of asserting that the case is now correct.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RefreshOutcome {
    /// Documents this case had in the index when the repair started. It is the
    /// size of the INDEX, not of the case: artifacts that were never indexed are
    /// not counted here and are not added by the repair.
    pub documents: usize,
    /// Documents whose stored name differed from the name the metadata implies,
    /// and which were re-emitted with the corrected one.
    pub renamed: usize,
    /// Documents whose stored metadata could not be read back as JSON, so no
    /// name could be computed for them. They are left in the index exactly as
    /// they were — still searchable, still stale — and reported rather than
    /// quietly skipped.
    pub undecodable: usize,
}

/// What the repair decided about one stored document.
enum RepairDecision {
    /// The stored name is already what the metadata implies. The document is
    /// left alone: not deleted, not re-added, not counted as repaired. This is
    /// what makes a second run of the repair a read-only pass.
    AlreadyCurrent,
    /// The stored metadata could not be parsed, so there is no honest name to
    /// compute. Left untouched and disclosed.
    Undecodable,
    /// A replacement document carrying the corrected name and every original
    /// `content` value.
    Rebuilt {
        artifact_id: Uuid,
        doc: TantivyDocument,
        content_bytes: usize,
    },
}

/// Decide what to do with one stored document, and build its replacement when
/// the name it carries is not the one its own metadata implies.
///
/// The replacement keeps the document's id, case, type and ALL of its `content`
/// values in their original order — value[0] is the metadata JSON, and for file
/// artifacts value[1] is the bounded text extracted from the file's bytes. Both
/// have to come back or the repair costs the case search coverage it had.
fn rebuild_with_display_name(stored: &TantivyDocument, fields: &DocFields) -> RepairDecision {
    let id_str = stored
        .get_first(fields.id)
        .and_then(|v| v.as_str())
        .unwrap_or("");
    // Without a readable id we cannot key the delete, so we cannot replace the
    // document without risking deleting something else. Leave it be.
    let Ok(artifact_id) = Uuid::parse_str(id_str) else {
        return RepairDecision::Undecodable;
    };
    let case_id_str = stored
        .get_first(fields.case_id)
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let artifact_type = stored
        .get_first(fields.artifact_type)
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let stored_name = stored
        .get_first(fields.name)
        .and_then(|v| v.as_str())
        .unwrap_or("");

    let contents: Vec<&str> = stored
        .get_all(fields.content)
        .filter_map(|v| v.as_str())
        .collect();
    let Some(metadata_json) = contents.first() else {
        return RepairDecision::Undecodable;
    };
    let Ok(metadata) = serde_json::from_str::<serde_json::Value>(metadata_json) else {
        return RepairDecision::Undecodable;
    };

    let name = seance_core::artifact::display_name(artifact_type, &metadata);
    if name == stored_name {
        return RepairDecision::AlreadyCurrent;
    }

    let mut doc = doc!(
        fields.id => id_str.to_string(),
        fields.case_id => case_id_str.to_string(),
        fields.artifact_type => artifact_type.to_string(),
    );
    doc.add_text(fields.name, &name);
    // Carry the stored kind across; a document that never had one is given the
    // one `build_doc` would give it, so the repair leaves no empty kind behind.
    let record_kind = stored
        .get_first(fields.record_kind)
        .and_then(|v| v.as_str())
        .filter(|k| !k.is_empty())
        .map_or_else(|| record_kind_of(&metadata, artifact_type), str::to_string);
    doc.add_text(fields.record_kind, &record_kind);
    let mut content_bytes = 0usize;
    for value in &contents {
        content_bytes += value.len();
        doc.add_text(fields.content, *value);
    }

    RepairDecision::Rebuilt {
        artifact_id,
        doc,
        content_bytes,
    }
}

/// The error a display-name repair stops with when documents were purged from
/// the index while that repair was in flight.
///
/// A purge is fail-closed on the request that asked for it: `delete_case`
/// refuses to destroy a case at all unless the index purge lands first, because
/// an index that still describes destroyed evidence keeps answering searches
/// with it. A repair works from a searcher snapshot taken before that purge and
/// re-emits whole stored documents keyed by artifact id, so a batch applied
/// after the purge puts the purged documents back — and, the purge having
/// already committed, they stay. Stopping the repair is the safe half of that
/// trade: the batches that already landed keep their corrected names, nothing
/// is missing that was not already missing, and the repair can simply be run
/// again once the deletion has settled.
fn purge_overtook_repair() -> anyhow::Error {
    anyhow::anyhow!(
        "documents were deleted from the search index while this display-name repair was in \
         flight; the repair stopped rather than re-add documents a delete had purged. Documents \
         repaired before it stopped keep their corrected names and the rest are unchanged; \
         re-run the repair once the deletion has completed"
    )
}

/// Hand one batch of replacements to the writer thread and wait for it to land.
/// Waiting is the point: the next batch reuses the memory this one held, and a
/// failure must stop the pass rather than pile more work behind it.
///
/// `purges_at_start` is the purge counter the repair read before it opened its
/// searcher. It travels with the batch rather than being checked here because
/// only the writer thread can compare it at the moment that matters; see
/// [`writer_loop`].
fn send_replace_batch(
    tx: &SyncSender<IndexCommand>,
    docs: Vec<(Uuid, TantivyDocument)>,
    purges_at_start: u64,
) -> Result<()> {
    if docs.is_empty() {
        return Ok(());
    }
    let (resp_tx, resp_rx) = std::sync::mpsc::channel();
    tx.send(IndexCommand::ReplaceDocuments(
        docs,
        purges_at_start,
        resp_tx,
    ))
    .map_err(|_| anyhow::anyhow!("search index writer thread is gone"))?;
    resp_rx
        .recv()
        .map_err(|_| anyhow::anyhow!("search index writer dropped the response"))?
}

/// Fold any fire-and-forget add/commit failures accumulated since the last
/// checkpoint into the result of an explicit `commit()`. A dropped
/// `add_document` (the enqueue already returned `Ok`) means those documents
/// never became searchable, so a syntactically-successful commit must still be
/// reported as an error at the next observable checkpoint — otherwise ingest
/// looks complete while case search is silently missing keywords (BUG-161).
fn commit_result_with_failures(
    committed: Result<()>,
    dropped: usize,
    failed_commits: usize,
) -> Result<()> {
    match committed {
        // A dropped document never became searchable and no later commit can
        // recover it: the index is short, and this must be reported.
        Ok(()) if dropped > 0 => Err(anyhow::anyhow!(
            "search index dropped {} document(s) since last commit; index is incomplete",
            dropped
        )),
        // A commit that failed and then succeeded lost nothing. Reporting it as
        // dropped documents (B8-044) claimed the index was short when it was
        // whole, which is its own false statement about the evidence.
        Ok(()) if failed_commits > 0 => {
            warn!(
                "search index recovered after {} failed commit(s); no documents were lost",
                failed_commits
            );
            Ok(())
        }
        other => other,
    }
}

/// Replace a batch of documents with rebuilt versions of themselves, atomically.
///
/// Every document this touches is deleted and re-added inside ONE commit, and
/// the delete is keyed on the artifact id rather than the case, which is what
/// makes the per-case display-name repair survivable:
///
/// * A crash, a kill, or an error between two batches leaves the batches that
///   committed repaired and the rest stale. Nothing is ever missing, so an
///   interrupted repair costs an examiner accuracy in a name column, never a
///   search hit. Deleting the case's documents first and re-adding them
///   afterwards — the shape `rebuild_index` invites — has a window in which the
///   case has no documents at all, and a search run in that window returns
///   "nothing matches" for evidence that is right there.
/// * Documents an ingest adds to the same case while the repair is running were
///   never in the batch and so are never deleted. A case-wide delete would take
///   them and not put them back.
///
/// A failed `add_document` is the one case that could still lose a document,
/// because its original is already staged for deletion in this same uncommitted
/// batch. The whole batch is rolled back instead, which is safe here and only
/// here: the writer thread processes one command at a time, and the flush below
/// means the only uncommitted operations at that moment are this batch's own.
fn replace_documents(
    writer: &mut IndexWriter,
    fields: &DocFields,
    docs: Vec<(Uuid, TantivyDocument)>,
    since_commit: &mut usize,
) -> Result<()> {
    if docs.is_empty() {
        return Ok(());
    }

    // Flush anything ingest left in the writer's buffer before staging work we
    // may have to roll back. `rollback` discards every uncommitted operation,
    // and we may only ever discard our own.
    if *since_commit > 0 {
        writer
            .commit()
            .context("failed to flush pending documents before a display-name repair")?;
        *since_commit = 0;
    }

    // Counted before the loop consumes `docs`, because a failed commit has to
    // hand these back to the retry path; see the `match` below.
    let staged = docs.len();

    for (id, _) in &docs {
        writer.delete_term(tantivy::Term::from_field_text(fields.id, &id.to_string()));
    }

    for (id, doc) in docs {
        if let Err(e) = writer.add_document(doc) {
            error!(
                "search index: rebuilt document for artifact {} could not be added ({}); rolling the batch back",
                id, e
            );
            // Report the rollback's own failure if it comes to that: it means
            // the batch's deletes are still staged and the next commit would
            // make them durable, which the caller has to know.
            writer.rollback().context(format!(
                "failed to roll back a display-name repair batch after artifact {} could not be re-added",
                id
            ))?;
            return Err(anyhow::anyhow!(
                "search index rejected the rebuilt document for artifact {}: {}; \
                 the batch was rolled back and those documents are unchanged",
                id,
                e
            ));
        }
    }

    // `since_commit` is zeroed only on success, for the same reason the `Add`
    // arm of `writer_loop` zeroes it only on success (B8-044): the idle flush
    // and the final flush on disconnect both fire only while the counter is
    // non-zero, so zeroing it after a FAILED commit strands this batch's
    // documents in the writer with nothing left that would ever retry them.
    // Restoring the count instead means the very next idle tick tries again.
    match writer.commit() {
        Ok(_) => {
            *since_commit = 0;
            Ok(())
        }
        Err(e) => {
            *since_commit = staged;
            Err(anyhow::Error::new(e).context("failed to commit a display-name repair batch"))
        }
    }
}

/// A window deliberately opened in the middle of pin acquisition, so that a
/// test can land a whole purge inside it.
///
/// A pin is made of two observations — the index snapshot and the purge counter
/// — and the hazard is a purge that commits *and* increments the counter between
/// them. In production that window is the width of `index_snapshot`: real, but
/// far too narrow to hit on demand, which is why the defect it caused survived
/// review. Without a way to widen it, a test can assert the invariant but cannot
/// demonstrate that the ordering is what upholds it.
///
/// Deliberately defined by POSITION — between the two observations — and not by
/// which observation comes first, so the same test judges either ordering.
///
/// Zero unless a test sets it, and compiled out of a normal build. It is a
/// process-wide static, so a test that sets it may slow another test's pin; it
/// cannot change what that pin observes.
#[cfg(test)]
static PIN_ACQUIRE_WINDOW_MS: AtomicU64 = AtomicU64::new(0);

#[cfg(test)]
fn pin_acquire_window() {
    let ms = PIN_ACQUIRE_WINDOW_MS.load(Ordering::SeqCst);
    if ms > 0 {
        std::thread::sleep(Duration::from_millis(ms));
    }
}

#[cfg(not(test))]
#[inline(always)]
fn pin_acquire_window() {}

/// Record that a command has removed documents from the index.
///
/// Called AFTER the delete's commit has been attempted, never before, and that
/// ordering is the whole point. A repair reads this counter and only then opens
/// its reader, so a purge already counted is a purge whose commit is already
/// durable and which the repair's searcher therefore already reflects. Counting
/// the purge first would open a window in which a repair reads the new value,
/// opens a reader that still shows the doomed documents, and — its value
/// matching — is allowed to put them back.
///
/// The count is bumped even when the commit returned an error: the deletes are
/// still staged in the writer and the next commit will make them durable, so a
/// repair working from a snapshot that predates them must still stop.
fn count_purge(purges: &AtomicU64) {
    purges.fetch_add(1, Ordering::SeqCst);
}

/// The reaper: the thread that turns the pin's release rules into a bound.
///
/// Two things it does that no other code path can. A purge has to release the
/// segment files holding the purged documents WHETHER OR NOT anyone asks that
/// pin for another page — an export whose client has walked away would otherwise
/// keep destroyed evidence mapped for the life of the process. And a client that
/// takes the response headers and then stops reading never drops its body, so
/// nothing else ever runs `Drop`.
///
/// It holds `Weak`s, so it can never keep a snapshot alive, and it prunes what
/// it can no longer upgrade. It waits rather than polls while nothing is pinned,
/// which is the state of almost every server almost all of the time.
fn pin_reaper_loop(registry: Arc<(std::sync::Mutex<PinRegistry>, std::sync::Condvar)>) {
    /// How long to sleep when there is nothing pinned. Woken early by
    /// `pin_searcher_with_idle_limit` and by the service's `Drop`, so the figure
    /// only bounds how long a shutdown could go unnoticed if both notifications
    /// were somehow missed.
    const IDLE_WAIT: Duration = Duration::from_secs(3600);

    let (lock, cvar) = &*registry;
    let mut guard = lock.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if guard.shutdown {
            return;
        }
        guard.pins.retain(|weak| match weak.upgrade() {
            Some(inner) => {
                inner.reap();
                true
            }
            // The export finished or was abandoned; its pin is already gone.
            None => false,
        });
        let wait = if guard.pins.is_empty() {
            IDLE_WAIT
        } else {
            PIN_REAP_INTERVAL
        };
        let (next, _) = cvar
            .wait_timeout(guard, wait)
            .unwrap_or_else(|e| e.into_inner());
        guard = next;
    }
}

/// Rewrite every segment that holds deleted documents, then collect the files
/// the rewrite orphaned.
///
/// A tantivy delete is a mark: the document stops answering queries, and its
/// text stays in the segment file until something merges that segment away.
/// For a case purge that is not good enough. Deleting a case is how an examiner
/// removes an exhibit from a workspace, and the names, paths, message bodies —
/// and, by the decision recorded as `SEC-004`, recovered credential values — of
/// a case deleted hours earlier were still readable with `grep` in
/// `workspace/search_index` (HUNT-092).
///
/// Neither step is allowed to fail the purge: the documents are already gone
/// from every query either way, and a purge that reported failure because a
/// merge could not run would be resumed from the beginning. Both are logged.
///
/// A case purge and a rebuild call this immediately: they are one deliberate
/// act over a whole case, and the examiner is waiting on it. The per-artifact
/// delete paths do not — rewriting every segment holding a delete costs the
/// whole index, which is proportionate to removing a case and not to removing
/// one file from one — so they mark the index as owing a rewrite and it is done
/// from the writer's idle tick, at most once per [`EXPUNGE_IDLE_INTERVAL`]
/// (HUNT-093). A burst of deletes therefore pays for one rewrite rather than
/// one per file, and no deleted artifact's text stays readable on disk beyond
/// the next quiet moment.
fn expunge_deleted_documents(writer: &mut IndexWriter) {
    let index = writer.index().clone();
    let segments_with_deletes = || -> Vec<tantivy::index::SegmentId> {
        match index.searchable_segment_metas() {
            Ok(metas) => metas
                .iter()
                .filter(|m| m.num_deleted_docs() > 0)
                .map(|m| m.id())
                .collect(),
            Err(e) => {
                warn!("search index: could not list segments to expunge deletes: {e}");
                Vec::new()
            }
        }
    };
    // Tantivy's own background merges, started by the commits that built the
    // index, may still be running: they refuse a merge of the same segments, and
    // the segment they produce can still carry documents deleted after they
    // started. So the rewrite is repeated against a fresh listing until no
    // segment holds a deleted document, bounded.
    let left = rewrite_until_no_deletes(
        segments_with_deletes,
        |ids| {
            info!(
                "search index: rewriting {} segment(s) to drop deleted documents",
                ids.len()
            );
            writer.merge(ids).wait().map(|_| ())
        },
        EXPUNGE_MERGE_ATTEMPTS,
        EXPUNGE_GC_PAUSE,
    );
    if left > 0 {
        warn!(
            "search index: {left} segment(s) still held deleted documents after {} \
             rewrite attempts; their text may remain readable until the next pass",
            EXPUNGE_MERGE_ATTEMPTS
        );
    }

    // Collection can run while the merge that orphaned the old files still
    // protects them, collect nothing, and leave the deleted text on disk until
    // some later pass. Repeat it, bounded, until nothing is orphaned.
    let left = collect_until_clean(
        || {
            if let Err(e) = writer.garbage_collect_files().wait() {
                warn!("search index: collecting orphaned segment files failed: {e}");
            }
        },
        || orphaned_segment_files(&index),
        EXPUNGE_GC_ATTEMPTS,
        EXPUNGE_GC_PAUSE,
    );
    if left > 0 {
        warn!(
            "search index: {left} orphaned segment file(s) were still on disk after {} \
             collection attempts; the text of deleted documents may remain readable until \
             the next pass",
            EXPUNGE_GC_ATTEMPTS
        );
    }
}

/// How many times a purge repeats the segment rewrite before reporting what is left.
const EXPUNGE_MERGE_ATTEMPTS: usize = 40;

/// Merge the segments `listing` reports as holding deleted documents, again with
/// a fresh listing after each refusal, until none does or `attempts` is spent;
/// returns how many segments still held deleted documents at the end.
fn rewrite_until_no_deletes<Id: Copy, E: std::fmt::Display>(
    listing: impl Fn() -> Vec<Id>,
    mut merge: impl FnMut(&[Id]) -> Result<(), E>,
    attempts: usize,
    pause: Duration,
) -> usize {
    let mut left = 0;
    for attempt in 0..attempts {
        let ids = listing();
        left = ids.len();
        if ids.is_empty() {
            break;
        }
        match merge(&ids) {
            Ok(()) => {}
            Err(e) => warn!("search index: merging segments with deletes failed: {e}"),
        }
        if attempt + 1 < attempts && !pause.is_zero() {
            std::thread::sleep(pause);
        }
    }
    if left > 0 {
        left = listing().len();
    }
    left
}

/// How many times a purge repeats file collection before reporting what is left.
const EXPUNGE_GC_ATTEMPTS: usize = 40;

/// The pause between collection attempts: long enough for the segment updater to
/// release the merge's protection, short enough that a purge stays prompt.
const EXPUNGE_GC_PAUSE: Duration = Duration::from_millis(25);

/// Run `collect`, then again while `leftover()` still reports orphaned files, up
/// to `attempts` times; returns how many were left at the end.
fn collect_until_clean(
    mut collect: impl FnMut(),
    leftover: impl Fn() -> usize,
    attempts: usize,
    pause: Duration,
) -> usize {
    let mut left = 0;
    for attempt in 0..attempts {
        collect();
        left = leftover();
        if left == 0 {
            break;
        }
        if attempt + 1 < attempts && !pause.is_zero() {
            std::thread::sleep(pause);
        }
    }
    left
}

/// Segment files on disk whose segment is no longer searchable: what a merge or
/// a purge has orphaned and collection has not yet removed.
///
/// Files are named `<segment id>.<extension>`; anything whose stem is not a
/// segment id (`meta.json`, the lock files) is not a segment file.
fn orphaned_segment_files(index: &Index) -> usize {
    let Ok(metas) = index.searchable_segment_metas() else {
        return 0;
    };
    let live: std::collections::HashSet<String> =
        metas.iter().map(|m| m.id().uuid_string()).collect();
    let files = index.directory().list_managed_files();
    files
        .iter()
        .filter_map(|f| f.file_stem().and_then(|s| s.to_str()))
        .filter(|stem| stem.len() == 32 && stem.bytes().all(|b| b.is_ascii_hexdigit()))
        .filter(|stem| !live.contains(*stem))
        .count()
}

/// The writer's heap budget. Named here because the revive path has to open the
/// replacement with the same budget the service opened the original with.
const WRITER_HEAP_BYTES: usize = 50_000_000;

/// How many documents may wait for the writer thread before a producer blocks.
///
/// The command channel was unbounded, and the writer is one thread indexing
/// what every worker produces: on a walk of 40,000 small files the workers ran
/// ahead by well over a hundred thousand documents, each carrying up to 16 MB
/// of content, and the process grew to 12 GB resident until the writer caught
/// up minutes after the walk had finished (HUNT-114). A producer that has to
/// wait for the writer is the correct shape — indexing is part of processing,
/// not something processing may outrun without bound. The writer never waits
/// on a producer, so a full channel cannot deadlock.
const COMMAND_QUEUE_DOCUMENTS: usize = 512;

/// How long the writer must have been idle before it rewrites the segments that
/// per-artifact deletes left text in. Long enough that a burst of deletes with
/// brief gaps cannot turn into a rewrite per gap; short enough that deleted
/// evidence does not sit readable on disk for a working session (HUNT-093).
const EXPUNGE_IDLE_INTERVAL: Duration = Duration::from_secs(30);

/// How long to wait between attempts to replace a writer tantivy killed. The
/// idle tick is 500 ms, and the usual cause is a full disk: retrying that fast
/// only grows the log.
const WRITER_REVIVE_BACKOFF: Duration = Duration::from_secs(5);

/// Did this failure mean the writer itself is gone rather than this one
/// operation having failed?
///
/// Tantivy kills the writer when an indexing worker thread dies — an
/// `io::Error` on a full disk is the ordinary way — and every later call on it
/// returns the same error for the life of the process. Matched on the message
/// because the error reaches the call sites in three shapes (`TantivyError`,
/// an `anyhow` chain, and a `Result` built by a helper), and all three carry
/// tantivy's own sentence.
fn writer_was_killed(e: &impl std::fmt::Display) -> bool {
    e.to_string().contains("index writer was killed")
}

/// Record the outcome of a commit on the writer's retry bookkeeping.
///
/// Success clears it. A FAILED commit leaves what it staged — adds or deletes —
/// uncommitted in the writer, so the counter must stay non-zero: the idle flush
/// fires only while it is, and zeroing it here stranded the staged work with
/// nothing to retry it (B8-044). That matters most for a delete, whose
/// artifact stays searchable until a commit lands.
fn settle_commit(
    committed: &Result<()>,
    since_commit: &mut usize,
    last_commit_failure: &mut Option<Instant>,
) {
    if committed.is_ok() {
        *since_commit = 0;
        *last_commit_failure = None;
    } else {
        *since_commit = (*since_commit).max(1);
        *last_commit_failure = Some(Instant::now());
    }
}

/// Pass a command's result through, noting whether it says the writer died.
fn note_dead(r: Result<()>, dead: &mut bool) -> Result<()> {
    if let Err(e) = &r {
        if writer_was_killed(e) {
            *dead = true;
        }
    }
    r
}

/// The sole owner of the Tantivy `IndexWriter`, and therefore the only place
/// that can decide the order of a delete and a repair batch.
///
/// `purges` counts every command that has REMOVED documents from the index. It
/// is the interlock between a purge and an in-flight display-name repair: the
/// repair reads the counter before it snapshots the index and sends the value
/// back with each batch, and a batch whose value is stale is refused rather
/// than applied. See [`purge_overtook_repair`] for why that direction is the
/// safe one.
///
/// The counter is deliberately global rather than per case. `DeleteArtifact`
/// and `DeleteArtifacts` name artifacts, not cases, so the writer cannot tell
/// whose documents they took; and stopping a repair that is re-runnable costs
/// an examiner a stale name column for a while, where re-adding a document some
/// delete removed costs the case its purge.
///
/// All mutations funnel through the
/// command channel, so ingest workers never touch the writer (no shared lock)
/// and commits (a 50MB flush + fsync) happen here, never on a worker.
fn writer_loop(
    index: Index,
    writer: IndexWriter,
    rx: std::sync::mpsc::Receiver<IndexCommand>,
    fields: DocFields,
    failures: Arc<std::sync::atomic::AtomicUsize>,
    commit_failures: Arc<std::sync::atomic::AtomicUsize>,
    purges: Arc<AtomicU64>,
) {
    // Commit every 1000 adds, and also flush on a short idle timeout so recently
    // indexed docs become searchable without waiting for an explicit commit.
    const COMMIT_EVERY: usize = 1000;
    /// How long to wait before retrying a commit that failed. The idle tick is
    /// 500ms; retrying that fast against a full disk only grows the log.
    const COMMIT_RETRY_BACKOFF: Duration = Duration::from_secs(5);
    let mut since_commit = 0usize;
    let mut last_commit_failure: Option<Instant> = None;
    // A killed writer used to stay dead for the life of the process: every
    // later add failed, ingest carried on writing the database, and the only
    // way to index anything again was a restart that discarded the in-flight
    // ingest (HUNT-075). The writer is held in a slot so it can be dropped —
    // which is what releases the index lock — and replaced.
    // Per-artifact deletes leave their text in the segment files exactly as a
    // case purge did, and rewriting every segment on each one would cost the
    // whole index per file. The rewrite is deferred to an idle moment instead
    // (HUNT-093).
    let mut deletes_awaiting_expunge = false;
    let mut last_expunge: Option<Instant> = None;
    let mut writer_slot = Some(writer);
    let mut last_revive: Option<Instant> = None;
    let mut lost_while_dead = 0usize;

    loop {
        if writer_slot.is_none()
            && last_revive.is_none_or(|at| at.elapsed() >= WRITER_REVIVE_BACKOFF)
        {
            last_revive = Some(Instant::now());
            match index.writer(WRITER_HEAP_BYTES) {
                Ok(replacement) => {
                    // The count is the point of the message: the documents lost
                    // between the death and here are not in the index and no
                    // error will be raised about them again. `index_incomplete`
                    // still says so on every search of the case, and the
                    // backfill is what repairs it.
                    warn!(
                        "search index writer was killed and has been replaced; {} document(s) \
                         were lost while it was dead and are NOT in the index — run the \
                         search backfill for the affected case(s) to repair it",
                        lost_while_dead
                    );
                    writer_slot = Some(replacement);
                    lost_while_dead = 0;
                }
                Err(e) => warn!(
                    "search index writer was killed and could not be replaced (retrying in {}s): \
                     {}",
                    WRITER_REVIVE_BACKOFF.as_secs(),
                    e
                ),
            }
        }

        let next = rx.recv_timeout(Duration::from_millis(500));

        // No writer: the commands still have to be answered. A caller left
        // waiting on a responder that never comes would hang; one told the
        // write failed can report it.
        let Some(writer) = writer_slot.as_mut() else {
            match next {
                Ok(command) => {
                    lost_while_dead = refuse_command(command, &failures, lost_while_dead);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            continue;
        };

        let mut dead = false;
        match next {
            Ok(IndexCommand::AddReplacing(doc, artifact_id)) => {
                writer.delete_term(tantivy::Term::from_field_text(fields.id, &artifact_id));
                if let Err(e) = writer.add_document(*doc) {
                    error!("search index add_document (replacing) failed: {}", e);
                    failures.fetch_add(1, Ordering::Relaxed);
                    dead |= writer_was_killed(&e);
                } else {
                    since_commit += 1;
                }
            }
            Ok(IndexCommand::Add(doc)) => {
                if let Err(e) = writer.add_document(*doc) {
                    error!("search index add_document failed: {}", e);
                    failures.fetch_add(1, Ordering::Relaxed);
                    dead |= writer_was_killed(&e);
                } else {
                    since_commit += 1;
                    if since_commit >= COMMIT_EVERY {
                        // `since_commit` is zeroed only on success. Zeroing it
                        // after a FAILED commit left the documents uncommitted
                        // and, because the idle flush below only fires while the
                        // counter is non-zero, nothing ever retried them: with no
                        // further Adds they stayed unsearchable for the life of
                        // the process, and the case reported a complete index
                        // (B8-044).
                        match writer.commit() {
                            Ok(_) => since_commit = 0,
                            Err(e) => {
                                error!("search index commit failed: {}", e);
                                dead |= writer_was_killed(&e);
                                commit_failures.fetch_add(1, Ordering::Relaxed);
                                last_commit_failure = Some(Instant::now());
                            }
                        }
                    }
                }
            }
            Ok(IndexCommand::Commit(resp)) => {
                let committed = writer.commit().map(|_| ()).map_err(anyhow::Error::from);
                settle_commit(&committed, &mut since_commit, &mut last_commit_failure);
                let committed = note_dead(committed, &mut dead);
                let dropped = failures.swap(0, Ordering::Relaxed);
                let failed_commits = commit_failures.swap(0, Ordering::Relaxed);
                let _ = resp.send(commit_result_with_failures(
                    committed,
                    dropped,
                    failed_commits,
                ));
            }
            Ok(IndexCommand::DeleteArtifact(id, resp)) => {
                deletes_awaiting_expunge = true;
                writer.delete_term(tantivy::Term::from_field_text(fields.id, &id.to_string()));
                let r = writer.commit().map(|_| ()).map_err(anyhow::Error::from);
                settle_commit(&r, &mut since_commit, &mut last_commit_failure);
                count_purge(&purges);
                let _ = resp.send(note_dead(r, &mut dead));
            }
            Ok(IndexCommand::DeleteArtifacts(ids, resp)) => {
                // One commit for the whole set (a recursive artifact delete can
                // remove a large subtree; N per-id commits would be N fsyncs).
                deletes_awaiting_expunge = true;
                for id in &ids {
                    writer.delete_term(tantivy::Term::from_field_text(fields.id, &id.to_string()));
                }
                let r = writer.commit().map(|_| ()).map_err(anyhow::Error::from);
                settle_commit(&r, &mut since_commit, &mut last_commit_failure);
                count_purge(&purges);
                let _ = resp.send(note_dead(r, &mut dead));
            }
            Ok(IndexCommand::DeleteCase(id, resp)) => {
                writer.delete_term(tantivy::Term::from_field_text(
                    fields.case_id,
                    &id.to_string(),
                ));
                let r = writer.commit().map(|_| ()).map_err(anyhow::Error::from);
                settle_commit(&r, &mut since_commit, &mut last_commit_failure);
                count_purge(&purges);
                if r.is_ok() {
                    expunge_deleted_documents(writer);
                }
                let _ = resp.send(note_dead(r, &mut dead));
            }
            Ok(IndexCommand::ReplaceDocuments(docs, purges_at_start, resp)) => {
                // The purge interlock, and the only place it can be honest.
                // A repair that tested the counter itself before sending would
                // still lose the race whose consequence matters: its batch can
                // be sitting in this queue BEHIND a delete that has not been
                // processed yet, and applying it afterwards re-adds precisely
                // the documents that delete purged. Tested here, at the moment
                // the batch would be applied, "the delete got there first"
                // always means the batch is refused, and "the batch got there
                // first" always means the delete that follows sweeps it up.
                let r = if purges.load(Ordering::SeqCst) == purges_at_start {
                    replace_documents(writer, &fields, docs, &mut since_commit)
                } else {
                    Err(purge_overtook_repair())
                };
                let _ = resp.send(note_dead(r, &mut dead));
            }
            Ok(IndexCommand::DeleteAll(resp)) => {
                let r = (|| -> Result<()> {
                    writer.delete_all_documents()?;
                    writer.commit()?;
                    Ok(())
                })();
                settle_commit(&r, &mut since_commit, &mut last_commit_failure);
                count_purge(&purges);
                if r.is_ok() {
                    // Every document here is deleted, so this is the cheap case
                    // of the rewrite and the one where leaving text behind would
                    // be least expected: "delete all documents" that leaves them
                    // all readable on disk.
                    expunge_deleted_documents(writer);
                }
                let _ = resp.send(note_dead(r, &mut dead));
            }
            Err(RecvTimeoutError::Timeout) => {
                // Retry a failed flush rather than abandoning it, but not on
                // every 500ms tick: a commit that fails because the disk is full
                // will keep failing, and the log is the only thing that would
                // grow.
                let backing_off =
                    last_commit_failure.is_some_and(|at| at.elapsed() < COMMIT_RETRY_BACKOFF);
                // The writer is idle: this is the moment to give back what the
                // per-artifact deletes only marked. Rate-limited so a long burst
                // of deletes with brief gaps cannot turn into a rewrite per gap.
                if deletes_awaiting_expunge
                    && since_commit == 0
                    && last_expunge.is_none_or(|at| at.elapsed() >= EXPUNGE_IDLE_INTERVAL)
                {
                    deletes_awaiting_expunge = false;
                    last_expunge = Some(Instant::now());
                    expunge_deleted_documents(writer);
                }
                if since_commit > 0 && !backing_off {
                    match writer.commit() {
                        Ok(_) => {
                            since_commit = 0;
                            last_commit_failure = None;
                        }
                        Err(e) => {
                            error!("search index idle-flush commit failed: {}", e);
                            dead |= writer_was_killed(&e);
                            commit_failures.fetch_add(1, Ordering::Relaxed);
                            last_commit_failure = Some(Instant::now());
                        }
                    }
                }
            }
            // All senders dropped (SearchService dropped): final flush and exit.
            Err(RecvTimeoutError::Disconnected) => {
                if since_commit > 0 {
                    let _ = writer.commit();
                }
                break;
            }
        }

        if dead {
            // Dropping it is what releases the index lock, so the replacement
            // opened at the top of the next iteration can take it.
            writer_slot = None;
            last_revive = None;
        }
    }
}

/// Answer a command that arrived while there was no writer to serve it.
///
/// Returns the running count of documents lost while dead. A responder that
/// never receives leaves its caller waiting, and a caller told nothing cannot
/// report that the write did not happen.
fn refuse_command(
    command: IndexCommand,
    failures: &Arc<std::sync::atomic::AtomicUsize>,
    lost_while_dead: usize,
) -> usize {
    fn gone<T>() -> Result<T> {
        Err(anyhow::anyhow!(
            "the search index writer was killed and has not been replaced yet; this write did \
             not happen"
        ))
    }
    match command {
        IndexCommand::Add(_) | IndexCommand::AddReplacing(_, _) => {
            failures.fetch_add(1, Ordering::Relaxed);
            return lost_while_dead.saturating_add(1);
        }
        IndexCommand::Commit(resp)
        | IndexCommand::DeleteArtifact(_, resp)
        | IndexCommand::DeleteArtifacts(_, resp)
        | IndexCommand::DeleteCase(_, resp)
        | IndexCommand::DeleteAll(resp)
        | IndexCommand::ReplaceDocuments(_, _, resp) => {
            let _ = resp.send(gone());
        }
    }
    lost_while_dead
}

pub struct SearchService {
    index: Index,
    /// Enqueues work for the writer thread. `Option` so `Drop` can close the
    /// channel (letting the thread do its final commit) before joining.
    command_tx: Option<SyncSender<IndexCommand>>,
    field_id: Field,
    field_case_id: Field,
    field_artifact_type: Field,
    field_name: Field,
    field_content: Field,
    field_record_kind: Field,
    writer_thread: Option<JoinHandle<()>>,
    /// Count of fire-and-forget add/commit failures the writer thread has hit
    /// since the last explicit commit drained it. Surfaced at commit so ingest
    /// can see the index is incomplete (BUG-161).
    index_failures: Arc<std::sync::atomic::AtomicUsize>,
    /// Set when this process found an index whose schema did not match and
    /// **rebuilt it from empty**.
    ///
    /// Until every case has been re-indexed (`POST /cases/{id}/search/backfill`),
    /// a search over such an index under-reports — and an empty index answers
    /// "no matches" for a case full of evidence, which is a false absence on a
    /// court-facing surface. Every search served by this process therefore
    /// carries the incompleteness marker while this is set. It stays set for
    /// the life of the process: the service cannot know which cases have since
    /// been backfilled, and over-disclosing completeness is the safe
    /// direction.
    rebuilt_from_empty: bool,
    /// How many commands the writer thread has processed that removed documents
    /// from the index. Written only by the writer thread; read by a
    /// display-name repair so a delete cannot be undone by a repair that was
    /// already in flight. See [`writer_loop`].
    purges: Arc<AtomicU64>,
    /// How many [`PinnedSearcher`]s are alive right now.
    ///
    /// Each one holds a snapshot's segment files open, so this is the count
    /// behind the only unbounded-looking cost pinning introduces. Held in an
    /// `Arc` rather than on the service directly because the decrement happens
    /// in the pin's `Drop`, which may run after the request that made it has
    /// gone.
    live_pins: Arc<std::sync::atomic::AtomicUsize>,
    /// Live pins, weakly held, and the reaper's wakeup.
    ///
    /// The reaper is what turns "a pin is released when its holder drops it"
    /// into a bound: a purge has to release the segment files holding the
    /// purged documents whether or not anyone asks this pin for another page,
    /// and a client that stopped reading never drops anything at all.
    pin_registry: Arc<(std::sync::Mutex<PinRegistry>, std::sync::Condvar)>,
    /// Joined on drop so the reaper does not outlive the service.
    reaper_thread: Option<std::thread::JoinHandle<()>>,
    /// Which text extractor version built each case's file documents
    /// (`SEARCH-002`). The search-universe statement is only the index's own
    /// when the case's documents were built by this build's extractor, and
    /// nothing else in the index says which one did.
    extractor_record: std::sync::Mutex<ExtractorRecord>,
    /// Where [`Self::extractor_record`] is kept: [`TEXT_EXTRACTOR_RECORD_FILE`]
    /// in the index directory.
    extractor_record_path: std::path::PathBuf,
}

/// The on-disk record behind [`SearchService::text_extractor_provenance`].
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct ExtractorRecord {
    #[serde(default)]
    cases: std::collections::BTreeMap<String, CaseExtractorRecord>,
}

/// One case's entry in the [`ExtractorRecord`].
#[derive(Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
struct CaseExtractorRecord {
    /// Every text extractor version that has indexed a file document of the
    /// case since versions were recorded.
    versions: std::collections::BTreeSet<u32>,
    /// Whether the index already held file documents for the case when the
    /// first version was recorded — documents a build that recorded nothing
    /// made, whose extractor is unknown and older than this one.
    #[serde(default)]
    earlier_file_documents: bool,
}

/// Read the extractor record, or start an empty one.
///
/// An unreadable or corrupt record is logged and treated as absent. That is
/// the safe direction: a case with file documents and no entry is reported as
/// indexed by an earlier extractor, never as current.
fn load_extractor_record(path: &Path) -> ExtractorRecord {
    match std::fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            warn!(
                "search index: text extractor record {:?} is unreadable ({}); every case \
                 with file documents will be reported as indexed by an earlier extractor",
                path, e
            );
            ExtractorRecord::default()
        }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => ExtractorRecord::default(),
        Err(e) => {
            warn!(
                "search index: cannot read text extractor record {:?} ({}); every case with \
                 file documents will be reported as indexed by an earlier extractor",
                path, e
            );
            ExtractorRecord::default()
        }
    }
}

impl Drop for SearchService {
    fn drop(&mut self) {
        // Close the channel so the writer thread performs its final commit and
        // exits, then join so that commit completes before we return.
        drop(self.command_tx.take());
        if let Some(handle) = self.writer_thread.take() {
            let _ = handle.join();
        }
        // Wake the reaper rather than waiting out its next tick: a service is
        // dropped once per test, and a quarter-second each would be minutes.
        {
            let (lock, cvar) = &*self.pin_registry;
            let mut registry = lock.lock().unwrap_or_else(|e| e.into_inner());
            registry.shutdown = true;
            cvar.notify_all();
        }
        if let Some(handle) = self.reaper_thread.take() {
            let _ = handle.join();
        }
    }
}

impl SearchService {
    pub fn new(index_dir: &Path) -> Result<Self> {
        // Ensure index directory exists
        std::fs::create_dir_all(index_dir)
            .context(format!("Failed to create index directory: {:?}", index_dir))?;

        let mut schema_builder = Schema::builder();
        let field_id = schema_builder.add_text_field("id", STRING | STORED);
        let field_case_id = schema_builder.add_text_field("case_id", STRING | STORED);
        let field_artifact_type = schema_builder.add_text_field("artifact_type", STRING | STORED);
        let field_name = schema_builder.add_text_field("name", TEXT | STORED);
        let field_content = schema_builder.add_text_field("content", TEXT | STORED);
        // The record kind: a parsed record's own `type` discriminator, falling
        // back to the artifact type. Stored so the pivot (§1.0) can group hits
        // by kind from the index alone, instead of taking every hit id back to
        // the database to ask what each one was — which is a chunked
        // `id IN (...)` round trip per pivot, on the interaction an examiner
        // makes most.
        let field_record_kind = schema_builder.add_text_field("record_kind", STRING | STORED);
        let schema = schema_builder.build();

        let directory = MmapDirectory::open(index_dir)
            .context(format!("Failed to open mmap directory at {:?}", index_dir))?;

        // Set by the schema-mismatch arm below. A rebuilt index starts empty,
        // and an empty index answers "no matches" — so every search this
        // process serves has to say so until the cases are backfilled.
        let mut rebuilt_from_empty = false;
        let index = match Index::open_or_create(directory, schema.clone()) {
            Ok(idx) => idx,
            // Only auto-recover from a schema mismatch. Any other error
            // (corruption, permissions, IO) must propagate: wiping the index
            // directory would destroy the search data for every case.
            Err(tantivy::TantivyError::SchemaError(msg)) => {
                warn!(
                    "Search index schema mismatch at {:?} ({}), rebuilding index from empty. \
                     Every case must be re-indexed (POST /cases/{{id}}/search/backfill) before \
                     a search over it is complete; until then every search this process serves \
                     is marked incomplete.",
                    index_dir, msg
                );
                rebuilt_from_empty = true;
                std::fs::remove_dir_all(index_dir)
                    .context(format!("Failed to remove stale index at {:?}", index_dir))?;
                std::fs::create_dir_all(index_dir).context(format!(
                    "Failed to recreate index directory: {:?}",
                    index_dir
                ))?;
                let directory = MmapDirectory::open(index_dir).context(format!(
                    "Failed to reopen mmap directory at {:?}",
                    index_dir
                ))?;
                Index::open_or_create(directory, schema.clone()).context(format!(
                    "Failed to create fresh Tantivy index at {:?}",
                    index_dir
                ))?
            }
            Err(e) => {
                return Err(anyhow::Error::new(e)
                    .context(format!("Failed to open Tantivy index at {:?}", index_dir)));
            }
        };

        let index_writer = index
            .writer(WRITER_HEAP_BYTES)
            .context("Failed to create Tantivy index writer")?;
        // The writer thread keeps its own handle so it can replace a writer
        // tantivy killed (HUNT-075).
        let writer_index = index.clone();

        let fields = DocFields {
            id: field_id,
            case_id: field_case_id,
            artifact_type: field_artifact_type,
            name: field_name,
            content: field_content,
            record_kind: field_record_kind,
        };
        let (command_tx, command_rx) = std::sync::mpsc::sync_channel(COMMAND_QUEUE_DOCUMENTS);
        let index_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_failures = index_failures.clone();
        // Counted apart from dropped documents: a commit that failed and was
        // retried lost nothing, and must not be reported as a short index.
        let commit_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let writer_commit_failures = commit_failures.clone();
        let purges = Arc::new(AtomicU64::new(0));
        let writer_purges = purges.clone();
        let writer_thread = std::thread::Builder::new()
            .name("seance-search-indexer".to_string())
            .spawn(move || {
                writer_loop(
                    writer_index,
                    index_writer,
                    command_rx,
                    fields,
                    writer_failures,
                    writer_commit_failures,
                    writer_purges,
                )
            })
            .context("Failed to spawn search index writer thread")?;

        let pin_registry = Arc::new((
            std::sync::Mutex::new(PinRegistry {
                pins: Vec::new(),
                shutdown: false,
            }),
            std::sync::Condvar::new(),
        ));
        let reaper_registry = pin_registry.clone();
        let reaper_thread = std::thread::Builder::new()
            .name("seance-search-pin-reaper".to_string())
            .spawn(move || pin_reaper_loop(reaper_registry))
            .context("Failed to spawn search pin reaper thread")?;

        Ok(Self {
            index,
            command_tx: Some(command_tx),
            field_id,
            field_case_id,
            field_artifact_type,
            field_name,
            field_content,
            field_record_kind,
            writer_thread: Some(writer_thread),
            index_failures,
            rebuilt_from_empty,
            purges,
            live_pins: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            pin_registry,
            reaper_thread: Some(reaper_thread),
            // Loaded after the schema check: a rebuilt-from-empty index took
            // its record with it, so this reads as empty exactly when the
            // documents are gone too.
            extractor_record: std::sync::Mutex::new(load_extractor_record(
                &index_dir.join(TEXT_EXTRACTOR_RECORD_FILE),
            )),
            extractor_record_path: index_dir.join(TEXT_EXTRACTOR_RECORD_FILE),
        })
    }

    /// Hold the index as it stands right now, for the life of one walk.
    ///
    /// The caller passes the returned [`PinnedSearcher`] to
    /// [`Self::search_after_pinned`] for every page of that walk, and drops it
    /// when the walk ends — including when it ends by being abandoned. See
    /// [`PinnedSearcher`] for what holding it costs, why an export takes that
    /// trade while interactive paging does not, and why a purge revokes it.
    pub fn pin_searcher(&self) -> Result<PinnedSearcher> {
        self.pin_searcher_with_idle_limit(PIN_IDLE_LIMIT)
    }

    /// [`Self::pin_searcher`] with an explicit idle bound.
    ///
    /// Public because the bound is a policy a caller may legitimately need to
    /// state — and because a bound measured in minutes cannot otherwise be
    /// tested at all, and an untested bound is a comment rather than a
    /// guarantee. `PIN_IDLE_LIMIT` is the figure the product uses.
    pub fn pin_searcher_with_idle_limit(&self, idle_limit: Duration) -> Result<PinnedSearcher> {
        // Read the purge counter BEFORE the searcher, and never after.
        //
        // The two reads are not interchangeable, and getting this backwards is
        // the one ordering that can put destroyed evidence into an exhibit.
        // `count_purge` bumps the counter AFTER the purge's commit, so a purge
        // occupies a window: commit at `c`, increment at `i`, with `c < i`. A
        // snapshot taken at `s` still contains the purged documents exactly when
        // `s < c`.
        //
        // Reading after the searcher (`s < r`) admits `s < c < i < r`: the whole
        // purge lands inside the acquisition, so `purges_at_pin` already counts
        // it, the counter never moves again, and the pin is never revoked —
        // while its snapshot still holds every document that purge destroyed.
        // `index_snapshot` walks the segment readers, so that window is real
        // work, not an instant.
        //
        // Reading first (`r < s`) cannot fail that way: if the snapshot is stale
        // (`s < c`) then `r < s < c < i`, the increment necessarily lands after
        // the value this pin recorded, and the next use revokes. The cost is the
        // mirror-image case — a purge landing between the read and the searcher
        // revokes a pin whose snapshot was in fact already clean. That is a walk
        // restarted needlessly, which is the correct direction to be wrong in.
        let purges_at_pin = self.purges.load(Ordering::SeqCst);
        pin_acquire_window();
        let reader = self.index.reader().context("Failed to get index reader")?;
        let searcher = reader.searcher();
        let snapshot = index_snapshot(&searcher);
        let inner = Arc::new(PinnedInner {
            state: std::sync::Mutex::new(PinState::Live(searcher)),
            snapshot,
            last_used: std::sync::Mutex::new(Instant::now()),
            idle_limit,
            purges_at_pin,
            purges: self.purges.clone(),
        });
        {
            let (lock, cvar) = &*self.pin_registry;
            let mut registry = lock.lock().unwrap_or_else(|e| e.into_inner());
            registry.pins.push(Arc::downgrade(&inner));
            // The reaper sleeps indefinitely while nothing is pinned; this is
            // what starts it working again.
            cvar.notify_all();
        }
        // Counted before the value exists, so the count can never be lower than
        // the number of pins actually holding files.
        self.live_pins.fetch_add(1, Ordering::Relaxed);
        Ok(PinnedSearcher {
            inner,
            live: self.live_pins.clone(),
        })
    }

    /// How many pinned searchers are alive on this service right now.
    ///
    /// The disk a pin holds open is invisible in the index directory once a
    /// merge has unlinked the superseded files, so this counter is how it is
    /// accounted for: zero means nothing is being held, and a figure that does
    /// not return to zero after exports finish is a leak, not load.
    ///
    /// There is no metrics endpoint on this server to publish it through, so
    /// citing it as an operator's mitigation on its own would be citing
    /// something an operator cannot reach. What they can reach is the log: the
    /// export handler emits this count when a pin is taken and when it is
    /// released, and warns once several are held at once.
    pub fn live_pinned_searchers(&self) -> usize {
        self.live_pins.load(Ordering::Relaxed)
    }

    /// Number of documents the writer thread has failed to add/commit since the
    /// last explicit commit drained the counter. Non-zero means case search is
    /// currently missing keywords for those artifacts (BUG-161); the next
    /// `commit()` reports and resets it.
    pub fn pending_index_failures(&self) -> usize {
        self.index_failures
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Reference to the command channel, or an error if the service is shutting
    /// down (channel taken by Drop).
    fn commands(&self) -> Result<&SyncSender<IndexCommand>> {
        self.command_tx
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("search index writer has shut down"))
    }

    fn doc_fields(&self) -> DocFields {
        DocFields {
            id: self.field_id,
            case_id: self.field_case_id,
            artifact_type: self.field_artifact_type,
            name: self.field_name,
            content: self.field_content,
            record_kind: self.field_record_kind,
        }
    }

    /// Send a command whose completion the caller waits on, off the async
    /// runtime. Used by commit/delete so the caller can observe durability.
    async fn command_and_wait(
        &self,
        make: impl FnOnce(CmdSender<Result<()>>) -> IndexCommand,
    ) -> Result<()> {
        let tx = self.commands()?.clone();
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        let cmd = make(resp_tx);
        tokio::task::spawn_blocking(move || {
            tx.send(cmd)
                .map_err(|_| anyhow::anyhow!("search index writer thread is gone"))?;
            resp_rx
                .recv()
                .map_err(|_| anyhow::anyhow!("search index writer dropped the response"))?
        })
        .await
        .context("search index command task panicked")?
    }

    /// Build the document (metadata serialize + bounded content read, in
    /// parallel on the caller) and enqueue it. Returns as soon as it is
    /// enqueued; the writer thread adds it. Because the channel is FIFO, anything
    /// enqueued before a later `commit()` is included in that commit.
    pub fn add_artifact_to_index_sync(&self, artifact: &Artifact) -> Result<()> {
        self.enqueue_document(artifact, |doc| IndexCommand::Add(Box::new(doc)))
    }

    /// Async wrapper around [`Self::add_artifact_to_index_sync`].
    pub async fn add_artifact_to_index(&self, artifact: &Artifact) -> Result<()> {
        self.add_artifact_to_index_sync(artifact)
    }

    /// Index an artifact, replacing any document already carrying its id.
    ///
    /// For a caller that decided what to index from a committed view of the
    /// index and cannot rule out a concurrent writer — the backfill
    /// (`LIVE-028`), which exists precisely for cases whose ingest is in doubt
    /// and may well be running. [`Self::add_artifact_to_index_sync`] appends,
    /// so in that situation it can leave two documents for one artifact.
    pub fn add_artifact_replacing_sync(&self, artifact: &Artifact) -> Result<()> {
        let id = artifact.id.to_string();
        self.enqueue_document(artifact, |doc| {
            IndexCommand::AddReplacing(Box::new(doc), id)
        })
    }

    /// Build the artifact's document and put `command(doc)` on the writer's
    /// channel.
    ///
    /// A failure at either step means the artifact never reached the writer, so
    /// it is not in the index. It is counted here, with the writer's own drops,
    /// so [`Self::pending_index_failures`] and `index_incomplete` say so; the
    /// caller also gets the error, but a caller that only logs it (the ingest
    /// indexer does) must not leave the searches claiming the index is whole.
    fn enqueue_document(
        &self,
        artifact: &Artifact,
        command: impl FnOnce(TantivyDocument) -> IndexCommand,
    ) -> Result<()> {
        let queued = build_doc(artifact, &self.doc_fields()).and_then(|doc| {
            self.note_text_extractor(artifact);
            self.commands()?
                .send(command(doc))
                .map_err(|_| anyhow::anyhow!("search index writer thread is gone"))
        });
        if queued.is_err() {
            self.index_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        queued
    }

    /// Commit synchronously (blocks the calling thread). Prefer `commit()` from
    /// async code. Waits for the writer thread to drain everything enqueued
    /// before this call and commit it.
    pub fn commit_sync(&self) -> Result<()> {
        let (resp_tx, resp_rx) = std::sync::mpsc::channel();
        self.commands()?
            .send(IndexCommand::Commit(resp_tx))
            .map_err(|_| anyhow::anyhow!("search index writer thread is gone"))?;
        resp_rx
            .recv()
            .map_err(|_| anyhow::anyhow!("search index writer dropped the response"))?
    }

    pub async fn commit(&self) -> Result<()> {
        self.command_and_wait(IndexCommand::Commit).await
    }

    /// Which text extractor built this case's file documents (`SEARCH-002`).
    ///
    /// * A recorded case is [`IndexTextExtractor::Current`] unless an older
    ///   version is recorded for it, or the index already held file documents
    ///   for it when this build first recorded one — then
    ///   [`IndexTextExtractor::Earlier`]. Adding evidence on this build does not
    ///   make a case's older documents current.
    /// * A case with no record and file documents in the index was indexed by
    ///   a build that recorded nothing: every build before this one, so
    ///   [`IndexTextExtractor::Earlier`].
    /// * No record and no file documents: [`IndexTextExtractor::NoFileDocuments`].
    /// * If the index cannot be counted: [`IndexTextExtractor::NotAssessed`] —
    ///   "could not look", never "current".
    ///
    /// Not handled: a DOWNGRADE, where a later build recorded a higher version
    /// and this build reads it. Such a case is reported as current.
    pub fn text_extractor_provenance(&self, case_id: Uuid) -> IndexTextProvenance {
        {
            let record = self
                .extractor_record
                .lock()
                .unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = record.cases.get(&case_id.to_string()) {
                let earlier = entry.earlier_file_documents
                    || entry.versions.iter().any(|v| *v < TEXT_EXTRACTOR_VERSION);
                return IndexTextProvenance {
                    status: if earlier {
                        IndexTextExtractor::Earlier
                    } else {
                        IndexTextExtractor::Current
                    },
                    recorded_versions: entry.versions.iter().copied().collect(),
                };
            }
        }
        let status = match self.count_file_documents(case_id) {
            Ok(0) => IndexTextExtractor::NoFileDocuments,
            Ok(_) => IndexTextExtractor::Earlier,
            Err(e) => {
                warn!(
                    "search index: could not count file documents of case {}: {}",
                    case_id, e
                );
                IndexTextExtractor::NotAssessed
            }
        };
        IndexTextProvenance {
            status,
            recorded_versions: Vec::new(),
        }
    }

    /// Committed documents of `case_id` whose type has its bytes read
    /// ([`scope::CONTENT_INDEXED_TYPES`]), with or without text.
    fn count_file_documents(&self, case_id: Uuid) -> Result<usize> {
        use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
        use tantivy::schema::IndexRecordOption;

        let reader = self
            .index
            .reader()
            .context("Failed to get index reader for a file-document count")?;
        let searcher = reader.searcher();
        let case_term: Box<dyn Query> = Box::new(TermQuery::new(
            tantivy::Term::from_field_text(self.field_case_id, &case_id.to_string()),
            IndexRecordOption::Basic,
        ));
        let types: Vec<(Occur, Box<dyn Query>)> = scope::CONTENT_INDEXED_TYPES
            .iter()
            .map(|t| {
                let q: Box<dyn Query> = Box::new(TermQuery::new(
                    tantivy::Term::from_field_text(self.field_artifact_type, &t.to_string()),
                    IndexRecordOption::Basic,
                ));
                (Occur::Should, q)
            })
            .collect();
        let query = BooleanQuery::new(vec![
            (Occur::Must, case_term),
            (Occur::Must, Box::new(BooleanQuery::new(types))),
        ]);
        Ok(searcher.search(&query, &tantivy::collector::Count)?)
    }

    /// Record that this build's extractor is indexing a file document of the
    /// artifact's case. Called before the document is queued.
    ///
    /// Every document of a file type counts, bytes or not: a fresh ingest
    /// indexes directories first, and if they were committed unrecorded the
    /// first recorded file would find them and take them for an earlier
    /// build's work.
    fn note_text_extractor(&self, artifact: &Artifact) {
        if !scope::CONTENT_INDEXED_TYPES.contains(&artifact.artifact_type) {
            return;
        }
        let key = artifact.case_id.to_string();
        let mut record = self
            .extractor_record
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        if record
            .cases
            .get(&key)
            .is_some_and(|c| c.versions.contains(&TEXT_EXTRACTOR_VERSION))
        {
            return;
        }
        if !record.cases.contains_key(&key) {
            // Anything already in the index for this case was put there by a
            // build that recorded nothing. A count that fails is taken as
            // "there were some": over-disclosing is the safe direction.
            let earlier = self
                .count_file_documents(artifact.case_id)
                .map(|n| n > 0)
                .unwrap_or_else(|e| {
                    warn!(
                        "search index: could not count file documents of case {}: {}",
                        artifact.case_id, e
                    );
                    true
                });
            record.cases.insert(
                key.clone(),
                CaseExtractorRecord {
                    versions: Default::default(),
                    earlier_file_documents: earlier,
                },
            );
        }
        if let Some(entry) = record.cases.get_mut(&key) {
            entry.versions.insert(TEXT_EXTRACTOR_VERSION);
        }
        self.persist_extractor_record(&record);
    }

    /// Drop one case's entry, or every entry when `case_id` is `None`.
    fn forget_text_extractor(&self, case_id: Option<Uuid>) {
        let mut record = self
            .extractor_record
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        match case_id {
            Some(id) => {
                record.cases.remove(&id.to_string());
            }
            None => record.cases.clear(),
        }
        self.persist_extractor_record(&record);
    }

    /// Write the record atomically (temporary file, then rename). A failure is
    /// logged, not raised: the in-memory record still serves this process,
    /// and a later process that finds no entry reports the case as indexed by
    /// an earlier extractor — over-disclosure, not a false "current".
    fn persist_extractor_record(&self, record: &ExtractorRecord) {
        let tmp = self.extractor_record_path.with_extension("json.tmp");
        let result = serde_json::to_vec(record)
            .map_err(anyhow::Error::from)
            .and_then(|bytes| std::fs::write(&tmp, bytes).map_err(anyhow::Error::from))
            .and_then(|()| {
                std::fs::rename(&tmp, &self.extractor_record_path).map_err(anyhow::Error::from)
            });
        if let Err(e) = result {
            warn!(
                "search index: could not write text extractor record {:?}: {}",
                self.extractor_record_path, e
            );
        }
    }

    /// The search universe of a search over `case_id` in `mode`: the build's
    /// coverage, qualified by which extractor built this case's documents.
    pub fn search_universe_for_case(&self, case_id: Uuid, mode: MatchMode) -> SearchUniverse {
        search_universe_for(&self.text_extractor_provenance(case_id), mode)
    }

    pub async fn delete_case(&self, case_id: Uuid) -> Result<()> {
        info!("Deleting documents for case {} from index...", case_id);
        self.command_and_wait(|resp| IndexCommand::DeleteCase(case_id, resp))
            .await?;
        // The case's documents are gone, so is what built them. A later
        // ingest under the same id is judged on what the index holds then.
        self.forget_text_extractor(Some(case_id));
        Ok(())
    }

    /// Remove a single artifact from the index by id and commit.
    pub async fn delete_artifact(&self, artifact_id: Uuid) -> Result<()> {
        info!("Deleting artifact {} from index...", artifact_id);
        self.command_and_wait(|resp| IndexCommand::DeleteArtifact(artifact_id, resp))
            .await
    }

    /// Remove many artifacts from the index by id in a single commit. Used when
    /// a recursive artifact delete removes a whole subtree, so its descendant
    /// documents don't linger in the index (stale search hits) until a reindex.
    pub async fn delete_artifacts(&self, artifact_ids: Vec<Uuid>) -> Result<()> {
        if artifact_ids.is_empty() {
            return Ok(());
        }
        info!("Deleting {} artifacts from index...", artifact_ids.len());
        self.command_and_wait(move |resp| IndexCommand::DeleteArtifacts(artifact_ids, resp))
            .await
    }

    /// Deliberately wipe the index, leaving it empty but usable.
    /// Callers are expected to re-index afterwards.
    ///
    /// # This is not a reindex
    ///
    /// It deletes the documents of EVERY case on this server and re-adds
    /// nothing. There is no caller inside the crate that repopulates what it
    /// removes, and it must never be reached from a per-case action: a request
    /// scoped to one case would empty the search index for all of them, and an
    /// examiner working an unrelated case would see their evidence answer no
    /// query at all. To repair the documents of a single case in place, use
    /// [`Self::refresh_case_display_names`].
    pub async fn rebuild_index(&self) -> Result<()> {
        warn!("Rebuilding search index: deleting all documents");
        self.command_and_wait(IndexCommand::DeleteAll).await?;
        self.forget_text_extractor(None);
        Ok(())
    }

    /// Which of `candidates` this case already has a document for.
    ///
    /// Asked in batches by the backfill (`LIVE-028`), which walks a case's
    /// artifacts in the database and needs to know which of them the index is
    /// missing. Asking per id would be one search per artifact over a
    /// 580,394-artifact case; asking for every id at once would hold the case's
    /// whole id set in memory. A batch of a thousand is neither.
    ///
    /// An id that is in the index for a DIFFERENT case does not count as
    /// present: the query is scoped to the case, because that is the question
    /// the caller is asking.
    pub fn indexed_ids_among(
        &self,
        case_id: Uuid,
        candidates: &[Uuid],
    ) -> Result<std::collections::HashSet<Uuid>> {
        use tantivy::query::{BooleanQuery, Occur, Query, TermQuery};
        use tantivy::schema::IndexRecordOption;

        let mut found = std::collections::HashSet::new();
        if candidates.is_empty() {
            return Ok(found);
        }
        let reader = self
            .index
            .reader()
            .context("Failed to get index reader for an indexed-id check")?;
        let searcher = reader.searcher();

        let case_term: Box<dyn Query> = Box::new(TermQuery::new(
            tantivy::Term::from_field_text(self.field_case_id, &case_id.to_string()),
            IndexRecordOption::Basic,
        ));
        let id_terms: Vec<(Occur, Box<dyn Query>)> = candidates
            .iter()
            .map(|id| {
                let q: Box<dyn Query> = Box::new(TermQuery::new(
                    tantivy::Term::from_field_text(self.field_id, &id.to_string()),
                    IndexRecordOption::Basic,
                ));
                (Occur::Should, q)
            })
            .collect();
        let any_id: Box<dyn Query> = Box::new(BooleanQuery::new(id_terms));
        let query = BooleanQuery::new(vec![(Occur::Must, case_term), (Occur::Must, any_id)]);

        let hits = searcher.search(&query, &DocSetCollector)?;
        for address in hits {
            let doc: TantivyDocument = searcher.doc(address)?;
            if let Some(id) = doc
                .get_first(self.field_id)
                .and_then(|v| v.as_str())
                .and_then(|s| Uuid::parse_str(s).ok())
            {
                found.insert(id);
            }
        }
        Ok(found)
    }

    /// Recompute the display name of every document this case already has in
    /// the index, from the artifact metadata stored in the document itself.
    ///
    /// This repairs what is indexed. It does NOT discover artifacts that were
    /// never indexed, and it cannot: the index is its own source of truth here.
    /// A case whose ingest dropped documents has a short index before this runs
    /// and the same short index afterwards. Only re-ingesting the evidence
    /// changes that, and callers that report the outcome to a user must say so.
    ///
    /// It reads from the index rather than the database on purpose. A
    /// database-loaded artifact carries no data source, so rebuilding documents
    /// from the `artifacts` table would silently drop the text extracted from
    /// every file's bytes — turning a keyword that is in the evidence into a
    /// search that says it is not there (B5-001). Re-emitting the stored
    /// document keeps all of its `content` values, file text included.
    pub async fn refresh_case_display_names(&self, case_id: Uuid) -> Result<RefreshOutcome> {
        self.refresh_case_display_names_with_progress(case_id, |_, _| {})
            .await
    }

    /// [`Self::refresh_case_display_names`], reporting `(examined, total)` as it
    /// goes so a long repair can be followed from the UI.
    pub async fn refresh_case_display_names_with_progress<F>(
        &self,
        case_id: Uuid,
        progress: F,
    ) -> Result<RefreshOutcome>
    where
        F: Fn(usize, usize) + Send + 'static,
    {
        let tx = self.commands()?.clone();
        // `Index` is a cheap handle; cloning it lets the whole pass — which is
        // synchronous IO per document, exactly like the regex and substring
        // scans — run on the blocking pool instead of stalling the runtime.
        let index = self.index.clone();
        let fields = self.doc_fields();
        let purges = self.purges.clone();
        tokio::task::spawn_blocking(move || {
            Self::refresh_display_names_blocking(index, tx, fields, case_id, progress, purges)
        })
        .await
        .context("search index display-name repair task panicked")?
    }

    /// The synchronous body of [`Self::refresh_case_display_names_with_progress`].
    ///
    /// Reads and replaces in bounded batches rather than materialising the whole
    /// case first: a 580k-document case holding every rebuilt document at once —
    /// each carrying its metadata JSON plus up to [`CONTENT_INDEX_CAP`] of
    /// extracted file text — is an allocation no server should be asked to make.
    /// The batch is also the unit of atomicity (see [`replace_documents`]).
    ///
    /// A pass can also be overtaken by a delete. Everything it re-emits comes
    /// from a snapshot of the index taken here, at the start, so a document
    /// purged after that snapshot is still sitting in this thread's hands
    /// minutes later. `purges` is what stops it going back in; see
    /// [`purge_overtook_repair`].
    fn refresh_display_names_blocking<F>(
        index: Index,
        tx: SyncSender<IndexCommand>,
        fields: DocFields,
        case_id: Uuid,
        progress: F,
        purges: Arc<AtomicU64>,
    ) -> Result<RefreshOutcome>
    where
        F: Fn(usize, usize),
    {
        /// Documents per replace batch.
        const BATCH_DOCS: usize = 500;
        /// Bytes of rebuilt `content` held before a batch is flushed early. A
        /// few very large files would otherwise blow past the document count.
        const BATCH_BYTES: usize = 32 * 1024 * 1024;

        // Read the purge counter BEFORE opening the reader, and never after.
        // The writer counts a purge only once its commit has been attempted, so
        // a purge already counted here is one the reader below already
        // reflects, and any purge the reader does NOT reflect is one that will
        // be counted later and will therefore stop this pass. Taking the
        // snapshot first and the counter second inverts that and lets a delete
        // slip into the gap.
        let purges_at_start = purges.load(Ordering::SeqCst);
        let reader = index
            .reader()
            .context("Failed to get index reader for display-name repair")?;
        let searcher = reader.searcher();
        let case_query = tantivy::query::TermQuery::new(
            tantivy::Term::from_field_text(fields.case_id, &case_id.to_string()),
            tantivy::schema::IndexRecordOption::Basic,
        );
        let doc_addresses = searcher.search(&case_query, &DocSetCollector)?;

        let total = doc_addresses.len();
        let mut outcome = RefreshOutcome {
            documents: total,
            renamed: 0,
            undecodable: 0,
        };
        let mut batch: Vec<(Uuid, TantivyDocument)> = Vec::new();
        let mut batch_bytes = 0usize;
        let mut examined = 0usize;

        for doc_address in doc_addresses {
            examined += 1;
            let stored: TantivyDocument = searcher.doc(doc_address)?;

            match rebuild_with_display_name(&stored, &fields) {
                RepairDecision::AlreadyCurrent => {
                    progress(examined, total);
                    continue;
                }
                RepairDecision::Undecodable => {
                    outcome.undecodable += 1;
                    progress(examined, total);
                    continue;
                }
                RepairDecision::Rebuilt {
                    artifact_id,
                    doc,
                    content_bytes,
                } => {
                    batch_bytes += content_bytes;
                    batch.push((artifact_id, doc));
                    outcome.renamed += 1;
                }
            }

            if batch.len() >= BATCH_DOCS || batch_bytes >= BATCH_BYTES {
                send_replace_batch(&tx, std::mem::take(&mut batch), purges_at_start)?;
                batch_bytes = 0;
            }
            progress(examined, total);
        }

        send_replace_batch(&tx, batch, purges_at_start)?;

        // A purge that landed after the last batch committed can no longer
        // resurrect anything, but it does make this outcome untrue: the counts
        // describe documents a delete has since removed, and the caller writes
        // them into the audit trail as what the repair left the case holding.
        // Report a stopped pass rather than renames that no longer exist.
        if purges.load(Ordering::SeqCst) != purges_at_start {
            return Err(purge_overtook_repair());
        }
        Ok(outcome)
    }

    pub async fn search(
        &self,
        case_id: Uuid,
        query_str: &str,
        limit: usize,
    ) -> Result<Vec<SearchResult>> {
        let options = SearchOptions {
            query: query_str.to_string(),
            limit,
            artifact_types: None,
            use_regex: false,
            file_extensions: None,
            fuzzy: None,
        };
        let response = self.search_with_options(case_id, options).await?;
        Ok(response.results)
    }

    /// The first page of a search. Equivalent to [`Self::search_page`] at
    /// offset 0, and kept as the name every existing caller already uses.
    pub async fn search_with_options(
        &self,
        case_id: Uuid,
        options: SearchOptions,
    ) -> Result<SearchResponse> {
        self.search_page(case_id, options, 0).await
    }

    /// One page of a search: skip `offset` matches, then return up to
    /// `options.limit` of the ones that follow.
    ///
    /// `total_count` describes the whole match set and does not move with
    /// `offset`, because it is read as the term's prevalence in the case.
    ///
    /// Two things about offset paging are worth stating plainly, because paging
    /// can imply scalability an engine does not have.
    ///
    /// First, COST — and the shape of it is not what it looks like. An offset
    /// does NOT make a page more expensive: measured over a 300,000-document
    /// case, a scan page costs ~210 ms at offset 0 and ~205 ms at offset
    /// 250,000, because the cost is a walk of the case rather than a seek into
    /// it (`tests/search_paging_cost_test.rs` re-runs the measurement). What is
    /// expensive is the WALK: every page pays that same full cost again, so
    /// reading a result set of M matches page by page costs
    /// `M / limit` walks of the whole case. That is the bill the old paging
    /// ceiling was capping, and capping it made the matches past it unreachable.
    /// [`Self::search_after`] is the answer to it: a cursor page resumes where
    /// the last one stopped, so the same walk costs one pass.
    ///
    /// Second, STABILITY. Pages join up only while the index does not change
    /// underneath them; [`index_snapshot`] on the response is how a caller
    /// detects that it did.
    pub async fn search_page(
        &self,
        case_id: Uuid,
        options: SearchOptions,
        offset: usize,
    ) -> Result<SearchResponse> {
        self.page(
            case_id,
            options,
            PageStart::Offset(offset),
            PageSearcher::Current,
        )
        .await
    }

    /// The page that continues where a previous page stopped.
    ///
    /// `cursor` is the opaque [`SearchResponse::next_cursor`] of the page
    /// before; `None` asks for the first page, which is exactly
    /// [`Self::search_page`] at offset 0.
    ///
    /// This is the route with no ceiling. Where an offset makes the engine walk
    /// the case from the beginning and discard what it passes, a cursor names
    /// the position the walk reached, so the engine seeks to it and examines
    /// only what lies beyond. Reaching match 4,000,000 costs one pass over the
    /// case spread across the pages that ask for it, instead of one pass per
    /// page.
    ///
    /// It can also be REFUSED, and that is the feature rather than a wart. A
    /// cursor is a promise about a position in an ordering, and this index's
    /// orderings move whenever a commit lands — which, on a case that is still
    /// being ingested, is constantly. A refusal ([`CursorRefused`], carrying a
    /// [`CursorRefusal`]) tells the examiner their walk was interrupted. The
    /// alternative — re-basing the position onto the enumeration the index has
    /// since become — would hand back rows that look like a continuation of a
    /// set that gained and lost members at the seam, with nothing on screen
    /// saying so.
    pub async fn search_after(
        &self,
        case_id: Uuid,
        options: SearchOptions,
        cursor: Option<&str>,
    ) -> Result<SearchResponse> {
        match cursor {
            Some(token) => {
                self.page(
                    case_id,
                    options,
                    PageStart::After(token),
                    PageSearcher::Current,
                )
                .await
            }
            None => {
                self.page(
                    case_id,
                    options,
                    PageStart::Offset(0),
                    PageSearcher::Current,
                )
                .await
            }
        }
    }

    /// The page that continues a walk being read from a PINNED snapshot.
    ///
    /// Identical to [`Self::search_after`] in every respect but one: the page
    /// is served from the searcher `pin` is holding rather than from whatever
    /// the index has committed by now. That single difference is what makes an
    /// export whole. Every page of the walk sees the same segments, so every
    /// page computes the same [`index_snapshot`], so no cursor minted inside
    /// the walk can be refused for a moved index — while ingest and background
    /// merges carry on underneath, unaffected and unhidden.
    ///
    /// It is a SEPARATE method, and deliberately not a flag on
    /// [`Self::search_after`], because the two have different forensic
    /// contracts and a caller must choose between them explicitly:
    ///
    /// * [`Self::search_after`] serves a cursor that may have been minted long
    ///   ago against an index state that is gone, and REFUSES it when it has —
    ///   which is the honest answer to a browser resuming an interrupted walk.
    /// * this serves a walk that holds its own index state open, which is only
    ///   sound while the caller is walking start-to-finish inside one request
    ///   and will drop the pin when it stops. A `PinnedSearcher` kept alive
    ///   between user interactions would be an examiner reading, indefinitely,
    ///   an index state the case has moved on from — and paying disk for the
    ///   privilege.
    ///
    /// The cursors this hands back are ordinary cursors carrying the pinned
    /// snapshot's fingerprint. Passed to [`Self::search_after`] later they are
    /// refused exactly like any other stale cursor, because by then nothing is
    /// holding that snapshot open.
    pub async fn search_after_pinned(
        &self,
        pin: &PinnedSearcher,
        case_id: Uuid,
        options: SearchOptions,
        cursor: Option<&str>,
    ) -> Result<SearchResponse> {
        let start = match cursor {
            Some(token) => PageStart::After(token),
            None => PageStart::Offset(0),
        };
        // Checked out before any work is done for the page, and the check is
        // what stops a purge reaching an exhibit: `take_searcher` revokes the
        // pin — dropping the searcher, releasing the segment files — the moment
        // the service's purge counter has moved since the pin was taken. See
        // [`PinnedSearcher`] for why that is the one kind of index movement a
        // pinned walk must not absorb.
        let searcher = pin.inner.take_searcher()?;
        self.page(case_id, options, start, PageSearcher::Pinned(searcher))
            .await
    }

    /// The one implementation behind [`Self::search_page`],
    /// [`Self::search_after`] and [`Self::search_after_pinned`]: they differ
    /// only in where the page starts and which snapshot it reads.
    async fn page(
        &self,
        case_id: Uuid,
        options: SearchOptions,
        start: PageStart<'_>,
        from: PageSearcher,
    ) -> Result<SearchResponse> {
        let start_time = Instant::now();
        // Documents the writer thread failed to add since the last commit are
        // not searchable, so every count below is short by an unknown amount.
        // The counter is case-agnostic — we cannot tell which case lost
        // documents — so the honest answer for any case is "at least N".
        let index_incomplete = self.pending_index_failures() > 0 || self.rebuilt_from_empty;
        // The snapshot fingerprint is taken from the SAME searcher this page is
        // served from, and before that searcher is moved onto the blocking
        // pool: it names the index state the rows actually came from rather
        // than whatever the index has become by the time the scan finishes.
        //
        // A pinned page recomputes it from the pinned searcher rather than
        // trusting a stored string, so a page that somehow read from a
        // different searcher would produce a different fingerprint and its
        // cursor would be refused — the refusal stays a real check on this path
        // rather than being switched off by it.
        let (searcher, snapshot) = match from {
            PageSearcher::Current => {
                let reader = self.index.reader().context("Failed to get index reader")?;
                let searcher = reader.searcher();
                let snapshot = index_snapshot(&searcher);
                (searcher, snapshot)
            }
            // An `Arc` clone of the held view, not a new one: this is what
            // keeps every page of an export on one set of segment readers.
            PageSearcher::Pinned(searcher) => {
                let snapshot = index_snapshot(&searcher);
                (searcher, snapshot)
            }
        };
        let shape = result_set_shape(case_id, &options);

        // A cursor is checked against the request it arrived with and the index
        // it would be served from, BEFORE any work is done for it. Both checks
        // refuse rather than approximate; see [`SearchCursor`].
        let origin = match start {
            PageStart::Offset(offset) => PageOrigin::Offset(offset),
            PageStart::After(token) => {
                let cursor = SearchCursor::decode(token)?;
                cursor.validate(shape, &snapshot)?;
                PageOrigin::After(cursor)
            }
        };

        // The two unranked scans. Both walk the case's documents in index order
        // and match-test each one; they differ only in the test, so they share
        // one loop and one resume path.
        let scan_matcher = if options.use_regex {
            // Cap the compiled program / DFA size so a pathological pattern
            // fails to build rather than consuming unbounded memory. The regex
            // crate has no backtracking, so match time is linear in input; the
            // per-search scan cost is bounded separately by `max_scan_docs` /
            // `SCAN_DEADLINE`.
            let re = RegexBuilder::new(&options.query)
                .case_insensitive(true)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
                .context(format!(
                    "Invalid or too-complex regex pattern: '{}'",
                    options.query
                ))?;
            Some(ScanMatcher::Regex(re))
        } else if options.fuzzy.is_none() && is_plain_query(&options.query) {
            // A plain keyword query is matched as a case-insensitive substring
            // rather than a whole-token term. This is what an examiner expects
            // from a keyword search — a shorter query is a superset of a longer
            // one, so searching "feel" finds "feeling" — and it makes
            // multi-word queries an AND of substrings. Queries that use the
            // structured syntax (booleans, phrases, wildcards) or fuzzy
            // matching keep the ranked path below.
            //
            // Split on whitespace only, so hyphens/dots/colons stay part of a
            // term (a forensic search for a timestamp or email is matched
            // verbatim).
            let terms: Vec<String> = options
                .query
                .split_whitespace()
                .map(|t| t.to_lowercase())
                .filter(|t| !t.is_empty())
                .collect();
            let highlight = terms_regex(&terms);
            Some(ScanMatcher::Substring { terms, highlight })
        } else {
            None
        };

        if let Some(matcher) = scan_matcher {
            let scan_start = ScanStart::from_origin(&origin)?;
            let fields = RegexSearchFields {
                id: self.field_id,
                case_id: self.field_case_id,
                artifact_type: self.field_artifact_type,
                name: self.field_name,
                content: self.field_content,
                record_kind: self.field_record_kind,
            };
            let snapshot_for_scan = snapshot.clone();
            // The scan walks stored documents; run it on the blocking pool so
            // it doesn't stall the async runtime.
            let scanned = tokio::task::spawn_blocking(move || {
                Self::search_scan_blocking(
                    searcher,
                    fields,
                    case_id,
                    options,
                    matcher,
                    scan_start,
                    shape,
                    snapshot_for_scan,
                    start_time,
                    MAX_SCAN_DOCS,
                )
            })
            .await
            .context("Search scan task panicked")?;
            return scanned.map(|mut response| {
                mark_index_incomplete(&mut response, index_incomplete);
                response
            });
        }

        // Build full-text search query. Tantivy's QueryParser already supports
        // boolean operators (AND/OR/NOT, +/-), grouping with parentheses, phrase
        // queries ("..."), and proximity/slop ("a b"~N). Fuzzy matching is opt-in
        // per request via `fuzzy` (Levenshtein distance on each term).
        // Set when the structured parse failed and the query was retried as a
        // literal phrase; carried onto the response rather than left in a log.
        let mut taken_literally: Option<String> = None;
        let search_query: Box<dyn Query> = {
            let mut query_parser =
                QueryParser::for_index(&self.index, vec![self.field_name, self.field_content]);
            if let Some(distance) = options.fuzzy {
                let distance = clamp_fuzzy_distance(distance);
                query_parser.set_field_fuzzy(self.field_name, false, distance, true);
                query_parser.set_field_fuzzy(self.field_content, false, distance, true);
            }
            match query_parser.parse_query(&options.query) {
                Ok(q) => q,
                Err(structured) => {
                    // A PLAIN STRING MUST NOT ANSWER WITH AN ERROR. Tantivy's
                    // syntax claims `(`, `)`, `:`, `+`, `-`, `[`, `]`, `^`,
                    // `"`, `~` and `*`, so `(901)555-1111` -- a phone number in
                    // the form anybody would type -- was a syntax error and the
                    // API returned a 500. Found by running NIST CFTT's
                    // Forensic String Search methodology, whose published
                    // target list includes exactly that number.
                    //
                    // So it is retried as a literal phrase. Not silently: the
                    // response says the query was taken literally, because an
                    // examiner whose structured query was quietly reinterpreted
                    // would be reading the answer to a different question.
                    let literal = format!("\"{}\"", options.query.replace('"', "\\\""));
                    match query_parser.parse_query(&literal) {
                        Ok(q) => {
                            taken_literally = Some(format!(
                                "This query does not parse as a structured query \
                                 ({structured}), so it was searched for LITERALLY, as the exact \
                                 text typed. Characters such as parentheses, colons and square \
                                 brackets are query syntax; if you meant them as syntax, the \
                                 query has a mistake in it, and if you meant them as text then \
                                 this is the search you asked for."
                            ));
                            q
                        }
                        // Neither reading parses. The original error is the
                        // one to report: it is about what the examiner typed.
                        Err(_) => {
                            return Err(anyhow::Error::new(structured).context(format!(
                                "Failed to parse search query: '{}'",
                                options.query
                            )))
                        }
                    }
                }
            }
        };

        // Filter by case_id
        let term_query_case_id = tantivy::query::TermQuery::new(
            tantivy::Term::from_field_text(self.field_case_id, &case_id.to_string()),
            tantivy::schema::IndexRecordOption::Basic,
        );

        // Build combined query with case filter
        let mut query_clauses: Vec<(tantivy::query::Occur, Box<dyn Query>)> = vec![
            (tantivy::query::Occur::Must, Box::new(term_query_case_id)),
            (tantivy::query::Occur::Must, search_query),
        ];

        // Add artifact type filter if specified. Empty names are dropped, and a
        // list of nothing but empty names is no filter: `?types=,` reaches here
        // as `["", ""]`, and a Should-clause over two empty terms matched no
        // document while the cursor shape (`result_set_shape`, which already
        // ignores empty names) described the request as unfiltered.
        if let Some(types) = options.artifact_types.as_deref().map(named_types) {
            if !types.is_empty() {
                let type_queries: Vec<(tantivy::query::Occur, Box<dyn Query>)> = types
                    .iter()
                    .map(|t| {
                        let term_query = tantivy::query::TermQuery::new(
                            tantivy::Term::from_field_text(self.field_artifact_type, t),
                            tantivy::schema::IndexRecordOption::Basic,
                        );
                        (
                            tantivy::query::Occur::Should,
                            Box::new(term_query) as Box<dyn Query>,
                        )
                    })
                    .collect();

                let type_boolean_query = tantivy::query::BooleanQuery::from(type_queries);
                query_clauses.push((tantivy::query::Occur::Must, Box::new(type_boolean_query)));
            }
        }

        let boolean_query = tantivy::query::BooleanQuery::from(query_clauses);

        // Where the requested page sits in the ranked order, and how many
        // matches precede it. Both come from the cursor when there is one:
        // `consumed` is the position the previous page stopped at, which is
        // what the response has to state so a page can never be read as the
        // head of the result set.
        let (offset, after_key) = match &origin {
            PageOrigin::Offset(offset) => (*offset, None),
            PageOrigin::After(cursor) => match cursor.position {
                CursorPosition::Ranked {
                    score_bits,
                    segment_ord,
                    doc_id,
                } => (
                    cursor.consumed,
                    Some(RankedKey {
                        score: f32::from_bits(score_bits),
                        segment_ord,
                        doc_id,
                    }),
                ),
                // A scan cursor cannot reach here: the routing above is decided
                // by the query, the regex flag and the fuzzy distance, all of
                // which are in the shape the cursor was already checked
                // against. Refused rather than reinterpreted all the same.
                CursorPosition::Scan { .. } => {
                    return Err(CursorRefused::new(
                        CursorRefusal::Malformed,
                        "this paging cursor names a position in a different kind of \
                         enumeration than this query produces. Start the search again from \
                         the first page",
                    )
                    .into())
                }
            },
        };
        let resuming = after_key.is_some();
        // The extension filter as it will actually be APPLIED, or `None` when
        // there is nothing to apply. A list that normalises to empty — reachable
        // from the URL as `?extensions=.`, which the API's `is_empty` check lets
        // through — must route exactly as no filter at all. Deciding
        // `ext_active` on `is_some()` moved the offset skip out of the
        // collector for a filter the post-filter block below then declined to
        // run, so the skipped rows were never drained: every page was page 1
        // while the response stated the offset it had not applied (CR-033 #1).
        let ext_lower = options
            .file_extensions
            .as_ref()
            .map(|exts| normalize_extensions(exts))
            .filter(|e| !e.is_empty());
        let ext_active = ext_lower.is_some();

        // Over-fetch when extension filtering is active to ensure enough results
        // after post-filter. The filter runs after retrieval, so on the offset
        // branch the candidate window has to cover the skipped rows too, and
        // the skip happens below once the surviving matches are known. On the
        // cursor branch there are no skipped rows to cover: the window only has
        // to hold this page's worth of survivors.
        let mut top_docs: Vec<(f32, tantivy::DocAddress)>;
        let fetch_limit: usize;
        let mut total_count: usize;
        let mut count_is_lower_bound: bool;
        if resuming {
            fetch_limit = if ext_active {
                options
                    .limit
                    .saturating_mul(5)
                    .min(MAX_EXTENSION_CANDIDATES)
            } else {
                options.limit
            }
            // `RankedAfter` with a limit of zero would collect nothing; a
            // caller asking for no rows gets the count and no rows rather than
            // a walk that returns an unusable cursor.
            .max(1);
            // One candidate past the window, so a window that came back full
            // can be told from one that held the whole remaining match set;
            // see `candidates_hit_cap` below.
            top_docs = searcher.search(
                &boolean_query,
                &RankedAfter {
                    limit: fetch_limit.saturating_add(1),
                    after: after_key,
                },
            )?;
            // The count established when the walk began. It is exact for the
            // snapshot this cursor is pinned to, and a cursor whose snapshot
            // moved was refused above — so carrying it forward states no more
            // than the first page already stated.
            let PageOrigin::After(cursor) = &origin else {
                unreachable!("resuming implies a cursor")
            };
            total_count = cursor.total;
            count_is_lower_bound = cursor.total_is_floor;
        } else {
            let window = offset.saturating_add(options.limit);
            let (limit_to_fetch, collector_offset) = if ext_active {
                (window.saturating_mul(5).min(MAX_EXTENSION_CANDIDATES), 0)
            } else {
                // Without a post-filter every retrieved document is a match, so
                // the skip belongs in the collector: it keeps `offset + limit`
                // scores in a heap but retrieves and decodes only the `limit`
                // documents this page will actually show.
                (options.limit, offset)
            };
            // `TopDocs::with_limit` panics on zero; a caller asking for no rows
            // gets the count and no rows rather than a crash.
            fetch_limit = limit_to_fetch.max(1);
            // `Count` runs alongside the ranked window so the exact number of
            // matching documents is known: an examiner who sees `limit` rows
            // must be able to tell "that is every match" from "that is the
            // first page of many". Without it a capped result set is
            // indistinguishable from a complete one.
            let (docs, total_matches) = searcher.search(
                &boolean_query,
                &(
                    TopDocs::with_limit(fetch_limit.saturating_add(1))
                        .and_offset(collector_offset)
                        .order_by_score(),
                    Count,
                ),
            )?;
            top_docs = docs;
            total_count = total_matches;
            count_is_lower_bound = false;
        }
        // Whether documents beyond the fetch window exist. With an extension
        // post-filter that means matches may have been missed, and either way
        // it means the enumeration did not end here.
        //
        // Both branches asked for ONE candidate more than the window, and that
        // extra candidate is the whole test: `len() >= fetch_limit` was also
        // true when the window held the entire remaining match set, so the
        // offset refusal below fired at the genuine end and told the examiner
        // "this is not the end of the match set" when it was (CR-033 #2). The
        // sentinel is dropped before anything reads the window: it was never
        // retrieved, and it must not be counted as examined or resumed from.
        let candidates_hit_cap = top_docs.len() > fetch_limit;
        top_docs.truncate(fetch_limit);
        // The worst-ranked candidate this request examined. Everything up to it
        // has been retrieved and either kept or discarded, so it is a sound
        // place to resume from when the page came back short of a filter.
        let last_candidate: Option<RankedKey> = top_docs.last().map(|(score, address)| RankedKey {
            score: *score,
            segment_ord: address.segment_ord,
            doc_id: address.doc_id,
        });
        let examined_documents = top_docs.len();

        // Highlight pattern built from the plain query terms.
        let highlight_re = terms_regex(&query_terms(&options.query));

        // Rows are carried with the ranked key they came from, so the cursor
        // minted below names the position of a row that was actually served
        // rather than of one the post-filter removed.
        let mut rows: Vec<(SearchResult, RankedKey)> = Vec::new();
        for (score, doc_address) in top_docs {
            let retrieved_doc: TantivyDocument = searcher.doc(doc_address)?;
            let id_field = retrieved_doc
                .get_first(self.field_id)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let name_field = retrieved_doc
                .get_first(self.field_name)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let content_field = joined_content(&retrieved_doc, self.field_content);
            let content_field = content_field.as_str();
            let artifact_type_field = retrieved_doc
                .get_first(self.field_artifact_type)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let record_kind_field = retrieved_doc
                .get_first(self.field_record_kind)
                .and_then(|v| v.as_str())
                .unwrap_or("");

            let (snippet, highlights) =
                snippet_for(name_field, content_field, highlight_re.as_ref());

            rows.push((
                SearchResult {
                    artifact_id: Uuid::parse_str(id_field)
                        .context("Invalid UUID in search result")?,
                    case_id,
                    artifact_type: artifact_type_field.to_string(),
                    name: name_field.to_string(),
                    snippet,
                    highlights,
                    score,
                    record_kind: record_kind_field.to_string(),
                },
                RankedKey {
                    score,
                    segment_ord: doc_address.segment_ord,
                    doc_id: doc_address.doc_id,
                },
            ));
        }

        // Post-filter by file extension if specified.
        //
        // `total_count` is how many artifacts MATCH, not how many rows came
        // back. Keyword triage searches each term with `limit: 1` and reads
        // `total_count` as that term's prevalence, so reporting the page size
        // would make every term in the case look like a single hit.
        //
        // With no post-filter `Count` gives the exact figure. With one, the
        // count was taken before filtering, so the honest figure is how many
        // survived the filter over the candidate window: exact when the window
        // was not exhausted, a lower bound when it was.
        if let Some(ref ext_lower) = ext_lower {
            rows.retain(|(result, _)| name_matches_extensions(&result.name, ext_lower));
            if !resuming {
                total_count = rows.len();
                // The candidate window was exhausted; matches beyond it
                // were never filtered, so the count is a floor.
                count_is_lower_bound = candidates_hit_cap;
                // A jump past every survivor in an exhausted window is
                // refused rather than answered with an empty page
                // (SHIP-034): the page would be shaped like the end of the
                // match set, and the match set has not ended — the window
                // has. Offset 0 is exempt: it is the first page, and an
                // empty first page with a cursor past the window is how a
                // walk through a thinly-spread extension begins.
                if candidates_hit_cap && offset > 0 && offset >= rows.len() {
                    return Err(OffsetUnreachable {
                        offset,
                        reachable: rows.len(),
                        examined: examined_documents,
                        cause: OffsetUnreachableCause::ExtensionPostFilter,
                    }
                    .into());
                }
                // Counted before the skip, sliced after it: `total_count`
                // is the size of the filtered match set, not of the page
                // cut out of it.
                rows.drain(..offset.min(rows.len()));
            } else if count_is_lower_bound {
                // A floor grows as the walk delivers (CR-023). The cursor
                // carries the floor the FIRST page established over its own
                // window — which, for a thinly-spread extension, is "at least
                // 0" — and taking it verbatim on every resumed page left the
                // export preamble and the audit row stating "at least 0" while
                // thousands of rows went out. Every row this walk has handed
                // out is a match, and so is every survivor in this window, so
                // the floor is at least their sum; and a window that was NOT
                // exhausted has seen everything past the cursor, which makes
                // the figure exact and the walk's last page the one that says
                // so. An exact count from the first page is left alone: it was
                // taken over the whole match set and nothing here can improve
                // on it.
                total_count = total_count.max(offset.saturating_add(rows.len()));
                count_is_lower_bound = candidates_hit_cap;
            }
        }
        // No `else` for the unfiltered branch: its skip happened inside the
        // collector, so the rows before this page were never retrieved at all.
        //
        // `TopDocs::with_limit` panics on zero and was floored at one above, so
        // a caller asking for no rows would otherwise be handed one. The count
        // is what such a caller is after; the row is not.
        rows.truncate(options.limit);

        let page_full = options.limit > 0 && rows.len() >= options.limit;
        let consumed_after = offset.saturating_add(rows.len());
        // Where the next page would resume from, and whether there is one.
        //
        // A full page resumes after its last row. A short page that exhausted
        // its fetch window is short because the post-filter ate the difference,
        // not because the result set ended, so it resumes after the last
        // candidate examined. A short page that did not exhaust its window has
        // reached the end of the enumeration and offers nothing to continue.
        let resume_key = if page_full {
            rows.last().map(|(_, key)| *key)
        } else if candidates_hit_cap {
            last_candidate
        } else {
            None
        };
        let has_more = if page_full {
            consumed_after < total_count || count_is_lower_bound
        } else {
            candidates_hit_cap
        };
        // An offset page that served no rows cannot say where a continuation
        // would start: `offset` is where the caller ASKED to be, not where the
        // enumeration got to. A cursor page always can — its position came from
        // the engine. So can the FIRST page, whatever it served: nothing was
        // skipped to reach it, so the last candidate examined is exactly where
        // the enumeration got to, and an empty first page under a post-filter
        // must carry a cursor or the walk can never start (SHIP-034). A page
        // size of zero cannot either: the candidates it retrieved were all
        // discarded undelivered, so a cursor past them would step over matches.
        // See the scan for the same reasoning.
        let position_known = options.limit > 0 && (resuming || offset == 0 || !rows.is_empty());

        let next_cursor = if has_more && position_known {
            resume_key.map(|key| {
                SearchCursor {
                    shape,
                    snapshot: snapshot.clone(),
                    position: CursorPosition::Ranked {
                        score_bits: key.score.to_bits(),
                        segment_ord: key.segment_ord,
                        doc_id: key.doc_id,
                    },
                    consumed: consumed_after,
                    total: total_count,
                    total_is_floor: count_is_lower_bound,
                }
                .encode()
            })
        } else {
            None
        };

        let results: Vec<SearchResult> = rows.into_iter().map(|(result, _)| result).collect();
        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        let truncated = count_is_lower_bound || total_count > results.len();

        let mut response = SearchResponse {
            results,
            total_count,
            // Set when the structured parse failed and the query was retried
            // as a literal phrase. Carried onto the response rather than left
            // in a log: an examiner whose structured query was quietly
            // reinterpreted would be reading the answer to a different
            // question.
            query_taken_literally: taken_literally,
            offset,
            index_snapshot: snapshot,
            next_cursor,
            examined_documents,
            query: options.query,
            elapsed_ms,
            truncated,
            count_is_lower_bound,
            // Set only by `mark_index_incomplete`, below: nothing this routing
            // does can lose a row, so nothing this routing does may claim one
            // was lost.
            index_incomplete: false,
        };
        mark_index_incomplete(&mut response, index_incomplete);
        Ok(response)
    }

    /// The unranked scan behind both the plain-keyword and the regex routings:
    /// walks the case's documents in index order, retrieves each stored
    /// document and match-tests it.
    ///
    /// Tantivy's `RegexQuery` operates on tokenized terms, which cannot match
    /// patterns spanning token boundaries (e.g. `report_2024_Q[12]`), and a
    /// tokenized term query cannot answer "which files contain this substring";
    /// hence a scan rather than an index lookup for both.
    ///
    /// Runs synchronously; callers must dispatch it via `spawn_blocking`.
    ///
    /// `start` decides what it costs. From an offset it walks the whole case,
    /// which is what makes the count exact and what made deep paging expensive
    /// enough to need a ceiling. From a cursor it seeks to the position the
    /// previous page reached and examines only what follows, and inherits that
    /// page's count instead of recomputing one.
    #[allow(clippy::too_many_arguments)]
    fn search_scan_blocking(
        searcher: tantivy::Searcher,
        fields: RegexSearchFields,
        case_id: Uuid,
        options: SearchOptions,
        matcher: ScanMatcher,
        start: ScanStart,
        shape: u64,
        snapshot: String,
        start_time: Instant,
        max_scan_docs: usize,
    ) -> Result<SearchResponse> {
        let limit = options.limit;
        let (offset, resume, mut total_count, mut count_is_lower_bound, resuming) = match start {
            ScanStart::Offset(offset) => (offset, None, 0usize, false, false),
            ScanStart::After {
                at,
                consumed,
                total,
                total_is_floor,
            } => (consumed, Some(at), total, total_is_floor, true),
        };
        // Whether the count this page inherited was a floor; read again after
        // the walk, when the loop may have flipped `count_is_lower_bound`.
        let cursor_total_is_floor = count_is_lower_bound;

        // A query with no searchable terms matches nothing, and says so rather
        // than walking the case to discover it.
        if matcher.is_empty() {
            return Ok(SearchResponse {
                results: Vec::new(),
                total_count: 0,
                query_taken_literally: None,
                query: options.query,
                elapsed_ms: start_time.elapsed().as_millis() as u64,
                truncated: false,
                count_is_lower_bound: false,
                index_incomplete: false,
                offset,
                index_snapshot: snapshot,
                next_cursor: None,
                examined_documents: 0,
            });
        }

        let case_query = tantivy::query::TermQuery::new(
            tantivy::Term::from_field_text(fields.case_id, &case_id.to_string()),
            tantivy::schema::IndexRecordOption::Basic,
        );
        let mut docs = OrderedDocs::new(&searcher, &case_query, resume)?;

        let ext_lower = options
            .file_extensions
            .as_ref()
            .map(|exts| normalize_extensions(exts))
            .filter(|e| !e.is_empty());
        let type_filter = options
            .artifact_types
            .as_deref()
            .map(named_types)
            .filter(|t| !t.is_empty());

        let mut results: Vec<SearchResult> = Vec::new();
        let mut examined = 0usize;
        let mut last_delivered: Option<tantivy::DocAddress> = None;
        let mut last_examined: Option<tantivy::DocAddress> = None;
        // True when the walk stopped short of the end of the enumeration, so
        // documents beyond this point have not been accounted for.
        let mut stopped_early = false;

        while let Some(doc_address) = docs.next()? {
            // Bound worst-case work: stop scanning once the document budget or
            // the wall-clock deadline is hit, and report the results as
            // truncated. Keeps one search from pinning a blocking-pool thread on
            // a pathological (huge or near-zero-match) case. A cursor page
            // resumes with a fresh budget, so a case larger than the budget is
            // walkable one page at a time rather than being cut off at it.
            if scan_budget_exhausted(examined, max_scan_docs, start_time) {
                count_is_lower_bound = true;
                stopped_early = true;
                break;
            }
            examined += 1;

            let retrieved_doc: TantivyDocument = searcher.doc(doc_address)?;
            let id_field = retrieved_doc
                .get_first(fields.id)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let name_field = retrieved_doc
                .get_first(fields.name)
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let artifact_type_field = retrieved_doc
                .get_first(fields.artifact_type)
                .and_then(|v| v.as_str())
                .unwrap_or("");

            // Everything at or before this address has now been accounted for:
            // delivered, counted, or ruled out.
            last_examined = Some(doc_address);

            // Apply artifact type filter. Empty names are not a filter; see
            // the ranked routing.
            if let Some(ref types) = type_filter {
                if !types.iter().any(|t| t == artifact_type_field) {
                    continue;
                }
            }

            // Apply file extension filter before counting toward the limit
            if let Some(ref exts) = ext_lower {
                if !name_matches_extensions(name_field, exts) {
                    continue;
                }
            }

            // Joined only now: an allocating copy of up to 16 MiB of content is
            // wasted on a document the filters above have already ruled out.
            let content_field = joined_content(&retrieved_doc, fields.content);
            let content_field = content_field.as_str();
            let Some(content_matched) = matcher.test(name_field, content_field) else {
                continue;
            };

            // A resumed page inherits its count from the cursor and starts
            // here, so it has nothing to count and nothing to skip.
            if !resuming {
                // Count the match whether or not it fits in the returned page:
                // the scan already visits (and match-tests) every document in
                // the case, so continuing past `limit` costs only the push we
                // skip. Stopping here instead would make `total_count` mean
                // "page size", which reads to an examiner as prevalence.
                total_count += 1;
                // Matches before the requested page are counted and then
                // dropped. The scan has to visit them either way, so skipping
                // costs nothing beyond the excerpt work it avoids.
                if total_count <= offset {
                    continue;
                }
            }
            if results.len() >= limit {
                // The page is full. An offset walk keeps going because it is
                // still counting the match set; a resumed page already has the
                // count and has nothing left to learn.
                if resuming {
                    stopped_early = true;
                    break;
                }
                continue;
            }

            // Excerpt from the content when that is what matched, else from the
            // name.
            let (snippet, highlights) = snippet_for(
                name_field,
                if content_matched { content_field } else { "" },
                matcher.highlight(),
            );

            results.push(SearchResult {
                artifact_id: Uuid::parse_str(id_field).context("Invalid UUID in search result")?,
                case_id,
                artifact_type: artifact_type_field.to_string(),
                name: name_field.to_string(),
                snippet,
                highlights,
                // Scans are unscored: every match is a match.
                score: 1.0,
                record_kind: retrieved_doc
                    .get_first(fields.record_kind)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
            });
            last_delivered = Some(doc_address);

            if resuming && results.len() >= limit {
                // The page is full and the count is already known, so there is
                // nothing left for this request to learn.
                stopped_early = true;
                break;
            }
        }

        if resuming {
            // The count a resumed page publishes (CR-023). The cursor's count
            // was either exact — the first page walked the whole case, and
            // nothing a later page does can improve on that — or a floor set
            // where the first page's budget stopped it. A floor grows as the
            // walk delivers: every row handed out so far is a match, so the
            // figure is at least `offset + results.len()`; and a resumed page
            // that ran out of documents rather than stopping early has seen the
            // rest of the case, so on that page the figure is exact. Before
            // this the floor was carried verbatim from page to page, and a
            // walk stated "at least N" long after it had delivered more than N.
            if cursor_total_is_floor {
                total_count = total_count.max(offset.saturating_add(results.len()));
                count_is_lower_bound = stopped_early;
            } else {
                // A budget stop on a resumed page bounds this page's WORK, not
                // the count, which was exact before the page began.
                count_is_lower_bound = false;
            }
        }

        let page_full = limit > 0 && results.len() >= limit;
        let consumed_after = offset.saturating_add(results.len());
        // Where a continuation resumes from.
        //
        // A full page resumes after its last delivered row: matches beyond it
        // were counted but never handed out. A short page that stopped at the
        // scan budget resumes after the last document examined — everything
        // between the last delivered row and it was examined and did not match,
        // so skipping it hides nothing. A page that ran out of documents has
        // nothing to continue.
        let resume_at = if page_full {
            last_delivered
        } else if stopped_early {
            last_examined
        } else {
            None
        };
        let has_more = if stopped_early && !page_full {
            // Stopped at the budget part-way through a page: there is more of
            // the index to walk, whatever the count says.
            true
        } else if page_full {
            consumed_after < total_count || count_is_lower_bound
        } else {
            false
        };
        // An offset walk that stopped at its budget before reaching the
        // requested offset is refused rather than answered (SHIP-034): the page
        // would be empty with a floored count, which is shaped exactly like the
        // end of the match set, and the match set has not ended — the budget
        // has. The refusal names how far the walk got, and the two routes that
        // do reach: the cursor, and the export. Offset 0 is exempt, since the
        // first page is where a walk begins and it carries the cursor below.
        //
        // `!resuming` matters as much as the rest of the condition, and it was
        // missing. A **cursor** page inherits `total_count` from the cursor and
        // is never recounted (the counting below is itself inside `!resuming`),
        // while `offset` is how far the walk has consumed — so on any case
        // larger than the scan budget `offset` overtakes `total` after a few
        // pages, and the next page that crosses a barren stretch and hits the
        // budget with no rows satisfies every other clause. The walk was then
        // aborted with advice to "follow the `next_cursor` each page carries" —
        // which the caller had just done. It killed interactive walking and
        // truncated a pinned export mid-file. The ranked path has always had
        // this guard; this one is the same statement about the same thing.
        if !resuming && stopped_early && offset > 0 && total_count <= offset && results.is_empty() {
            return Err(OffsetUnreachable {
                offset,
                reachable: total_count,
                examined,
                // The scan's walk budget, not an extension post-filter: this
                // routing answers substring and regex queries and may have no
                // extension filter at all.
                cause: OffsetUnreachableCause::ScanBudget,
            }
            .into());
        }
        // An offset walk that never reached the requested offset cannot state
        // where a continuation would start: `offset` is where the caller asked
        // to be, not where the walk got to. A resumed page always can, and so
        // can the first page whatever it served: nothing was skipped to reach
        // it, so the last document examined is where the walk got to.
        //
        // A page size of zero cannot state one either: the walk stops on the
        // first match it may not deliver, and a cursor placed there would step
        // over that match on the next request. Such a caller is after the count
        // rather than a walk (keyword triage searches with `limit: 1`), and
        // gets the count.
        let position_known = limit > 0 && (resuming || total_count >= offset);

        let next_cursor = if has_more && position_known {
            resume_at.map(|address| {
                SearchCursor {
                    shape,
                    snapshot: snapshot.clone(),
                    position: CursorPosition::Scan {
                        segment_ord: address.segment_ord,
                        doc_id: address.doc_id,
                    },
                    consumed: consumed_after,
                    total: total_count,
                    total_is_floor: count_is_lower_bound,
                }
                .encode()
            })
        } else {
            None
        };

        let elapsed_ms = start_time.elapsed().as_millis() as u64;
        let truncated = count_is_lower_bound || total_count > results.len();

        Ok(SearchResponse {
            results,
            total_count,
            // The scan path builds its own matcher and never runs the
            // structured query parser, so there is no fall-back to report.
            query_taken_literally: None,
            query: options.query,
            elapsed_ms,
            truncated,
            count_is_lower_bound,
            // The scan budget bounds the COUNT and hands back a cursor
            // positioned after the last document it examined, so the walk
            // resumes past it and no match is skipped. Only
            // `mark_index_incomplete` may set this.
            index_incomplete: false,
            offset,
            index_snapshot: snapshot,
            next_cursor,
            examined_documents: examined,
        })
    }

    /// The plain-keyword routing of [`Self::search_scan_blocking`], addressed
    /// the way the unit tests below address it: by the routing rather than by
    /// the matcher the routing happens to build.
    #[cfg(test)]
    fn search_substring_blocking(
        searcher: tantivy::Searcher,
        fields: RegexSearchFields,
        case_id: Uuid,
        options: SearchOptions,
        offset: usize,
        start_time: Instant,
        max_scan_docs: usize,
    ) -> Result<SearchResponse> {
        let terms: Vec<String> = options
            .query
            .split_whitespace()
            .map(|t| t.to_lowercase())
            .filter(|t| !t.is_empty())
            .collect();
        let highlight = terms_regex(&terms);
        Self::search_scan_blocking(
            searcher,
            fields,
            case_id,
            options,
            ScanMatcher::Substring { terms, highlight },
            ScanStart::Offset(offset),
            0,
            String::new(),
            start_time,
            max_scan_docs,
        )
    }

    /// The regex routing of [`Self::search_scan_blocking`]; see above.
    #[cfg(test)]
    fn search_regex_blocking(
        searcher: tantivy::Searcher,
        fields: RegexSearchFields,
        case_id: Uuid,
        options: SearchOptions,
        offset: usize,
        start_time: Instant,
        max_scan_docs: usize,
    ) -> Result<SearchResponse> {
        let re = RegexBuilder::new(&options.query)
            .case_insensitive(true)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .context(format!(
                "Invalid or too-complex regex pattern: '{}'",
                options.query
            ))?;
        Self::search_scan_blocking(
            searcher,
            fields,
            case_id,
            options,
            ScanMatcher::Regex(re),
            ScanStart::Offset(offset),
            0,
            String::new(),
            start_time,
            max_scan_docs,
        )
    }
}

/// Where a page of results starts.
enum PageStart<'a> {
    /// Skip this many matches from the head of the enumeration.
    Offset(usize),
    /// Resume after the position this opaque cursor names.
    After(&'a str),
}

/// Which index state a page reads from.
///
/// The two are kept apart at the type level because they are two different
/// promises to the examiner, not two settings. `Current` is a page of the index
/// as it is NOW, whose cursor is refused once the index moves; `Pinned` is a
/// page of one held snapshot, which is only sound inside a single
/// start-to-finish walk. See [`PinnedSearcher`].
enum PageSearcher {
    /// Whatever is committed at the moment the page is served. Interactive
    /// paging, and every caller that is not walking a whole set in one request.
    Current,
    /// The snapshot an export is holding open for the life of its walk, already
    /// checked out of its pin. Resolved before the page starts so a revoked pin
    /// fails the request rather than being discovered half way down it.
    Pinned(tantivy::Searcher),
}

/// [`PageStart`] once the cursor has been read and checked.
enum PageOrigin {
    Offset(usize),
    After(SearchCursor),
}

/// Where an unranked scan starts, which is [`PageOrigin`] narrowed to the
/// position kind a scan can use.
enum ScanStart {
    /// Walk from the head of the enumeration, skipping `offset` matches. The
    /// walk continues to the end of the case, which is what makes the count
    /// exact.
    Offset(usize),
    /// Resume strictly after `at`, `consumed` matches into the set, with the
    /// count the walk established when it began.
    After {
        at: (u32, u32),
        consumed: usize,
        total: usize,
        total_is_floor: bool,
    },
}

impl ScanStart {
    fn from_origin(origin: &PageOrigin) -> std::result::Result<Self, CursorRefused> {
        match origin {
            PageOrigin::Offset(offset) => Ok(Self::Offset(*offset)),
            PageOrigin::After(cursor) => match cursor.position {
                CursorPosition::Scan {
                    segment_ord,
                    doc_id,
                } => Ok(Self::After {
                    at: (segment_ord, doc_id),
                    consumed: cursor.consumed,
                    total: cursor.total,
                    total_is_floor: cursor.total_is_floor,
                }),
                // Unreachable while the shape check holds — routing is decided
                // by fields the shape covers — but reinterpreting a ranked
                // position as a physical one would silently start the walk in
                // the wrong place, so it is refused instead.
                CursorPosition::Ranked { .. } => Err(CursorRefused::new(
                    CursorRefusal::Malformed,
                    "this paging cursor names a position in a different kind of enumeration \
                     than this query produces. Start the search again from the first page",
                )),
            },
        }
    }
}

/// How an unranked scan decides whether a document matches.
///
/// The plain-keyword and regex routings differ only in this test, in what they
/// highlight, and in nothing else — so they share one loop rather than two that
/// have to be kept in step. They were two loops, and the resume logic would
/// have had to be written into both.
enum ScanMatcher {
    /// A user-supplied regular expression, matched against name and content.
    Regex(Regex),
    /// Plain keyword terms, lower-cased. Every term must appear somewhere (name
    /// or content) — a multi-word keyword query is an AND.
    Substring {
        terms: Vec<String>,
        /// Highlights any occurrence of any term in the returned excerpt.
        highlight: Option<Regex>,
    },
}

impl ScanMatcher {
    /// Whether this matcher has anything to match with. A query of nothing but
    /// whitespace matches no document rather than every document.
    fn is_empty(&self) -> bool {
        match self {
            Self::Regex(_) => false,
            Self::Substring { terms, .. } => terms.is_empty(),
        }
    }

    /// `None` when the document does not match. `Some(true)` when the CONTENT
    /// is what matched, which is where the excerpt is then cut from;
    /// `Some(false)` when only the name did.
    fn test(&self, name: &str, content: &str) -> Option<bool> {
        match self {
            Self::Regex(re) => {
                let name_match = re.is_match(name);
                let content_match = re.is_match(content);
                (name_match || content_match).then_some(content_match)
            }
            Self::Substring { terms, .. } => {
                let name_lower = name.to_lowercase();
                let content_lower = content.to_lowercase();
                let all_present = terms
                    .iter()
                    .all(|t| name_lower.contains(t) || content_lower.contains(t));
                if !all_present {
                    return None;
                }
                Some(terms.iter().any(|t| content_lower.contains(t)))
            }
        }
    }

    fn highlight(&self) -> Option<&Regex> {
        match self {
            Self::Regex(re) => Some(re),
            Self::Substring { highlight, .. } => highlight.as_ref(),
        }
    }
}

/// Downgrade a search result to "at least N" when the index it was served from
/// is known to be missing documents.
///
/// A dropped `add_document` (BUG-161) leaves artifacts unsearchable, so the
/// match count is short by an unknown amount and the rows on screen are not the
/// whole match set. `total_count` is quoted as prevalence, so an exact-looking
/// figure taken from a lossy index is a claim the evidence does not support.
/// Nothing is withheld: the rows still come back, they are just no longer
/// presented as complete.
///
/// Three flags, because the caller has three different decisions to make.
/// `count_is_lower_bound` and `truncated` say the figures are bounded — which
/// they also are for a scan that stopped at its budget, where no row is lost.
/// [`SearchResponse::index_incomplete`] says the ROWS are short, which is true
/// here and true nowhere else, and is what an exhibit's completeness verdict
/// must be decided on.
fn mark_index_incomplete(response: &mut SearchResponse, index_incomplete: bool) {
    if index_incomplete {
        response.count_is_lower_bound = true;
        response.truncated = true;
        response.index_incomplete = true;
    }
}

/// Field handles needed by the blocking regex scan (Field is Copy).
#[derive(Clone, Copy)]
struct RegexSearchFields {
    id: Field,
    case_id: Field,
    artifact_type: Field,
    name: Field,
    content: Field,
    record_kind: Field,
}

/// Normalize user-supplied extensions: strip leading dots, lowercase, drop empties.
/// The artifact-type names in a filter that actually name a type. `?types=,`
/// arrives as two empty strings, and an empty string is not a type.
fn named_types(types: &[String]) -> Vec<String> {
    types.iter().filter(|t| !t.is_empty()).cloned().collect()
}

fn normalize_extensions(extensions: &[String]) -> Vec<String> {
    extensions
        .iter()
        .map(|e| e.trim_start_matches('.').to_lowercase())
        .filter(|e| !e.is_empty())
        .collect()
}

/// Case-insensitive check that a file name ends with one of the extensions.
/// Whether an indexed name ends in one of the requested extensions.
///
/// Since record names carry the file a record is *about* (LIVE-022), this now
/// also matches parsed records — an `exif: FullSizeRender.jpg` row answers an
/// extension filter for `jpg`. That is deliberate: the row genuinely concerns a
/// `.jpg`, and it is the analysis of the very file the examiner asked for. It
/// was previously excluded only because every such record was named
/// "ParsedRecord" and so matched nothing. Narrowing to files alone is what the
/// artifact-type facet is for.
fn name_matches_extensions(name: &str, ext_lower: &[String]) -> bool {
    let name_lower = name.to_lowercase();
    ext_lower
        .iter()
        .any(|ext| name_lower.ends_with(&format!(".{}", ext)))
}

/// Options for configuring a search query
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchOptions {
    /// The search query string. Matched exact-form: no Unicode normalisation
    /// is applied to it or to the indexed text, so a precomposed (NFC) term
    /// does not find the decomposed (NFD) spelling of the same word, nor the
    /// reverse (`VAL-001`, owner decision 2026-09-26).
    pub query: String,
    /// Maximum number of results to return
    pub limit: usize,
    /// Optional filter for specific artifact types
    pub artifact_types: Option<Vec<String>>,
    /// Enable regex mode instead of full-text search
    pub use_regex: bool,
    /// Optional filter by file extensions (e.g., ["exe", "docx"])
    #[serde(default)]
    pub file_extensions: Option<Vec<String>>,
    /// Fuzzy full-text matching with the given Levenshtein edit distance (1 or
    /// 2). `None` = exact term matching. Ignored in regex mode.
    #[serde(default)]
    pub fuzzy: Option<u8>,
}

/// Response from a search query including metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchResponse {
    /// The search results, at most `limit` of them.
    pub results: Vec<SearchResult>,
    /// How many artifacts MATCH the query, which is not `results.len()` once
    /// the limit bites. Callers read this as the term's prevalence in the case
    /// (keyword triage searches with `limit: 1` and shows this number), so it
    /// must never be the size of the returned page.
    ///
    /// Exact unless [`SearchResponse::count_is_lower_bound`] is set.
    pub total_count: usize,
    /// The original query string
    pub query: String,
    /// Set when the query did not parse as a structured query and was taken
    /// **literally** instead, with the sentence saying so.
    ///
    /// An examiner searching for `(901)555-1111` -- a phone number in the form
    /// anybody would type -- used to get a 500: the parentheses are grouping
    /// syntax and the query was a syntax error. A forensic search must not
    /// answer a plain string with an internal server error, and it must not
    /// silently reinterpret one either, so the fall-back is taken and stated.
    ///
    /// Found by running NIST CFTT's Forensic String Search methodology
    /// (`ROADMAP` §5.2), whose published target list includes that number.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query_taken_literally: Option<String>,
    /// Time taken to execute the search in milliseconds
    pub elapsed_ms: u64,
    /// True when the returned rows are not the whole story: more matches exist
    /// beyond `limit`, or the count itself is a floor. Exports should surface
    /// this to the user.
    #[serde(default)]
    pub truncated: bool,
    /// True when `total_count` is a LOWER BOUND, not an exact figure. "At least
    /// N" and "exactly N" must not look alike to an examiner writing a
    /// prevalence figure into a triage note.
    ///
    /// It is a claim about the COUNT and about nothing else, and reading it as
    /// "rows are missing" is wrong on two of its three causes. Set by:
    ///
    /// * the scan stopping at its document/wall-clock budget
    ///   ([`scan_budget_exhausted`]). The count stops there; the WALK does not
    ///   — this page hands back a cursor positioned strictly after the last
    ///   document it examined, and the next page resumes with a fresh budget.
    ///   Follow the cursors and every match is still enumerated.
    /// * an extension post-filter running over a capped candidate window on the
    ///   ranked routing ([`MAX_EXTENSION_CANDIDATES`], and the ordinary case of
    ///   the window simply coming back full). Matches beyond the window were
    ///   never filtered, so they were never counted — but the page resumes from
    ///   the worst-ranked candidate it examined, so they are still walked.
    /// * [`SearchResponse::index_incomplete`], which is the one cause that DOES
    ///   mean rows are gone.
    ///
    /// So a caller that must decide whether an exhibit is short reads
    /// `index_incomplete`, not this. `seance_search/src/lib.rs`'s
    /// `a_budget_stopped_scan_floors_the_count_without_skipping_a_row` pins the
    /// difference.
    #[serde(default)]
    pub count_is_lower_bound: bool,
    /// True when the search index itself is known to be missing documents, so
    /// matches exist that NO page, walk or export of this query can produce.
    ///
    /// The one condition under which rows are genuinely absent rather than
    /// merely uncounted: the writer thread failed to add documents (BUG-161),
    /// so those artifacts are unsearchable until the index is repaired.
    /// Re-running the search does not help, and neither does paging.
    ///
    /// Kept apart from [`SearchResponse::count_is_lower_bound`] because they are
    /// different facts with different remedies, and merging them puts an untrue
    /// sentence into an exhibit: a search export whose walk reached the end used
    /// to be stamped INCOMPLETE — "documents are missing from the search index
    /// … matches … are absent from this file and from every other export of
    /// this query" — because a scan budget had bounded its count. The rows were
    /// all there.
    #[serde(default)]
    pub index_incomplete: bool,
    /// How many matches were skipped before this page was filled — i.e. which
    /// page of the match set `results` is.
    ///
    /// Stated rather than assumed so a page can never be read as the head of
    /// the result set. An export or a screenshot showing rows 1,001–1,100 and a
    /// count of 34,000 is a different document from one showing rows 1–100, and
    /// the two must not be indistinguishable once separated from the request
    /// that produced them.
    #[serde(default)]
    pub offset: usize,
    /// Fingerprint of the index snapshot this response was served from; see
    /// [`index_snapshot`].
    ///
    /// Two responses carrying the same value enumerate one fixed result set, so
    /// their pages join up. Two carrying different values do not, and a caller
    /// paging across the change must say so rather than present the pages as
    /// one walk.
    #[serde(default)]
    pub index_snapshot: String,
    /// An opaque token that continues this walk from where this page stopped,
    /// or `None` when this page is the end of the enumeration.
    ///
    /// This is the route that has no depth ceiling: it names a POSITION rather
    /// than a distance from the start, so the engine resumes rather than
    /// re-walking. `None` is a claim, not a shrug — it means the engine reached
    /// the end of the result set, and a caller may render "that is all of them"
    /// on the strength of it.
    ///
    /// A cursor is only valid against the [`SearchResponse::index_snapshot`] it
    /// was minted under and the query it was minted for; handing it back with
    /// either changed is refused rather than approximated. See
    /// [`SearchService::search_after`].
    #[serde(default)]
    pub next_cursor: Option<String>,
    /// How many stored documents this request retrieved and examined.
    ///
    /// The cost of the request, in the unit that actually dominates it, so the
    /// claim that a cursor page does not re-read the pages behind it is
    /// something a test can assert and an operator can watch rather than
    /// something a comment asserts. An offset page on a scan routing examines
    /// every document in the case however deep it is; a resumed page examines
    /// only what lies ahead of the cursor. The ranked routing reports the
    /// candidates it retrieved, which is a page's worth rather than a case's.
    #[serde(default)]
    pub examined_documents: usize,
}

/// A single search result with optional snippet highlighting
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SearchResult {
    pub artifact_id: Uuid,
    pub case_id: Uuid,
    pub artifact_type: String,
    pub name: String,
    /// Plain-text excerpt centered on the first query-term hit (ellipsized,
    /// cut at word boundaries). Name-only matches return the name itself.
    pub snippet: Option<String>,
    /// Byte-offset [start, end) ranges into `snippet` marking query-term
    /// matches, at most 8 per result.
    #[serde(default)]
    pub highlights: Vec<(usize, usize)>,
    /// Relevance score from Tantivy
    pub score: f32,
    /// The record kind: a parsed record's own `type`, else the artifact type.
    ///
    /// Read from the index rather than fetched per hit from the database, so
    /// the pivot can group a page of hits by kind without a round trip
    /// (§1.0). Empty only for a document written before `record_kind` was
    /// indexed — the caller falls back to `artifact_type` rather than
    /// showing a blank kind.
    #[serde(default)]
    pub record_kind: String,
}

pub struct SearchIndexer {
    search_service: Arc<SearchService>,
}

impl SearchIndexer {
    pub fn new(search_service: Arc<SearchService>) -> Self {
        Self { search_service }
    }
}

impl ForensicsModule for SearchIndexer {
    fn id(&self) -> &str {
        "plugin.search.indexer"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::RawEvidence,
            ArtifactType::Partition,
            ArtifactType::UnallocatedSpace,
            ArtifactType::FileSystem,
            ArtifactType::FileEntry,
            ArtifactType::FileContent,
            ArtifactType::SystemArtifact,
            ArtifactType::ParsedRecord,
            ArtifactType::TimelineEvent,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        // The indexer primarily reads metadata, but might read content later.
        // For now, assume metadata is sufficient, so no direct DataSource capability needed.
        InputCapability::Stream // Or None, if not reading raw data directly
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Index synchronously: adding a document to the writer buffer is a
        // cheap in-memory operation, and doing it inline guarantees the
        // document is included in the next commit. The previous fire-and-forget
        // tokio::spawn lost any documents still in flight when commit ran.
        if let Err(e) = self.search_service.add_artifact_to_index_sync(artifact) {
            error!("Failed to index artifact {}: {}", artifact.id, e);
        }
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {

    /// LIVE-022: record names now carry the file the record is about, so an
    /// extension filter reaches the analysis of that file as well as the file
    /// itself. Pinned because it is a deliberate consequence of the naming fix,
    /// not an accident of string matching.
    #[test]
    fn an_extension_filter_reaches_a_records_subject_file() {
        let exts = super::normalize_extensions(&["jpg".to_string()]);
        assert!(super::name_matches_extensions(
            "exif: FullSizeRender.jpg",
            &exts
        ));
        assert!(super::name_matches_extensions("FullSizeRender.jpg", &exts));
        // A record about something else must still not match.
        assert!(!super::name_matches_extensions("exif: notes.txt", &exts));
        // And a bare type name, which is what these used to be, matches nothing.
        assert!(!super::name_matches_extensions("ParsedRecord", &exts));
    }

    use super::*;

    fn re(pattern: &str) -> Regex {
        RegexBuilder::new(pattern)
            .case_insensitive(true)
            .build()
            .unwrap()
    }

    use seance_core::test_support::TruncatedSource;

    fn test_doc_fields() -> (Schema, DocFields) {
        let mut b = Schema::builder();
        let fields = DocFields {
            id: b.add_text_field("id", STRING | STORED),
            case_id: b.add_text_field("case_id", STRING | STORED),
            artifact_type: b.add_text_field("artifact_type", STRING | STORED),
            name: b.add_text_field("name", TEXT | STORED),
            content: b.add_text_field("content", TEXT | STORED),
            record_kind: b.add_text_field("record_kind", STRING | STORED),
        };
        (b.build(), fields)
    }

    fn indexed_text(doc: &TantivyDocument, field: Field) -> String {
        doc.get_all(field)
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect::<Vec<_>>()
            .join(" ")
    }

    /// UI-008. The indexed content begins with the record's serialised
    /// metadata, so a match in it used to excerpt raw JSON straight onto a
    /// court-facing screen.
    #[test]
    fn a_match_in_a_metadata_field_reads_as_that_field_not_as_json() {
        let content = serde_json::json!({
            "type": "FileSignatureAnalysis",
            "analysis_type": "file_analysis",
            "detected_type": "PNG image data",
            "actual_extension": "txt",
        })
        .to_string();

        let (snippet, highlights) = snippet_for("sig-1", &content, Some(&re("PNG")));
        let snippet = snippet.expect("a snippet is produced");

        assert!(
            !snippet.contains('{') && !snippet.contains("\":\""),
            "the snippet must not be raw JSON: {snippet}"
        );
        assert_eq!(snippet, "Detected type: PNG image data");
        assert_eq!(highlights.len(), 1, "the term is still highlighted");
        let (a, b) = highlights[0];
        assert_eq!(&snippet[a..b], "PNG", "and the highlight points at it");
    }

    /// A term that matches a field *name* rather than a value: the record is
    /// rendered readably instead. Nothing is hidden — every scalar field is
    /// still there — but the braces, quotes and escapes are gone.
    #[test]
    fn a_match_on_a_field_name_renders_the_record_readably() {
        let content = serde_json::json!({
            "type": "FileSignatureAnalysis",
            "detected_type": "PNG image data",
            "size": 4096,
        })
        .to_string();

        let (snippet, _) = snippet_for("sig-1", &content, Some(&re("detected_type")));
        let snippet = snippet.expect("a snippet is produced");

        assert!(!snippet.contains('{'), "{snippet}");
        assert!(
            snippet.contains("Detected type: PNG image data"),
            "{snippet}"
        );
        assert!(
            snippet.contains("Size: 4096"),
            "a numeric field is rendered too: {snippet}"
        );
    }

    /// The file's own bytes are content and must still look like content. A
    /// document whose metadata does not match falls through to the ordinary
    /// text excerpt over the extracted strings.
    #[test]
    fn a_match_in_the_files_own_text_is_excerpted_as_text() {
        let metadata = serde_json::json!({ "name": "notes.txt" }).to_string();
        let content = format!("{metadata}\nthe quick brown fox jumps over the lazy dog");

        let (snippet, highlights) = snippet_for("notes.txt", &content, Some(&re("fox")));
        let snippet = snippet.expect("a snippet is produced");

        assert!(snippet.contains("quick brown fox"), "{snippet}");
        assert!(
            !snippet.contains("Name:"),
            "the metadata did not match; it must not be substituted for the text: {snippet}"
        );
        assert_eq!(highlights.len(), 1);
    }

    /// A content value that is not JSON at all is untouched by any of this.
    #[test]
    fn plain_content_is_excerpted_exactly_as_before() {
        let content = "the quick brown fox jumps over the lazy dog";
        let (snippet, highlights) = snippet_for("notes.txt", content, Some(&re("fox")));
        assert_eq!(snippet.as_deref(), Some(content));
        assert_eq!(highlights.len(), 1);
    }

    /// A JSON *array* at the head of the content is not a record's metadata and
    /// is not treated as one; nor is a truncated object. Both fall through to
    /// the text path rather than being dropped.
    #[test]
    fn content_that_only_looks_like_metadata_falls_through() {
        for head in ["[1,2,3]", "{\"unterminated\": "] {
            let content = format!("{head} fox");
            let (snippet, _) = snippet_for("x", &content, Some(&re("fox")));
            let snippet = snippet.expect("a snippet is produced");
            assert!(
                snippet.contains("fox"),
                "the match must still be shown for {head:?}: {snippet}"
            );
        }
    }

    /// A field value long enough to need cutting is cut the same way any
    /// excerpt is — around the match, with ellipses — and the highlight still
    /// points at the term after the field-name prefix is added.
    #[test]
    fn a_long_metadata_value_is_excerpted_around_the_match() {
        let long = format!("{} needle {}", "a ".repeat(400), "b ".repeat(400));
        let content = serde_json::json!({ "description": long }).to_string();

        let (snippet, highlights) = snippet_for("x", &content, Some(&re("needle")));
        let snippet = snippet.expect("a snippet is produced");

        assert!(snippet.starts_with("Description: ..."), "{snippet}");
        assert!(snippet.ends_with("..."), "{snippet}");
        assert!(snippet.len() < long.len(), "it must actually be cut");
        let (a, b) = highlights[0];
        assert_eq!(&snippet[a..b], "needle");
    }

    #[test]
    fn a_metadata_key_becomes_a_readable_label() {
        assert_eq!(humanise_key("detected_type"), "Detected type");
        assert_eq!(humanise_key("lsn"), "Lsn");
        assert_eq!(humanise_key("target-path"), "Target path");
        // Nothing to work with: returned as it came, never blanked.
        assert_eq!(humanise_key("_"), "_");
        assert_eq!(humanise_key(""), "");
    }

    #[test]
    fn a_short_read_marks_the_indexed_content_incomplete() {
        // B2-117: the loop stops at EOF and indexes what it has. Keywords past
        // the shortfall can never match, so the document must carry a marker
        // rather than look like a fully indexed file.
        let (_schema, fields) = test_doc_fields();
        let source = TruncatedSource::new(b"secret dossier alpha".to_vec(), 4096);
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(source)),
            serde_json::json!({ "name": "notes.txt" }),
        );

        let doc = build_doc(&artifact, &fields).unwrap();
        let text = indexed_text(&doc, fields.content);
        assert!(
            text.contains("secret dossier alpha"),
            "the readable prefix is still searchable: {text}"
        );
        assert!(
            text.contains(INDEX_INCOMPLETE_TOKEN) && text.contains("short_read"),
            "a partially indexed artifact must be findable as such: {text}"
        );
    }

    #[test]
    fn a_fully_indexed_artifact_carries_no_incomplete_marker() {
        let (_schema, fields) = test_doc_fields();
        let data = b"ordinary readable content".to_vec();
        let source = seance_core::data_source::ByteSliceDataSource::new(data);
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(source)),
            serde_json::json!({ "name": "notes.txt" }),
        );

        let doc = build_doc(&artifact, &fields).unwrap();
        let text = indexed_text(&doc, fields.content);
        assert!(
            !text.contains(INDEX_INCOMPLETE_TOKEN),
            "a complete index must not claim incompleteness: {text}"
        );
    }

    #[test]
    fn commit_reports_dropped_documents_as_error() {
        // A successful commit that follows dropped add_document calls must still
        // be an error so ingest learns the index is incomplete (BUG-161).
        assert!(commit_result_with_failures(Ok(()), 3, 0).is_err());
        // No drops: a clean commit stays Ok.
        assert!(commit_result_with_failures(Ok(()), 0, 0).is_ok());
        // A failed commit stays an error regardless of the drop count.
        assert!(commit_result_with_failures(Err(anyhow::anyhow!("io")), 0, 0).is_err());
        assert!(commit_result_with_failures(Err(anyhow::anyhow!("io")), 5, 0).is_err());
    }

    /// B8-044. A commit that failed and was then retried successfully lost
    /// nothing, so it must not be reported as dropped documents — that claims a
    /// short index when the index is whole, which is as wrong as the reverse.
    #[test]
    fn a_retried_commit_is_not_reported_as_lost_documents() {
        assert!(
            commit_result_with_failures(Ok(()), 0, 2).is_ok(),
            "two failed commits followed by a successful one lost no documents"
        );
        // A real drop still wins: documents that never became searchable cannot
        // be recovered by any later commit.
        assert!(commit_result_with_failures(Ok(()), 1, 2).is_err());
    }

    /// The purge guarantee (HUNT-092) is that a deleted case's text is off disk
    /// when the purge returns. Tantivy's file collection can run while the merge
    /// that orphaned the old segment files still protects them, collect nothing,
    /// and leave the text readable until some later pass. Collection is therefore
    /// repeated, a bounded number of times, until nothing is orphaned.
    #[test]
    fn collection_repeats_until_no_orphaned_file_remains() {
        use std::cell::Cell;
        let calls = Cell::new(0usize);
        // Protected for the first two passes, released by the third.
        let leftover = || if calls.get() >= 3 { 0 } else { 2 };
        let left = collect_until_clean(
            || calls.set(calls.get() + 1),
            leftover,
            10,
            std::time::Duration::ZERO,
        );
        assert_eq!(calls.get(), 3, "it stops as soon as the directory is clean");
        assert_eq!(left, 0);
    }

    #[test]
    fn collection_gives_up_after_its_bound_and_says_how_much_was_left() {
        use std::cell::Cell;
        let calls = Cell::new(0usize);
        let left = collect_until_clean(
            || calls.set(calls.get() + 1),
            || 4,
            5,
            std::time::Duration::ZERO,
        );
        assert_eq!(calls.get(), 5, "bounded");
        assert_eq!(left, 4, "the caller is told what is still on disk");
    }

    /// Segments still being merged by tantivy's own background policy refuse a
    /// purge's merge request, and the segment that merge produces can itself
    /// carry marked-deleted documents. The rewrite is therefore repeated against
    /// a fresh listing until no segment holds a deleted document.
    #[test]
    fn the_rewrite_repeats_until_no_segment_holds_a_deleted_document() {
        use std::cell::{Cell, RefCell};
        // Two refusals (segments busy), then the merge goes through.
        let refusals = Cell::new(2usize);
        let with_deletes = RefCell::new(vec![1u32, 2]);
        let mut attempts_made = 0usize;
        let left = rewrite_until_no_deletes(
            || with_deletes.borrow().clone(),
            |ids| {
                attempts_made += 1;
                assert!(!ids.is_empty());
                if refusals.get() > 0 {
                    refusals.set(refusals.get() - 1);
                    return Err("segment is being merged");
                }
                with_deletes.borrow_mut().clear();
                Ok(())
            },
            10,
            std::time::Duration::ZERO,
        );
        assert_eq!(left, 0);
        assert_eq!(attempts_made, 3, "two refusals and the merge that worked");
    }

    #[test]
    fn the_rewrite_gives_up_after_its_bound_and_reports_the_segments_left() {
        let mut tried = 0usize;
        let left = rewrite_until_no_deletes(
            || vec![7u32],
            |_| {
                tried += 1;
                Err("busy")
            },
            4,
            std::time::Duration::ZERO,
        );
        assert_eq!(tried, 4, "bounded");
        assert_eq!(
            left, 1,
            "the caller is told a segment still holds deleted text"
        );
    }

    #[test]
    fn nothing_is_merged_when_no_segment_holds_a_deleted_document() {
        let left = rewrite_until_no_deletes(
            Vec::<u32>::new,
            |_| -> Result<(), &str> { panic!("no merge is needed") },
            4,
            std::time::Duration::ZERO,
        );
        assert_eq!(left, 0);
    }

    /// A clean index lists no orphan, and a merged-away segment's files are
    /// listed until they are collected.
    #[test]
    fn orphaned_segment_files_are_those_of_segments_no_longer_searchable() {
        let dir = tempfile::tempdir().unwrap();
        let (schema, fields) = test_doc_fields();
        let index = Index::create_in_dir(dir.path(), schema).unwrap();
        let mut writer: IndexWriter = index.writer(15_000_000).unwrap();
        for i in 0..3 {
            let mut doc = TantivyDocument::default();
            doc.add_text(fields.id, Uuid::new_v4().to_string());
            doc.add_text(fields.case_id, "c");
            doc.add_text(fields.artifact_type, "File");
            doc.add_text(fields.name, format!("n{i}"));
            doc.add_text(fields.content, "text");
            writer.add_document(doc).unwrap();
            writer.commit().unwrap();
        }
        assert_eq!(orphaned_segment_files(&index), 0);
        let ids: Vec<_> = index
            .searchable_segment_metas()
            .unwrap()
            .iter()
            .map(|m| m.id())
            .collect();
        writer.merge(&ids).wait().unwrap();
        writer.garbage_collect_files().wait().unwrap();
        assert_eq!(
            orphaned_segment_files(&index),
            0,
            "collected files are gone"
        );
    }

    /// B8-044 again, this time on the repair path: a display-name repair batch
    /// whose commit FAILS must leave the staged work counted, because the idle
    /// flush and the final flush both only fire while `since_commit` is
    /// non-zero. Zeroing it unconditionally is what made the original bug
    /// unrecoverable — documents staged, counter at zero, nothing left to
    /// retry them — and the repair path must not reintroduce it.
    #[test]
    fn a_failed_repair_commit_leaves_its_work_countable_for_retry() {
        let dir = tempfile::tempdir().unwrap();
        let (schema, fields) = test_doc_fields();
        let index = Index::create_in_dir(dir.path(), schema).unwrap();
        let mut writer: IndexWriter = index.writer(15_000_000).unwrap();

        let id = Uuid::new_v4();
        let mut doc = TantivyDocument::default();
        doc.add_text(fields.id, id.to_string());
        doc.add_text(fields.case_id, Uuid::new_v4().to_string());
        doc.add_text(fields.artifact_type, "File");
        doc.add_text(fields.name, "repaired.txt");
        doc.add_text(fields.content, "content");

        // Take the index directory away so the batch's commit fails the way a
        // full or vanished disk makes it fail: the documents are staged in the
        // writer and nothing durable was produced. A missing directory refuses
        // every user alike, root included, so this runs everywhere rather than
        // passing silently where permission bits are not enforced.
        let moved = dir.path().with_extension("moved");
        std::fs::rename(dir.path(), &moved).unwrap();

        let mut since_commit = 0usize;
        let result = replace_documents(&mut writer, &fields, vec![(id, doc)], &mut since_commit);

        // Put the directory back before any assertion can unwind, so the
        // TempDir's own cleanup finds it.
        std::fs::rename(&moved, dir.path()).unwrap();

        assert!(
            result.is_err(),
            "a repair batch whose commit could not be written must report failure"
        );
        assert_eq!(
            since_commit, 1,
            "the batch's staged document must still be counted so the idle \
             flush and the final flush retry it (B8-044)"
        );
    }

    /// B8-044 on the Commit and delete arms of the writer: a failed commit must
    /// leave the retry bookkeeping set so the idle flush tries again, and a
    /// successful one clears it. Zeroing the counter regardless left a purged
    /// artifact searchable with nothing scheduled to commit its delete.
    #[test]
    fn a_failed_commit_keeps_the_idle_flush_armed_and_a_good_one_clears_it() {
        let mut since_commit = 0usize;
        let mut failed_at: Option<Instant> = None;

        // A delete staged nothing the counter knew about, then its commit failed.
        settle_commit(
            &Err(anyhow::anyhow!("disk full")),
            &mut since_commit,
            &mut failed_at,
        );
        assert_eq!(since_commit, 1, "staged work must still be retried");
        assert!(failed_at.is_some(), "the retry is paced by the backoff");

        // Work already counted is not reduced by a failure.
        since_commit = 7;
        settle_commit(
            &Err(anyhow::anyhow!("disk full")),
            &mut since_commit,
            &mut failed_at,
        );
        assert_eq!(since_commit, 7);

        settle_commit(&Ok(()), &mut since_commit, &mut failed_at);
        assert_eq!(since_commit, 0);
        assert!(failed_at.is_none());
    }

    #[test]
    fn excerpt_short_content_no_ellipses() {
        let content = "The quick brown fox jumps over the lazy dog";
        let (snippet, highlights) = build_excerpt(content, &re("fox")).unwrap();
        assert_eq!(snippet, content);
        assert_eq!(highlights, vec![(16, 19)]);
        assert_eq!(&snippet[16..19], "fox");
    }

    #[test]
    fn excerpt_no_match_returns_none() {
        assert!(build_excerpt("some text", &re("elephant")).is_none());
    }

    #[test]
    fn excerpt_truncates_with_ellipses_at_word_boundaries() {
        let filler = "word ".repeat(100);
        let content = format!("{filler}needle {filler}");
        let (snippet, highlights) = build_excerpt(&content, &re("needle")).unwrap();
        assert!(snippet.starts_with("..."));
        assert!(snippet.ends_with("..."));
        // Word-boundary cuts: no partial "ord " fragments at either edge
        assert!(
            snippet[3..].starts_with("word "),
            "snippet was: {snippet:?}"
        );
        assert!(snippet.len() <= 6 + 2 * EXCERPT_RADIUS + "needle".len());
        // Highlight offsets index into the returned snippet
        let (s, e) = highlights[0];
        assert_eq!(&snippet[s..e], "needle");
    }

    #[test]
    fn excerpt_is_case_insensitive_and_preserves_original_case() {
        let (snippet, highlights) = build_excerpt("The Windows Registry", &re("windows")).unwrap();
        let (s, e) = highlights[0];
        assert_eq!(&snippet[s..e], "Windows");
    }

    #[test]
    fn excerpt_caps_highlights_at_max() {
        let content = "hit ".repeat(20);
        let (snippet, highlights) = build_excerpt(&content, &re("hit")).unwrap();
        assert_eq!(highlights.len(), MAX_HIGHLIGHTS);
        for (s, e) in highlights {
            assert_eq!(&snippet[s..e], "hit");
        }
    }

    #[test]
    fn excerpt_handles_multibyte_content() {
        let content = format!("{}needle{}", "日本語 ".repeat(40), " 日本語".repeat(40));
        let (snippet, highlights) = build_excerpt(&content, &re("needle")).unwrap();
        let (s, e) = highlights[0];
        assert_eq!(&snippet[s..e], "needle");
    }

    #[test]
    fn query_terms_strips_syntax_and_operators() {
        let terms = query_terms("\"exact phrase\" +required -excluded AND name:foo*");
        assert_eq!(
            terms,
            vec!["exact", "phrase", "required", "excluded", "name", "foo"]
        );
        assert!(query_terms("").is_empty());
    }

    #[test]
    fn snippet_for_falls_back_to_name() {
        // Pattern matches neither content nor name -> bare name, no highlights
        let (snippet, highlights) = snippet_for("report.pdf", "contents", Some(&re("zzz")));
        assert_eq!(snippet.as_deref(), Some("report.pdf"));
        assert!(highlights.is_empty());

        // Pattern matches only the name -> name excerpt with highlights
        let (snippet, highlights) = snippet_for("report.pdf", "contents", Some(&re("report")));
        assert_eq!(snippet.as_deref(), Some("report.pdf"));
        assert_eq!(highlights, vec![(0, 6)]);
    }

    #[test]
    fn test_search_response_truncated_defaults_false_on_deserialize() {
        // Older payloads without the field must still deserialize
        let json = r#"{"results":[],"total_count":0,"query":"q","elapsed_ms":1}"#;
        let response: SearchResponse = serde_json::from_str(json).unwrap();
        assert!(!response.truncated);
        assert!(!response.count_is_lower_bound);
    }

    #[test]
    fn is_plain_query_routes_substring_vs_structured() {
        // Bare keywords (including forensic literals with hyphens/dots/colons)
        // take the substring path.
        assert!(is_plain_query("feel"));
        assert!(is_plain_query("feel good"));
        assert!(is_plain_query("2024-01-02"));
        assert!(is_plain_query("alice@example.com"));
        assert!(is_plain_query("C:/Users/evidence"));
        // Structured syntax stays on the tokenized parser.
        assert!(!is_plain_query("\"exact phrase\""));
        assert!(!is_plain_query("feel AND good"));
        assert!(!is_plain_query("malware NOT clean"));
        assert!(!is_plain_query("(a OR b)"));
        assert!(!is_plain_query("prefix*"));
        // Nothing to match is not "plain".
        assert!(!is_plain_query(""));
        assert!(!is_plain_query("   "));
    }

    /// A resumed scan page is never refused for the reason an OFFSET jump is.
    ///
    /// `SHIP-034` refuses an offset jump the scan's budget cannot reach and says
    /// so by naming the two routes that do reach: the cursor, and the export.
    /// That refusal was not gated on `resuming`, so it fired on **cursor** pages
    /// too — aborting the very walk it recommends, with advice the caller had
    /// just followed. It killed interactive walking and truncated a pinned
    /// export mid-file on any case larger than the scan budget.
    ///
    /// The state that triggers it is not reachable by a short honest walk, which
    /// is why this is a unit test: a resumed page inherits `total` from the
    /// cursor and never recounts, while `offset` is how far the walk has
    /// consumed, so `consumed` overtakes `total` after a few pages on a big
    /// case. All three clauses are put here directly — consumed past the
    /// inherited total, a budget of one document so the page stops early, and a
    /// term that document does not carry so the page comes back empty. That is
    /// the exact shape the guard was matching on.
    #[test]
    fn a_resumed_scan_page_is_not_refused_by_the_offset_jump_guard() {
        let (_dir, svc, case_id) = indexed_service(40);
        let searcher = searcher_for(&svc);

        let response = SearchService::search_scan_blocking(
            searcher,
            regex_fields(&svc),
            case_id,
            plain_opts("absent-from-every-document", false),
            ScanMatcher::Substring {
                terms: vec!["absent-from-every-document".to_string()],
                highlight: None,
            },
            ScanStart::After {
                at: (0, 0),
                consumed: 10,
                total: 3,
                total_is_floor: true,
            },
            0,
            "snapshot".to_string(),
            Instant::now(),
            1,
        )
        .expect(
            "a cursor page must not be refused with the offset-jump error — that error's own \
             advice is to walk by cursor, which is what this is",
        );

        // Served, not refused. An empty page here is the honest answer: this
        // stretch of the enumeration held no match and the walk goes on.
        assert!(response.results.is_empty());
    }

    /// The clamp is stated by whoever reports it, not re-derived.
    ///
    /// `?fuzzy=9` used to reach a court-facing export's preamble verbatim
    /// (`# filter.fuzzy_edit_distance,9`) over an edit-distance-2 match set —
    /// a filter the exhibit claimed and the engine never applied. Two call
    /// sites, one bound.
    #[test]
    fn the_fuzzy_distance_an_export_states_is_the_one_the_engine_uses() {
        assert_eq!(clamp_fuzzy_distance(1), 1);
        assert_eq!(clamp_fuzzy_distance(2), 2);
        // Above the automaton's range, and below it.
        assert_eq!(clamp_fuzzy_distance(9), 2);
        assert_eq!(clamp_fuzzy_distance(255), 2);
        assert_eq!(clamp_fuzzy_distance(0), 1);
    }

    /// The premise the credential redaction rests on: the record's metadata is
    /// the FIRST value of the indexed content, and it is one line.
    ///
    /// `metadata_excerpt` reads `content.split('\n').next()` and refuses to
    /// print a redacted field from it. If `build_doc` ever indexed the file's
    /// text first, or wrote metadata that spanned lines, that read would find
    /// something else and the redaction would silently stop applying — a
    /// security property lost to a reordering nobody connected to it.
    ///
    /// So the premise is asserted here rather than assumed in a comment.
    #[test]
    fn the_indexed_content_begins_with_the_records_metadata_on_one_line() {
        let (_schema, fields) = test_doc_fields();
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            serde_json::json!({
                "type": "MemoryCredential",
                // A newline INSIDE a value: `serde_json` escapes it, so the
                // serialised object is still one line. That is the half of the
                // premise that is about the encoder rather than about order.
                "note": "recovered from\nthe SAM hive",
                "value": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }),
        );

        let doc = build_doc(&artifact, &fields).unwrap();
        let content = joined_content(&doc, fields.content);
        let first_line = content.split('\n').next().unwrap();

        assert!(
            first_line.starts_with('{') && first_line.ends_with('}'),
            "the first line must be the whole serialised metadata: {first_line}"
        );
        let parsed: serde_json::Value = serde_json::from_str(first_line)
            .expect("the first line parses as the record's metadata");
        assert_eq!(parsed["type"], "MemoryCredential");
        assert_eq!(parsed["note"], "recovered from\nthe SAM hive");
    }

    /// A schema change wipes the index and rebuilds it from empty, and an
    /// empty index answers "no matches" — which for a case full of evidence is
    /// a false absence on a court-facing surface. Every search this process
    /// serves must therefore say the index is incomplete until the cases are
    /// backfilled.
    #[tokio::test]
    async fn an_index_rebuilt_for_a_schema_change_says_every_search_is_incomplete() {
        let dir = tempfile::tempdir().expect("temp dir");

        // An index at this path whose schema is NOT the service's: one field,
        // named nothing the service knows. Opening the service over it is the
        // schema mismatch the recovery path exists for.
        {
            let mut b = Schema::builder();
            b.add_text_field("something_else", TEXT | STORED);
            let foreign = b.build();
            let directory = MmapDirectory::open(dir.path()).expect("mmap dir");
            Index::open_or_create(directory, foreign).expect("foreign index");
        }

        let svc = SearchService::new(dir.path()).expect("service rebuilds");
        assert!(
            svc.rebuilt_from_empty,
            "the service must know it started from an empty index"
        );

        // Index one document and search for it: the hit is found, and the
        // response still discloses that the index cannot be relied on for
        // absence, because every OTHER case is still missing from it.
        let case_id = Uuid::new_v4();
        let a = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            serde_json::json!({ "name": "present.txt" }),
        );
        svc.add_artifact_to_index_sync(&a).expect("index");
        svc.commit_sync().expect("commit");

        let page = svc
            .search_page(case_id, plain_opts("present", false), 0)
            .await
            .expect("search");
        assert_eq!(page.results.len(), 1, "the indexed document is found");
        assert!(
            page.index_incomplete,
            "a search over a rebuilt-from-empty index must be marked incomplete"
        );
        assert!(
            page.count_is_lower_bound,
            "its counts are a floor, not a total"
        );
    }

    /// A service over a matching schema makes no such claim: the marker has to
    /// mean something, so it must not fire on an ordinary index.
    /// An artifact that never reached the writer is not in the index. The
    /// ingest indexer only logs the error it gets back, so the service itself
    /// has to count it, or every later search claims an exact, complete index.
    #[tokio::test]
    async fn an_artifact_that_never_reached_the_writer_makes_searches_incomplete() {
        let dir = tempfile::tempdir().expect("temp dir");
        let mut svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let a = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            serde_json::json!({ "name": "lost.txt" }),
        );
        // The service shutting down: the channel is gone.
        drop(svc.command_tx.take());
        assert_eq!(svc.pending_index_failures(), 0);

        assert!(svc.add_artifact_to_index_sync(&a).is_err());
        assert!(svc.add_artifact_replacing_sync(&a).is_err());
        assert_eq!(svc.pending_index_failures(), 2);

        let page = svc
            .search_page(case_id, plain_opts("lost", false), 0)
            .await
            .expect("search");
        assert!(
            page.index_incomplete,
            "a document that was never enqueued must not leave the index claiming completeness"
        );
    }

    #[tokio::test]
    async fn an_ordinary_index_does_not_claim_to_be_incomplete() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        assert!(!svc.rebuilt_from_empty);
        let case_id = Uuid::new_v4();
        let a = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            serde_json::json!({ "name": "present.txt" }),
        );
        svc.add_artifact_to_index_sync(&a).expect("index");
        svc.commit_sync().expect("commit");
        let page = svc
            .search_page(case_id, plain_opts("present", false), 0)
            .await
            .expect("search");
        assert_eq!(page.results.len(), 1);
        assert!(
            !page.index_incomplete,
            "nothing was lost, so nothing is claimed"
        );
    }

    /// The question the backfill asks a page at a time (`LIVE-028`): of these
    /// ids, which does this case already have documents for?
    #[tokio::test]
    async fn the_index_reports_which_of_a_batch_of_ids_it_already_holds() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let other_case = Uuid::new_v4();

        let indexed: Vec<Artifact> = (0..3)
            .map(|i| {
                Artifact::new(
                    case_id,
                    ArtifactType::FileEntry,
                    None,
                    serde_json::json!({ "name": format!("indexed_{i}.txt") }),
                )
            })
            .collect();
        for a in &indexed {
            svc.add_artifact_to_index_sync(a).expect("index");
        }
        // Same id space, different case: present in the index, absent from this
        // case's answer, because the caller is asking about this case.
        let elsewhere = Artifact::new(
            other_case,
            ArtifactType::FileEntry,
            None,
            serde_json::json!({ "name": "elsewhere.txt" }),
        );
        svc.add_artifact_to_index_sync(&elsewhere).expect("index");
        svc.commit_sync().expect("commit");

        let missing = Uuid::new_v4();
        let mut ask: Vec<Uuid> = indexed.iter().map(|a| a.id).collect();
        ask.push(missing);
        ask.push(elsewhere.id);

        let found = svc.indexed_ids_among(case_id, &ask).expect("check");
        assert_eq!(found.len(), 3, "exactly the three this case has");
        for a in &indexed {
            assert!(found.contains(&a.id), "{} must be reported present", a.id);
        }
        assert!(
            !found.contains(&missing),
            "an id with no document must not be reported present"
        );
        assert!(
            !found.contains(&elsewhere.id),
            "a document belonging to another case is not this case's"
        );

        assert!(
            svc.indexed_ids_among(case_id, &[])
                .expect("empty")
                .is_empty(),
            "an empty question has an empty answer, and asks the index nothing"
        );
    }

    /// A keyword search must answer "is this term in the evidence", and the
    /// product's own prose about an artifact is not evidence.
    ///
    /// The MFT parser explains each timestamp indicator in a sentence — "a
    /// copy, which preserves the source's modification time in $SI…" — and on
    /// the NIST CFReDS image 4,026 files carried one. Indexed as content, a
    /// search for `rename` returned 1,386 artifacts, none of them because the
    /// word was in a file. The explanation stays in the metadata the API serves
    /// and the UI renders; it is simply not a word the evidence contains.
    #[tokio::test]
    async fn the_products_own_analysis_prose_is_not_searchable_as_evidence() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            None,
            serde_json::json!({
                "name": "installed.dll",
                "path": "/WINDOWS/system32/installed.dll",
                "timestomp_suspected": false,
                "timestomp_reasons": [],
                "timestamp_indicators": [{
                    "reason": "SI Modified precedes FN Created",
                    "strength": "weak",
                    "also_produced_by":
                        "a copy, which preserves the source's modification time in $SI while $FN \
                         records when the copy landed",
                }],
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        svc.commit_sync().expect("commit");

        for term in ["preserves", "rename", "copy"] {
            let hits = svc.search(case_id, term, 10).await.expect("search");
            assert!(
                hits.is_empty(),
                "'{term}' comes from the tool's own sentence, not from the evidence: {hits:?}"
            );
        }
        // What the evidence does say is still found, and the artifact is still
        // in the index — this removes words, not documents.
        let found = svc
            .search(case_id, "installed.dll", 10)
            .await
            .expect("search");
        assert_eq!(found.len(), 1, "the artifact itself must remain searchable");
    }

    /// A recovered credential's value must not reach a search result.
    ///
    /// `MemoryCredential` records carry the decrypted NT hash in
    /// `metadata.value`, and `seance_api`'s `reveal_memory_credential` is the
    /// **audited** path a value is supposed to travel by — it writes an audit
    /// entry naming the examiner who asked. `build_doc` indexes every
    /// artifact's whole metadata JSON, so the value is in the index; if it also
    /// reaches a snippet, an ordinary search discloses it with nothing in the
    /// custody trail recording that anyone saw it.
    ///
    /// This asserts the snippet, which is what a screen shows. The index itself
    /// is a separate question and is recorded as its own defect.
    #[tokio::test]
    async fn a_recovered_credential_value_is_never_put_in_a_snippet() {
        const HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";

        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let art = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::json!({
                "type": "MemoryCredential",
                "record_type": "MemoryCredential",
                "stage": "credentials",
                "source": "sam",
                "username": "analyst",
                "rid": 1001,
                "format": "nt_hash",
                "value": HASH,
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        svc.commit_sync().expect("commit");

        // The ordinary way an examiner reaches this record: by the account name.
        let results = svc.search(case_id, "analyst", 10).await.expect("search");
        assert_eq!(results.len(), 1, "the record is findable, which is correct");

        let snippet = results[0].snippet.clone().unwrap_or_default();
        assert!(
            !snippet.contains(HASH),
            "the recovered hash reached a search snippet, bypassing the audited \
             reveal endpoint entirely: {snippet}"
        );
        assert!(
            !results[0].name.contains(HASH),
            "nor may it reach the result's name: {}",
            results[0].name
        );

        // Searching for the hash itself must not confirm it either: a snippet
        // echoing the query term back is the same disclosure by another route.
        let by_value = svc.search(case_id, HASH, 10).await.expect("search");
        for hit in &by_value {
            let snippet = hit.snippet.clone().unwrap_or_default();
            assert!(
                !snippet.contains(HASH),
                "searching for the value echoed it back in the snippet: {snippet}"
            );
        }
    }

    /// The record stays findable, and stays readable, minus the one field.
    ///
    /// Redaction that hid the whole record would be its own defect: an examiner
    /// searching for an account would find nothing where a credential record
    /// exists, and a false absence on a court-facing surface is treated here as
    /// severely as a false statement.
    #[tokio::test]
    async fn a_redacted_credential_record_is_still_found_and_still_readable() {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let art = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::json!({
                "type": "MemoryCredential",
                "username": "analyst",
                "rid": 1001,
                "format": "nt_hash",
                "value": "31d6cfe0d16ae931b73c59d7e0c089c0",
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        svc.commit_sync().expect("commit");

        let results = svc.search(case_id, "analyst", 10).await.expect("search");
        assert_eq!(results.len(), 1, "the record must still be findable");

        let snippet = results[0].snippet.clone().unwrap_or_default();
        assert!(snippet.contains("analyst"), "{snippet}");
        assert!(
            snippet.contains("Rid: 1001") || snippet.contains("Username: analyst"),
            "the rest of the record is still shown: {snippet}"
        );
        assert!(
            snippet.contains("audited reveal"),
            "and the withheld value is stated, not silently dropped: {snippet}"
        );
    }

    /// Searching for a hash an examiner already holds finds the record that
    /// carries it. This is the capability `SEC-004` was decided in favour of on
    /// 2026-09-08: the value stays in the index, so pivoting from a hash
    /// recovered in one case to the same hash in another is a search, which is
    /// how a reused local-administrator password is found across a fleet.
    ///
    /// The test is here to make that decision break loudly. Excluding `value`
    /// from the indexed text is a four-line change that no other test would
    /// notice — the snippet is withheld either way — and it would turn this
    /// search into "no results", which on this product's terms is a false
    /// absence. If this test is failing, think before changing it: the
    /// exposure it accepts was weighed once already.
    #[tokio::test]
    async fn a_hash_the_examiner_already_holds_finds_the_record_that_carries_it() {
        const HASH: &str = "31d6cfe0d16ae931b73c59d7e0c089c0";
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let art = Artifact::new(
            case_id,
            ArtifactType::ParsedRecord,
            None,
            serde_json::json!({
                "type": "MemoryCredential",
                "username": "administrator",
                "rid": 500,
                "format": "nt_hash",
                "value": HASH,
            }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        svc.commit_sync().expect("commit");

        let results = svc.search(case_id, HASH, 10).await.expect("search");
        assert_eq!(
            results.len(),
            1,
            "a hash carried in a credential record must be findable by that hash"
        );

        // Found by it, and still not printed by it: the snippet says a value
        // was withheld rather than showing the hash back to the searcher.
        let snippet = results[0].snippet.clone().unwrap_or_default();
        assert!(!snippet.contains(HASH), "{snippet}");
        assert!(snippet.contains("audited reveal"), "{snippet}");
    }

    /// A record whose only substance is the redacted field says what it is
    /// rather than falling through to the raw-JSON excerpt, which is where the
    /// value lives.
    #[tokio::test]
    async fn a_record_that_is_only_a_secret_says_so_instead_of_leaking_it() {
        const HASH: &str = "aad3b435b51404eeaad3b435b51404ee";
        let content = serde_json::json!({ "type": "MemoryCredential", "value": HASH }).to_string();

        let (snippet, highlights) = snippet_for("credential", &content, Some(&re(HASH)));
        let snippet = snippet.expect("a snippet is produced");

        assert!(!snippet.contains(HASH), "{snippet}");
        assert!(snippet.contains("audited reveal"), "{snippet}");
        assert!(highlights.is_empty(), "nothing to highlight but the secret");
    }

    /// And a record that is not a credential is untouched by any of this.
    #[test]
    fn redaction_does_not_reach_past_the_record_type_it_is_for() {
        let content =
            serde_json::json!({ "type": "BrowserCookie", "value": "session-abc" }).to_string();

        let (snippet, _) = snippet_for("cookie", &content, Some(&re("session-abc")));
        assert_eq!(snippet.as_deref(), Some("Value: session-abc"));
    }

    // --- Bounded scan (BUG-123 substring / BUG-086 regex) ---

    /// Index `n` records that all share a common marker into one fresh case.
    fn indexed_service(n: usize) -> (tempfile::TempDir, SearchService, Uuid) {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        for i in 0..n {
            let art = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::json!({ "name": format!("record_{i}"), "marker": "commonmarker" }),
            );
            svc.add_artifact_to_index_sync(&art).expect("index");
        }
        svc.commit_sync().expect("commit");
        (dir, svc, case_id)
    }

    fn searcher_for(svc: &SearchService) -> tantivy::Searcher {
        svc.index.reader().expect("reader").searcher()
    }

    fn regex_fields(svc: &SearchService) -> RegexSearchFields {
        RegexSearchFields {
            id: svc.field_id,
            case_id: svc.field_case_id,
            artifact_type: svc.field_artifact_type,
            name: svc.field_name,
            content: svc.field_content,
            record_kind: svc.field_record_kind,
        }
    }

    fn plain_opts(query: &str, use_regex: bool) -> SearchOptions {
        SearchOptions {
            query: query.to_string(),
            // Far above the match count so only the scan budget, not the result
            // limit, can set `truncated`.
            limit: 1000,
            artifact_types: None,
            use_regex,
            file_extensions: None,
            fuzzy: None,
        }
    }

    #[test]
    fn substring_scan_stops_at_doc_budget_and_flags_truncated() {
        let (_dir, svc, case_id) = indexed_service(5);

        // A 2-document budget must stop the scan early and report truncation,
        // even though all 5 docs match and the result limit is 1000.
        let resp = SearchService::search_substring_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            plain_opts("commonmarker", false),
            0,
            Instant::now(),
            2,
        )
        .unwrap();
        assert!(resp.truncated, "small scan budget must set truncated");
        assert!(
            resp.results.len() <= 2,
            "must not scan past the budget, got {}",
            resp.results.len()
        );

        // A generous budget over the same small case returns everything and is
        // NOT truncated (result semantics unchanged for normal cases).
        let resp_full = SearchService::search_substring_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            plain_opts("commonmarker", false),
            0,
            Instant::now(),
            MAX_SCAN_DOCS,
        )
        .unwrap();
        assert!(
            !resp_full.truncated,
            "full budget over a small case must not truncate"
        );
        assert_eq!(resp_full.results.len(), 5);
    }

    #[test]
    fn regex_scan_stops_at_doc_budget_and_flags_truncated() {
        let (_dir, svc, case_id) = indexed_service(5);

        let resp = SearchService::search_regex_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            plain_opts("record_[0-9]", true),
            0,
            Instant::now(),
            2,
        )
        .unwrap();
        assert!(resp.truncated, "small scan budget must set truncated");
        assert!(
            resp.results.len() <= 2,
            "must not scan past the budget, got {}",
            resp.results.len()
        );

        let resp_full = SearchService::search_regex_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            plain_opts("record_[0-9]", true),
            0,
            Instant::now(),
            MAX_SCAN_DOCS,
        )
        .unwrap();
        assert!(!resp_full.truncated);
        assert_eq!(resp_full.results.len(), 5);
    }

    /// Keyword triage searches each term with `limit: 1` and prints
    /// `total_count` as that term's prevalence. If the scan stops at the limit
    /// and reports the page size, every term in the case reads as one hit and
    /// the triage note understates the evidence.
    #[test]
    fn substring_scan_counts_matches_beyond_the_limit() {
        let (_dir, svc, case_id) = indexed_service(5);

        let mut opts = plain_opts("commonmarker", false);
        opts.limit = 1;
        let resp = SearchService::search_substring_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            opts,
            0,
            Instant::now(),
            MAX_SCAN_DOCS,
        )
        .unwrap();

        assert_eq!(resp.results.len(), 1, "limit must still bound the rows");
        assert_eq!(
            resp.total_count, 5,
            "total_count is the match count, not the page size"
        );
        assert!(
            !resp.count_is_lower_bound,
            "a completed scan yields an exact count"
        );
        assert!(resp.truncated, "1 row of 5 matches is a partial view");
    }

    /// Same contract on the regex scan.
    #[test]
    fn regex_scan_counts_matches_beyond_the_limit() {
        let (_dir, svc, case_id) = indexed_service(5);

        let mut opts = plain_opts("record_[0-9]", true);
        opts.limit = 2;
        let resp = SearchService::search_regex_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            opts,
            0,
            Instant::now(),
            MAX_SCAN_DOCS,
        )
        .unwrap();

        assert_eq!(resp.results.len(), 2);
        assert_eq!(resp.total_count, 5);
        assert!(!resp.count_is_lower_bound);
        assert!(resp.truncated);
    }

    /// A scan cut short by its budget cannot know the true count. It must say
    /// so rather than hand back a floor that reads as exact.
    #[test]
    fn budget_exhausted_scan_marks_the_count_a_lower_bound() {
        let (_dir, svc, case_id) = indexed_service(5);

        for use_regex in [false, true] {
            let query = if use_regex {
                "record_[0-9]"
            } else {
                "commonmarker"
            };
            let mut opts = plain_opts(query, use_regex);
            opts.limit = 1;
            // A 2-document budget over a 5-match case: the scan cannot see the
            // other 3, so it must publish its count as a floor.
            let scan = if use_regex {
                SearchService::search_regex_blocking(
                    searcher_for(&svc),
                    regex_fields(&svc),
                    case_id,
                    opts,
                    0,
                    Instant::now(),
                    2,
                )
            } else {
                SearchService::search_substring_blocking(
                    searcher_for(&svc),
                    regex_fields(&svc),
                    case_id,
                    opts,
                    0,
                    Instant::now(),
                    2,
                )
            };
            let resp = scan.unwrap();

            assert!(
                resp.count_is_lower_bound,
                "a scan stopped by its budget must not claim an exact count (regex={use_regex})"
            );
            assert!(
                resp.total_count <= 2,
                "cannot count past the 2-document budget, got {}",
                resp.total_count
            );
            assert!(resp.truncated);
        }
    }

    /// The same honesty rule applied to a lossy index, on every search route.
    ///
    /// `total_count` is quoted as prevalence, so a search served while the
    /// writer thread has documents it failed to add (BUG-161) must publish its
    /// count as a floor. Otherwise an index that silently lost artifacts hands
    /// an examiner an exact-looking figure, and "not present in this evidence"
    /// becomes indistinguishable from "not indexed".
    #[tokio::test]
    async fn a_lossy_index_makes_every_search_count_a_lower_bound() {
        // Control: a healthy index over the same data claims exactness.
        let (_clean_dir, clean, clean_case) = indexed_service(5);
        let healthy = clean
            .search_with_options(clean_case, plain_opts("commonmarker", false))
            .await
            .unwrap();
        assert_eq!(healthy.total_count, 5);
        assert!(
            !healthy.count_is_lower_bound,
            "a healthy index must not hedge a count it can prove"
        );
        assert!(!healthy.truncated);

        let (_dir, svc, case_id) = indexed_service(5);
        // One document the writer thread could not add: it is not searchable,
        // so no count taken from this index is exact.
        svc.index_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        // All three routes: substring (plain), full-text (query syntax), regex.
        for (query, use_regex) in [
            ("commonmarker", false),
            ("commonmarker OR absent_term", false),
            ("record_[0-9]", true),
        ] {
            let resp = svc
                .search_with_options(case_id, plain_opts(query, use_regex))
                .await
                .unwrap();
            assert!(
                resp.count_is_lower_bound,
                "count from an index missing documents must be a floor ({query})"
            );
            assert!(
                resp.truncated,
                "an incomplete index means an incomplete result set ({query})"
            );
            assert!(
                !resp.results.is_empty(),
                "evidence must still be returned, only marked incomplete ({query})"
            );
        }
    }

    // --- A floor on the COUNT is not a gap in the ROWS ---

    /// Walk a scan routing to the end one budget-limited page at a time,
    /// returning every page. The budget is deliberately smaller than the case,
    /// so every page but the last stops at it.
    fn walk_scan_by_cursor(
        svc: &SearchService,
        case_id: Uuid,
        options: SearchOptions,
        max_scan_docs: usize,
    ) -> Vec<SearchResponse> {
        let shape = result_set_shape(case_id, &options);
        let mut pages: Vec<SearchResponse> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let origin = match &cursor {
                None => PageOrigin::Offset(0),
                Some(token) => PageOrigin::After(SearchCursor::decode(token).expect("decode")),
            };
            let start = ScanStart::from_origin(&origin).expect("scan start");
            let searcher = searcher_for(svc);
            let snapshot = index_snapshot(&searcher);
            let page = SearchService::search_scan_blocking(
                searcher,
                regex_fields(svc),
                case_id,
                options.clone(),
                ScanMatcher::Substring {
                    terms: vec![options.query.to_lowercase()],
                    highlight: None,
                },
                start,
                shape,
                snapshot,
                Instant::now(),
                max_scan_docs,
            )
            .expect("scan page");
            cursor = page.next_cursor.clone();
            pages.push(page);
            if cursor.is_none() {
                break;
            }
            assert!(
                pages.len() < 100,
                "the walk must terminate; a budget-limited scan that never ends \
                 is a hang, not a bound"
            );
        }
        pages
    }

    /// The fact the export's completeness verdict rests on.
    ///
    /// A scan stopped by its document budget publishes its count as a floor,
    /// and that is right: it did not see the rest of the case, so it cannot
    /// state the size of the match set. What it does NOT mean is that rows were
    /// skipped — the next cursor page resumes strictly after the last document
    /// the budget stopped on, so a walk that follows the cursors to the end
    /// still enumerates every match. The two claims are separate facts and an
    /// exhibit that merges them tells the examiner something untrue.
    #[test]
    fn a_budget_stopped_scan_floors_the_count_without_skipping_a_row() {
        let (_dir, svc, case_id) = indexed_service(5);
        let pages = walk_scan_by_cursor(&svc, case_id, plain_opts("commonmarker", false), 2);

        assert!(
            pages.len() > 1,
            "the fixture is only meaningful if the budget actually stopped a \
             page short: got {} page(s)",
            pages.len()
        );
        assert!(
            pages[0].count_is_lower_bound,
            "a scan stopped by its budget must publish its count as a floor"
        );
        assert!(
            pages[0].total_count < 5,
            "and the floor must really be short of the truth, or the fixture \
             proves nothing: {}",
            pages[0].total_count
        );

        let delivered: usize = pages.iter().map(|p| p.results.len()).sum();
        assert_eq!(
            delivered, 5,
            "the walk must still reach every match: the budget bounds one \
             page's work, not the enumeration"
        );
        let mut ids: Vec<String> = pages
            .iter()
            .flat_map(|p| p.results.iter().map(|r| r.artifact_id.to_string()))
            .collect();
        ids.sort();
        ids.dedup();
        assert_eq!(
            ids.len(),
            5,
            "and must reach each of them exactly once: a budget that skipped or \
             repeated rows would be a gap the count flag does not describe"
        );

        for (n, page) in pages.iter().enumerate() {
            assert!(
                !page.index_incomplete,
                "page {n}: nothing is missing from this index. A bounded count \
                 must never assert that rows are absent from the index — that \
                 is the claim an export prints as 'matches exist which are \
                 absent from this file and from every other export'"
            );
        }
    }

    /// Index records under the given file names, all sharing one marker, into
    /// one fresh case. For the extension post-filter tests: what survives the
    /// filter is decided by the name alone.
    fn indexed_named_service(names: &[&str]) -> (tempfile::TempDir, SearchService, Uuid) {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        for name in names {
            let art = Artifact::new(
                case_id,
                ArtifactType::FileEntry,
                None,
                serde_json::json!({ "name": name, "marker": "commonmarker" }),
            );
            svc.add_artifact_to_index_sync(&art).expect("index");
        }
        svc.commit_sync().expect("commit");
        (dir, svc, case_id)
    }

    /// A PHRASE query, so the request takes the ranked routing: a plain
    /// keyword is answered by the substring scan (see `page`).
    fn ranked_opts(limit: usize, extensions: Option<&[&str]>) -> SearchOptions {
        SearchOptions {
            query: "\"commonmarker\"".to_string(),
            limit,
            artifact_types: None,
            use_regex: false,
            file_extensions: extensions
                .map(|exts| exts.iter().map(|e| e.to_string()).collect::<Vec<String>>()),
            fuzzy: None,
        }
    }

    /// Follow a ranked walk from its first page to the page that offers no
    /// continuation, the way the export does.
    async fn walk_ranked_by_cursor(
        svc: &SearchService,
        case_id: Uuid,
        options: SearchOptions,
    ) -> Vec<SearchResponse> {
        let mut pages: Vec<SearchResponse> = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let page = match &cursor {
                None => svc.search_page(case_id, options.clone(), 0).await,
                Some(token) => {
                    svc.search_after(case_id, options.clone(), Some(token))
                        .await
                }
            }
            .expect("ranked page");
            cursor = page.next_cursor.clone();
            pages.push(page);
            if cursor.is_none() {
                break;
            }
            assert!(pages.len() < 200, "the walk must terminate");
        }
        pages
    }

    /// An extension list that normalises to nothing is no filter at all, and
    /// must route as none (CR-033 #1).
    ///
    /// `?extensions=.` reaches the engine as `Some(vec!["."])`: one entry that
    /// survives the API's `is_empty` check and normalises to an empty list.
    /// `ext_active` used to be `file_extensions.is_some()`, which moved the
    /// offset skip out of the collector — and the post-filter block, seeing an
    /// empty normalised list, then declined to drain the skipped rows. Every
    /// page was page 1, under a response that stated the offset it had not
    /// applied.
    #[tokio::test]
    async fn an_extension_list_that_normalises_to_nothing_still_applies_the_offset() {
        let names: Vec<String> = (0..12).map(|i| format!("record_{i}.txt")).collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let (_dir, svc, case_id) = indexed_named_service(&name_refs);

        let first = svc
            .search_page(case_id, ranked_opts(5, Some(&["."])), 0)
            .await
            .expect("first page");
        let second = svc
            .search_page(case_id, ranked_opts(5, Some(&["."])), 5)
            .await
            .expect("second page");

        assert_eq!(first.results.len(), 5);
        assert_eq!(second.results.len(), 5);
        assert_eq!(
            second.offset, 5,
            "the response states the offset it applied"
        );
        assert_eq!(second.total_count, 12);
        let first_ids: std::collections::HashSet<Uuid> =
            first.results.iter().map(|r| r.artifact_id).collect();
        assert!(
            second
                .results
                .iter()
                .all(|r| !first_ids.contains(&r.artifact_id)),
            "page 2 must not repeat page 1: the offset was stated and must have been applied"
        );
    }

    /// A candidate window that holds the whole remaining match set is the END
    /// of the enumeration, not a full window (CR-033 #2).
    ///
    /// `candidates_hit_cap` was `top_docs.len() >= fetch_limit`, which is also
    /// true when the match set is exactly the size of the window. The first
    /// page then floored a count that was exact and minted a cursor into
    /// nothing; a jump was refused with "This is not the end of the match set"
    /// when it was.
    #[tokio::test]
    async fn a_window_that_holds_the_whole_match_set_is_the_end_not_a_full_window() {
        // Ten matches, none of them a .zip. Offset 0 + limit 2 fetches a
        // window of exactly ten candidates.
        let names: Vec<String> = (0..10).map(|i| format!("record_{i}.txt")).collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let (_dir, svc, case_id) = indexed_named_service(&name_refs);

        let first = svc
            .search_page(case_id, ranked_opts(2, Some(&["zip"])), 0)
            .await
            .expect("first page");
        assert!(first.results.is_empty());
        assert_eq!(first.total_count, 0);
        assert!(
            !first.count_is_lower_bound,
            "every candidate was examined, so zero is exact, not a floor"
        );
        assert!(
            first.next_cursor.is_none(),
            "there is nothing past the window to continue into"
        );

        // Offset 1 + limit 1 fetches the same ten. A jump past every survivor
        // in a window that was NOT exhausted is an empty page, not a refusal
        // that claims more matches lie beyond it.
        let jumped = svc
            .search_page(case_id, ranked_opts(1, Some(&["zip"])), 1)
            .await
            .expect("a jump past the end of a fully examined match set is an empty page");
        assert!(jumped.results.is_empty());
        assert!(!jumped.count_is_lower_bound);

        // And a window that really is full still says so: eleven matches
        // against a window of ten leaves one unexamined.
        let mut more: Vec<String> = names.clone();
        more.push("record_10.txt".to_string());
        let more_refs: Vec<&str> = more.iter().map(String::as_str).collect();
        let (_dir2, svc2, case2) = indexed_named_service(&more_refs);
        let capped = svc2
            .search_page(case2, ranked_opts(2, Some(&["zip"])), 0)
            .await
            .expect("first page");
        assert!(
            capped.count_is_lower_bound,
            "one candidate was never filtered"
        );
        assert!(capped.next_cursor.is_some(), "and the walk can go on to it");
    }

    /// A floored count grows as a ranked walk delivers, and becomes exact when
    /// the walk reaches the end (CR-023).
    ///
    /// The first page under a thinly-spread extension filter floors its count
    /// over its own window — "at least 0" or "at least 1" — and resumed pages
    /// took the cursor's figure verbatim. An export of a rare extension wrote
    /// `matching_artifacts,at least 0` into its preamble and `matches 1-100 of
    /// at least 0` into the audit chain while delivering thousands of rows.
    #[tokio::test]
    async fn a_ranked_walks_floor_grows_with_what_it_delivers_and_ends_exact() {
        // Five .zip records spread through a hundred, so a two-row page's
        // ten-candidate window sees at most one of them.
        let names: Vec<String> = (0..100)
            .map(|i| {
                if i % 20 == 0 {
                    format!("archive_{i}.zip")
                } else {
                    format!("record_{i}.txt")
                }
            })
            .collect();
        let name_refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let (_dir, svc, case_id) = indexed_named_service(&name_refs);

        let pages = walk_ranked_by_cursor(&svc, case_id, ranked_opts(2, Some(&["zip"]))).await;
        assert!(
            pages.len() > 1 && pages[0].count_is_lower_bound,
            "the fixture only proves anything if the first page's window was \
             exhausted and the walk went on: {} page(s)",
            pages.len()
        );

        let delivered: usize = pages.iter().map(|p| p.results.len()).sum();
        assert_eq!(delivered, 5, "the walk still reaches every match");

        for (n, page) in pages.iter().enumerate() {
            assert!(
                page.total_count >= page.offset + page.results.len(),
                "page {n}: a walk that has delivered {} rows cannot state a total of {}{}",
                page.offset + page.results.len(),
                if page.count_is_lower_bound {
                    "at least "
                } else {
                    ""
                },
                page.total_count
            );
        }
        let last = pages.last().expect("at least one page");
        assert!(
            !last.count_is_lower_bound,
            "the page that reaches the end has seen everything and states an exact count"
        );
        assert_eq!(last.total_count, 5);
    }

    /// The same statement for the scan routing: a resumed page inherits a
    /// floor, and the floor must not lag what the walk has handed out (CR-023).
    #[test]
    fn a_scans_floor_grows_with_what_it_delivers_and_ends_exact() {
        let (_dir, svc, case_id) = indexed_service(5);
        let pages = walk_scan_by_cursor(&svc, case_id, plain_opts("commonmarker", false), 2);
        assert!(pages.len() > 1 && pages[0].count_is_lower_bound);

        for (n, page) in pages.iter().enumerate() {
            assert!(
                page.total_count >= page.offset + page.results.len(),
                "page {n}: stated total {} lags the {} rows delivered",
                page.total_count,
                page.offset + page.results.len()
            );
        }
        let last = pages.last().expect("at least one page");
        assert!(
            !last.count_is_lower_bound,
            "the last page ran out of documents"
        );
        assert_eq!(last.total_count, 5);
    }

    /// A type list of nothing but empty names is no type filter, on both
    /// routings — the cursor shape already said so, and the results disagreed.
    #[tokio::test]
    async fn a_type_list_of_empty_names_is_no_filter_on_either_routing() {
        let (_dir, svc, case_id) = indexed_service(4);
        let empty_types = Some(vec![String::new(), String::new()]);

        let mut scan = plain_opts("commonmarker", false);
        scan.artifact_types = empty_types.clone();
        let page = svc.search_with_options(case_id, scan).await.expect("scan");
        assert_eq!(
            page.total_count, 4,
            "the scan must not filter on an empty name"
        );

        let mut ranked = ranked_opts(10, None);
        ranked.artifact_types = empty_types;
        let page = svc
            .search_with_options(case_id, ranked)
            .await
            .expect("ranked");
        assert_eq!(page.total_count, 4, "nor may the ranked routing");

        // A real name beside an empty one still filters on the real one.
        let mut mixed = ranked_opts(10, None);
        mixed.artifact_types = Some(vec!["ParsedRecord".to_string(), String::new()]);
        let page = svc
            .search_with_options(case_id, mixed)
            .await
            .expect("ranked");
        assert_eq!(page.total_count, 4);
        let mut other = ranked_opts(10, None);
        other.artifact_types = Some(vec!["FileEntry".to_string(), String::new()]);
        let page = svc
            .search_with_options(case_id, other)
            .await
            .expect("ranked");
        assert_eq!(page.total_count, 0);
    }

    /// A jump the scan cannot reach within its budget is refused, not served
    /// as an empty page (SHIP-034). The page would carry a floored count and no
    /// rows, which is exactly what the end of the match set looks like — and
    /// the match set has not ended, the budget has. The first page is exempt:
    /// it is where a walk starts, and it carries the cursor.
    #[test]
    fn a_jump_past_the_scan_budget_is_refused_and_names_the_reach() {
        let (_dir, svc, case_id) = indexed_service(5);
        let options = plain_opts("commonmarker", false);

        let first = SearchService::search_substring_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            options.clone(),
            0,
            Instant::now(),
            2,
        )
        .expect("the first page is never refused");
        assert!(first.count_is_lower_bound && first.next_cursor.is_some());

        let err = SearchService::search_substring_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            options,
            3,
            Instant::now(),
            2,
        )
        .expect_err("a jump the budget cannot reach must be refused");
        let refused = err
            .downcast_ref::<OffsetUnreachable>()
            .unwrap_or_else(|| panic!("the refusal must be typed: {err}"));
        assert_eq!(refused.offset, 3);
        assert!(
            refused.reachable < 3,
            "reach {} is short of the jump",
            refused.reachable
        );
        assert_eq!(refused.examined, 2, "the budget is what stopped the walk");
        let message = refused.to_string();
        assert!(message.contains("not the end of the match set") && message.contains("export"));

        // The reason must be the one that actually applied. This query carries
        // NO extension filter (`plain_opts` sets `file_extensions: None`) and
        // this routing does not rank, so the extension-post-filter sentence is
        // false of it in three separate claims. A refusal that names the wrong
        // reason is worse than one that names none: an examiner reading it would
        // go looking for an extension filter to relax.
        assert_eq!(refused.cause, OffsetUnreachableCause::ScanBudget);
        assert!(
            !message.contains("extension"),
            "no extension filter was in play: {message}"
        );
        assert!(
            !message.contains("ranked by relevance"),
            "a scan is not ranked: {message}"
        );
        assert!(
            message.contains("scanning") && message.contains("budget"),
            "the refusal must name the limit that actually stopped it: {message}"
        );
    }

    /// The refusal must not name the offset it is refusing as one that works.
    ///
    /// `reachable` is a COUNT of rows and the guard is `offset >= reachable`, so
    /// the deepest offset actually served is one less. Printing `reachable` as
    /// the reach meant that at `offset == reachable` the sentence refused offset
    /// 12 and, in the same breath, told the examiner offset 12 was the deepest
    /// one it could reach. Acting on that advice is refused again with identical
    /// wording. The help page promises this surface "states how deep a jump
    /// reaches", so it is a false statement about what the server will serve.
    #[test]
    fn the_refusal_states_a_reachable_offset_not_the_one_it_just_refused() {
        for cause in [
            OffsetUnreachableCause::ExtensionPostFilter,
            OffsetUnreachableCause::ScanBudget,
        ] {
            // The boundary case: the offset asked for is exactly the count.
            let at_boundary = OffsetUnreachable {
                offset: 12,
                reachable: 12,
                examined: 5000,
                cause,
            };
            let message = at_boundary.to_string();
            assert!(
                message.contains("deepest 'offset' it can be given is 11"),
                "the deepest offset is one less than the count of reachable \
                 rows: {message}"
            );
            assert!(
                message.contains("only those 12 rows"),
                "the count of rows a jump reaches is still worth stating, as a \
                 count: {message}"
            );

            // A reach of zero is stated without underflowing. Offset 0 is exempt
            // from the refusal and is served empty with a cursor, so naming it is
            // true.
            let none = OffsetUnreachable {
                offset: 1,
                reachable: 0,
                examined: 5000,
                cause,
            };
            assert!(
                none.to_string()
                    .contains("deepest 'offset' it can be given is 0"),
                "{}",
                none.to_string()
            );
        }
    }

    /// The other side of the same line, and the only thing on it.
    ///
    /// A document the writer thread failed to add is not in the index, so it is
    /// not in any page, any walk, or any export of any query — and re-running
    /// will not produce it. That is the one condition that genuinely means rows
    /// are missing, so it is the one condition that may say so.
    #[tokio::test]
    async fn only_a_lossy_index_reports_rows_missing_rather_than_a_bounded_count() {
        let (_clean_dir, clean, clean_case) = indexed_service(5);
        let healthy = clean
            .search_with_options(clean_case, plain_opts("commonmarker", false))
            .await
            .unwrap();
        assert!(!healthy.count_is_lower_bound);
        assert!(
            !healthy.index_incomplete,
            "a healthy index must not report itself as missing documents"
        );

        let (_dir, svc, case_id) = indexed_service(5);
        svc.index_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let lossy = svc
            .search_with_options(case_id, plain_opts("commonmarker", false))
            .await
            .unwrap();
        assert!(
            lossy.index_incomplete,
            "documents the writer thread dropped are absent from every result \
             set this index can produce, and that has to be sayable on its own"
        );
        assert!(
            lossy.count_is_lower_bound,
            "and the count is a floor as well — but the count being a floor is \
             the weaker of the two facts and must not be the only one on record"
        );
    }

    /// A pathological regex whose compiled program exceeds the size limit must
    /// fail to build (fail closed) rather than consume unbounded memory.
    #[test]
    fn oversized_regex_fails_closed() {
        let (_dir, svc, case_id) = indexed_service(1);
        // Nested counted repetition of a non-literal atom: ~4M instructions,
        // well past REGEX_SIZE_LIMIT. `a?` prevents collapse to a plain literal.
        let result = SearchService::search_regex_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            plain_opts("(?:(?:a?){2000}){2000}", true),
            0,
            Instant::now(),
            MAX_SCAN_DOCS,
        );
        assert!(
            result.is_err(),
            "over-complex regex must be rejected at build"
        );
    }

    /// Index one FileEntry whose *bytes* carry a keyword that appears nowhere in
    /// its metadata. The `content` field then holds two values: the metadata
    /// JSON and the extracted file text.
    fn service_with_body_keyword() -> (tempfile::TempDir, SearchService, Uuid) {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let body = b"ransom note follows: zebracrossing at midnight".to_vec();
        let art = Artifact::new(
            case_id,
            ArtifactType::FileEntry,
            Some(Arc::new(
                seance_core::data_source::ByteSliceDataSource::new(body),
            )),
            serde_json::json!({ "name": "notes.txt", "path": "/evidence/notes.txt" }),
        );
        svc.add_artifact_to_index_sync(&art).expect("index");
        svc.commit_sync().expect("commit");
        (dir, svc, case_id)
    }

    #[test]
    fn regex_search_matches_keywords_that_live_only_in_the_file_body() {
        // B5-001: `content` is multi-valued (metadata JSON + extracted file
        // text). The regex scan read only the first value, so a keyword present
        // solely in the file's bytes came back as "not present in evidence" —
        // while plain substring search over the same case found it.
        let (_dir, svc, case_id) = service_with_body_keyword();

        let regex_resp = SearchService::search_regex_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            plain_opts("zebracross(ing)?", true),
            0,
            Instant::now(),
            MAX_SCAN_DOCS,
        )
        .unwrap();
        assert_eq!(
            regex_resp.results.len(),
            1,
            "regex mode must see the file body, not just the metadata JSON"
        );

        // Plain substring mode is the reference answer: the two modes must agree
        // about what is in the evidence.
        let substr_resp = SearchService::search_substring_blocking(
            searcher_for(&svc),
            regex_fields(&svc),
            case_id,
            plain_opts("zebracrossing", false),
            0,
            Instant::now(),
            MAX_SCAN_DOCS,
        )
        .unwrap();
        assert_eq!(
            substr_resp.results.len(),
            regex_resp.results.len(),
            "plain and regex search must not disagree about the same evidence"
        );

        // The excerpt must come from the matching body text too.
        let snippet = regex_resp.results[0].snippet.clone().unwrap_or_default();
        assert!(
            snippet.contains("zebracrossing"),
            "regex excerpt must quote the matching file text: {snippet}"
        );
    }

    #[tokio::test]
    async fn tokenized_snippets_quote_the_matching_file_body() {
        // B7-022: the tokenized/fuzzy path matches across every `content` value
        // but excerpted only the first one, so a real hit in the file body was
        // presented with a metadata-JSON snippet that never contains the term.
        let (_dir, svc, case_id) = service_with_body_keyword();

        // A quoted phrase routes to the tokenized parser rather than the
        // substring scan.
        let resp = svc
            .search_with_options(case_id, plain_opts("\"zebracrossing\"", false))
            .await
            .unwrap();
        assert_eq!(resp.results.len(), 1, "tokenized index matches all values");
        let snippet = resp.results[0].snippet.clone().unwrap_or_default();
        assert!(
            snippet.contains("zebracrossing"),
            "excerpt must show the matched body text, not the metadata JSON: {snippet}"
        );
        assert!(
            !resp.results[0].highlights.is_empty(),
            "a body match must be highlighted"
        );
    }

    /// Seed the index with a document shaped the way documents were written
    /// BEFORE the LIVE-022 naming fix: `name` is the bare artifact type, while
    /// the metadata JSON sitting in `content` names the file the record is
    /// about. `build_doc` cannot produce that shape any more, so reproducing
    /// the stale state means going round it to the writer command directly —
    /// which is why this fixture has to live in-crate.
    ///
    /// `extra_content` is appended as a second `content` value, standing in for
    /// the bounded file text a FileEntry carries.
    fn service_with_stale_document(
        artifact_type: &str,
        metadata: &str,
        extra_content: Option<&str>,
    ) -> (tempfile::TempDir, SearchService, Uuid, Uuid) {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let artifact_id = Uuid::new_v4();
        let mut stale = doc!(
            svc.field_id => artifact_id.to_string(),
            svc.field_case_id => case_id.to_string(),
            svc.field_artifact_type => artifact_type.to_string(),
        );
        stale.add_text(svc.field_name, artifact_type);
        stale.add_text(svc.field_content, metadata);
        if let Some(text) = extra_content {
            stale.add_text(svc.field_content, text);
        }
        svc.commands()
            .expect("writer channel")
            .send(IndexCommand::Add(Box::new(stale)))
            .expect("enqueue stale document");
        svc.commit_sync().expect("commit");
        (dir, svc, case_id, artifact_id)
    }

    #[tokio::test]
    async fn refreshing_display_names_renames_a_stale_parsed_record_document() {
        // LIVE-022 follow-up: the naming fix only reaches documents written
        // after it shipped. A case indexed before it keeps showing the literal
        // word "ParsedRecord" in every result row, and re-ingesting the
        // evidence was the only way to change that.
        let (_dir, svc, case_id, artifact_id) = service_with_stale_document(
            "ParsedRecord",
            r#"{"subtype":"FileSignatureAnalysis","source_name":"FullSizeRender.jpg"}"#,
            None,
        );

        let before = svc.search(case_id, "FullSizeRender", 10).await.unwrap();
        assert_eq!(before.len(), 1, "the fixture must be searchable to start");
        assert_eq!(
            before[0].name, "ParsedRecord",
            "the fixture must reproduce the pre-fix state"
        );

        let outcome = svc.refresh_case_display_names(case_id).await.unwrap();
        assert_eq!(outcome.documents, 1);
        assert_eq!(outcome.renamed, 1);
        assert_eq!(outcome.undecodable, 0);

        let after = svc.search(case_id, "FullSizeRender", 10).await.unwrap();
        assert_eq!(after.len(), 1, "the document must survive its own repair");
        assert_eq!(
            after[0].artifact_id, artifact_id,
            "a repaired document must still point at the same artifact"
        );
        assert_eq!(
            after[0].name, "FileSignatureAnalysis: FullSizeRender.jpg",
            "the name must be recomputed from the metadata already indexed"
        );
    }

    #[tokio::test]
    async fn a_repaired_document_keeps_its_record_kind() {
        // The pivot groups by `record_kind` straight from the index; a repair
        // that rebuilt the document without it left an empty kind and sent every
        // renamed hit back to the database for it.
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let seed = |kind: Option<&str>, word: &str| {
            let mut stale = doc!(
                svc.field_id => Uuid::new_v4().to_string(),
                svc.field_case_id => case_id.to_string(),
                svc.field_artifact_type => "ParsedRecord",
            );
            stale.add_text(svc.field_name, "ParsedRecord");
            stale.add_text(
                svc.field_content,
                format!(r#"{{"subtype":"Sub","source_name":"{word}.jpg"}}"#),
            );
            if let Some(kind) = kind {
                stale.add_text(svc.field_record_kind, kind);
            }
            svc.commands()
                .expect("writer channel")
                .send(IndexCommand::Add(Box::new(stale)))
                .expect("enqueue stale document");
        };
        seed(Some("StoredKind"), "withkind");
        seed(None, "nokind");
        svc.commit_sync().expect("commit");

        let outcome = svc.refresh_case_display_names(case_id).await.unwrap();
        assert_eq!(outcome.renamed, 2);

        let with = svc.search(case_id, "withkind", 10).await.unwrap();
        assert_eq!(with.len(), 1);
        assert_eq!(
            with[0].record_kind, "StoredKind",
            "the stored kind must survive the repair"
        );
        let without = svc.search(case_id, "nokind", 10).await.unwrap();
        assert_eq!(without.len(), 1);
        assert_eq!(
            without[0].record_kind, "ParsedRecord",
            "a document with no kind is given the one build_doc would give it"
        );
    }

    #[tokio::test]
    async fn a_repaired_document_keeps_the_text_extracted_from_the_file_body() {
        // The reason this repair reads the index rather than the database: a
        // DB-loaded artifact carries `data: None`, so rebuilding from the
        // database would drop every keyword that lives only inside a file's
        // bytes and present it to an examiner as "not in evidence" (B5-001).
        // Re-emitting the document must carry ALL of its `content` values.
        let (_dir, svc, case_id, _artifact_id) = service_with_stale_document(
            "FileEntry",
            r#"{"path":"/evidence/notes.txt","subtype":"ext4"}"#,
            Some("ransom note follows: zebracrossing at midnight"),
        );

        assert_eq!(
            svc.search(case_id, "zebracrossing", 10)
                .await
                .unwrap()
                .len(),
            1,
            "the body keyword must match before the repair"
        );

        let outcome = svc.refresh_case_display_names(case_id).await.unwrap();
        assert_eq!(outcome.renamed, 1);

        let after = svc.search(case_id, "zebracrossing", 10).await.unwrap();
        assert_eq!(
            after.len(),
            1,
            "a keyword that lives only in the file body must survive the repair"
        );
        assert_eq!(after[0].name, "ext4: notes.txt");
        let snippet = after[0].snippet.clone().unwrap_or_default();
        assert!(
            snippet.contains("zebracrossing"),
            "the excerpt must still be able to quote the body text: {snippet}"
        );
    }

    #[tokio::test]
    async fn a_document_whose_metadata_will_not_parse_is_counted_and_left_searchable() {
        // A document we cannot rename is not a document we may drop. The repair
        // discloses it as undecodable and leaves it exactly as it was, so the
        // case is never made less searchable by being repaired.
        let (_dir, svc, case_id, _artifact_id) =
            service_with_stale_document("ParsedRecord", "{not valid json: sasquatch", None);

        let outcome = svc.refresh_case_display_names(case_id).await.unwrap();
        assert_eq!(outcome.documents, 1);
        assert_eq!(outcome.renamed, 0);
        assert_eq!(
            outcome.undecodable, 1,
            "a document that cannot be renamed must be disclosed, not hidden"
        );

        let after = svc.search(case_id, "sasquatch", 10).await.unwrap();
        assert_eq!(after.len(), 1, "the undecodable document must still match");
        assert_eq!(after[0].name, "ParsedRecord");
    }

    #[tokio::test]
    async fn repeating_the_repair_changes_nothing_the_second_time() {
        // Documents whose name is already what `display_name` would compute are
        // never deleted and never re-added: a second run is a read-only pass.
        // That is what makes the operation safe to re-run after a failure.
        let (_dir, svc, case_id, _artifact_id) = service_with_stale_document(
            "ParsedRecord",
            r#"{"subtype":"exif","source_name":"IMG_0042.JPG"}"#,
            None,
        );

        assert_eq!(
            svc.refresh_case_display_names(case_id)
                .await
                .unwrap()
                .renamed,
            1
        );
        let second = svc.refresh_case_display_names(case_id).await.unwrap();
        assert_eq!(second.documents, 1);
        assert_eq!(second.renamed, 0, "a repaired case must settle");

        let after = svc.search(case_id, "IMG_0042", 10).await.unwrap();
        assert_eq!(after.len(), 1, "and must not be duplicated by the re-run");
        assert_eq!(after[0].name, "exif: IMG_0042.JPG");
    }

    #[tokio::test]
    async fn a_case_larger_than_one_batch_is_repaired_without_losing_documents() {
        // The repair replaces documents in bounded batches, so the batch
        // boundary is where a document would go missing if the delete and the
        // re-add ever came apart. A case with more documents than fit in one
        // batch pins that they do not.
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let count = 1200;
        for i in 0..count {
            let metadata = format!(r#"{{"subtype":"exif","source_name":"IMG_{i:04}.JPG"}}"#);
            let mut stale = doc!(
                svc.field_id => Uuid::new_v4().to_string(),
                svc.field_case_id => case_id.to_string(),
                svc.field_artifact_type => "ParsedRecord".to_string(),
            );
            stale.add_text(svc.field_name, "ParsedRecord");
            stale.add_text(svc.field_content, &metadata);
            svc.commands()
                .expect("writer channel")
                .send(IndexCommand::Add(Box::new(stale)))
                .expect("enqueue stale document");
        }
        svc.commit_sync().expect("commit");

        let outcome = svc.refresh_case_display_names(case_id).await.unwrap();
        assert_eq!(outcome.documents, count);
        assert_eq!(outcome.renamed, count);
        assert_eq!(outcome.undecodable, 0);

        let after = svc.search(case_id, "IMG_", count * 2).await.unwrap();
        assert_eq!(
            after.len(),
            count,
            "every document must survive its batch, and none may be duplicated"
        );
        assert!(
            after.iter().all(|r| r.name.starts_with("exif: IMG_")),
            "every document must carry its repaired name"
        );
    }

    /// Seed one case with `count` documents shaped the way they were written
    /// before the LIVE-022 naming fix, so that a repair over this case has real
    /// work to do in every batch. Returns the artifact ids in the order they
    /// were enqueued.
    ///
    /// Like [`service_with_stale_document`] this has to go round `build_doc`,
    /// which cannot produce the stale shape any more, and so has to live
    /// in-crate.
    fn service_with_stale_case(
        count: usize,
    ) -> (tempfile::TempDir, SearchService, Uuid, Vec<Uuid>) {
        let dir = tempfile::tempdir().expect("temp dir");
        let svc = SearchService::new(dir.path()).expect("service");
        let case_id = Uuid::new_v4();
        let mut ids = Vec::with_capacity(count);
        for i in 0..count {
            let artifact_id = Uuid::new_v4();
            ids.push(artifact_id);
            let metadata = format!(r#"{{"subtype":"exif","source_name":"IMG_{i:04}.JPG"}}"#);
            let mut stale = doc!(
                svc.field_id => artifact_id.to_string(),
                svc.field_case_id => case_id.to_string(),
                svc.field_artifact_type => "ParsedRecord".to_string(),
            );
            stale.add_text(svc.field_name, "ParsedRecord");
            stale.add_text(svc.field_content, &metadata);
            svc.commands()
                .expect("writer channel")
                .send(IndexCommand::Add(Box::new(stale)))
                .expect("enqueue stale document");
        }
        svc.commit_sync().expect("commit");
        (dir, svc, case_id, ids)
    }

    /// A progress callback that parks the repair the first time it has examined
    /// `at` documents, tells the test it is parked, and waits to be released.
    /// With a 500-document batch, parking at 600 leaves the first batch
    /// committed and the second half built — the state in which the repair is
    /// holding purged evidence in memory.
    fn parked_progress(
        at: usize,
    ) -> (
        impl Fn(usize, usize) + Send + 'static,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        let (reached_tx, reached_rx) = std::sync::mpsc::channel::<()>();
        let (resume_tx, resume_rx) = std::sync::mpsc::channel::<()>();
        let progress = move |examined: usize, _total: usize| {
            if examined == at {
                let _ = reached_tx.send(());
                let _ = resume_rx.recv();
            }
        };
        (progress, reached_rx, resume_tx)
    }

    /// Block until the parked repair says it is parked, without stalling the
    /// test's runtime: the callback is running on the blocking pool and the
    /// wait for it has to happen there too.
    async fn wait_until_parked(reached_rx: std::sync::mpsc::Receiver<()>) {
        tokio::task::spawn_blocking(move || reached_rx.recv())
            .await
            .expect("rendezvous task")
            .expect("the repair must reach the point it was asked to park at");
    }

    /// A pin taken while a purge is landing must never keep serving what that
    /// purge destroyed.
    ///
    /// The invariant is stated in terms an examiner can check, not in terms of
    /// the counter that implements it: **once a case has been purged from the
    /// index, no pinned searcher may serve its documents.** A pin whose snapshot
    /// predates the purge is allowed to fail — that is `PinRevoked::Purged`, and
    /// the walk restarts — but it is not allowed to succeed and hand back
    /// destroyed evidence, because the caller holding the pin is an export
    /// writing rows into an exhibit.
    ///
    /// The defect this pins: `pin_searcher_with_idle_limit` read the purge
    /// counter AFTER taking the searcher. `count_purge` bumps that counter after
    /// the purge's commit, so a purge that both committed and incremented inside
    /// the acquisition window was already counted in `purges_at_pin`. The
    /// counter then never moved again, the pin never revoked, and it walked a
    /// snapshot still holding every purged document for as long as the export
    /// ran. Reading the counter first cannot fail that way: a stale snapshot
    /// always has the increment land after the value the pin recorded.
    ///
    /// ONE purge, not many, and that is the point. A burst of purges hides the
    /// defect — the pin misses the purge it raced, then the next purge's
    /// increment revokes it anyway — which is exactly the shape a stress loop
    /// produces and why one passes against the broken ordering. The case that
    /// reaches an exhibit is the quiet one: a single deletion during a long
    /// export, with nothing following it to move the counter again.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn a_pin_racing_one_purge_never_keeps_serving_the_purged_documents() {
        const DOCS: usize = 50;
        // Wide enough that the purge lands inside it with room to spare; the
        // straddle assertion below fails the test rather than passing quietly
        // if it ever does not.
        const WINDOW_MS: u64 = 600;
        const PURGE_AT_MS: u64 = 120;

        let dir = tempfile::tempdir().expect("temp dir");
        let svc = Arc::new(SearchService::new(dir.path()).expect("service"));
        let case_id = Uuid::new_v4();
        for i in 0..DOCS {
            let art = Artifact::new(
                case_id,
                ArtifactType::ParsedRecord,
                None,
                serde_json::json!({ "name": format!("record_{i}"), "marker": "commonmarker" }),
            );
            svc.add_artifact_to_index_sync(&art).expect("index");
        }
        svc.commit_sync().expect("commit");

        let opts = || SearchOptions {
            query: "commonmarker".to_string(),
            limit: 50,
            artifact_types: None,
            use_regex: false,
            file_extensions: None,
            fuzzy: None,
        };

        // The single purge, timed to land in the middle of the pin acquisition.
        let purger = {
            let svc = svc.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(PURGE_AT_MS)).await;
                svc.delete_case(case_id).await.expect("delete case");
            })
        };

        PIN_ACQUIRE_WINDOW_MS.store(WINDOW_MS, Ordering::SeqCst);
        let pin = svc.pin_searcher().expect("pin");
        PIN_ACQUIRE_WINDOW_MS.store(0, Ordering::SeqCst);
        purger.await.expect("purge task");

        // The case is gone from the index. A fresh searcher proves it.
        let fresh = svc
            .search_with_options(case_id, opts())
            .await
            .expect("search after purge");
        assert!(
            fresh.results.is_empty(),
            "the purge did not take: {} document(s) still in the live index",
            fresh.results.len(),
        );

        match svc.search_after_pinned(&pin, case_id, opts(), None).await {
            // Revoked. The correct outcome: the walk is stopped and restarted.
            Err(_) => {}
            Ok(page) if page.results.is_empty() => panic!(
                "the pin holds a POST-purge snapshot, so the purge never landed inside the \
                 acquisition window and this test proved nothing. Widen WINDOW_MS or check \
                 that pin_acquire_window() still sits between the two observations"
            ),
            Ok(page) => panic!(
                "the pin served {} purged document(s) — the first was {} — after the case had \
                 been deleted from the index. A pin that outlives a purge must revoke, not hand \
                 destroyed evidence to the export holding it",
                page.results.len(),
                page.results[0].artifact_id,
            ),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_case_deleted_mid_repair_is_not_put_back_by_that_repair() {
        // `delete_case` purges the case's documents and fails the whole
        // deletion closed if that purge does not land, because an index that
        // still describes destroyed evidence keeps answering searches with it.
        // A repair in flight holds documents read before the purge and re-adds
        // them afterwards by artifact id, which would quietly undo it. The
        // repair must stop instead.
        let (_dir, svc, case_id, _ids) = service_with_stale_case(1200);
        let svc = Arc::new(svc);
        let (progress, reached_rx, resume_tx) = parked_progress(600);

        let repair = {
            let svc = svc.clone();
            tokio::spawn(async move {
                svc.refresh_case_display_names_with_progress(case_id, progress)
                    .await
            })
        };
        wait_until_parked(reached_rx).await;

        // The delete lands between two batches, with the repair holding the
        // rest of the case in memory.
        svc.delete_case(case_id).await.expect("the purge must land");
        let _ = resume_tx.send(());

        let repair_result = repair.await.expect("repair task");

        // The custody assertion first, because it is the one that matters: the
        // purge was fail-closed and must still be in force.
        assert_eq!(
            svc.search(case_id, "IMG_", 4000).await.unwrap().len(),
            0,
            "the purge must stand: a deleted case's documents may not return to the index"
        );
        let err = repair_result
            .expect_err("a repair overtaken by a delete must stop rather than report a success");
        assert!(
            err.to_string().contains("deleted from the search index"),
            "the repair must say why it stopped, so the audit trail can: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_delete_racing_a_repair_batch_still_leaves_the_case_purged() {
        // The delete that is hardest to reason about is the one that reaches
        // the writer while a batch is already queued: it lands between that
        // batch's read and its commit. Both orders have to be safe, so this
        // test does not fix one — it releases the repair and the delete
        // together and asserts the invariant that must hold either way. If the
        // delete is processed first the batch is refused; if the batch is
        // processed first the delete that follows sweeps it up.
        let (_dir, svc, case_id, _ids) = service_with_stale_case(1200);
        let svc = Arc::new(svc);
        let (progress, reached_rx, resume_tx) = parked_progress(600);

        let repair = {
            let svc = svc.clone();
            tokio::spawn(async move {
                svc.refresh_case_display_names_with_progress(case_id, progress)
                    .await
            })
        };
        wait_until_parked(reached_rx).await;

        let purge = {
            let svc = svc.clone();
            tokio::spawn(async move { svc.delete_case(case_id).await })
        };
        // Deliberately not awaited before the repair resumes.
        let _ = resume_tx.send(());

        let repair_result = repair.await.expect("repair task");
        purge
            .await
            .expect("purge task")
            .expect("the purge itself must succeed");

        assert_eq!(
            svc.search(case_id, "IMG_", 4000).await.unwrap().len(),
            0,
            "however the delete and the repair batch interleave, the purge must stand"
        );
        if let Err(e) = repair_result {
            assert!(
                e.to_string().contains("deleted from the search index"),
                "a repair that stopped must say why: {e}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_artifact_deleted_mid_repair_is_not_put_back_by_that_repair() {
        // The same resurrection is available one artifact at a time: an
        // examiner deleting a single artifact during a repair would watch it
        // reappear in search results. The interlock does not distinguish which
        // case the deleted artifact belonged to, so this repair stops too.
        let (_dir, svc, case_id, ids) = service_with_stale_case(1200);
        let svc = Arc::new(svc);
        let doomed = ids[900];
        let (progress, reached_rx, resume_tx) = parked_progress(600);

        let repair = {
            let svc = svc.clone();
            tokio::spawn(async move {
                svc.refresh_case_display_names_with_progress(case_id, progress)
                    .await
            })
        };
        wait_until_parked(reached_rx).await;

        svc.delete_artifact(doomed).await.expect("the purge lands");
        let _ = resume_tx.send(());

        let repair_result = repair.await.expect("repair task");
        let after = svc.search(case_id, "IMG_", 4000).await.unwrap();
        assert!(
            after.iter().all(|r| r.artifact_id != doomed),
            "a deleted artifact must not be re-added to the index by a repair in flight"
        );
        assert_eq!(
            after.len(),
            1199,
            "and stopping the repair must cost the case nothing else: every other document \
             stays searchable, merely with the name it already had"
        );
        let err = repair_result
            .expect_err("a repair overtaken by a delete must stop rather than report a success");
        assert!(
            err.to_string().contains("deleted from the search index"),
            "the repair must say why it stopped: {err}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_repair_no_delete_interrupts_still_reports_its_renames() {
        // The interlock must not make ordinary repairs fail. Nothing is deleted
        // here, so the pass has to run to the end and report what it did.
        let (_dir, svc, case_id, _ids) = service_with_stale_case(1200);
        let outcome = svc
            .refresh_case_display_names(case_id)
            .await
            .expect("an uninterrupted repair must succeed");
        assert_eq!(outcome.documents, 1200);
        assert_eq!(outcome.renamed, 1200);
        assert_eq!(svc.search(case_id, "IMG_", 4000).await.unwrap().len(), 1200);
    }
}

#[cfg(test)]
mod killed_writer_tests {
    use super::*;

    /// HUNT-075. Tantivy kills its writer when an indexing worker dies — a full
    /// disk is the ordinary cause — and every later call returns the same
    /// error. Recognising it is what separates "this write failed" from "every
    /// write from here on will fail until the process restarts".
    #[test]
    fn tantivys_own_sentences_are_recognised() {
        // Both of tantivy 0.22's phrasings, quoted from its source.
        assert!(writer_was_killed(&"An index writer was killed."));
        assert!(writer_was_killed(
            &"The index writer was killed. It can happen if an indexing worker encountered \
              an error"
        ));
        // Wrapped in the shapes the call sites actually hold.
        let wrapped =
            anyhow::anyhow!("An index writer was killed.").context("search index commit failed");
        assert!(writer_was_killed(&format!("{wrapped:#}")));

        // An ordinary failure is not a death: treating it as one would drop and
        // reopen the writer on every full-disk commit.
        assert!(!writer_was_killed(&"No space left on device"));
        assert!(!writer_was_killed(&"Failed to open Tantivy index"));
    }

    /// A command that arrives while there is no writer must be ANSWERED. The
    /// callers of every responder-carrying command block on it; one that never
    /// receives leaves an examiner's delete or commit hanging with nothing said.
    #[test]
    fn commands_arriving_with_no_writer_are_refused_not_dropped() {
        let failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let (tx, rx) = std::sync::mpsc::channel();
        let lost = refuse_command(IndexCommand::DeleteCase(Uuid::new_v4(), tx), &failures, 0);
        let answer = rx.recv().expect("the caller is answered, not left waiting");
        assert!(answer.is_err());
        assert!(
            answer.unwrap_err().to_string().contains("did not happen"),
            "the refusal must say the write did not happen"
        );
        assert_eq!(lost, 0, "a delete is not a lost document");

        // An add has no responder, so the only way it can be reported is the
        // failure counter that makes a search say `index_incomplete`.
        let doc = TantivyDocument::default();
        let lost = refuse_command(IndexCommand::Add(Box::new(doc)), &failures, 3);
        assert_eq!(lost, 4, "documents lost while dead are counted");
        assert_eq!(failures.load(Ordering::Relaxed), 1);
    }
}

/// What the index can and cannot find inside a file's bytes.
///
/// These exist because a search that returns nothing is read as "the term is
/// absent from the evidence", and until 2026-09-15 three whole classes of text
/// were silently not findable. Measured by running the real extractor:
///
/// | bytes | indexed as |
/// |---|---|
/// | ASCII `SecretKey` | `SecretKey` |
/// | UTF-16LE `SecretKey` | `SecretKey` |
/// | UTF-16BE `SecretKey` | `SecretKe` — **minus its last character** |
/// | UTF-8 `cañón` | nothing at all |
/// | UTF-16LE `cañón` | `n` |
///
/// The UTF-16BE case came of sniffing for a zero byte *after* a printable one,
/// which in big-endian order lands on the byte before each character's own
/// null and so drops the final character of every run. The other two came of a
/// byte-wise printable test that treats every byte over `0x7e` as a separator,
/// so an accented or non-Latin word is shredded into fragments below the
/// minimum run length and discarded.
///
/// None of that was a theoretical concern: NIST CFTT's Forensic String Search
/// key asks for 220 hits in UTF-16BE, 217 in UTF-16LE and terms including
/// `cañón`.
#[cfg(test)]
mod searchable_text_tests {
    use super::{extract_searchable_text, MIN_STRING_LEN};

    /// Wrap in non-printable bytes, the way a real file surrounds a string.
    fn embedded(bytes: &[u8]) -> Vec<u8> {
        let mut out = vec![0xFF, 0x00, 0xFF];
        out.extend_from_slice(bytes);
        out.extend_from_slice(&[0xFF, 0x00, 0xFF]);
        out
    }

    fn utf16le(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn utf16be(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_be_bytes).collect()
    }

    fn finds(bytes: &[u8], term: &str) -> bool {
        extract_searchable_text(bytes)
            .to_lowercase()
            .contains(&term.to_lowercase())
    }

    #[test]
    fn ascii_text_is_found() {
        assert!(finds(&embedded(b"SecretKey"), "SecretKey"));
        assert!(finds(&embedded(b"the quick brown fox"), "quick"));
    }

    /// A term whose trailing space is part of it — 35 rows of the CFTT key ask
    /// for one, and `plan ` is not `plan`.
    #[test]
    fn a_term_with_a_trailing_space_is_found_with_its_space() {
        assert!(finds(&embedded(b"the plan for friday"), "plan "));
    }

    #[test]
    fn utf16le_text_is_found() {
        assert!(finds(&embedded(&utf16le("SecretKey")), "SecretKey"));
    }

    /// **The off-by-one.** A UTF-16BE run was indexed without its last
    /// character, so the full term missed and the term-minus-one-character hit.
    #[test]
    fn utf16be_text_is_found_including_its_last_character() {
        let bytes = embedded(&utf16be("SecretKey"));
        assert!(
            finds(&bytes, "SecretKey"),
            "got {:?}",
            extract_searchable_text(&bytes)
        );
    }

    /// **Non-ASCII text in UTF-8 is found.** `cañón` is a real term in the
    /// CFTT key and was findable in no encoding at all.
    #[test]
    fn non_ascii_utf8_text_is_found() {
        let e = embedded("cañón".as_bytes());
        assert!(finds(&e, "cañón"), "got {:?}", extract_searchable_text(&e));
    }

    /// Non-Latin scripts in UTF-8, for the same reason: a byte-wise ASCII
    /// test made every one of them invisible.
    #[test]
    fn a_non_latin_script_is_found_in_utf8() {
        // Each at least MIN_STRING_LEN characters: `密码` is two, and a
        // two-character run is discarded in every encoding, which is the
        // bound that keeps a binary file out of the index.
        for term in ["Пароль", "密码文件", "パスワード", "كلمة"] {
            let e = embedded(term.as_bytes());
            assert!(
                finds(&e, term),
                "{term}: got {:?}",
                extract_searchable_text(&e)
            );
        }
    }

    /// **And CJK and Korean text in UTF-16 is still NOT found**, which is what
    /// remains of `SEARCH-002`, by owner decision (2026-09-26).
    ///
    /// Accented Latin and the single-block alphabets (Greek, Cyrillic,
    /// Hebrew, Arabic, kana) are found since 2026-09-26, each unit vouched
    /// for by a structural test. CJK ideographs and Hangul span dozens of
    /// high bytes, so no single-block test can guard them, and random bytes
    /// would put about one junk run per hundred alignments into the index.
    /// The search universe statement says so and points at the byte sweep,
    /// which does search them.
    ///
    /// When this changes, this test fails, and that is the point: it must not
    /// be possible to change it without the statement, the help and the
    /// register entry saying so.
    #[test]
    fn cjk_and_hangul_utf16_text_is_still_not_found_and_that_is_search_002() {
        for term in ["密码文件", "東京都庁", "서울특별시"] {
            for (label, bytes) in [("utf-16le", utf16le(term)), ("utf-16be", utf16be(term))] {
                let e = embedded(&bytes);
                assert!(
                    !finds(&e, term),
                    "{term} in {label} is now findable — SEARCH-002, the universe statement \
                     and this test must all be updated to say so: got {:?}",
                    extract_searchable_text(&e)
                );
            }
        }
    }

    /// **Accented Latin text in UTF-16 is found** (`SEARCH-002`, first half).
    ///
    /// A code unit in U+00C0–U+00FE still has a zero high byte — the same
    /// structural signal the ASCII-range pass relies on — so the Latin-1
    /// letters (less `×` and `÷`) are accepted in both byte orders. The terms
    /// are the Latin-1 NFC terms of NIST CFTT's string-search key.
    #[test]
    fn latin1_accented_text_in_utf16_is_found() {
        for term in ["cañón", "Schönheit", "garçon", "Mäuse", "libertà", "mañana"] {
            for (label, bytes) in [("utf-16le", utf16le(term)), ("utf-16be", utf16be(term))] {
                let e = embedded(&bytes);
                assert!(
                    finds(&e, term),
                    "{term} in {label}: got {:?}",
                    extract_searchable_text(&e)
                );
            }
        }
    }

    /// The same for decomposed (NFD) Latin text in UTF-16: a combining mark
    /// from U+0300–U+036F is kept when it follows a character of a run in
    /// progress, the rule the UTF-8 pass applies (`VAL-001`). Without it a
    /// UTF-16 `man` + U+0303 + `ana` was indexed as `ana` alone.
    #[test]
    fn a_decomposed_latin_term_in_utf16_is_found_with_its_combining_mark() {
        for term in ["man\u{303}ana", "liberta\u{300}", "Ma\u{308}use"] {
            for (label, bytes) in [("utf-16le", utf16le(term)), ("utf-16be", utf16be(term))] {
                let e = embedded(&bytes);
                assert!(
                    finds(&e, term),
                    "{term:?} in {label}: got {:?}",
                    extract_searchable_text(&e)
                );
            }
        }
    }

    /// **Alphabets that fit in one high byte are found in UTF-16**
    /// (`SEARCH-002`, second half): Greek, Cyrillic, Hebrew, Arabic and kana.
    /// A run's non-ASCII units must all share one high byte, and that byte
    /// must be one of those blocks — the noise control, measured below.
    #[test]
    fn single_block_scripts_in_utf16_are_found() {
        for term in [
            "Пароль",
            "Россия",
            "Сибирь",
            "الكسكس",
            "فلافل",
            "みつびし",
            "Ελλάδα",
            "שלום",
            // ASCII inside a run of one script is still one run.
            "==> Россия 1063",
        ] {
            for (label, bytes) in [("utf-16le", utf16le(term)), ("utf-16be", utf16be(term))] {
                let e = embedded(&bytes);
                assert!(
                    finds(&e, term),
                    "{term} in {label}: got {:?}",
                    extract_searchable_text(&e)
                );
            }
        }
    }

    /// A run that changes script block mid-way is broken there: alternating
    /// Cyrillic and Arabic units never make a run of four, so nothing of
    /// them is kept. This is the coherence test that keeps two arbitrary
    /// bytes from being read as a letter.
    #[test]
    fn a_run_that_changes_script_block_is_not_accepted() {
        let units: [u16; 8] = [
            0x041F, 0x0627, 0x0430, 0x0644, 0x0440, 0x0643, 0x043E, 0x0633,
        ];
        for bytes in [
            units
                .iter()
                .flat_map(|u| u.to_le_bytes())
                .collect::<Vec<u8>>(),
            units
                .iter()
                .flat_map(|u| u.to_be_bytes())
                .collect::<Vec<u8>>(),
        ] {
            let runs = utf16_runs_of(&embedded(&bytes));
            assert!(
                runs.iter().all(|r| r.chars().all(|c| (c as u32) < 0x100)),
                "got {runs:?}"
            );
        }
    }

    /// **The script-coherence rule adds no measurable noise.** Measured
    /// 2026-09-26 on the fixed megabyte: **zero** fragments with a character
    /// at or above U+0100 came out of the UTF-16 passes, against the
    /// `懿戀㴀Ø揞搀`-class runs an any-alphabetic rule produced from the same
    /// kind of input. A guard, like the Latin-1 one: it passed before the
    /// change too. It does not measure structured binary (a table of `u16`
    /// values in 0x0400–0x04FF is read as Cyrillic, and that rate is not
    /// measured).
    #[test]
    fn script_coherent_utf16_adds_no_measurable_noise() {
        let runs = utf16_runs_of(&lcg_megabyte());
        let scripted: Vec<&String> = runs
            .iter()
            .filter(|r| r.chars().any(|c| (c as u32) >= 0x100))
            .collect();
        assert_eq!(scripted.len(), 0, "{scripted:?}");
    }

    /// **ASCII digit text is not read as UTF-16 kana.** The kana block's high
    /// byte 0x30 is ASCII `0`, so 8-bit text like `01020304050607` is, two
    /// bytes at a time, U+3031–U+3037 — kana iteration marks and Hangzhou
    /// numerals, which are "numeric" and were indexed as `〱〲〳〴〵`. The kana
    /// block is taken from U+3041 up (the kana themselves), so an ASCII digit
    /// after a `0` (U+3030–U+3039) is never a letter. Synthetic bytes: pins the
    /// mechanism only.
    #[test]
    fn ascii_digit_text_is_not_read_as_utf16_kana() {
        for text in [&b"01020304050607"[..], b"x 0102030405060708090 y"] {
            let runs = utf16_runs_of(&embedded(text));
            let kana: Vec<&String> = runs
                .iter()
                .filter(|r| r.chars().any(|c| (c as u32) >= 0x100))
                .collect();
            assert!(
                kana.is_empty(),
                "{:?} gave {kana:?}",
                String::from_utf8_lossy(text)
            );
        }
    }

    /// **A recorded limitation, not a guarantee: ASCII hex text still reads as
    /// kana.** `0D0A0D0A`, `0a0b0c0d` and `0x0A0B0C0D` are, byte for byte, the
    /// UTF-16 of real hiragana (`い`, `ぁ`, `ち`, `へ` …), as `0B0W0L0h0F` is the
    /// UTF-16BE of `あしがとう` — so no local test tells them
    /// apart without also dropping real kana words such as `つづいて`. The
    /// index therefore holds kana junk from such text, and a kana search can
    /// hit it. This test pins that the residue exists so that a change which
    /// removes it is noticed and the caveat is withdrawn with it.
    #[test]
    fn ascii_hex_text_still_reads_as_kana_and_that_is_recorded() {
        let runs = utf16_runs_of(&embedded(b"0D0A0D0A0D0A"));
        assert!(runs.iter().any(|r| r.contains("いぁいぁ")), "got {runs:?}");
    }

    /// The published bytes of three UTF-16BE CFTT targets, quoted so the test
    /// runs without the image. Each is `dd bs=1 skip=<hit-10> count=36` of
    /// NIST CFTT's `ss-win-07-25-18.dd`, the hit offsets taken from the data
    /// set's own `win_hit-dump.txt`: `Россия` [1063] at 8492430, `みつびし`
    /// [2311] at 8303994, `الكسكس` [1479] at 8140146. They pin the mechanism
    /// on real evidence bytes; the end-to-end grade is the CFTT re-run.
    #[test]
    fn the_real_utf16be_bytes_of_single_block_cftt_targets_are_indexed() {
        let russia: [u8; 36] = [
            0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3e, 0x00, 0x20, 0x04, 0x20, 0x04, 0x3e,
            0x04, 0x41, 0x04, 0x41, 0x04, 0x38, 0x04, 0x4f, 0x00, 0x20, 0x00, 0x31, 0x00, 0x30,
            0x00, 0x36, 0x00, 0x33, 0x00, 0x20, 0x00, 0x3c,
        ];
        let kana: [u8; 36] = [
            0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3e, 0x00, 0x20, 0x30, 0x7f, 0x30, 0x64,
            0x30, 0x73, 0x30, 0x57, 0x00, 0x20, 0x00, 0x32, 0x00, 0x33, 0x00, 0x31, 0x00, 0x31,
            0x00, 0x20, 0x00, 0x3c, 0x00, 0x3d, 0x00, 0x3d,
        ];
        let arabic: [u8; 36] = [
            0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3e, 0x00, 0x20, 0x06, 0x27, 0x06, 0x44,
            0x06, 0x43, 0x06, 0x33, 0x06, 0x43, 0x06, 0x33, 0x00, 0x20, 0x00, 0x31, 0x00, 0x34,
            0x00, 0x37, 0x00, 0x39, 0x00, 0x20, 0x00, 0x3c,
        ];
        for (bytes, term) in [
            (&russia[..], "Россия"),
            (&kana[..], "みつびし"),
            (&arabic[..], "الكسكس"),
        ] {
            let text = extract_searchable_text(bytes);
            assert!(text.contains(term), "{term}: got {text:?}");
        }
    }

    /// The published bytes of a UTF-16LE CFTT target, quoted so the test runs
    /// without the image: `dd bs=1 skip=8054140 count=40` of NIST CFTT's
    /// `ss-win-07-25-18.dd` gives `====> Schönheit 2502` in UTF-16LE, `ö` as
    /// the unit `f6 00`. The key places `Schönheit` (id 2502, utf-16-le) at
    /// byte 8054152. This pins the mechanism on real evidence bytes; the
    /// end-to-end grade is the CFTT re-run in `VALIDATION.md`.
    #[test]
    fn the_real_utf16le_bytes_of_a_cftt_target_are_indexed() {
        let real: [u8; 40] = [
            0x3d, 0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3d, 0x00, 0x3e, 0x00, 0x20, 0x00, 0x53, 0x00,
            0x63, 0x00, 0x68, 0x00, 0xf6, 0x00, 0x6e, 0x00, 0x68, 0x00, 0x65, 0x00, 0x69, 0x00,
            0x74, 0x00, 0x20, 0x00, 0x32, 0x00, 0x35, 0x00, 0x30, 0x00, 0x32, 0x00,
        ];
        let text = extract_searchable_text(&real);
        assert!(text.contains("Schönheit"), "got {text:?}");
    }

    /// The exact bytes at a published CFTT offset, so the extractor is measured
    /// against the evidence rather than against a fixture that resembles it.
    ///
    /// `dd bs=1 skip=9368745 count=16` of `ss-win-07-25-18.dd`:
    ///
    /// ```text
    /// 3d 3d 3e 20 6d 61 c3 b1 61 6e 61 20 32 39 36 31   ==> ma..ana 2961
    /// ```
    ///
    /// `c3 b1` is U+00F1, precomposed — so the file holds NFC `mañana`, and a
    /// search for it must match with no normalisation step at all.
    #[test]
    fn the_real_bytes_of_a_cftt_target_are_indexed() {
        let real: &[u8] = &[
            0x3d, 0x3d, 0x3e, 0x20, 0x6d, 0x61, 0xc3, 0xb1, 0x61, 0x6e, 0x61, 0x20, 0x32, 0x39,
            0x36, 0x31,
        ];
        let text = extract_searchable_text(real);
        assert!(
            text.contains("mañana"),
            "the extractor must index the term the published key puts at that offset: got {text:?}"
        );
    }

    /// A run shorter than the minimum is still discarded, in every encoding —
    /// that bound is what keeps a binary file from filling the index with
    /// two-character noise.
    #[test]
    fn a_run_below_the_minimum_length_is_still_discarded() {
        assert_eq!(MIN_STRING_LEN, 4);
        assert!(!finds(&embedded(b"cat"), "cat"));
        assert!(!finds(&embedded(&utf16le("cat")), "cat"));
        assert!(finds(&embedded(b"cats"), "cats"));
    }

    /// **Binary noise must not explode the index.** A megabyte of random bytes
    /// decodes as very little text, and a change that made non-ASCII findable
    /// must not have made every high byte a character.
    #[test]
    fn random_bytes_do_not_become_text() {
        // A deterministic pseudo-random megabyte: no `rand` dependency, and a
        // fixed input so the bound below is a fact rather than a sample.
        let mut bytes = Vec::with_capacity(1 << 20);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..(1 << 20) {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            bytes.push((x >> 16) as u8);
        }
        let text = extract_searchable_text(&bytes);
        assert!(
            text.len() < bytes.len() / 4,
            "a megabyte of noise produced {} characters of \"text\", which would fill the \
             index with nothing",
            text.len()
        );
    }

    /// The fixed pseudo-random megabyte the noise tests measure against: no
    /// `rand` dependency, and a fixed input so each bound is a fact rather
    /// than a sample. Synthetic by design — what it measures is the
    /// acceptance rate on arbitrary bytes, which is exactly what it exercises.
    fn lcg_megabyte() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(1 << 20);
        let mut x: u32 = 0x1234_5678;
        for _ in 0..(1 << 20) {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            bytes.push((x >> 16) as u8);
        }
        bytes
    }

    /// The UTF-16 passes alone, both byte orders, split into kept runs.
    fn utf16_runs_of(bytes: &[u8]) -> Vec<String> {
        let mut out = String::new();
        super::utf16_runs(bytes, super::Endian::Little, &mut out);
        out.push('\u{0}');
        super::utf16_runs(bytes, super::Endian::Big, &mut out);
        // Runs are space-separated and may hold spaces, so this yields
        // fragments rather than whole runs. That is enough for the tests that
        // use it: they count fragments holding a non-ASCII character, and a
        // run holds one exactly when one of its fragments does.
        out.split(['\u{0}', ' '])
            .filter(|r| !r.is_empty())
            .map(str::to_string)
            .collect()
    }

    /// **Widening UTF-16 to Latin-1 letters adds no measurable noise.**
    ///
    /// Measured 2026-09-26 on the fixed megabyte: **zero** fragments holding
    /// a U+00C0–U+00FE character came out of the UTF-16 passes (a run of four
    /// needs four consecutive units with a zero high byte, under 2^-32 per
    /// alignment on uniform bytes). The bound is that measurement, so a
    /// change that loosens the rule fails here. A guard rather than a
    /// red/green test: it passed before the widening too. It says nothing
    /// about STRUCTURED binary — a table of little-endian `u16` values
    /// 0xC0–0xFE is indexed as Latin-1 text — and that is not measured.
    #[test]
    fn latin1_widening_adds_no_measurable_noise() {
        let runs = utf16_runs_of(&lcg_megabyte());
        let latin1: Vec<&String> = runs
            .iter()
            .filter(|r| r.chars().any(|c| ('\u{C0}'..='\u{FE}').contains(&c)))
            .collect();
        assert_eq!(latin1.len(), 0, "{latin1:?}");
    }

    /// A four-byte UTF-8 character is decoded whole, and a character that is
    /// **not a letter or a digit** breaks the run rather than joining it.
    ///
    /// An emoji is a symbol, not alphabetic, so it is a separator -- the same
    /// rule that keeps a binary file's punctuation out of the index. This test
    /// was written the other way round first, on the assumption that "decoded
    /// whole" meant "indexed": it does not, and the two halves either side of
    /// the symbol are runs in their own right.
    #[test]
    fn a_four_byte_utf8_character_breaks_a_run_rather_than_joining_it() {
        let text = extract_searchable_text(&embedded("abcd\u{1F600}efgh".as_bytes()));
        assert!(text.contains("abcd"), "got {text:?}");
        assert!(text.contains("efgh"), "got {text:?}");
        assert!(
            !text.contains("abcd\u{1F600}efgh"),
            "a symbol is a separator, not a letter: got {text:?}"
        );

        // A four-byte ALPHABETIC character is kept: U+20000, a CJK ideograph
        // in plane 2.
        let deep = "abcd\u{20000}efgh";
        let text = extract_searchable_text(&embedded(deep.as_bytes()));
        assert!(text.contains(deep), "got {text:?}");

        // And in UTF-16 the run breaks at the surrogate rather than losing
        // what follows it.
        for bytes in [utf16le("abcd\u{1F600}efgh"), utf16be("abcd\u{1F600}efgh")] {
            let wide = extract_searchable_text(&embedded(&bytes));
            assert!(wide.contains("abcd"), "got {wide:?}");
            assert!(wide.contains("efgh"), "got {wide:?}");
        }
    }

    /// An unpaired surrogate is not a character, and must not stop the run it
    /// sits in from being read — a carved or truncated file produces them.
    #[test]
    fn an_unpaired_surrogate_does_not_lose_the_rest_of_the_run() {
        let mut bytes = utf16le("before");
        bytes.extend_from_slice(&0xD800u16.to_le_bytes()); // a lone high surrogate
        bytes.extend(utf16le("after"));
        let text = extract_searchable_text(&embedded(&bytes));
        assert!(text.contains("before"), "got {text:?}");
        assert!(text.contains("after"), "got {text:?}");
    }

    /// **A decomposed (NFD) word is indexed whole (`VAL-001`).** A combining
    /// mark is neither alphabetic nor numeric, so it used to end the run it
    /// sat in: `man` + U+0303 + `ana` was indexed as `man ana`, and 18 CFTT
    /// rows whose files were recovered were reported as not found. The three
    /// terms are the three NFD terms in the CFTT key.
    #[test]
    fn a_decomposed_nfd_term_is_found_with_its_combining_mark() {
        for term in ["man\u{303}ana", "liberta\u{300}", "Ma\u{308}use"] {
            let e = embedded(term.as_bytes());
            assert!(
                finds(&e, term),
                "{term:?} must be found: got {:?}",
                extract_searchable_text(&e)
            );
        }
    }

    /// The same, on the real bytes. These 16 bytes are read from NIST CFTT's
    /// `ss-win-07-25-18.dd` at offset 9405605 (key id 3153,
    /// `LIVE-NFD-tomorrow-fat-utf-8.txt`, term at 9405609) -- quoted here so
    /// the test runs without the image. They pin the mechanism on the
    /// published bytes; the end-to-end grade is the CFTT re-run in
    /// `VALIDATION.md`.
    #[test]
    fn the_real_bytes_of_a_cftt_nfd_target_are_indexed() {
        let bytes: [u8; 16] = [
            0x3d, 0x3d, 0x3e, 0x20, 0x6d, 0x61, 0x6e, 0xcc, 0x83, 0x61, 0x6e, 0x61, 0x20, 0x33,
            0x31, 0x35,
        ];
        let text = extract_searchable_text(&bytes);
        assert!(text.contains("man\u{303}ana"), "got {text:?}");
    }

    /// A combining mark with no base character before it is not text: it does
    /// not start a run, so a string of bare marks yields nothing. The noise
    /// control for the rule above.
    #[test]
    fn a_combining_mark_with_no_base_does_not_start_a_run() {
        let text =
            extract_searchable_text(&embedded("\u{303}\u{303}\u{303}\u{303}\u{303}".as_bytes()));
        assert!(!text.contains('\u{303}'), "got {text:?}");
    }

    /// A mark does not count toward the minimum run length: `ca` + U+0301 +
    /// `t` is three characters and still discarded.
    #[test]
    fn a_combining_mark_does_not_count_toward_the_minimum_length() {
        let text = extract_searchable_text(&embedded("ca\u{301}t".as_bytes()));
        assert!(!text.contains("ca\u{301}t"), "got {text:?}");
        assert!(
            !text.contains("ca"),
            "a discarded run leaves nothing: got {text:?}"
        );
    }

    /// Invalid UTF-8 does not lose the valid text around it.
    #[test]
    fn invalid_utf8_does_not_lose_the_text_around_it() {
        let mut bytes = b"before".to_vec();
        bytes.extend_from_slice(&[0xC3, 0x28]); // an invalid two-byte sequence
        bytes.extend_from_slice(b"after");
        let text = extract_searchable_text(&bytes);
        assert!(text.contains("before"), "got {text:?}");
        assert!(text.contains("after"), "got {text:?}");
    }

    /// The extractor is bounded by its input and does not loop on any byte
    /// pattern — including odd lengths, which a UTF-16 pass must survive.
    #[test]
    fn an_odd_length_input_terminates() {
        for len in 0..40usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let _ = extract_searchable_text(&bytes);
        }
        let _ = extract_searchable_text(&[0x41]);
        let _ = extract_searchable_text(&[0x41, 0x00, 0x42]);
    }
}
