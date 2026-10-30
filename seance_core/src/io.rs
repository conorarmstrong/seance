//! Shared bounded-read helpers for parsers that pull a whole artifact into RAM.
//!
//! The capped short-read loop was copy-pasted (`read_all`) into ~11 plugins, and
//! several other parsers sized a buffer straight from `DataSource::size()` with
//! no upper bound — an OOM vector on hostile/corrupt size metadata. This is the
//! single implementation; every caller passes an explicit cap.

use crate::data_source::DataSource;

/// Read at most `max_bytes` of `ds` into memory, looping over short reads (a
/// windowed source may return fewer bytes than requested). Never allocates more
/// than `min(ds.size(), max_bytes)`, so a hostile size cannot OOM the worker.
/// A read error or premature EOF simply ends the read; the bytes gathered so far
/// are returned (parsers degrade rather than fail the pipeline).
///
/// The returned length is therefore evidence in itself: when it is less than
/// `ds.size()` the caller holds a PREFIX of the object, and whatever it parses
/// out of that prefix is a subset of what the object contains. Compare
/// `buf.len()` against `ds.size()` and stamp
/// [`IncompleteReason::CapReached`] / [`IncompleteReason::ShortRead`] on the
/// artifacts — a partial parse presented as a complete one is the defect this
/// note exists to prevent.
pub fn read_capped(ds: &dyn DataSource, max_bytes: u64) -> Vec<u8> {
    let size = ds.size().min(max_bytes);
    let mut buf = vec![0u8; size as usize];
    let mut off = 0usize;
    while off < buf.len() {
        match ds.read_at(off as u64, &mut buf[off..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n,
        }
    }
    buf.truncate(off);
    buf
}

/// Fill `buf` from `ds` at `offset`, looping over short reads, and FAIL if the
/// buffer cannot be filled completely.
///
/// This is the fail-closed counterpart to [`read_capped`], and the primitive
/// every structural parse should use. The recurring defect it exists to
/// eliminate is:
///
/// ```rust,ignore
/// let mut buf = vec![0u8; n];        // pre-zeroed
/// source.read_at(off, &mut buf)?;    // may fill FEWER than n bytes
/// parse(&buf);                       // the unread tail is parsed as real zeros
/// ```
///
/// A single `read_at` is permitted to return fewer bytes than requested, so the
/// unread tail stays zero and is indistinguishable from genuine on-disk zeros.
/// In a forensic tool that is evidence fabrication: truncated or I/O-broken
/// evidence silently becomes plausible-looking content that then hashes as if
/// complete. Structural reads (superblocks, inodes, directory blocks, headers)
/// must therefore error instead of parsing a padded buffer.
///
/// Use [`read_capped`] only where a *best-effort* partial read is genuinely
/// correct and the caller accounts for the short length.
pub fn read_exact_or_fail(
    ds: &dyn DataSource,
    offset: u64,
    buf: &mut [u8],
    what: &str,
) -> std::io::Result<()> {
    let mut off = 0usize;
    while off < buf.len() {
        match ds.read_at(offset + off as u64, &mut buf[off..]) {
            Ok(0) => break, // EOF before the buffer was filled
            Ok(n) => off += n,
            Err(e) => return Err(e),
        }
    }
    if off == buf.len() {
        Ok(())
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!(
                "short read of {what} at offset {offset}: got {off} of {} bytes; \
                 refusing to parse a zero-padded buffer",
                buf.len()
            ),
        ))
    }
}

/// Fill `buf` from `ds` at `offset`, looping over short reads, returning how
/// many bytes were actually read.
///
/// For the callers that legitimately tolerate a short read but MUST know it
/// happened (so they can bound their scan to `n` or set an incomplete flag)
/// rather than silently treating the zero tail as content. Prefer
/// [`read_exact_or_fail`] whenever a short read means the parse is invalid.
#[must_use]
pub fn read_full(ds: &dyn DataSource, offset: u64, buf: &mut [u8]) -> usize {
    let mut off = 0usize;
    while off < buf.len() {
        match ds.read_at(offset + off as u64, &mut buf[off..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => off += n,
        }
    }
    off
}

/// Why a reconstruction is incomplete. Parsers stamp the `&'static str` onto the
/// artifact so an examiner can tell "this really is all there was" apart from
/// "we stopped early" — the two must never look identical.
///
/// The recurring defect this exists to eliminate is a safety cap (max extents,
/// max chain length, max directory bytes) that truncates the result and then
/// reports it as complete, after which downstream code zero-fills the missing
/// tail as if it were a genuine sparse hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IncompleteReason {
    /// A parser safety cap (max extents / runs / entries) was hit.
    CapReached,
    /// A read returned fewer bytes than the structure requires.
    ShortRead,
    /// A structure referenced data that could not be located or parsed.
    UnresolvedStructure,
    /// Content is encrypted at rest and was not decrypted.
    Encrypted,
    /// Content is compressed and was not decompressed.
    Compressed,
    /// The bytes were produced by a codepath that has never been validated
    /// against ground truth, so they may be structurally plausible but wrong.
    ///
    /// Reserved for reconstruction whose *format* is transcribed from a
    /// reference but whose *output* no test has ever confirmed against a real
    /// capture — an older hibernation layout for which no corpus exists, say.
    /// It is the loudest honesty signal the pipeline has: not "a gap here", but
    /// "treat everything this produced as unverified". Kept distinct from
    /// [`Self::UnresolvedStructure`] because that means a parse gave up, whereas
    /// this means a parse *succeeded* on rules nobody has checked.
    Unvalidated,
    /// The range was never mapped, so there were no bytes to read.
    ///
    /// Distinct from [`Self::ShortRead`] on purpose, and the distinction is the
    /// difference between "evidence may have been missed here" and "nothing
    /// could ever have been here". Only the first is a gap in an examination.
    ///
    /// Sweeping a reserved-but-uncommitted region of a 64-bit process reports
    /// terabytes this way; tagging that `ShortRead` put a claim of possible
    /// missed evidence on address space no page ever backed, and buried the
    /// kilobytes that were a real gap on the same record.
    Unmapped,
}

impl IncompleteReason {
    /// Stable identifier stored in artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            IncompleteReason::CapReached => "cap_reached",
            IncompleteReason::ShortRead => "short_read",
            IncompleteReason::UnresolvedStructure => "unresolved_structure",
            IncompleteReason::Encrypted => "encrypted",
            IncompleteReason::Compressed => "compressed",
            IncompleteReason::Unvalidated => "unvalidated",
            IncompleteReason::Unmapped => "unmapped",
        }
    }

    /// The inverse of [`IncompleteReason::as_str`].
    ///
    /// Incompleteness is recorded on artifacts as JSON and has to survive the
    /// round trip: a consumer that could not tell "capped" from "encrypted"
    /// could not tell an examiner what to do about it.
    // Inherent rather than `FromStr`: this answers `Option`, and the trait
    // demands an associated error type that would have to be invented for a
    // name that simply is not one of the variants.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(name: &str) -> Option<Self> {
        Some(match name {
            "cap_reached" => IncompleteReason::CapReached,
            "short_read" => IncompleteReason::ShortRead,
            "unresolved_structure" => IncompleteReason::UnresolvedStructure,
            "encrypted" => IncompleteReason::Encrypted,
            "compressed" => IncompleteReason::Compressed,
            "unvalidated" => IncompleteReason::Unvalidated,
            "unmapped" => IncompleteReason::Unmapped,
            _ => return None,
        })
    }
}

/// Metadata key carrying "this artifact was built from an incomplete read".
///
/// This lives beside [`IncompleteReason`] rather than in a test-only module
/// because the many hundreds of sites that spell it by hand are PRODUCERS: a plugin cannot
/// name a constant that only exists behind a test-only feature without turning
/// that feature on over a real dependency edge, which would drag the test
/// doubles into a release build. A key only tests can reference is a key
/// production keeps duplicating.
pub const CONTENT_INCOMPLETE: &str = "content_incomplete";

/// Metadata key carrying WHY the read was incomplete; values are
/// [`IncompleteReason::as_str`].
pub const CONTENT_INCOMPLETE_REASON: &str = "content_incomplete_reason";

/// The SQLite 3 file-header magic (`"SQLite format 3\0"`).
pub const SQLITE_MAGIC: &[u8; 16] = b"SQLite format 3\0";

/// True if `bytes` begins with the SQLite 3 file-header magic.
pub fn is_sqlite_header(bytes: &[u8]) -> bool {
    bytes.len() >= SQLITE_MAGIC.len() && &bytes[..SQLITE_MAGIC.len()] == SQLITE_MAGIC
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_source::ByteSliceDataSource;

    #[test]
    fn read_capped_respects_the_cap() {
        let ds = ByteSliceDataSource::new(vec![7u8; 1000]);
        let out = read_capped(&ds, 100);
        assert_eq!(out.len(), 100);
        assert!(out.iter().all(|&b| b == 7));
    }

    #[test]
    fn read_capped_returns_whole_source_when_under_cap() {
        let ds = ByteSliceDataSource::new(vec![1u8, 2, 3, 4]);
        assert_eq!(read_capped(&ds, 1024), vec![1, 2, 3, 4]);
    }

    use crate::test_support::DribbleSource;

    #[test]
    fn read_exact_or_fail_loops_over_partial_reads() {
        // All 64 bytes exist; the source just dribbles them 8 at a time.
        let ds = DribbleSource::new((0..64u8).collect(), 8);
        let mut buf = [0u8; 64];
        read_exact_or_fail(&ds, 0, &mut buf, "test structure").expect("must fill");
        assert_eq!(buf.to_vec(), (0..64u8).collect::<Vec<_>>());
        ds.assert_dribbled();
    }

    #[test]
    fn read_exact_or_fail_errors_instead_of_zero_padding() {
        // Only 10 bytes exist but 32 are required: the tail would be zeros.
        let ds = ByteSliceDataSource::new(vec![0xAB; 10]);
        let mut buf = [0u8; 32];
        let err = read_exact_or_fail(&ds, 0, &mut buf, "inode")
            .expect_err("a truncated structure must not parse");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        assert!(
            err.to_string().contains("inode"),
            "the error names what was being read: {err}"
        );
    }

    #[test]
    fn read_full_reports_how_much_was_actually_read() {
        let ds = ByteSliceDataSource::new(vec![9u8; 10]);
        let mut buf = [0u8; 32];
        // Honest short count, so the caller can bound its scan to 10 rather
        // than treating the 22 zero bytes as content.
        assert_eq!(read_full(&ds, 0, &mut buf), 10);
    }

    #[test]
    fn incomplete_reasons_have_stable_identifiers() {
        assert_eq!(IncompleteReason::CapReached.as_str(), "cap_reached");
        assert_eq!(IncompleteReason::ShortRead.as_str(), "short_read");
    }

    #[test]
    fn every_incomplete_reason_round_trips_through_its_identifier() {
        for reason in [
            IncompleteReason::CapReached,
            IncompleteReason::ShortRead,
            IncompleteReason::UnresolvedStructure,
            IncompleteReason::Encrypted,
            IncompleteReason::Compressed,
            IncompleteReason::Unvalidated,
            IncompleteReason::Unmapped,
        ] {
            assert_eq!(IncompleteReason::from_str(reason.as_str()), Some(reason));
        }
        assert_eq!(IncompleteReason::from_str("bogus"), None);
    }

    #[test]
    fn the_incompleteness_keys_match_what_producers_already_write() {
        // Pins the constants' VALUES, not the producers: the same strings are
        // hand-written at many hundreds of stamp sites across the tree, which
        // this test cannot see. Changing a value here must be a deliberate act
        // that fails this test, because those artifacts would otherwise carry a
        // key nothing reads, i.e. a partial parse that presents to an examiner
        // as a complete one.
        assert_eq!(CONTENT_INCOMPLETE, "content_incomplete");
        assert_eq!(CONTENT_INCOMPLETE_REASON, "content_incomplete_reason");
    }

    #[test]
    fn detects_sqlite_header() {
        let mut db = SQLITE_MAGIC.to_vec();
        db.extend_from_slice(&[0u8; 84]);
        assert!(is_sqlite_header(&db));
        assert!(!is_sqlite_header(b"not a database"));
        assert!(!is_sqlite_header(b"SQLite")); // too short
    }
}
