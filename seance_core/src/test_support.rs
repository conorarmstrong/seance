//! Shared [`DataSource`] test doubles that prove the short-read contract in
//! [`crate::io`].
//!
//! # Why this module exists
//!
//! A short read parsed as zeros is how "no record of deletion" ends up in a
//! court report: [`DataSource::read_at`] is permitted to return fewer bytes
//! than asked for, so a pre-zeroed buffer that is only partly filled parses as
//! genuine on-disk zeros. [`crate::io::read_exact_or_fail`],
//! [`crate::io::read_full`] and [`crate::io::read_capped`] exist to make that
//! impossible, and the doubles below exist to prove they do.
//!
//! Before this module, `TruncatedSource` was redefined in 23 files and
//! `DribbleSource` in 13, under at least nine further aliases
//! (`ShortSource`, `ShortReadSource`, `UnderDeliveringSource`,
//! `OversizeSource`/`OversizedSource`, `HugeDeclaredSource`, `LyingSizeSource`,
//! `OverReportSource`, `HalfReadSource`, `ChunkedSource`). Each crate therefore
//! asserted a slightly different contract, and a plugin could pass its own copy
//! of the test while breaking the real invariant. ROADMAP §5.11 retired the
//! last of those copies (and the in-memory `MemSource` copies, now
//! [`crate::data_source::ByteSliceDataSource`]);
//! `seance_tests/tests/no_private_io_doubles_test.rs` fails on a new one.
//!
//! # Which helper each double is designed to break
//!
//! | Double | Breaks | The defect it catches |
//! |--------|--------|-----------------------|
//! | [`TruncatedSource`] | [`read_capped`](crate::io::read_capped), [`read_exact_or_fail`](crate::io::read_exact_or_fail) | a parser that trusts `size()` and treats the unread tail as content |
//! | [`DribbleSource`] | [`read_exact_or_fail`](crate::io::read_exact_or_fail), [`read_full`](crate::io::read_full) | a caller that treats ONE `read_at` as the whole answer |
//! | [`StallingSource`] | [`read_capped`](crate::io::read_capped), [`read_full`](crate::io::read_full) | a mid-stream `Ok(0)`, which every loop reads as EOF |
//! | [`UnreadableSource`] | [`read_exact_or_fail`](crate::io::read_exact_or_fail) | an I/O error swallowed into a "successful" empty parse |
//!
//! # Availability
//!
//! Gated behind `#[cfg(any(test, feature = "test-support"))]`. A downstream
//! crate opts in with
//! `seance_core = { path = "../seance_core", features = ["test-support"] }`
//! under `[dev-dependencies]`; with resolver 2 that feature is not unified into
//! a normal build, so an ordinary `cargo build` does not compile this module.
//!
//! It is NOT an absolute guarantee: `cargo build --all-features` (and the
//! `--all-features` clippy job in `.github/workflows/test.yml`) turns the
//! feature on workspace-wide. Nothing here has side effects, but do not treat
//! the gate as a claim that these doubles are unreachable — treat it as a claim
//! that no dependency edge enables them.

use crate::artifact::Artifact;
use crate::data_source::DataSource;
use crate::io::IncompleteReason;
use std::io;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Copy the prefix of `bytes` starting at `offset` into `buf`, returning how
/// many bytes were copied (`0` once `offset` is at or past the end).
///
/// The bounds check happens in `u64` space *before* the cast to `usize`. Every
/// hand-written copy of these doubles wrote `let off = offset as usize;` first,
/// which on a 32-bit target wraps a 4 GiB offset to `0` and serves the bytes
/// from the START of the buffer as if they came from the requested offset —
/// a test harness fabricating evidence.
fn copy_prefix(bytes: &[u8], offset: u64, buf: &mut [u8]) -> usize {
    if offset >= bytes.len() as u64 {
        return 0;
    }
    // Provably less than `bytes.len()`, so the cast cannot wrap.
    let off = offset as usize;
    let n = buf.len().min(bytes.len() - off);
    buf[..n].copy_from_slice(&bytes[off..off + n]);
    n
}

/// What a double actually did, so a test can prove the double was not a no-op.
///
/// The silent failure this exists to kill: a double that shortens reads to N
/// bytes proves nothing about a parser that never asks for more than N. The
/// test still passes, and the contract is unverified. See
/// [`DribbleSource::assert_dribbled`].
#[derive(Debug, Default)]
pub struct ReadStats {
    calls: AtomicUsize,
    partial_calls: AtomicUsize,
    bytes_returned: AtomicU64,
}

impl ReadStats {
    /// Claim the next 0-based call index, counting the invocation.
    fn next_call_index(&self) -> usize {
        self.calls.fetch_add(1, Ordering::Relaxed)
    }

    /// Record the outcome of a call that has already been counted.
    fn record_delivery(&self, requested: usize, returned: usize) {
        if returned > 0 && returned < requested {
            self.partial_calls.fetch_add(1, Ordering::Relaxed);
        }
        self.bytes_returned
            .fetch_add(returned as u64, Ordering::Relaxed);
    }

    /// Total `read_at` invocations, including those that returned `Ok(0)` or an
    /// error.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::Relaxed)
    }

    /// Invocations that returned FEWER bytes than were asked for while still
    /// returning some — i.e. the short reads this harness exists to inject.
    /// End-of-data (`Ok(0)`) and errors are excluded: they are not short reads,
    /// they are the end of the answer.
    pub fn partial_calls(&self) -> usize {
        self.partial_calls.load(Ordering::Relaxed)
    }

    /// Total bytes actually delivered across every call.
    pub fn bytes_returned(&self) -> u64 {
        self.bytes_returned.load(Ordering::Relaxed)
    }
}

/// How a [`TruncatedSource`] answers a read that starts past the bytes it
/// actually holds.
///
/// Both are real acquisition failures and they are NOT interchangeable: a
/// truncated image file signals EOF, whereas an unreadable sector or a
/// disconnected device signals an error. [`crate::io::read_exact_or_fail`]
/// synthesizes `UnexpectedEof` for the first and PROPAGATES the second, so a
/// caller that only ever tested one has not tested the other.
///
/// Deliberately private: [`TruncatedSource::erroring_past_end`] is the only way
/// to select a variant, so a public enum here would be API surface no caller
/// outside this module could ever construct or pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PastEnd {
    /// `Ok(0)` — the image simply stops, as a truncated file does.
    Eof,
    /// `Err(..)` — the bytes exist on paper but cannot be read, as a bad sector
    /// or a dropped device does.
    Error,
}

/// A source that DECLARES more bytes than it can deliver.
///
/// This is the staging-shortfall double: `size()` reports the file's real
/// length (from directory metadata, a container index or a filesystem record)
/// while the bytes behind it were never fully materialised.
///
/// Breaks:
/// - [`crate::io::read_capped`], which returns a PREFIX. A caller that does not
///   compare `buf.len()` against `ds.size()` reports a partial parse as a
///   complete one.
/// - [`crate::io::read_exact_or_fail`], which must return `UnexpectedEof`
///   instead of parsing a zero-padded structure.
///
/// # Variants this replaces
///
/// The 18 tuple-struct copies hard-coded `size() = len * 2`. That is not a
/// parameter choice, it is a limitation with two failure modes:
/// - it cannot express a one-byte shortfall at a structure boundary, the
///   commonest real truncation;
/// - on an EMPTY fixture it yields `size() == 0`, so the double stops being
///   truncated at all and the test passes vacuously.
///
/// [`TruncatedSource::new`] therefore takes the declared size explicitly and
/// rejects a declaration that is not actually short.
/// [`TruncatedSource::halved`] preserves the `len * 2` convention for tests that
/// only need "clearly short", and rejects the empty fixture outright.
#[derive(Debug)]
pub struct TruncatedSource {
    available: Vec<u8>,
    declared: u64,
    past_end: PastEnd,
    stats: ReadStats,
}

impl TruncatedSource {
    /// Declare `declared` bytes while holding only `available`.
    ///
    /// An EMPTY `available` is legal and is its own variant: every `read_at`
    /// answers `Ok(0)` while `size()` stays large. That is the shape a naive
    /// `while got < ds.size()` loop never escapes, and it is what
    /// `seance_plugin_browser_history`'s `HugeDeclaredSource` was written to
    /// produce. [`crate::io::read_capped`] and [`crate::io::read_full`] break on
    /// `Ok(0)` and so terminate; a hand-rolled loop is what spins.
    ///
    /// # Panics
    ///
    /// If `declared <= available.len()`. A "truncated" source that is not short
    /// verifies nothing, and every assertion written against it passes for the
    /// wrong reason.
    pub fn new(available: Vec<u8>, declared: u64) -> Self {
        assert!(
            declared > available.len() as u64,
            "TruncatedSource must be short: declared {declared} but holds {} bytes; \
             a source that delivers everything it declares proves nothing about the \
             short-read contract (use ByteSliceDataSource for an honest source)",
            available.len()
        );
        Self {
            available,
            declared,
            past_end: PastEnd::Eof,
            stats: ReadStats::default(),
        }
    }

    /// Declare exactly twice what is held — the convention the 18 copied
    /// definitions used.
    ///
    /// # Panics
    ///
    /// If `available` is empty, because `0 * 2 == 0` would silently produce an
    /// honest source. Each copied definition had this hole.
    pub fn halved(available: Vec<u8>) -> Self {
        assert!(
            !available.is_empty(),
            "TruncatedSource::halved on empty bytes declares a size of 0, which is \
             not short at all; supply a non-empty prefix or use \
             TruncatedSource::new(Vec::new(), declared)"
        );
        let declared = (available.len() as u64).saturating_mul(2);
        Self::new(available, declared)
    }

    /// Serve only the first `readable` bytes of `full`, while still declaring
    /// the length `full` actually had.
    ///
    /// The third construction convention in this tree, after `halved`'s
    /// `len * 2` and an explicit unrelated number: an acquisition that stopped
    /// part-way through a file whose TRUE length is known independently — from
    /// an OLE2 directory entry (`seance_container_archive::ole2`) or a memory
    /// image's segment list (`seance_memory::translate::virt`). It exists so
    /// that a test which cuts the tail off a real fixture never has to restate
    /// the declared size by hand, which is the one number in these doubles that
    /// is easy to get wrong and impossible to notice when wrong.
    ///
    /// Breaks the same two helpers as [`TruncatedSource::new`]:
    /// [`crate::io::read_capped`], which returns only the readable prefix, and
    /// [`crate::io::read_exact_or_fail`], which must refuse the tail rather than
    /// hand back the zeros still sitting in the buffer.
    ///
    /// # Panics
    ///
    /// If `readable >= full.len()`, because nothing would be cut and the
    /// resulting source would be honest.
    pub fn cut_to(mut full: Vec<u8>, readable: usize) -> Self {
        let declared = full.len() as u64;
        assert!(
            readable < full.len(),
            "TruncatedSource::cut_to must actually remove bytes: asked to keep \
             {readable} of {declared}, which leaves a source that delivers \
             everything it declares"
        );
        full.truncate(readable);
        Self::new(full, declared)
    }

    /// Answer reads past the available bytes with an I/O error rather than EOF,
    /// modelling an unreadable sector instead of a truncated file.
    #[must_use]
    pub fn erroring_past_end(mut self) -> Self {
        self.past_end = PastEnd::Error;
        self
    }

    /// What this double was actually asked for, and what it delivered.
    pub fn reads(&self) -> &ReadStats {
        &self.stats
    }
}

impl DataSource for TruncatedSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.stats.next_call_index();
        if offset >= self.available.len() as u64 {
            self.stats.record_delivery(buf.len(), 0);
            return match self.past_end {
                PastEnd::Eof => Ok(0),
                PastEnd::Error => Err(io::Error::other(format!(
                    "simulated unreadable region at offset {offset}: only {} of the \
                     {} declared bytes were staged",
                    self.available.len(),
                    self.declared
                ))),
            };
        }
        let n = copy_prefix(&self.available, offset, buf);
        self.stats.record_delivery(buf.len(), n);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.declared
    }
}

/// A source holding EVERY byte it declares, which nonetheless returns at most
/// `chunk` bytes per call.
///
/// This is the windowed/run-list/container-backed shape: nothing is missing, so
/// a correct caller recovers the whole object, but a caller that treats one
/// `read_at` as the whole answer silently loses the tail. Because the source is
/// complete, that loss carries NO incompleteness marker — the parser believes
/// it saw everything.
///
/// Breaks [`crate::io::read_exact_or_fail`] and [`crate::io::read_full`] if
/// either stops after the first call.
///
/// # Variants this replaces
///
/// Ten copies hard-coded `chunk = 4`; `seance_sqlite_util` used a tuple field,
/// `seance_container_vdisk` a named field, `seance_plugin_srum` 512 and
/// `seance_plugin_webcache` 256. The chunk size is a genuine requirement, not
/// an accident — it must sit below the parser's smallest structural read to
/// exercise anything — so it is a parameter here. A hard-coded 4 was silently a
/// no-op for any parser whose reads were already 4 bytes or fewer; see
/// [`DribbleSource::assert_dribbled`].
#[derive(Debug)]
pub struct DribbleSource {
    data: Vec<u8>,
    chunk: usize,
    stats: ReadStats,
}

impl DribbleSource {
    /// Hold all of `data` but never return more than `chunk` bytes per call.
    ///
    /// # Panics
    ///
    /// If `chunk == 0`. A zero chunk returns `Ok(0)` forever, which every loop
    /// in [`crate::io`] reads as end-of-data — the double would quietly turn
    /// into a [`TruncatedSource`] that declares the full size and delivers
    /// nothing, and any test asserting "still parsed in full" would fail for a
    /// reason unrelated to the code under test.
    pub fn new(data: Vec<u8>, chunk: usize) -> Self {
        assert!(
            chunk > 0,
            "DribbleSource chunk must be greater than 0: a chunk of 0 returns Ok(0) \
             forever, which is indistinguishable from end-of-data"
        );
        Self {
            data,
            chunk,
            stats: ReadStats::default(),
        }
    }

    /// What this double was actually asked for, and what it delivered.
    pub fn reads(&self) -> &ReadStats {
        &self.stats
    }

    /// Assert the double actually shortened at least one read.
    ///
    /// # Panics
    ///
    /// If every read was satisfied in full, which means the code under test
    /// never asked for more than `chunk` bytes and the short-read path was
    /// never entered. Without this check such a test is green and proves
    /// nothing — the exact false pass that made 12 divergent copies of this
    /// double survive unnoticed.
    pub fn assert_dribbled(&self) {
        assert!(
            self.stats.partial_calls() > 0,
            "DribbleSource never shortened a read: {} call(s), none partial. \
             The code under test never asked for more than {} bytes, so the \
             short-read path was not exercised; lower the chunk size.",
            self.stats.calls(),
            self.chunk
        );
    }
}

impl DataSource for DribbleSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.stats.next_call_index();
        let want = buf.len().min(self.chunk);
        let n = copy_prefix(&self.data, offset, &mut buf[..want]);
        self.stats.record_delivery(buf.len(), n);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// A source that holds every byte it declares but returns a spurious `Ok(0)` on
/// one call, with data still remaining.
///
/// `Ok(0)` is defined as end-of-data, so every loop in [`crate::io`] stops on
/// it. A caching or container layer that reports a transient failure this way
/// is therefore INDISTINGUISHABLE from truncation to anything downstream, which
/// is precisely why [`crate::io::read_exact_or_fail`] must refuse the buffer
/// rather than hand back a partly-filled one:
/// [`crate::io::read_capped`] and [`crate::io::read_full`] cannot tell the
/// difference and will report an honest-looking short length for a source that
/// is not actually short.
///
/// Modelled on the `FlakyShortSource` in `seance_core/tests/caching_data_source_test.rs`,
/// which is the only place in the tree that exercised this shape.
#[derive(Debug)]
pub struct StallingSource {
    data: Vec<u8>,
    stall_on_call: usize,
    stats: ReadStats,
}

impl StallingSource {
    /// Return `Ok(0)` on the `stall_on_call`-th call (0-based), serving the real
    /// bytes on every other call.
    pub fn new(data: Vec<u8>, stall_on_call: usize) -> Self {
        Self {
            data,
            stall_on_call,
            stats: ReadStats::default(),
        }
    }

    /// What this double was actually asked for, and what it delivered.
    pub fn reads(&self) -> &ReadStats {
        &self.stats
    }
}

impl DataSource for StallingSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let index = self.stats.next_call_index();
        let n = if index == self.stall_on_call {
            0
        } else {
            copy_prefix(&self.data, offset, buf)
        };
        self.stats.record_delivery(buf.len(), n);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// A source that declares a size but fails every read.
///
/// The device is present and its size is known — from a partition table, a
/// container index or a directory entry — but the bytes cannot be read at all.
///
/// Breaks [`crate::io::read_exact_or_fail`], which must PROPAGATE the error
/// rather than convert it into `UnexpectedEof`: "the read failed" and "the file
/// ended" are different findings and an examiner must be able to tell them
/// apart. [`crate::io::read_capped`] and [`crate::io::read_full`] degrade to an
/// empty result here, so any caller of those must treat a zero-length answer
/// from a non-zero-sized source as unexplained, never as "the file was empty".
///
/// Replaces the `UnreadableSource` in `seance_plugin_signal`, whose size was
/// hard-coded to 4096.
#[derive(Debug)]
pub struct UnreadableSource {
    declared: u64,
    stats: ReadStats,
}

impl UnreadableSource {
    /// Declare `declared` bytes that can never be read.
    pub fn new(declared: u64) -> Self {
        Self {
            declared,
            stats: ReadStats::default(),
        }
    }

    /// What this double was actually asked for, and what it delivered.
    pub fn reads(&self) -> &ReadStats {
        &self.stats
    }
}

impl DataSource for UnreadableSource {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        self.stats.next_call_index();
        self.stats.record_delivery(buf.len(), 0);
        Err(io::Error::other(format!(
            "simulated device read error at offset {offset} of {} declared bytes",
            self.declared
        )))
    }

    fn size(&self) -> u64 {
        self.declared
    }
}

/// The incompleteness metadata keys, re-exported so a test can name them
/// without the `crate::io` path. They are DEFINED in [`crate::io`] because the
/// sites that spell them by hand are producers, and a producer cannot reference
/// a constant gated behind a test-only feature.
pub use crate::io::{CONTENT_INCOMPLETE, CONTENT_INCOMPLETE_REASON};

/// Assert that EVERY artifact produced from a short read carries the
/// incompleteness pair.
///
/// # Panics
///
/// - If the sequence is empty. An empty sequence satisfies a `for` loop
///   vacuously, so several hand-written copies of this assertion could pass on a
///   parser that produced nothing at all — "we found no messages" and "the
///   database was unreadable" would then be the same green test.
/// - If any artifact is missing [`CONTENT_INCOMPLETE`], has it set to anything
///   but `true`, or carries a reason other than `reason`.
pub fn assert_short_read_stamps<'a, I>(artifacts: I, reason: IncompleteReason)
where
    I: IntoIterator<Item = &'a Artifact>,
{
    let mut seen = 0usize;
    for (index, artifact) in artifacts.into_iter().enumerate() {
        seen += 1;
        assert_eq!(
            artifact.metadata.get(CONTENT_INCOMPLETE),
            Some(&serde_json::Value::Bool(true)),
            "artifact #{index} came out of an incomplete read but is not marked \
             `{}`, so it reads as a complete record: {}",
            CONTENT_INCOMPLETE,
            artifact.metadata
        );
        assert_eq!(
            artifact
                .metadata
                .get(CONTENT_INCOMPLETE_REASON)
                .and_then(|v| v.as_str()),
            Some(reason.as_str()),
            "artifact #{index} must explain the incompleteness as `{}`: {}",
            reason.as_str(),
            artifact.metadata
        );
    }
    assert!(
        seen > 0,
        "no artifacts to check: an empty result satisfies every per-artifact \
         assertion vacuously, so this test would pass against a parser that \
         produced nothing at all"
    );
}

/// Assert that artifacts parsed from a COMPLETE source carry no incompleteness
/// marks.
///
/// The counterpart to [`assert_short_read_stamps`], and not optional: a marker
/// stamped on everything says nothing, so the negative case is what gives the
/// positive case meaning.
///
/// # Panics
///
/// If the sequence is empty (same vacuous-pass reason as above), or if any
/// artifact carries [`CONTENT_INCOMPLETE`] or [`CONTENT_INCOMPLETE_REASON`].
pub fn assert_no_incompleteness_stamps<'a, I>(artifacts: I)
where
    I: IntoIterator<Item = &'a Artifact>,
{
    let mut seen = 0usize;
    for (index, artifact) in artifacts.into_iter().enumerate() {
        seen += 1;
        assert!(
            artifact.metadata.get(CONTENT_INCOMPLETE).is_none(),
            "artifact #{index} came from a complete source but is marked \
             `{}`; a marker present on everything tells an examiner nothing: {}",
            CONTENT_INCOMPLETE,
            artifact.metadata
        );
        assert!(
            artifact.metadata.get(CONTENT_INCOMPLETE_REASON).is_none(),
            "artifact #{index} came from a complete source but carries `{}`: {}",
            CONTENT_INCOMPLETE_REASON,
            artifact.metadata
        );
    }
    assert!(
        seen > 0,
        "no artifacts to check: an empty result satisfies every per-artifact \
         assertion vacuously"
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, ArtifactType};
    use crate::io::{read_capped, read_exact_or_fail, read_full};
    use serde_json::json;
    use uuid::Uuid;

    fn artifact(metadata: serde_json::Value) -> Artifact {
        Artifact::new(Uuid::new_v4(), ArtifactType::FileEntry, None, metadata)
    }

    // ---- TruncatedSource -------------------------------------------------

    #[test]
    fn truncated_declares_more_than_it_can_deliver() {
        let ds = TruncatedSource::new(vec![0xAAu8; 100], 4096);
        assert_eq!(ds.size(), 4096);
        let got = read_capped(&ds, 1 << 20);
        assert_eq!(
            got.len(),
            100,
            "read_capped returns a PREFIX; the caller must compare it against size()"
        );
        assert_eq!(ds.reads().bytes_returned(), 100);
    }

    #[test]
    fn truncated_makes_a_structural_read_fail_instead_of_zero_padding() {
        let ds = TruncatedSource::new(vec![0xAAu8; 10], 32);
        let mut buf = [0u8; 32];
        let err = read_exact_or_fail(&ds, 0, &mut buf, "inode")
            .expect_err("32 declared bytes with 10 staged must not parse");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        // The unfixed shape — one read_at into a pre-zeroed buffer — would have
        // "succeeded" with 22 fabricated zero bytes.
        assert_eq!(read_full(&ds, 0, &mut buf), 10, "the honest short count");
    }

    #[test]
    #[should_panic(expected = "must be short")]
    fn truncated_rejects_a_declaration_that_is_not_short() {
        let _ = TruncatedSource::new(vec![1u8, 2, 3], 3);
    }

    #[test]
    #[should_panic(expected = "declares a size of 0")]
    fn halved_rejects_the_empty_fixture_that_made_the_copied_doubles_honest() {
        // Every `size() = len * 2` copy silently degraded to an honest source
        // here, and its short-read assertions passed for the wrong reason.
        let _ = TruncatedSource::halved(Vec::new());
    }

    #[test]
    fn halved_keeps_the_two_times_convention_for_non_empty_fixtures() {
        let ds = TruncatedSource::halved(vec![7u8; 64]);
        assert_eq!(ds.size(), 128);
        assert_eq!(read_capped(&ds, 1 << 20).len(), 64);
    }

    #[test]
    fn cut_to_keeps_the_fixtures_original_length_as_the_declared_size() {
        // The ole2/virt shape: a real fixture with its tail removed, whose true
        // length is still on record in the directory entry or segment list.
        let ds = TruncatedSource::cut_to((0..=255u8).collect(), 200);
        assert_eq!(ds.size(), 256, "the directory entry still says 256");
        assert_eq!(read_capped(&ds, 1 << 20).len(), 200);
        let mut buf = [0u8; 256];
        assert_eq!(
            read_exact_or_fail(&ds, 0, &mut buf, "stream")
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    #[test]
    #[should_panic(expected = "must actually remove bytes")]
    fn cut_to_rejects_a_cut_that_removes_nothing() {
        let _ = TruncatedSource::cut_to(vec![1u8; 8], 8);
    }

    #[test]
    fn an_empty_prefix_declares_a_size_and_then_delivers_nothing_at_all() {
        // browser_history's HugeDeclaredSource: size() is large, every read is
        // Ok(0). The helpers in `io` break on Ok(0) and terminate; a hand-rolled
        // `while got < ds.size()` loop is the one that spins here.
        let ds = TruncatedSource::new(Vec::new(), 1 << 40);
        assert_eq!(ds.size(), 1 << 40);
        let mut buf = [0u8; 64];
        assert_eq!(ds.read_at(0, &mut buf).unwrap(), 0);
        assert_eq!(ds.read_at(1 << 20, &mut buf).unwrap(), 0);
        assert!(read_capped(&ds, 1 << 20).is_empty());
        assert_eq!(
            read_exact_or_fail(&ds, 0, &mut buf, "header")
                .unwrap_err()
                .kind(),
            io::ErrorKind::UnexpectedEof
        );
        assert_eq!(ds.reads().bytes_returned(), 0);
    }

    #[test]
    fn an_unreadable_region_errors_where_a_truncated_file_signals_eof() {
        let truncated = TruncatedSource::new(vec![1u8; 8], 64);
        let mut buf = [0u8; 64];
        let eof = read_exact_or_fail(&truncated, 0, &mut buf, "record").unwrap_err();
        assert_eq!(eof.kind(), io::ErrorKind::UnexpectedEof);

        let bad_sector = TruncatedSource::new(vec![1u8; 8], 64).erroring_past_end();
        let raised = read_exact_or_fail(&bad_sector, 0, &mut buf, "record").unwrap_err();
        assert!(
            raised.to_string().contains("simulated unreadable region"),
            "the device error must survive, not be rewritten as end-of-file: {raised}"
        );
        // read_capped degrades to the readable prefix either way.
        assert_eq!(read_capped(&bad_sector, 1 << 20).len(), 8);
    }

    // ---- DribbleSource ---------------------------------------------------

    #[test]
    fn dribble_holds_everything_and_still_shortens_each_read() {
        let ds = DribbleSource::new((0..64u8).collect(), 4);
        assert_eq!(ds.size(), 64, "a dribbling source is NOT short overall");

        let mut once = [0u8; 64];
        assert_eq!(
            ds.read_at(0, &mut once).unwrap(),
            4,
            "one read_at is never the whole answer"
        );

        let mut buf = [0u8; 64];
        read_exact_or_fail(&ds, 0, &mut buf, "record").expect("looping fills it");
        assert_eq!(buf.to_vec(), (0..64u8).collect::<Vec<_>>());
        ds.assert_dribbled();
        assert!(ds.reads().partial_calls() >= 16);
    }

    #[test]
    fn dribble_lets_read_capped_recover_the_whole_source() {
        let ds = DribbleSource::new(vec![3u8; 1000], 7);
        assert_eq!(read_capped(&ds, 1 << 20).len(), 1000);
    }

    #[test]
    #[should_panic(expected = "chunk must be greater than 0")]
    fn dribble_rejects_a_zero_chunk_that_would_mimic_end_of_data() {
        let _ = DribbleSource::new(vec![1u8; 16], 0);
    }

    #[test]
    #[should_panic(expected = "never shortened a read")]
    fn assert_dribbled_catches_a_double_that_was_a_no_op() {
        // The hard-coded chunk of 4 in the copied definitions was exactly this
        // no-op for any parser reading 4 bytes or fewer at a time.
        let ds = DribbleSource::new(vec![1u8; 16], 4);
        let mut buf = [0u8; 4];
        ds.read_at(0, &mut buf).unwrap();
        ds.assert_dribbled();
    }

    // ---- StallingSource --------------------------------------------------

    #[test]
    fn a_mid_stream_zero_is_indistinguishable_from_truncation() {
        // Complete source, but the second call reports Ok(0).
        let ds = StallingSource::new((0..64u8).collect(), 1);
        let mut buf = [0u8; 64];
        // First call fills everything, so no stall is reached.
        assert_eq!(ds.read_at(0, &mut buf).unwrap(), 64);
        assert_eq!(ds.read_at(0, &mut buf).unwrap(), 0, "the spurious EOF");

        // With a smaller buffer the loop hits the stall mid-structure and
        // read_exact_or_fail refuses the half-filled buffer.
        let ds = StallingSource::new((0..64u8).collect(), 1);
        let mut small = [0u8; 8];
        assert_eq!(ds.read_at(0, &mut small).unwrap(), 8);
        let err = read_exact_or_fail(&ds, 8, &mut small, "record")
            .expect_err("a stalled read must not yield a zero-padded structure");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        // read_capped cannot tell, which is the point: it reports a short
        // length for a source that declares — and holds — 64 bytes.
        let ds = StallingSource::new((0..64u8).collect(), 0);
        assert_eq!(ds.size(), 64);
        assert!(read_capped(&ds, 1 << 20).is_empty());
    }

    // ---- UnreadableSource ------------------------------------------------

    #[test]
    fn an_io_error_reaches_the_caller_and_is_never_an_empty_file() {
        let ds = UnreadableSource::new(4096);
        assert_eq!(ds.size(), 4096);

        let mut buf = [0u8; 512];
        let err = read_exact_or_fail(&ds, 0, &mut buf, "superblock").unwrap_err();
        assert!(
            err.to_string().contains("simulated device read error"),
            "the device error must be propagated verbatim, not turned into EOF: {err}"
        );

        // The best-effort helpers degrade to nothing; a caller seeing 0 bytes
        // from a 4096-byte source must never report "the file was empty".
        assert_eq!(read_full(&ds, 0, &mut buf), 0);
        assert!(read_capped(&ds, 1 << 20).is_empty());
        assert!(ds.reads().calls() >= 3);
        assert_eq!(ds.reads().bytes_returned(), 0);
    }

    // ---- metadata assertions ---------------------------------------------

    #[test]
    fn short_read_stamps_are_accepted_when_present_on_every_artifact() {
        let out = vec![
            artifact(
                json!({"content_incomplete": true, "content_incomplete_reason": "short_read"}),
            ),
            artifact(
                json!({"content_incomplete": true, "content_incomplete_reason": "short_read"}),
            ),
        ];
        assert_short_read_stamps(&out, IncompleteReason::ShortRead);
    }

    #[test]
    #[should_panic(expected = "is not marked")]
    fn an_unstamped_artifact_from_a_partial_read_is_rejected() {
        let out = vec![
            artifact(
                json!({"content_incomplete": true, "content_incomplete_reason": "short_read"}),
            ),
            artifact(json!({"name": "row"})),
        ];
        assert_short_read_stamps(&out, IncompleteReason::ShortRead);
    }

    #[test]
    #[should_panic(expected = "must explain the incompleteness")]
    fn the_wrong_reason_is_rejected() {
        let out = vec![artifact(
            json!({"content_incomplete": true, "content_incomplete_reason": "cap_reached"}),
        )];
        assert_short_read_stamps(&out, IncompleteReason::ShortRead);
    }

    #[test]
    #[should_panic(expected = "no artifacts to check")]
    fn an_empty_result_never_counts_as_correctly_stamped() {
        assert_short_read_stamps(&Vec::<Artifact>::new(), IncompleteReason::ShortRead);
    }

    #[test]
    fn a_complete_source_leaves_no_marks() {
        let out = vec![artifact(json!({"name": "row"}))];
        assert_no_incompleteness_stamps(&out);
    }

    #[test]
    #[should_panic(expected = "tells an examiner nothing")]
    fn a_mark_on_a_complete_parse_is_rejected() {
        let out = vec![artifact(json!({"content_incomplete": true}))];
        assert_no_incompleteness_stamps(&out);
    }

    #[test]
    #[should_panic(expected = "no artifacts to check")]
    fn an_empty_complete_result_is_rejected_too() {
        assert_no_incompleteness_stamps(&Vec::<Artifact>::new());
    }

    // ---- the borrowed-slice ergonomics the 23 call sites need -------------

    #[test]
    fn the_assertions_accept_a_filtered_borrow_as_well_as_the_whole_vec() {
        let out = [
            artifact(
                json!({"type": "Message", "content_incomplete": true, "content_incomplete_reason": "short_read"}),
            ),
            artifact(json!({"type": "Status"})),
        ];
        let messages: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["type"] == json!("Message"))
            .collect();
        assert_short_read_stamps(messages, IncompleteReason::ShortRead);
    }
}

/// Resolving a corpus of real evidence that a test needs, so that a run which
/// examined nothing cannot report as a run that passed.
///
/// # Why this module exists
///
/// Tests gated on a corpus were all written the same way:
///
/// ```ignore
/// let dir = PathBuf::from(std::env::var("SEANCE_MEM_IMAGES").ok()?);
/// let path = dir.join("linux-sample-1.bin");
/// if !path.exists() {
///     eprintln!("skipping: {} not present", path.display());
///     return None;
/// }
/// ```
///
/// The test body then returns early, and `cargo test` prints `ok`. Rust has no
/// third result between pass and fail, so a skip is indistinguishable from a
/// comparison that ran and agreed.
///
/// That is not hypothetical here. The Volatility parity suite printed `ok` for
/// its entire existence while comparing zero rows, which is how `psscan`
/// returning 0 processes against the oracle's 103 went unnoticed. 72 tests
/// across the workspace were gated this way and only 4 of them failed when the
/// corpus was named but absent.
///
/// # The distinction this draws
///
/// Two situations were being collapsed into one:
///
/// 1. **The variable is unset.** The corpus was never provisioned. Skipping is
///    correct, and the run says so loudly.
/// 2. **The variable is set and the path is missing.** The operator believes
///    the gate is ON. Reporting `ok` here tells them a comparison happened when
///    none did, which is worse than failing. This panics.
///
/// Set `SEANCE_REQUIRE_CORPUS=1` to turn case 1 into a failure too, so CI can
/// demand that the corpus was actually present rather than hoping.
pub mod corpus {
    use std::path::PathBuf;

    /// True when the caller has demanded that corpora be present.
    fn required() -> bool {
        std::env::var("SEANCE_REQUIRE_CORPUS").is_ok_and(|v| v != "0" && !v.is_empty())
    }

    /// Announce a skip in a form that survives `cargo test`'s output capture
    /// being off, and that reads as a skip rather than as nothing at all.
    fn announce_skip(var: &str, detail: &str) {
        eprintln!("SKIPPED (no corpus): {var} is not set — {detail}");
    }

    /// The corpus directory named by `var`.
    ///
    /// `None` means "not provisioned, and the run has said so". A directory
    /// that was named and is not there panics rather than skipping.
    pub fn dir(var: &str) -> Option<PathBuf> {
        let path = path(var)?;
        assert!(
            path.is_dir(),
            "{var} is set to {}, which exists but is not a directory. The corpus gate is ON \
             and cannot open — reporting this run as a pass would claim a comparison that \
             did not happen.",
            path.display()
        );
        Some(path)
    }

    /// A named file inside the corpus directory named by `var`.
    ///
    /// Same contract as [`dir`]: absent variable skips, named-but-missing
    /// panics.
    pub fn file(var: &str, name: &str) -> Option<PathBuf> {
        let path = dir(var)?.join(name);
        assert!(
            path.is_file(),
            "{} is missing from the corpus named by {var}. The gate is ON and cannot open — \
             a pass here would report a comparison that never ran.",
            path.display()
        );
        Some(path)
    }

    /// A corpus path given directly by `var` (the variable IS the path, rather
    /// than naming a directory to look inside).
    pub fn path(var: &str) -> Option<PathBuf> {
        resolve(var, std::env::var(var).ok(), required())
    }

    /// The decision itself, with the environment passed in.
    ///
    /// Separated from [`path`] so the contract can be tested without mutating
    /// the process environment: `std::env::set_var` is `unsafe` under this
    /// edition and the workspace denies `unsafe_code`, and a test that mutates
    /// shared environment is a race against every other test in the binary
    /// anyway.
    pub(super) fn resolve(var: &str, raw: Option<String>, required: bool) -> Option<PathBuf> {
        let Some(raw) = raw else {
            assert!(
                !required,
                "{var} is not set, but SEANCE_REQUIRE_CORPUS demands it. This run would have \
                 reported a pass having compared nothing."
            );
            announce_skip(var, "this test compared nothing");
            return None;
        };
        let path = PathBuf::from(&raw);
        assert!(
            path.exists(),
            "{var} is set to {raw:?}, which does not exist. The corpus gate is ON and cannot \
             open — a pass here would claim a comparison that did not happen."
        );
        Some(path)
    }
}

#[cfg(test)]
mod corpus_tests {
    use super::corpus;

    /// The whole point: a corpus that was named and cannot be honoured must end
    /// the test, not skip it. Before this, it skipped and printed `ok`.
    #[test]
    #[should_panic(expected = "gate is ON and cannot open")]
    fn a_named_corpus_that_is_absent_fails_rather_than_skipping() {
        corpus::resolve(
            "SEANCE_CORPUS_GATE_SELFTEST",
            Some("/no/such/corpus/anywhere".to_string()),
            false,
        );
    }

    /// An unprovisioned corpus is a legitimate skip, and stays one.
    #[test]
    fn an_unset_variable_skips() {
        assert!(corpus::resolve("SEANCE_CORPUS_GATE_SELFTEST", None, false).is_none());
    }

    /// ...unless the caller demanded it, which is how CI asks for proof that
    /// the comparison actually ran.
    #[test]
    #[should_panic(expected = "SEANCE_REQUIRE_CORPUS demands it")]
    fn an_unset_variable_fails_when_the_corpus_is_required() {
        corpus::resolve("SEANCE_CORPUS_GATE_SELFTEST", None, true);
    }

    /// A corpus that is present resolves, and does not warn about anything.
    #[test]
    fn a_present_corpus_resolves() {
        let here = env!("CARGO_MANIFEST_DIR").to_string();
        assert_eq!(
            corpus::resolve("SEANCE_CORPUS_GATE_SELFTEST", Some(here.clone()), true),
            Some(std::path::PathBuf::from(here))
        );
    }
}
