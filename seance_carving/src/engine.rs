use crate::registry::SignatureRegistry;
use crate::signature::{DataCheckResult, FileRecovery, FileSignature, RecoveryInit};
use std::io;
use std::sync::Arc;
use tracing::{debug, trace};

/// A file discovered by the carving engine.
#[derive(Debug, Clone)]
pub struct CarvedFile {
    /// Byte offset in the source where the file starts
    pub offset: u64,
    /// Size of the recovered file in bytes
    pub size: u64,
    /// File extension (e.g., "jpg")
    pub extension: String,
    /// Name of the signature that matched (e.g., "JPEG")
    pub signature_name: String,
    /// Validation outcome:
    /// - `Some(true)`: the signature confirmed the file end — `data_check`
    ///   found the terminator and, where the signature implements
    ///   `verify_footer`, that independent check agreed
    /// - `Some(false)`: heuristic truncation (interrupted by a new header, the
    ///   end of the source, or the signature's `max_file_size` ceiling), or the
    ///   signature's `verify_footer` rejected the recovered tail; either way the
    ///   file was NOT footer-validated
    /// - `None`: no validation performed (size taken directly from the header)
    pub validated: Option<bool>,
}

/// Result of a carving scan, including whether it was cancelled early.
#[derive(Debug, Clone)]
pub struct ScanResult {
    /// Files recovered before completion or cancellation
    pub files: Vec<CarvedFile>,
    /// True if the scan stopped early due to a cancellation request
    pub cancelled: bool,
    /// Bytes scanned before completion or cancellation
    pub bytes_scanned: u64,
    /// Carves that matched a header and ran for real bytes but ended short of
    /// their signature's `min_filesize` (interrupted by a new header, the end
    /// of the source, a size cap or a data check), so were not recorded as
    /// files. `min_filesize` is a noise filter, but several signatures derive
    /// it from a header field a damaged or truncated file gets wrong; each such
    /// candidate is listed here (validated `Some(false)`, never silently
    /// dropped) so a caller can say "found but too short" instead of "nothing".
    pub below_minimum: Vec<CarvedFile>,
}

/// Where a finished carve goes: recorded files, or candidates that ended short
/// of their minimum size.
#[derive(Default)]
struct Outcomes {
    files: Vec<CarvedFile>,
    below_minimum: Vec<CarvedFile>,
}

impl Outcomes {
    /// Record `ar` as a file of `size` bytes if it reached its minimum size;
    /// otherwise note it in `below_minimum`. A zero-byte carve (a header that
    /// refused its own block) recovered nothing and is not noted.
    fn settle(&mut self, ar: &ActiveRecovery, size: u64, validated: Option<bool>) {
        let carved = CarvedFile {
            offset: ar.recovery.offset_start,
            size,
            extension: ar.recovery.extension.clone(),
            signature_name: ar.signature.name().to_string(),
            validated,
        };
        if size >= ar.recovery.min_filesize {
            self.files.push(carved);
        } else if size > 0 {
            debug!(
                "{} candidate at offset {} ended at {} bytes, below its {}-byte minimum: not recorded as a file",
                carved.signature_name, carved.offset, size, ar.recovery.min_filesize
            );
            self.below_minimum.push(carved);
        }
    }
}

/// Emit a progress callback every this many scanned bytes (64 MiB).
const PROGRESS_INTERVAL_BYTES: u64 = 64 * 1024 * 1024;

/// Cap on bytes read back to refine a calculated-size file's extension.
const CONTENT_REFINE_CAP: u64 = 16 * 1024 * 1024;

/// Check the cancellation callback every this many blocks (~128 KiB at the
/// default 512-byte block size).
const CANCEL_CHECK_BLOCKS: u64 = 256;

/// State of an active file recovery in progress.
struct ActiveRecovery {
    signature: Arc<dyn FileSignature>,
    recovery: FileRecovery,
    /// The offset of the first header-sized object recorded while this carve
    /// ran, and the furthest end of any such object (CARVE-016). A sized
    /// object is recorded without ending the carve, because it may be nested
    /// inside it (a thumbnail, an icon); the carve keeps its whole extent
    /// only if its own terminator is found past the object. Otherwise it is
    /// recorded as it always was: cut at the object's start, not validated.
    sized_cut: Option<(u64, u64)>,
}

impl ActiveRecovery {
    /// Record this carve cut at the first sized object met inside it, if one
    /// was. Returns whether the carve was settled that way; `false` leaves
    /// the caller to record it on its own path.
    fn record_cut_at_sized(&mut self, out: &mut Outcomes) -> bool {
        let Some((cut, _)) = self.sized_cut else {
            return false;
        };
        let file_size = cut - self.recovery.offset_start;
        self.recovery.file_size = file_size;
        out.settle(self, file_size, Some(false));
        if file_size >= self.recovery.min_filesize {
            debug!(
                "Carved {} at offset {} ({} bytes, interrupted by a sized header; \
                 no terminator of its own past the object)",
                self.signature.name(),
                self.recovery.offset_start,
                file_size
            );
        }
        true
    }
}

/// Trait abstracting the data source for the carving engine.
///
/// This mirrors `seance_core::data_source::DataSource` but avoids coupling
/// the carving library to seance_core. Callers provide a thin adapter.
pub trait CarvingDataSource: Send + Sync {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize>;
    fn size(&self) -> u64;
}

/// Read up to `buf.len()` bytes at `offset`, looping over partial reads so a
/// source that returns short at a run/extent boundary still fills the block.
/// Returns the number of bytes actually read; a value below `buf.len()` means
/// real end-of-data (or an I/O error). Callers must bound their scan to this
/// count and never treat the unread tail as content — fabricated zeros can
/// match footers/patterns and produce false carves (BUG-159).
pub(crate) fn read_full<S: CarvingDataSource + ?Sized>(
    source: &S,
    offset: u64,
    buf: &mut [u8],
) -> usize {
    let mut total = 0;
    while total < buf.len() {
        match source.read_at(offset + total as u64, &mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    total
}

/// Extra bytes read beyond the window each time the lookahead is refilled, so
/// one read serves about a thousand consecutive 512-byte blocks.
const LOOKAHEAD_EXTRA: usize = 1024 * 1024;

/// A read-ahead buffer that shows header checks more than one block.
///
/// Some formats put the proof of their identity past the first block: an ISO 9660
/// volume descriptor at 0x8000, an ext superblock magic at 0x438, an InnoDB page
/// at 0xc063. Their signatures declare `header_window()` and the engine hands
/// them the file's first bytes up to that many, read from the source here and
/// refilled only when the block being scanned nears the end of what is held.
#[derive(Default)]
struct Lookahead {
    start: u64,
    data: Vec<u8>,
    /// The last refill came back short: the source ends (or fails) at the end
    /// of `data`, so asking again would return the same.
    at_end: bool,
}

impl Lookahead {
    /// The up-to-`want` bytes of the source starting at `offset`; shorter only
    /// where the source ends or a read fails.
    fn window<S: CarvingDataSource>(&mut self, source: &S, offset: u64, want: usize) -> &[u8] {
        let held_end = self.start + self.data.len() as u64;
        let covered = offset >= self.start
            && (offset + want as u64 <= held_end || (self.at_end && offset <= held_end));
        if !covered {
            let request = want + LOOKAHEAD_EXTRA;
            self.data.resize(request, 0);
            let n = read_full(source, offset, &mut self.data);
            self.data.truncate(n);
            self.start = offset;
            self.at_end = n < request;
        }
        let from = ((offset - self.start) as usize).min(self.data.len());
        let to = (from + want).min(self.data.len());
        &self.data[from..to]
    }
}

/// Block-by-block carving engine with double-buffered scanning.
pub struct CarvingEngine {
    registry: Arc<SignatureRegistry>,
    block_size: usize,
}

impl CarvingEngine {
    pub fn new(registry: Arc<SignatureRegistry>) -> Self {
        Self {
            registry,
            block_size: 512,
        }
    }

    pub fn with_block_size(mut self, block_size: usize) -> Self {
        self.block_size = block_size;
        self
    }

    /// Scan a data source for carved files.
    ///
    /// Convenience wrapper around [`scan_with_progress`](Self::scan_with_progress)
    /// with no progress callback or cancellation.
    pub fn scan<S: CarvingDataSource>(&self, source: &S, size: u64) -> Vec<CarvedFile> {
        self.scan_with_progress(source, size, None, None).files
    }

    /// Scan a data source for carved files with progress and cancellation.
    ///
    /// Uses double-buffered block-by-block scanning (prev_block + current_block)
    /// following the PhotoRec pattern. For each block position, checks the registry
    /// for header matches. When matched, begins recovery calling data_check on
    /// subsequent blocks until Stop or max_file_size.
    ///
    /// `progress` is invoked as `(bytes_scanned, bytes_total)` roughly every
    /// 64 MiB scanned plus once at the end. `cancel` is polled periodically;
    /// when it returns true the scan stops and returns the partial results
    /// with `cancelled: true` (any unfinished recovery is discarded).
    pub fn scan_with_progress<S: CarvingDataSource>(
        &self,
        source: &S,
        size: u64,
        mut progress: Option<&mut dyn FnMut(u64, u64)>,
        cancel: Option<&dyn Fn() -> bool>,
    ) -> ScanResult {
        let mut results = Outcomes::default();
        let bs = self.block_size;
        // Signatures whose header lies past one block (ISO's volume descriptor,
        // an ext superblock) are shown a lookahead window; see `Lookahead`.
        let window_len = self.registry.max_header_window().max(bs);
        let mut lookahead = (window_len > bs).then(Lookahead::default);

        // One block buffer. (A previous double-buffer kept a "prev" half that
        // was never read -- find_matches/data_check only ever saw the current
        // block -- so it just cost a bs-byte memmove per block across the whole
        // image. Dropped.)
        let mut buf = vec![0u8; bs];
        let mut active: Option<ActiveRecovery> = None;
        let mut offset: u64 = 0;
        let mut cancelled = false;
        let mut blocks_scanned: u64 = 0;
        let mut last_progress_offset: u64 = 0;

        // Read the first block, looping over partial reads.
        let initial_read = read_full(source, 0, &mut buf);
        if initial_read == 0 {
            return ScanResult {
                files: Vec::new(),
                cancelled: false,
                bytes_scanned: 0,
                below_minimum: Vec::new(),
            };
        }
        // Only the bytes actually read are real content. The header/data scan is
        // bounded to `valid_len` so a short read never feeds fabricated zeros to
        // find_matches or data_check (BUG-159).
        let mut valid_len = initial_read;
        // One past the last source byte actually read. A carve running to "the
        // end of the source" may only claim up to here: bytes past a read that
        // returned nothing were never examined.
        let mut read_end = initial_read as u64;

        loop {
            if offset >= size {
                break;
            }

            // Cooperative cancellation, polled every CANCEL_CHECK_BLOCKS blocks.
            if blocks_scanned.is_multiple_of(CANCEL_CHECK_BLOCKS) {
                if let Some(cancel) = cancel {
                    if cancel() {
                        debug!("Carving scan cancelled at offset {} of {}", offset, size);
                        cancelled = true;
                        break;
                    }
                }
            }
            blocks_scanned += 1;

            // Progress callback every PROGRESS_INTERVAL_BYTES.
            if offset - last_progress_offset >= PROGRESS_INTERVAL_BYTES {
                if let Some(progress) = progress.as_deref_mut() {
                    progress(offset, size);
                }
                last_progress_offset = offset;
            }

            let current_block = &buf[..valid_len];

            // Check for new file headers in the current block
            let window = match lookahead.as_mut() {
                Some(la) => {
                    let w = la.window(source, offset, window_len);
                    if w.len() >= current_block.len() {
                        w
                    } else {
                        current_block
                    }
                }
                None => current_block,
            };
            let header_matches = self.registry.find_matches(window);

            for (sig, _match_off) in &header_matches {
                // find_matches only matches a pattern at its registered offset
                // from the block start, so the file itself always begins at the
                // block boundary (registered offset N means the magic is N bytes
                // into the file). Carve and header-check from the block start so
                // offset-N signatures (e.g. MP4/MOV: 4-byte size then atom type)
                // keep their leading bytes instead of starting at the magic.
                let absolute_offset = offset;

                // Header check from the block (file) start. find_matches only
                // pattern-matched the magic at its registered offset; validate it
                // with header_check before acting, because a loose signature (e.g. a
                // 1-byte OpenPGP packet tag) matches random data ~1.5% of the time.
                // Only a confirmed new file may interrupt the active recovery --
                // otherwise a spurious match on a block boundary would truncate the
                // real file being carved.
                let header_buf = if sig.header_window() > current_block.len() {
                    &window[..window.len().min(sig.header_window())]
                } else {
                    current_block
                };
                if let Some(mut init) = sig.header_check(header_buf, 0) {
                    // A format whose extent is the structure that follows its
                    // header is sized by walking that structure (CARVE-013).
                    if init.calculated_file_size.is_none() {
                        init.calculated_file_size = sig.extent_from_source(source, absolute_offset);
                    }
                    // A header match is only a claim. It ends the carve already
                    // running only once it would itself record a file: a sized
                    // match whose size is accepted, or an unsized match that
                    // survives its own data check on this block. A loose magic
                    // inside the running file's body otherwise cuts that file
                    // short and then records nothing in its place (CARVE-015).
                    // A weak header (a magic with no layout checked past it)
                    // may start a carve but never ends one (CARVE-015).
                    if active.is_some()
                        && (sig.weak_header()
                            || !Self::new_match_survives(
                                sig,
                                &init,
                                current_block,
                                source,
                                size,
                                absolute_offset,
                            ))
                    {
                        continue;
                    }
                    // A sized new file is recorded whole below and never
                    // starts a recovery of its own, so it need not end the
                    // one running: it may be nested inside it. The running
                    // carve remembers where it was met and how far it runs,
                    // and is settled when it ends (CARVE-016).
                    let is_sized = init.calculated_file_size.is_some();
                    if let (true, Some(ar)) = (is_sized, active.as_mut()) {
                        let object_end = absolute_offset.saturating_add(
                            init.calculated_file_size
                                .unwrap_or(0)
                                .min(size.saturating_sub(absolute_offset)),
                        );
                        ar.sized_cut = Some(match ar.sized_cut {
                            Some((cut, end)) => (cut, end.max(object_end)),
                            None => (absolute_offset, object_end),
                        });
                    }
                    // A genuine unsized new file starts here: finalize any
                    // active recovery, recording it as interrupted by the new
                    // header — at the first sized object inside it, if one
                    // was met, since that is where its evidence stops.
                    if let (false, Some(ar)) = (is_sized, active.as_mut()) {
                        if ar.record_cut_at_sized(&mut results) {
                            active = None;
                        }
                    }
                    if let (false, Some(ref mut ar)) = (is_sized, active.as_mut()) {
                        let file_size = absolute_offset - ar.recovery.offset_start;
                        ar.recovery.file_size = file_size;
                        results.settle(ar, file_size, Some(false));
                        if file_size >= ar.recovery.min_filesize {
                            debug!(
                                "Carved {} at offset {} ({} bytes, interrupted by new header)",
                                ar.signature.name(),
                                ar.recovery.offset_start,
                                ar.recovery.file_size
                            );
                        }
                        active = None;
                    }
                    // If the size is already known from the header, record it directly
                    if let Some(declared_size) = init.calculated_file_size {
                        // A header-declared size is attacker/corruption controlled.
                        // It is first accepted or rejected on its own merits, then
                        // clamped to the bytes that actually exist after the
                        // header: without the clamp the carved window runs past
                        // the end of the source and its digests cover a prefix
                        // while claiming the declared length (BUG-267).
                        let available = size.saturating_sub(absolute_offset);
                        let mut overruns_source = declared_size > available;
                        let calc_size = declared_size.min(available);
                        if declared_size >= init.min_filesize
                            && declared_size <= sig.max_file_size()
                            && calc_size >= init.min_filesize
                        {
                            // Optionally read the carved bytes so the signature
                            // can refine the extension from content (e.g. OLE2).
                            let mut extension = init.extension.clone();
                            let mut final_size = calc_size;
                            if sig.refines_extension() {
                                let cap = calc_size.min(CONTENT_REFINE_CAP) as usize;
                                let mut data = vec![0u8; cap];
                                let mut read = 0usize;
                                while read < cap {
                                    match source
                                        .read_at(absolute_offset + read as u64, &mut data[read..])
                                    {
                                        Ok(0) => break,
                                        Ok(n) => read += n,
                                        Err(_) => break,
                                    }
                                }
                                data.truncate(read);
                                let mut rec = FileRecovery::from_init(&init, absolute_offset);
                                sig.file_check(&data, &mut rec);
                                extension = rec.extension;
                                // file_check may refine the size DOWN from the
                                // header's worst-case estimate (e.g. OLE2 reading
                                // its FAT). Only shrink, and only within bounds,
                                // so an over-carve stops swallowing the next file.
                                if let Some(refined) = rec.calculated_file_size {
                                    if refined >= init.min_filesize && refined <= final_size {
                                        final_size = refined;
                                        // The file's own structure sized it
                                        // inside the source: it was not clamped
                                        // at the source's end, even when it
                                        // ends exactly there.
                                        overruns_source = false;
                                    }
                                }
                            }
                            results.files.push(CarvedFile {
                                offset: absolute_offset,
                                size: final_size,
                                extension,
                                signature_name: sig.name().to_string(),
                                // A file clamped to the end of the source was not
                                // validated and is short of its declared length:
                                // that is the same "heuristic truncation" the
                                // end-of-source path reports, never "unknown".
                                validated: if overruns_source { Some(false) } else { None },
                            });
                            if overruns_source {
                                debug!(
                                    "Carved {} at offset {} truncated to {} bytes: header size ran past the end of the source",
                                    sig.name(),
                                    absolute_offset,
                                    final_size
                                );
                            } else {
                                debug!(
                                    "Carved {} at offset {} ({} bytes, size from header)",
                                    sig.name(),
                                    absolute_offset,
                                    calc_size
                                );
                            }
                        }
                        // Size known from header: either recorded or rejected. Don't start active recovery.
                        continue;
                    }

                    // Begin active recovery (no calculated size; need data_check)
                    let recovery = FileRecovery::from_init(&init, absolute_offset);
                    active = Some(ActiveRecovery {
                        signature: sig.clone(),
                        recovery,
                        sized_cut: None,
                    });
                    trace!(
                        "Started recovery for {} at offset {}",
                        sig.name(),
                        absolute_offset
                    );
                }
            }

            // If we have an active recovery, feed data_check
            if let Some(ref mut ar) = active {
                // Set file_size to the start of the current block relative to recovery start.
                // This allows data_check to compute final sizes as file_size + position_in_block.
                let block_start_in_file = offset.saturating_sub(ar.recovery.offset_start);
                ar.recovery.file_size = block_start_in_file;
                // `valid_len`, not `bs`: on a short last block only the bytes
                // that were actually read are part of the file. Counting the
                // whole block fires the size cap up to a block early and
                // truncates a carve that had not reached it (B5-037).
                let bytes_so_far = block_start_in_file + valid_len as u64;

                // Check max file size. The cap bounds how far one recovery may
                // run, but it must not make the file disappear: a header was
                // matched and its bytes exist. Emit the extent up to the cap and
                // mark it NOT footer-validated, the same way a file clamped at
                // the end of the source is reported. Dropping it silently would
                // leave a real large file absent from the carve results with
                // nothing saying why (B2-144).
                if bytes_so_far > ar.signature.max_file_size() {
                    debug!(
                        "Max file size exceeded for {} at offset {} ({}>{} bytes): recording truncated carve",
                        ar.signature.name(),
                        ar.recovery.offset_start,
                        bytes_so_far,
                        ar.signature.max_file_size()
                    );
                    let available = size.saturating_sub(ar.recovery.offset_start);
                    let capped_size = ar.signature.max_file_size().min(available);
                    if ar.record_cut_at_sized(&mut results) {
                        // Settled at the sized object it met (CARVE-016).
                    } else {
                        ar.recovery.file_size = capped_size;
                        results.settle(ar, capped_size, Some(false));
                    }
                    active = None;
                } else {
                    match ar.signature.data_check(current_block, &mut ar.recovery) {
                        DataCheckResult::Continue => {
                            // Keep going
                        }
                        DataCheckResult::Stop(final_size) => {
                            // A signature may keep a trailing allowance past its
                            // footer; a footer near the end of the source then
                            // puts the stop past the bytes that exist. Clamp to
                            // them, and report the carve as not validated, as the
                            // sized path does for a header size that overruns.
                            let available = size.saturating_sub(ar.recovery.offset_start);
                            let clamped = final_size > available;
                            let final_size = final_size.min(available);
                            ar.recovery.file_size = final_size;

                            // Run file_check for final validation over the file's
                            // tail window. Loop the read so a short return at a
                            // run/extent boundary is not mistaken for EOF.
                            let check_size = final_size.min(8192) as usize;
                            let check_offset = ar.recovery.offset_start
                                + final_size.saturating_sub(check_size as u64);
                            let mut check_buf = vec![0u8; check_size];
                            let read_len = read_full(source, check_offset, &mut check_buf);
                            // A short read means the window is zero-padded. Do NOT
                            // run file_check on fabricated bytes (it can mutate the
                            // recovered size/extension from zeros) and never report
                            // a positive validation for content we could not read:
                            // the outcome is unknown (None) (BUG-159).
                            let validated = if clamped {
                                Some(false)
                            } else if read_len < check_size {
                                None
                            } else {
                                // Ask the signature to confirm the terminator on
                                // the bytes actually recovered, before file_check
                                // is allowed to adjust size or extension. A
                                // signature that disowns the tail marks the carve
                                // heuristic; one with no footer to check leaves
                                // the data_check verdict standing (B2-143).
                                let footer_ok = ar.signature.verify_footer(&check_buf);
                                ar.signature.file_check(&check_buf, &mut ar.recovery);
                                match footer_ok {
                                    Some(false) => Some(false),
                                    _ => Some(true),
                                }
                            };

                            // Past a sized object met inside it, the carve keeps
                            // its whole extent only on a terminator of its own
                            // beyond the object's end, confirmed; a terminator
                            // inside the object is the object's content
                            // (CARVE-016).
                            let keeps_whole_extent = match ar.sized_cut {
                                None => true,
                                Some((_, object_end)) => {
                                    validated == Some(true)
                                        && ar.recovery.offset_start + ar.recovery.file_size
                                            > object_end
                                }
                            };
                            if !keeps_whole_extent {
                                ar.record_cut_at_sized(&mut results);
                            } else {
                                results.settle(ar, ar.recovery.file_size, validated);
                                debug!(
                                    "Carved {} at offset {} ({} bytes)",
                                    ar.signature.name(),
                                    ar.recovery.offset_start,
                                    ar.recovery.file_size
                                );
                            }
                            active = None;
                        }
                        DataCheckResult::Error => {
                            // A header matched and its bytes exist; the
                            // structure stopped making sense partway through.
                            // Dropping the recovery outright removes a real
                            // object from the results with nothing saying why,
                            // which reads as "no such file was ever here".
                            // Emit what was recovered up to the block the check
                            // failed on, marked NOT validated — the same way
                            // the max-size and interrupted-by-header paths
                            // report a heuristic extent (B7-014).
                            let recovered = block_start_in_file;
                            if ar.record_cut_at_sized(&mut results) {
                                // Settled at the sized object it met (CARVE-016).
                            } else {
                                // A refusal on the header block itself (a
                                // header that failed its own structural check,
                                // CARVE-015) recovered nothing: `settle` records
                                // no zero-byte carve for it.
                                ar.recovery.file_size = recovered;
                                results.settle(ar, recovered, Some(false));
                            }
                            debug!(
                                "Data check error for {} at offset {}: recording {} recovered bytes as a heuristic carve",
                                ar.signature.name(),
                                ar.recovery.offset_start,
                                recovered
                            );
                            active = None;
                        }
                    }
                }
            }

            // Advance to the next block.
            offset += bs as u64;

            if offset >= size {
                break;
            }

            let bytes_read = read_full(source, offset, &mut buf);
            if bytes_read == 0 {
                break;
            }
            // Bound the next iteration's scan to the bytes actually read; the
            // unread tail of `buf` is never examined (BUG-159).
            valid_len = bytes_read;
            read_end = offset + bytes_read as u64;
        }

        // Finalize any active recovery at end of data. On cancellation the
        // unfinished recovery is discarded: its extent past the scanned range
        // was never examined, so emitting it would fabricate evidence.
        // A carve that met a sized object is settled at that object either
        // way: its bytes up to there were examined (CARVE-016).
        if let Some(ref mut ar) = active {
            if ar.record_cut_at_sized(&mut results) {
                active = None;
            }
        }
        if !cancelled {
            if let Some(ref mut ar) = active {
                // Clamp to the signature's cap rather than discarding: an extent
                // that reaches the end of the source is real content, and the
                // cap is our limit, not the file's (B2-144).
                // The extent is bounded by what was actually read: a read that
                // came back empty or failed mid-source leaves the bytes past it
                // unexamined, and the carve must not claim them.
                let final_size = read_end
                    .min(size)
                    .saturating_sub(ar.recovery.offset_start)
                    .min(ar.signature.max_file_size());
                ar.recovery.file_size = final_size;
                results.settle(ar, final_size, Some(false));
                if final_size >= ar.recovery.min_filesize {
                    debug!(
                        "Carved {} at offset {} ({} bytes, at end of source)",
                        ar.signature.name(),
                        ar.recovery.offset_start,
                        ar.recovery.file_size
                    );
                }
            }
        }

        let bytes_scanned = offset.min(size);
        if let Some(progress) = progress {
            progress(bytes_scanned, size);
        }

        ScanResult {
            files: results.files,
            cancelled,
            bytes_scanned,
            below_minimum: results.below_minimum,
        }
    }

    /// Whether a header match that `header_check` accepted would record a
    /// file of its own, judged before it is allowed to end a running carve
    /// (CARVE-015).
    ///
    /// - A sized match survives when its size passes the same bounds the
    ///   sized path applies before recording it.
    /// - Either kind does not survive when its signature, reading past the
    ///   header block in `source`, refutes the header
    ///   (`header_confirmed_by_source` is `Some(false)`).
    /// - An unsized match survives when its signature's `data_check` on the
    ///   header block, run on a fresh recovery exactly as the recovery itself
    ///   will first run it, neither refuses the block (`Error`) nor stops the
    ///   file short of its minimum size (which records nothing).
    pub(crate) fn new_match_survives(
        sig: &Arc<dyn FileSignature>,
        init: &RecoveryInit,
        block: &[u8],
        source: &dyn CarvingDataSource,
        size: u64,
        absolute_offset: u64,
    ) -> bool {
        // A header whose proof lies past its block (a TIFF directory) is
        // checked where it lies; a refutation there is treated as a stray
        // magic (a genuine file whose directory lies in a non-contiguous
        // fragment is treated the same way, a stated limit).
        if sig.header_confirmed_by_source(source, absolute_offset) == Some(false) {
            return false;
        }
        if let Some(declared_size) = init.calculated_file_size {
            let available = size.saturating_sub(absolute_offset);
            let calc_size = declared_size.min(available);
            return declared_size >= init.min_filesize
                && declared_size <= sig.max_file_size()
                && calc_size >= init.min_filesize;
        }
        let mut trial = FileRecovery::from_init(init, absolute_offset);
        trial.file_size = 0;
        match sig.data_check(block, &mut trial) {
            DataCheckResult::Continue => true,
            DataCheckResult::Stop(final_size) => final_size >= init.min_filesize,
            DataCheckResult::Error => false,
        }
    }

    /// Carve recoverable content from a file's slack space.
    ///
    /// Slack is the region between a file's logical end and the end of its last
    /// allocated cluster. `slack_offset` is the absolute byte offset of the
    /// slack start within `source`, `slack_len` its length in bytes, and
    /// `cluster_size` the allocation unit. Slack never spans a full cluster, so
    /// `slack_len` is defensively clamped to `cluster_size`.
    ///
    /// Runs signature detection plus a printable-ASCII strings pass over the
    /// slack bytes. Returned [`CarvedFile`] offsets are absolute within
    /// `source`. Zero-filled slack yields nothing (no fabrication).
    pub fn carve_slack<S: CarvingDataSource>(
        &self,
        source: &S,
        slack_offset: u64,
        slack_len: u64,
        cluster_size: u64,
    ) -> Vec<CarvedFile> {
        // Slack is always less than one cluster; clamp defensively so a bogus
        // length can never make us read (and attribute) another file's data.
        let slack_len = if cluster_size > 0 {
            slack_len.min(cluster_size)
        } else {
            slack_len
        };
        if slack_len == 0 {
            return Vec::new();
        }

        let mut buf = vec![0u8; slack_len as usize];
        // Loop the read: a source that returns short at a run or extent
        // boundary would otherwise have its remaining slack analysed as though
        // it were the whole window, and the untouched tail of the buffer is
        // zeros that were never on the disk — zeros that match footers and
        // produce carves out of nothing (BUG-159, B5-024).
        let n = read_full(source, slack_offset, &mut buf);
        buf.truncate(n);
        if buf.is_empty() {
            return Vec::new();
        }

        // Printable-ASCII strings pass (offsets made absolute in `source`).
        let mut results = extract_ascii_strings(&buf, slack_offset);

        // Signature detection over an in-memory view of the slack bytes.
        let mem = InMemorySlice { data: buf };
        let mem_size = mem.size();
        let scan = self.scan_with_progress(&mem, mem_size, None, None);
        for mut cf in scan.files {
            cf.offset += slack_offset;
            results.push(cf);
        }

        results
    }

    /// Compute the slack region for a file.
    ///
    /// Given the file's logical size, the allocation `cluster_size`, and the
    /// absolute byte offset of the end of its last allocated cluster
    /// (`allocation_end_absolute`), returns `(slack_offset_absolute, slack_len)`
    /// or `None` when there is no slack (logical size is a whole number of
    /// clusters, or the geometry is degenerate).
    pub fn slack_region(
        logical_size: u64,
        cluster_size: u64,
        allocation_end_absolute: u64,
    ) -> Option<(u64, u64)> {
        if cluster_size == 0 || logical_size == 0 {
            return None;
        }
        let rem = logical_size % cluster_size;
        if rem == 0 {
            return None;
        }
        let slack_len = cluster_size - rem;
        if slack_len == 0 || slack_len > allocation_end_absolute {
            return None;
        }
        Some((allocation_end_absolute - slack_len, slack_len))
    }
}

/// Minimum length of a printable-ASCII run recovered from slack as a string.
const MIN_SLACK_STRING_LEN: usize = 8;

/// In-memory carving source backing the slack strings/signature passes.
struct InMemorySlice {
    data: Vec<u8>,
}

impl CarvingDataSource for InMemorySlice {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let off = offset as usize;
        if off >= self.data.len() {
            return Ok(0);
        }
        let avail = self.data.len() - off;
        let n = buf.len().min(avail);
        buf[..n].copy_from_slice(&self.data[off..off + n]);
        Ok(n)
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}

/// Printable-ASCII test for the slack strings pass (includes tab/newline/CR so
/// multi-line text stays a single run). Zero bytes are never printable.
fn is_ascii_text(b: u8) -> bool {
    (0x20..=0x7E).contains(&b) || b == b'\t' || b == b'\n' || b == b'\r'
}

/// Extract printable-ASCII runs of at least [`MIN_SLACK_STRING_LEN`] bytes as
/// `Strings` carved files. `base_offset` is added so offsets are absolute.
fn extract_ascii_strings(buf: &[u8], base_offset: u64) -> Vec<CarvedFile> {
    let mut out = Vec::new();
    let mut run_start = 0usize;
    let mut in_run = false;
    for i in 0..=buf.len() {
        let printable = i < buf.len() && is_ascii_text(buf[i]);
        if printable && !in_run {
            in_run = true;
            run_start = i;
        } else if !printable && in_run {
            in_run = false;
            let len = i - run_start;
            if len >= MIN_SLACK_STRING_LEN {
                out.push(CarvedFile {
                    offset: base_offset + run_start as u64,
                    size: len as u64,
                    extension: "txt".to_string(),
                    signature_name: "Strings".to_string(),
                    validated: None,
                });
            }
        }
    }
    out
}
