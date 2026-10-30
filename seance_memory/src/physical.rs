//! [`PhysicalLayer`]: the leaf of every memory layer chain.

use seance_core::data_source::{DataSource, PhysicalMap};
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::format::MemoryImageFormat;
use crate::layer::{LayerError, MappedRange, MemoryHole, MemoryLayer};
use crate::meta::LayerMeta;

/// Flat physical memory over an arbitrary Séance [`DataSource`]: offset *is*
/// physical address, one to one.
///
/// This is the layer that makes a memory image immediately useful. Wrapping a
/// `.raw`/`.mem` dump — or a decoded LiME/crash-dump view, or a window inside
/// an E01 — in a `PhysicalLayer` gives it a memory address space without
/// copying a byte, and because a memory layer is still a `DataSource`, the
/// hasher, the 358-signature carving engine, the search indexer and the API
/// content resolver all work over it with no memory-specific code.
///
/// A flat acquisition has no holes by construction: every offset from `0` to
/// `size - 1` is backed. That is what "physical memory image" means when the
/// image really is flat, and it is why [`PhysicalLayer::mapping`] can answer
/// with a single identity run.
///
/// It is **not** true of every source this layer gets wrapped around. A decoded
/// LiME or crash dump presents memory-space addressing with genuine holes where
/// the acquisition skipped a region, and handing that to a layer that answers
/// "all of it is backed" produces a false completeness claim: `is_valid` and any
/// coverage calculation treat unacquired ranges as present, and the mapping then
/// disagrees with the read that later fails on the same address. So a caller
/// that knows the geometry supplies it with [`PhysicalLayer::with_backed`], and
/// a caller that does not gets the flat answer, which is the honest one for a
/// flat image.
#[derive(Debug)]
pub struct PhysicalLayer {
    inner: Arc<dyn DataSource>,
    size: u64,
    meta: LayerMeta,
    /// The ranges actually backed by acquired bytes, as `(start, length)` pairs
    /// sorted by start and non-overlapping. `None` means flat: everything in
    /// range is backed.
    backed: Option<Vec<(u64, u64)>>,
}

impl PhysicalLayer {
    /// Wrap `inner` as flat physical memory.
    ///
    /// # Errors
    ///
    /// [`LayerError::EmptySource`] if `inner` is empty. An address space with
    /// no addresses has no meaningful `max_address`, and inventing one would
    /// make every bound in this crate a special case.
    pub fn new(inner: Arc<dyn DataSource>, meta: LayerMeta) -> Result<Self, LayerError> {
        let size = inner.size();
        if size == 0 {
            return Err(LayerError::EmptySource);
        }
        Ok(Self {
            inner,
            size,
            meta,
            backed: None,
        })
    }

    /// Declare which ranges of this layer are actually backed by acquired bytes.
    ///
    /// For a source that is flat, do not call this: the default answer — every
    /// address in range is backed — is correct and cheaper.
    ///
    /// Call it whenever the geometry is known to be sparse. A decoded LiME or
    /// crash dump reaches analysis as an opaque `DataSource` that has already
    /// been translated into memory space, so the holes are invisible unless the
    /// producer says where they are. Without that, the layer reports full
    /// coverage for an image with gaps in it, which is the claim an examiner
    /// would act on.
    ///
    /// Ranges are normalised: sorted, empty ones dropped, and touching or
    /// overlapping ones merged, so `mapping` can walk them once.
    pub fn with_backed(mut self, mut ranges: Vec<(u64, u64)>) -> Self {
        ranges.retain(|(_, len)| *len > 0);
        ranges.sort_unstable();
        let mut merged: Vec<(u64, u64)> = Vec::with_capacity(ranges.len());
        for (start, len) in ranges {
            match merged.last_mut() {
                Some((prev_start, prev_len)) if start <= prev_start.saturating_add(*prev_len) => {
                    let end = start.saturating_add(len);
                    let prev_end = prev_start.saturating_add(*prev_len);
                    *prev_len = end.max(prev_end) - *prev_start;
                }
                _ => merged.push((start, len)),
            }
        }
        self.backed = Some(merged);
        self
    }

    /// The backed ranges, when the geometry was declared.
    pub fn backed(&self) -> Option<&[(u64, u64)]> {
        self.backed.as_deref()
    }

    /// Wrap `inner` as raw physical memory.
    ///
    /// Reserved for the case where an **examiner has declared** the source to
    /// be a memory image. Raw memory carries no magic and cannot be detected
    /// (see [`MemoryImageFormat::Raw`]), so calling this on a source that was
    /// merely *assumed* to be memory records a format claim nothing supports.
    pub fn raw(inner: Arc<dyn DataSource>) -> Result<Self, LayerError> {
        Self::new(inner, LayerMeta::new(MemoryImageFormat::Raw))
    }

    /// The source this layer projects onto.
    pub fn inner(&self) -> &Arc<dyn DataSource> {
        &self.inner
    }
}

impl DataSource for PhysicalLayer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let Some(backed) = self.backed.as_deref() else {
            // Delegation is deliberate and total: a flat layer has no holes, so
            // every failure mode here is the inner source's, unchanged.
            return self.inner.read_at(offset, buf);
        };

        // Above the top of the address space, or nothing asked for: genuine
        // EOF, and the `DataSource` contract for that is `Ok(0)`. It must be
        // answered BEFORE the geometry is consulted — the last acquired run of
        // a sparse image usually ends before `size`, so treating the end of the
        // evidence as an unacquired hole would make every streaming consumer
        // (hasher, carver, indexer) fail on the final read of every sparse
        // image, and would say "not captured" about an address that does not
        // exist. See `MemoryHole`'s table: EOF and hole are distinct outcomes.
        if buf.is_empty() || offset >= self.size {
            return Ok(0);
        }

        // Sparse geometry, so the layer's own coordinates have holes in them —
        // and the inner source does not. It is a flat file of `size` bytes with
        // *something* at every offset: zeroes, padding, or whichever bytes the
        // decoder happened to leave. Reading through it for an address the
        // geometry calls unacquired hands the caller bytes that were never in
        // the machine's RAM, and `mapping` has already said those addresses are
        // a hole. Coverage and content must not be able to disagree.
        let Some(&(start, len)) = backed
            .iter()
            .find(|(start, len)| offset >= *start && offset < start.saturating_add(*len))
        else {
            // A typed hole, not a generic I/O error: `MemoryHole::from_io` is
            // how a memory-aware caller turns this into a named gap with its
            // exact range (dump extraction records `unacquired`/`unmapped`
            // rather than `read_failed`, and structural readers stamp
            // `IncompleteReason::ShortRead`). `backed` is sorted, so the next
            // run's start — or the top of the space — bounds the hole.
            let next = backed
                .iter()
                .map(|(start, _)| *start)
                .find(|start| *start > offset)
                .unwrap_or(self.size);
            return Err(MemoryHole::unmapped(offset, next.saturating_sub(offset)).into_io());
        };

        // Clipped at the end of the run the read started in. A caller wanting
        // the whole request either loops — and is told at the hole — or asks
        // `mapping` first. A short read here is the truth; a full one would be
        // the hole served as memory.
        let available = start
            .saturating_add(len)
            .saturating_sub(offset)
            .min(buf.len() as u64) as usize;
        self.inner.read_at(offset, &mut buf[..available])
    }

    fn size(&self) -> u64 {
        self.size
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.inner.get_underlying_path()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        // Kept reachable so a format reader can find a `.vmss` beside a
        // `.vmem`, or a pagefile beside a raw dump, even inside a container.
        self.inner.open_sibling(suffix)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        // Identity coordinates: this layer's offset is the inner source's
        // offset, so "where in the acquisition file is physical address X" is
        // answered by the chain below with no adjustment.
        self.inner.physical_map(offset, len)
    }
}

impl MemoryLayer for PhysicalLayer {
    fn min_address(&self) -> u64 {
        0
    }

    fn max_address(&self) -> u64 {
        // `size >= 1` is enforced at construction.
        self.size - 1
    }

    fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        if offset > self.max_address() {
            return Err(LayerError::OutOfRange {
                address: offset,
                max_address: self.max_address(),
            });
        }
        // Clip at the top of the address space, exactly as any DataSource read
        // would. A caller that needs to know whether the whole request came
        // back asks `is_valid`, or `backed_len` over these runs — not
        // `covered_len`, which answers how much address space the runs describe
        // and is only equal to the request for a layer like this one, whose
        // runs happen to be clipped to it.
        let available = self.size - offset;
        let length = length.min(available);

        let Some(backed) = self.backed.as_deref() else {
            // Flat by construction: every address in range is backed.
            return Ok(vec![MappedRange::identity(offset, length, offset)]);
        };

        // Sparse: report only the parts genuinely covered. A gap produces no
        // run rather than a fabricated one, so `backed_len` comes back short
        // and the caller learns the request was not fully satisfiable BEFORE
        // reading, instead of discovering it from a read that fails later.
        let end = offset.saturating_add(length);
        let mut runs = Vec::new();
        for &(start, len) in backed {
            let range_end = start.saturating_add(len);
            if range_end <= offset {
                continue;
            }
            if start >= end {
                break;
            }
            let from = start.max(offset);
            let to = range_end.min(end);
            if to > from {
                runs.push(MappedRange::identity(from, to - from, from));
            }
        }
        Ok(runs)
    }

    /// Answered from the declared geometry, which is the whole reason this
    /// layer can report a window inside a hole as `Ok` with no runs: it knows
    /// where the next acquired byte is. See [`MemoryLayer::next_backed`].
    fn next_backed(&self, address: u64) -> Option<u64> {
        if address > self.max_address() {
            return None;
        }
        let Some(backed) = self.backed.as_deref() else {
            // Flat: every address in range is backed.
            return Some(address);
        };
        backed
            .iter()
            .filter(|(start, len)| start.saturating_add(*len) > address)
            .map(|(start, _)| (*start).max(address))
            .min()
    }

    fn layer_meta(&self) -> &LayerMeta {
        &self.meta
    }

    fn as_data_source(&self) -> &dyn DataSource {
        self
    }
}

#[cfg(test)]
mod backed_tests {
    use super::*;
    use crate::layer::covered_len;
    use seance_core::data_source::ByteSliceDataSource;

    fn image(len: usize) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(
            (0..len).map(|i| (i % 251) as u8).collect(),
        ))
    }

    fn sparse() -> PhysicalLayer {
        // 0x4000 bytes addressable, but only 0..0x1000 and 0x3000..0x4000 were
        // ever acquired — the shape a LiME or crash dump has after decoding.
        PhysicalLayer::raw(image(0x4000))
            .expect("non-empty")
            .with_backed(vec![(0, 0x1000), (0x3000, 0x1000)])
    }

    #[test]
    fn a_sparse_layer_does_not_claim_the_hole_is_backed() {
        // The defect this guards: a decoded sparse acquisition wrapped in a
        // layer that answered with one identity run. Every coverage figure and
        // every `is_valid` then treated the unacquired middle as present, and
        // the mapping disagreed with the read that later failed on it.
        let layer = sparse();
        let runs = layer.mapping(0, 0x4000).expect("in range");
        assert_eq!(runs.len(), 2, "the gap must not be papered over: {runs:?}");
        assert_eq!(
            covered_len(&runs),
            0x2000,
            "only what was acquired is covered"
        );
    }

    #[test]
    fn a_request_landing_entirely_in_a_hole_yields_no_runs() {
        let layer = sparse();
        let runs = layer.mapping(0x1800, 0x400).expect("in range");
        assert!(
            runs.is_empty(),
            "an unacquired range is not partly acquired"
        );
        assert_eq!(covered_len(&runs), 0);
    }

    #[test]
    fn a_request_straddling_a_hole_reports_only_the_acquired_part() {
        let layer = sparse();
        let runs = layer.mapping(0x0F00, 0x2200).expect("in range");
        assert_eq!(
            covered_len(&runs),
            0x100 + 0x100,
            "0x0F00..0x1000 and 0x3000..0x3100"
        );
    }

    #[test]
    fn a_read_in_a_declared_hole_fails_rather_than_serving_the_bytes_underneath() {
        // The inner source is a flat file with something at every offset. If
        // the layer reads through it for an address its own geometry calls
        // unacquired, an examiner gets bytes that were never in RAM — usually
        // zeroes, indistinguishable from acquired zeroes — while `mapping` for
        // the same address says nothing is there. Coverage and content would
        // then disagree, and the content is the half that reaches a report.
        let layer = sparse();

        let mut buf = [0u8; 0x100];
        let err = layer
            .read_at(0x1800, &mut buf)
            .expect_err("an unacquired address has no bytes to serve");
        assert!(err.to_string().contains("0x1800"), "{err}");
        // And it travels as a typed hole, so a caller records the exact
        // unacquired range instead of only "a read failed".
        let hole = MemoryHole::from_io(&err).expect("the hole must reach the caller");
        assert_eq!(hole.address, 0x1800);
        assert_eq!(hole.length, 0x3000 - 0x1800, "up to the next acquired run");

        // A read that starts inside an acquired run stops at its end rather
        // than running on into the hole.
        let mut buf = [0u8; 0x200];
        let read = layer
            .read_at(0x0F00, &mut buf)
            .expect("the acquired part is readable");
        assert_eq!(read, 0x100, "clipped at the end of the acquired run");

        // And an entirely acquired read is unaffected.
        let mut buf = [0u8; 0x10];
        assert_eq!(layer.read_at(0x3000, &mut buf).expect("acquired"), 0x10);
    }

    #[test]
    fn the_end_of_a_sparse_address_space_is_eof_not_an_unacquired_hole() {
        // The last acquired run of a sparse image rarely reaches `size`, so a
        // geometry check that ran before the EOF check would report the end of
        // the evidence as "the acquisition did not capture this" and would make
        // every streaming consumer error on its final read.
        let layer = sparse();
        let mut buf = [0u8; 0x10];
        assert_eq!(
            layer.read_at(0x4000, &mut buf).expect("EOF is Ok(0)"),
            0,
            "past the top of the address space is EOF, never a hole"
        );
        assert_eq!(
            layer.read_at(0x8000, &mut buf).expect("EOF is Ok(0)"),
            0,
            "well past the top is still EOF"
        );
        // A zero-length read is not a claim about the address at all.
        assert_eq!(layer.read_at(0x1800, &mut []).expect("nothing asked"), 0);
    }

    /// **A sparse layer says where the next acquired byte is.** It reports a
    /// window inside a hole as `Ok` with no runs rather than refusing, which a
    /// walk cannot tell from a layer that cannot describe itself — so it has
    /// to be able to answer this. Before it could, a scan of every sparse
    /// image ended at its first hole.
    #[test]
    fn a_sparse_layer_says_where_the_next_acquired_byte_is() {
        let layer = sparse();
        // Inside the first acquired run: itself.
        assert_eq!(layer.next_backed(0x0), Some(0x0));
        assert_eq!(layer.next_backed(0x500), Some(0x500));
        // Inside the hole: the start of the next acquired run.
        assert_eq!(layer.next_backed(0x1800), Some(0x3000));
        // Inside the second run: itself.
        assert_eq!(layer.next_backed(0x3500), Some(0x3500));
        // Above every run: nothing is backed above this, and the answer is
        // `None` rather than an address that holds nothing.
        assert_eq!(layer.next_backed(0x4000), None);
        assert_eq!(layer.next_backed(0x9000), None);
    }

    /// And a flat layer answers with the address itself, which is the default
    /// every other layer takes.
    #[test]
    fn a_flat_layer_says_every_address_in_range_is_backed() {
        let layer = PhysicalLayer::raw(image(0x4000)).expect("non-empty");
        assert_eq!(layer.next_backed(0), Some(0));
        assert_eq!(layer.next_backed(0x3FFF), Some(0x3FFF));
        assert_eq!(layer.next_backed(0x4000), None, "past the top");
    }

    #[test]
    fn a_flat_layer_still_answers_with_one_run() {
        // The default must stay cheap and correct for a genuinely flat image:
        // declaring geometry is for callers that know it is sparse.
        let layer = PhysicalLayer::raw(image(0x4000)).expect("non-empty");
        let runs = layer.mapping(0, 0x4000).expect("in range");
        assert_eq!(runs.len(), 1);
        assert_eq!(covered_len(&runs), 0x4000);
        assert!(layer.backed().is_none());
    }

    #[test]
    fn touching_and_overlapping_ranges_are_merged() {
        let layer = PhysicalLayer::raw(image(0x4000))
            .expect("non-empty")
            .with_backed(vec![
                (0x1000, 0x1000),
                (0x2000, 0x800),
                (0, 0x400),
                (0x100, 0x100),
            ]);
        let backed = layer.backed().expect("declared");
        assert_eq!(backed, &[(0, 0x400), (0x1000, 0x1800)]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{covered_len, Encoding, MemoryHole};
    use crate::meta::Architecture;
    use seance_core::data_source::{
        ByteSliceDataSource, DeviceImageSource, ExtentPrecision, WindowSource,
    };
    use seance_core::io::{read_exact_or_fail, IncompleteReason};

    fn image(len: usize) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(
            (0..len).map(|i| (i % 251) as u8).collect(),
        ))
    }

    fn layer(len: usize) -> PhysicalLayer {
        PhysicalLayer::raw(image(len)).expect("non-empty source")
    }

    #[test]
    fn a_valid_image_reads_at_its_physical_addresses() {
        let l = layer(0x4000);
        assert_eq!(l.size(), 0x4000);
        assert_eq!(l.min_address(), 0);
        assert_eq!(l.max_address(), 0x3FFF);

        let mut buf = [0u8; 16];
        assert_eq!(l.read_at(0x1000, &mut buf).unwrap(), 16);
        let expected: Vec<u8> = (0x1000..0x1010).map(|i: usize| (i % 251) as u8).collect();
        assert_eq!(buf.to_vec(), expected);
    }

    #[test]
    fn the_whole_space_maps_as_one_identity_run() {
        let l = layer(0x4000);
        let runs = l.mapping(0, 0x4000).expect("fully mapped");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0], MappedRange::identity(0, 0x4000, 0));
        assert_eq!(runs[0].encoding, Encoding::Identity);
        assert!(l.is_valid(0, 0x4000));
    }

    #[test]
    fn a_flat_layer_has_no_holes_anywhere_in_its_space() {
        let l = layer(0x4000);
        for addr in [0u64, 1, 0x800, 0x3FFF] {
            assert!(l.is_valid(addr, 1), "address {addr:#x} must be backed");
            assert_eq!(l.mapping(addr, 1).unwrap()[0].mapped_offset, addr);
        }
    }

    #[test]
    fn reads_past_the_top_are_eof_not_holes() {
        // The distinction that keeps "the image ends here" apart from "these
        // bytes were never captured".
        let l = layer(0x1000);
        let mut buf = [0u8; 8];
        assert_eq!(l.read_at(0x1000, &mut buf).unwrap(), 0);
        assert_eq!(l.read_at(0xFFFF_FFFF, &mut buf).unwrap(), 0);
    }

    #[test]
    fn mapping_clips_at_the_top_and_reports_it_honestly() {
        let l = layer(0x1000);
        let runs = l.mapping(0xF00, 0x1000).expect("start is in range");
        assert_eq!(covered_len(&runs), 0x100, "clipped, not extended");
        assert!(
            !l.is_valid(0xF00, 0x1000),
            "a request running off the end is not fully valid"
        );
    }

    #[test]
    fn mapping_above_the_top_is_out_of_range_not_a_hole() {
        let l = layer(0x1000);
        let err = l.mapping(0x1000, 16).expect_err("no such address");
        assert!(err.hole().is_none(), "past the end is not a memory hole");
        assert!(matches!(
            err,
            LayerError::OutOfRange {
                address: 0x1000,
                max_address: 0xFFF
            }
        ));
    }

    #[test]
    fn a_zero_length_mapping_is_an_empty_run_list() {
        let l = layer(0x1000);
        assert!(l.mapping(0x400, 0).unwrap().is_empty());
    }

    #[test]
    fn an_empty_source_is_refused_rather_than_given_undefined_bounds() {
        let empty: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(Vec::new()));
        let err = PhysicalLayer::raw(empty).expect_err("an empty address space is not a layer");
        assert!(matches!(err, LayerError::EmptySource));
    }

    #[test]
    fn a_truncated_structural_read_fails_closed() {
        // Ten bytes exist where a 32-byte header is expected. The shared helper
        // must refuse rather than parse twenty-two fabricated zeros.
        let l = layer(10);
        let mut buf = [0u8; 32];
        let err = read_exact_or_fail(l.as_data_source(), 0, &mut buf, "LiME segment header")
            .expect_err("must not parse a padded buffer");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("LiME segment header"));
        // And it is EOF, not a hole: the evidence ended, nothing is missing
        // from inside it.
        assert!(MemoryHole::from_io(&err).is_none());
    }

    #[test]
    fn a_source_that_dribbles_bytes_does_not_produce_a_short_layer_read() {
        let l = PhysicalLayer::raw(Arc::new(seance_core::test_support::DribbleSource::new(
            vec![0xC3; 100],
            7,
        )))
        .unwrap();
        let mut buf = [0u8; 64];
        // The layer forwards the short read verbatim (that is the DataSource
        // contract); the shared helper is what loops.
        assert_eq!(l.read_at(0, &mut buf).unwrap(), 7);
        read_exact_or_fail(l.as_data_source(), 0, &mut buf, "header").expect("all 64 bytes exist");
        assert!(buf.iter().all(|&b| b == 0xC3));
    }

    #[test]
    fn physical_addresses_project_back_to_the_acquisition_file() {
        // The payoff described in the plan: "which offset in the acquisition
        // file holds this physical address" falls out of the existing API.
        let device: Arc<dyn DataSource> = Arc::new(DeviceImageSource::new(image(0x10_0000)));
        // The memory image sits at offset 0x2_0000 inside the device image.
        let window: Arc<dyn DataSource> = Arc::new(WindowSource::new(device, 0x2_0000, 0x1_0000));
        let l = PhysicalLayer::raw(window).unwrap();

        let map = l.physical_map(0x1000, 0x400);
        assert_eq!(map.precision, ExtentPrecision::Exact);
        assert_eq!(map.extents.len(), 1);
        assert_eq!(map.extents[0].device_offset, Some(0x2_1000));
        assert_eq!(map.extents[0].length, 0x400);
    }

    #[test]
    fn metadata_is_carried_and_inheritable() {
        let meta = LayerMeta::new(MemoryImageFormat::WindowsCrashDump64)
            .with_architecture(Architecture::X64)
            .with_declared_size(0x8000_0000)
            .with_note("directory_table_base", 0x1a_b000u64)
            .with_incomplete(IncompleteReason::ShortRead, "final run past end of file");
        let l = PhysicalLayer::new(image(0x1000), meta).unwrap();

        let m = l.layer_meta();
        assert_eq!(m.format(), Some(MemoryImageFormat::WindowsCrashDump64));
        assert_eq!(m.architecture(), Some(Architecture::X64));
        assert_eq!(m.declared_size(), Some(0x8000_0000));
        assert_eq!(m.incomplete_chain().len(), 1);
        assert!(m.note("directory_table_base").is_some());
    }

    #[test]
    fn declared_size_can_disagree_with_the_actual_source_size() {
        // A truncated acquisition: the header says 2 GiB, the file holds 4 KiB.
        // Both numbers survive, because the discrepancy is the evidence.
        let meta = LayerMeta::new(MemoryImageFormat::Lime)
            .with_declared_size(0x8000_0000)
            .with_incomplete(IncompleteReason::ShortRead, "acquisition truncated");
        let l = PhysicalLayer::new(image(0x1000), meta).unwrap();
        assert_eq!(l.size(), 0x1000);
        assert_eq!(l.layer_meta().declared_size(), Some(0x8000_0000));
        assert!(!l.layer_meta().incomplete().is_empty());
    }

    #[test]
    fn siblings_and_paths_stay_reachable_through_the_layer() {
        use seance_core::data_source::SiblingBundleSource;
        use std::collections::HashMap;

        let pagefile: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![1, 2, 3]));
        let mut siblings = HashMap::new();
        siblings.insert(".vmss".to_string(), pagefile);
        let bundled: Arc<dyn DataSource> =
            Arc::new(SiblingBundleSource::new(image(0x1000), siblings));

        let l = PhysicalLayer::raw(bundled).unwrap();
        assert!(l.open_sibling(".vmss").is_some());
        assert!(l.open_sibling(".vmsn").is_none());
        assert!(l.get_underlying_path().is_none());
    }

    #[test]
    fn the_layer_is_usable_as_a_trait_object() {
        let l: Arc<dyn MemoryLayer> = Arc::new(layer(0x2000));
        assert_eq!(l.max_address(), 0x1FFF);
        let mut buf = [0u8; 4];
        assert_eq!(l.as_data_source().read_at(0, &mut buf).unwrap(), 4);
    }
}
