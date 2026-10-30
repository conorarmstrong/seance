//! [`SegmentedLayer`]: the run-list machinery every non-flat acquisition format
//! shares.
//!
//! LiME, ELF64 core, Windows crash dumps (both the run-list and bitmap
//! variants), VMware and Xen all reduce to the same statement: *a list of
//! `(file_offset, memory_offset, length)` triples*. Implementing that once
//! means each format reader only has to produce its segment list; it never
//! writes an address-lookup loop, and therefore never gets one wrong.
//!
//! Volatility factors this the same way (`layers/segmented.py`), with one
//! difference that matters more than all the rest: upstream's `mapping()` takes
//! an `ignore_errors` flag that **skips straight over an unmapped gap**. A
//! caller that passes it reads the far side of a gap believing it was
//! contiguous with the near side, which is how a scanner ends up reporting a
//! hit at an address that does not hold it. Here, a gap is
//! [`crate::layer::MemoryHole`], always, in both `read_at` and `mapping`.
//!
//! ## Strided runs, and why a run list is not always a list of extents
//!
//! One acquisition format breaks the "triple" shape: a QEMU `savevm` writes an
//! eight-byte address word *before every 4096-byte page*, so a bulk migration
//! pass is contiguous in the guest and interleaved in the file. Modelled as one
//! [`Segment`] per page it costs a run per page, and [`MAX_SEGMENTS`] is reached
//! at 4 GiB of guest RAM — a hard refusal for every larger guest, which is a
//! ceiling imposed by the index rather than by the evidence.
//!
//! So a [`Segment`] is a run of equally-spaced **chunks**: `chunk` memory bytes
//! per chunk, `stride` source bytes from one chunk to the next, contiguous in
//! memory throughout. An ordinary extent is the degenerate case of exactly one
//! chunk, which is what [`Segment::new`] builds and what every other reader
//! produces. Raising [`MAX_SEGMENTS`] instead would have traded the hard error
//! for an allocation proportional to guest size, which is the same refusal
//! arriving later and less legibly.

use seance_core::data_source::{DataSource, ExtentPrecision, PhysicalExtent, PhysicalMap};
use seance_core::io::read_full;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::layer::{
    BackingSource, Encoding, LayerError, MappedRange, MemoryHole, MemoryLayer, MAX_SEGMENTS,
};
use crate::meta::LayerMeta;

/// Where one chunk of a [`Segment`] sits, in both address spaces.
///
/// Returned by [`Segment::chunk_containing`], which is the only correct way to
/// get from a memory address to the bytes behind it. For a strided run the
/// source offset is *not* `file_offset + (address - memory_offset)`, and
/// computing it that way serves the bytes of a different page while looking
/// entirely right.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkLocation {
    /// First memory address the chunk covers.
    pub memory_offset: u64,
    /// Memory bytes the chunk covers.
    pub length: u64,
    /// Offset of the chunk's stored bytes in the underlying source.
    pub file_offset: u64,
    /// Bytes the source stores for the chunk. Equal to `length` unless the
    /// chunk is encoded, in which case they decode, as a unit, to `length`.
    pub stored_len: u64,
}

impl ChunkLocation {
    /// Whether the stored bytes are the memory bytes, byte for byte.
    pub fn is_identity(&self) -> bool {
        self.stored_len == self.length
    }
}

/// One run of acquired memory, contiguous in the layer's address space.
///
/// The ordinary case is a single chunk: `length` bytes living at `file_offset`
/// in the acquisition source, holding the memory addresses
/// `[memory_offset, memory_offset + length)`. That is what [`Segment::new`]
/// builds, and every field below collapses to `length` for it, so a reader that
/// only produces extents never has to think about the rest.
///
/// The general case is a **strided** run of `length / chunk` chunks: chunk *i*
/// holds the memory addresses
/// `[memory_offset + i * chunk, memory_offset + (i + 1) * chunk)` in
/// `chunk_stored` source bytes at `file_offset + i * stride`. Memory stays
/// contiguous across the whole run; only the source side is interleaved. See
/// the module documentation for the acquisition format that needs this and what
/// modelling it chunk-by-chunk cost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// Offset of the backing bytes in the underlying source. For a strided run
    /// this is the *first* chunk's; the rest follow every `stride` bytes.
    pub file_offset: u64,
    /// Address of the first byte in the layer's memory address space.
    pub memory_offset: u64,
    /// Length of the run in the memory address space, which is contiguous
    /// across the whole run whatever the source side looks like.
    pub length: u64,
    /// Memory bytes one stored chunk accounts for. Equal to `length` for an
    /// ordinary run, and `length` is always a whole multiple of it.
    pub chunk: u64,
    /// Bytes the source stores per chunk. Equal to `chunk` unless the chunks
    /// are encoded, in which case they decode, as a unit, to `chunk` bytes.
    pub chunk_stored: u64,
    /// Distance in the source from one chunk's stored bytes to the next's.
    /// Equal to `chunk` for an ordinary run, and never below `chunk_stored`, or
    /// consecutive chunks would overlap in the source.
    pub stride: u64,
}

impl Segment {
    /// One contiguous extent: `length` bytes at `file_offset`, byte for byte.
    pub fn new(file_offset: u64, memory_offset: u64, length: u64) -> Self {
        Self {
            file_offset,
            memory_offset,
            length,
            chunk: length,
            chunk_stored: length,
            stride: length,
        }
    }

    /// `length / chunk` byte-for-byte chunks of `chunk` bytes, each `stride`
    /// source bytes after the last.
    ///
    /// The run covers `length` contiguous memory bytes; `stride` is the source
    /// distance, so `stride - chunk` is whatever the format interleaves between
    /// them (a per-page header, in the case this exists for).
    pub fn strided(
        file_offset: u64,
        memory_offset: u64,
        length: u64,
        chunk: u64,
        stride: u64,
    ) -> Self {
        Self {
            file_offset,
            memory_offset,
            length,
            chunk,
            chunk_stored: chunk,
            stride,
        }
    }

    /// `length / chunk` **encoded** chunks: `chunk_stored` source bytes
    /// decoding, as a unit, to `chunk` memory bytes, each `stride` source bytes
    /// after the last.
    ///
    /// [`SegmentedLayer`] indexes these and describes them — [`Segment`] says
    /// where they are, [`SegmentedLayer::mapping`] reports them as
    /// [`Encoding::Encoded`] — but it cannot *decode* them, because the decode
    /// belongs to the format that chose the encoding. So
    /// [`SegmentedLayer::read_at`] refuses an encoded chunk by name rather than
    /// serving the stored bytes as though they were the decoded ones, and the
    /// format reader that produced the run serves the read itself.
    pub fn chunked(
        file_offset: u64,
        memory_offset: u64,
        length: u64,
        chunk: u64,
        chunk_stored: u64,
        stride: u64,
    ) -> Self {
        Self {
            file_offset,
            memory_offset,
            length,
            chunk,
            chunk_stored,
            stride,
        }
    }

    /// Number of chunks in the run. `1` for an ordinary extent.
    pub fn chunk_count(&self) -> u64 {
        self.length.checked_div(self.chunk).unwrap_or(0)
    }

    /// Whether the run is one contiguous, byte-for-byte extent.
    pub fn is_contiguous(&self) -> bool {
        self.chunk == self.length && self.chunk_stored == self.length
    }

    /// Whether each chunk's stored bytes must be decoded before they mean
    /// anything, which is what makes the run unreadable through
    /// [`SegmentedLayer`] itself.
    pub fn is_encoded(&self) -> bool {
        self.chunk_stored != self.chunk
    }

    /// One past the last memory address, or `None` if the segment's declared
    /// extent overflows `u64`.
    pub fn memory_end(&self) -> Option<u64> {
        self.memory_offset.checked_add(self.length)
    }

    /// One past the last backing byte, or `None` on overflow.
    ///
    /// For a strided run this is the end of the **last** chunk, not
    /// `file_offset + length`: the run occupies
    /// `(chunk_count - 1) * stride + chunk_stored` source bytes, which for a
    /// page-interleaved acquisition is larger than the memory it carries and
    /// for an encoded one is very much smaller.
    pub fn file_end(&self) -> Option<u64> {
        let last = self.chunk_count().checked_sub(1)?;
        self.file_offset
            .checked_add(last.checked_mul(self.stride)?)?
            .checked_add(self.chunk_stored)
    }

    /// The chunk holding `address`, or `None` if `address` is outside the run.
    ///
    /// This is the one supported way to turn a memory address into a source
    /// offset. Doing the subtraction by hand is correct only for a contiguous
    /// run and silently wrong for every other, which is exactly the class of
    /// mistake the shared machinery exists to make impossible.
    pub fn chunk_containing(&self, address: u64) -> Option<ChunkLocation> {
        if self.chunk == 0 || address < self.memory_offset {
            return None;
        }
        let within = address - self.memory_offset;
        if within >= self.length {
            return None;
        }
        let index = within / self.chunk;
        Some(ChunkLocation {
            // A validated segment cannot overflow here: the last chunk's
            // memory end is `memory_end()` and its source end is `file_end()`,
            // both proved finite at construction.
            memory_offset: self.memory_offset.saturating_add(index * self.chunk),
            length: self.chunk,
            file_offset: self
                .file_offset
                .saturating_add(index.saturating_mul(self.stride)),
            stored_len: self.chunk_stored,
        })
    }
}

/// A memory layer defined by a sorted, non-overlapping list of [`Segment`]s.
///
/// # Address space
///
/// The space runs from the first segment's `memory_offset` to the last
/// segment's last byte, inclusive. [`DataSource::size`] is the *span* of that
/// range, which for an image with holes is larger than
/// [`SegmentedLayer::mapped_len`]. That is deliberate: callers index by
/// address, and an address inside a hole is a real address whose bytes were not
/// acquired — not an address that does not exist.
///
/// # Holes
///
/// Any read or mapping that touches an address inside the span but outside
/// every segment fails with [`MemoryHole`], carrying the gap's exact start and
/// length. Nothing is skipped and nothing is zero-filled; see [`MemoryHole`]
/// for why.
///
/// # Encoded chunks
///
/// A segment built with [`Segment::chunked`] stores fewer (or more) source
/// bytes per chunk than the memory it carries, and only the format reader that
/// chose the encoding can decode it. Such a chunk is *indexed* here — its
/// address range counts towards [`SegmentedLayer::mapped_len`], and
/// [`SegmentedLayer::mapping`] reports it as an [`Encoding::Encoded`] run — but
/// [`DataSource::read_at`] **refuses** it rather than serving the stored bytes
/// as though they were the decoded ones. A reader that produces encoded chunks
/// therefore has to serve its own reads, exactly as
/// [`crate::formats::qemu::QemuLayer`] does for a fill-byte page. An encoded
/// chunk is not a hole: the acquisition holds those bytes, and saying otherwise
/// would understate the capture.
#[derive(Debug)]
pub struct SegmentedLayer {
    inner: Arc<dyn DataSource>,
    /// Sorted by `memory_offset`, non-overlapping, every length non-zero.
    segments: Vec<Segment>,
    /// `segments[i].memory_offset`, kept separately so the hot lookup binary
    /// searches a dense `u64` slice instead of a struct array.
    starts: Vec<u64>,
    min_address: u64,
    max_address: u64,
    /// `max_address + 1`, precomputed; construction guarantees it does not
    /// overflow.
    span: u64,
    mapped_len: u64,
    meta: LayerMeta,
}

impl SegmentedLayer {
    /// Build a layer from a format reader's segment list.
    ///
    /// The list may arrive in any order; it is sorted here. Every other
    /// property is *validated*, not repaired, because a segment list that
    /// violates them means the format reader misparsed the image, and quietly
    /// fixing it up would hide that.
    ///
    /// # Errors
    ///
    /// - [`LayerError::NoSegments`] on an empty list. An image that declares no
    ///   memory is a parse failure, not an empty success.
    /// - [`LayerError::TooManySegments`] above [`MAX_SEGMENTS`]. A corrupt or
    ///   hostile header can claim millions of runs.
    /// - [`LayerError::MalformedSegment`] for a zero-length segment, one whose
    ///   extent overflows `u64` in either space, or one whose chunking does not
    ///   describe its own length: a chunk size that does not divide `length`, or
    ///   a stride shorter than the bytes each chunk stores, which would make
    ///   consecutive chunks overlap in the source.
    /// - [`LayerError::OverlappingSegments`] when two segments claim the same
    ///   memory address. There is no principled way to pick a winner, so the
    ///   layer refuses to exist rather than serve one set of bytes and hide the
    ///   other.
    pub fn new(
        inner: Arc<dyn DataSource>,
        segments: Vec<Segment>,
        meta: LayerMeta,
    ) -> Result<Self, LayerError> {
        if segments.is_empty() {
            return Err(LayerError::NoSegments(
                "the format reader produced no segments".to_string(),
            ));
        }
        if segments.len() > MAX_SEGMENTS {
            return Err(LayerError::TooManySegments {
                count: segments.len(),
                cap: MAX_SEGMENTS,
            });
        }

        // Validate against the caller's original indices so an error names the
        // segment the reader produced, not a position in our sorted copy.
        let mut indexed: Vec<(usize, Segment)> = segments.into_iter().enumerate().collect();
        for (index, seg) in &indexed {
            if seg.length == 0 {
                return Err(LayerError::MalformedSegment {
                    index: *index,
                    detail: "zero length".to_string(),
                });
            }
            if seg.chunk == 0 || seg.chunk_stored == 0 {
                return Err(LayerError::MalformedSegment {
                    index: *index,
                    detail: format!(
                        "zero-length chunk ({:#x} memory bytes from {:#x} stored bytes)",
                        seg.chunk, seg.chunk_stored
                    ),
                });
            }
            if seg.length % seg.chunk != 0 {
                // A trailing part-chunk has no defined source offset, and
                // guessing one would put real memory bytes at an address that
                // is not theirs.
                return Err(LayerError::MalformedSegment {
                    index: *index,
                    detail: format!(
                        "run of {:#x} bytes is not a whole number of {:#x}-byte chunks",
                        seg.length, seg.chunk
                    ),
                });
            }
            if seg.stride < seg.chunk_stored {
                return Err(LayerError::MalformedSegment {
                    index: *index,
                    detail: format!(
                        "chunk stride {:#x} is shorter than the {:#x} bytes each chunk stores, \
                         so consecutive chunks would overlap in the source",
                        seg.stride, seg.chunk_stored
                    ),
                });
            }
            if seg.memory_end().is_none() {
                return Err(LayerError::MalformedSegment {
                    index: *index,
                    detail: format!(
                        "memory extent {:#x}+{:#x} overflows the address space",
                        seg.memory_offset, seg.length
                    ),
                });
            }
            if seg.file_end().is_none() {
                return Err(LayerError::MalformedSegment {
                    index: *index,
                    detail: format!(
                        "file extent of {} chunk(s) from {:#x}, {:#x} apart, overflows the source",
                        seg.chunk_count(),
                        seg.file_offset,
                        seg.stride
                    ),
                });
            }
        }

        indexed.sort_by_key(|(_, seg)| seg.memory_offset);

        for window in indexed.windows(2) {
            let (prev_index, prev) = window[0];
            let (next_index, next) = window[1];
            // `memory_end` is Some for every segment by the check above.
            if prev.memory_end().unwrap_or(u64::MAX) > next.memory_offset {
                return Err(LayerError::OverlappingSegments {
                    first: prev_index,
                    second: next_index,
                });
            }
        }

        let segments: Vec<Segment> = indexed.into_iter().map(|(_, seg)| seg).collect();
        let starts: Vec<u64> = segments.iter().map(|s| s.memory_offset).collect();
        let min_address = segments[0].memory_offset;
        // Sorted and non-overlapping means ends increase, so the last segment
        // holds the highest address.
        let last = segments[segments.len() - 1];
        // The address space runs to whichever is higher: the last mapped byte,
        // or the top the image itself declared.
        //
        // These differ whenever a reader skipped a segment it could not honour —
        // an ELF `PT_LOAD` whose `p_filesz` is short of its `p_memsz`, a LiME
        // range cut off by a truncated capture. That memory existed on the
        // target and the image says so; we simply do not have its bytes.
        //
        // Taking only the last segment's end would make such a region read as
        // EOF, and EOF asserts something false: that the image stops there. A
        // scanner would walk to the last captured byte and finish, never
        // learning that declared memory was missing. Extending the span to the
        // declared top instead leaves the gap *inside* the address space, where
        // it reads as a hole — which is the truth, and which
        // `read_exact_or_fail` already refuses to parse across.
        let mapped_top = last.memory_end().unwrap_or(u64::MAX);
        let span = meta.declared_size().unwrap_or(0).max(mapped_top);
        let max_address = span - 1;
        let mapped_len = segments
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.length));

        Ok(Self {
            inner,
            segments,
            starts,
            min_address,
            max_address,
            span,
            mapped_len,
            meta,
        })
    }

    /// The validated, sorted segment list.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Bytes actually acquired, i.e. the sum of the segment lengths.
    ///
    /// Always less than or equal to [`DataSource::size`]; strictly less when
    /// the image has holes. Reporting the two separately is what lets a report
    /// say "8 GiB address space, 7.7 GiB acquired" instead of implying the
    /// capture was complete.
    pub fn mapped_len(&self) -> u64 {
        self.mapped_len
    }

    /// The source the segments project onto.
    pub fn inner(&self) -> &Arc<dyn DataSource> {
        &self.inner
    }

    /// Index of the segment containing `address`, by binary search.
    fn find_segment(&self, address: u64) -> Option<usize> {
        // Number of segments starting at or below `address`.
        let idx = self.starts.partition_point(|&start| start <= address);
        if idx == 0 {
            return None;
        }
        let candidate = idx - 1;
        let seg = &self.segments[candidate];
        // `address >= seg.memory_offset` holds by construction of `idx`.
        if address - seg.memory_offset < seg.length {
            Some(candidate)
        } else {
            None
        }
    }

    /// Start address of the first segment above `address`, for sizing a hole.
    fn next_segment_start(&self, address: u64) -> Option<u64> {
        let idx = self.starts.partition_point(|&start| start <= address);
        self.starts.get(idx).copied()
    }

    /// The gap beginning at `address`, which the caller has already established
    /// is unmapped and below `span`.
    fn hole_at(&self, address: u64) -> MemoryHole {
        let end = self.next_segment_start(address).unwrap_or(self.span);
        MemoryHole::unmapped(address, end.saturating_sub(address))
    }

    /// The chunk of `segment` holding `address`.
    ///
    /// Only ever called after [`SegmentedLayer::find_segment`] has placed
    /// `address` inside the segment, and every validated segment has a non-zero
    /// chunk size, so `None` means the index and the run description disagree
    /// with each other. That is an internal fault and is reported as one: a
    /// hole would claim the acquisition never held these bytes, which is a
    /// statement about the evidence rather than about this code.
    fn chunk_at(&self, segment: Segment, address: u64) -> io::Result<ChunkLocation> {
        segment.chunk_containing(address).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "the segment at {:#x}+{:#x} was indexed as holding address {address:#x} but \
                     cannot locate the chunk for it",
                    segment.memory_offset, segment.length
                ),
            )
        })
    }
}

/// The refusal a caller gets when it asks [`SegmentedLayer`] to read bytes that
/// only the format reader knows how to decode.
fn encoded_chunk_refusal(chunk: ChunkLocation) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "the memory at {:#x} is stored as {} encoded byte(s) at file offset {:#x} that decode \
             to {} bytes; SegmentedLayer indexes encoded chunks but cannot decode them, so the \
             format reader that produced this run has to serve the read",
            chunk.memory_offset, chunk.stored_len, chunk.file_offset, chunk.length
        ),
    )
}

impl DataSource for SegmentedLayer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || offset >= self.span {
            // Above the top of the address space: genuine EOF, never a hole.
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.span - offset);
        let end = offset + want;

        let mut pos = offset;
        let mut written = 0usize;
        while pos < end {
            let Some(index) = self.find_segment(pos) else {
                // Either the read started in a gap, or it walked into one. Both
                // are the same fact and both must be errors: returning the
                // near-side bytes and then silently resuming on the far side
                // would present two unrelated regions as contiguous memory.
                return Err(self.hole_at(pos).into_io());
            };
            let seg = self.segments[index];
            // Per chunk, not per segment: for a strided run the source offset
            // of an address is not its distance from the run's start, and one
            // read across a chunk boundary would splice in the bytes the format
            // interleaves between them.
            let chunk = self.chunk_at(seg, pos)?;
            if !chunk.is_identity() {
                return Err(encoded_chunk_refusal(chunk));
            }
            let within = pos - chunk.memory_offset;
            let take = (chunk.length - within).min(end - pos) as usize;
            let source_offset = chunk.file_offset + within;
            let got = read_full(
                &*self.inner,
                source_offset,
                &mut buf[written..written + take],
            );
            written += got;
            pos += got as u64;
            if got < take {
                // The acquisition file is shorter than its own segment list
                // claims. That is truncated evidence, and the honest short
                // count is what says so: `read_exact_or_fail` refuses it, and
                // nothing downstream sees fabricated bytes.
                return Ok(written);
            }
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.span
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.inner.get_underlying_path()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        self.inner.open_sibling(suffix)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        let mut accumulated = PhysicalMap::empty(ExtentPrecision::Exact);
        if len == 0 || offset >= self.span {
            return accumulated;
        }
        let end = offset.saturating_add(len).min(self.span);
        let mut pos = offset;
        while pos < end {
            match self.find_segment(pos) {
                Some(index) => {
                    let seg = self.segments[index];
                    let Some(chunk) = seg.chunk_containing(pos) else {
                        // The index and the run description disagree. This map
                        // is advisory and cannot fail, so the honest answer is
                        // "not located" rather than a device offset nothing
                        // justifies.
                        accumulated.extents.push(PhysicalExtent::hole(end - pos));
                        accumulated.precision =
                            accumulated.precision.worst(ExtentPrecision::Synthetic);
                        pos = end;
                        continue;
                    };
                    let within = pos - chunk.memory_offset;
                    let take = (chunk.length - within).min(end - pos);
                    if chunk.is_identity() {
                        let sub = self.inner.physical_map(chunk.file_offset + within, take);
                        // `absorb` rather than `extend`: an inner map's auxiliary source
                        // indices are meaningful only against its own table.
                        accumulated.absorb(sub);
                    } else {
                        // Located to the compression unit — the chunk's stored
                        // bytes — and not to the individual memory byte, which
                        // is exactly what `Compressed` means.
                        let sub = self.inner.physical_map(chunk.file_offset, chunk.stored_len);
                        // An auxiliary-backed inner extent has no name in this
                        // projection, so it is reported as unlocated rather
                        // than as an image offset.
                        let located = sub
                            .extents
                            .first()
                            .filter(|e| !e.is_auxiliary())
                            .and_then(|e| e.device_offset);
                        accumulated.extents.push(match located {
                            Some(at) => PhysicalExtent::device(at, take),
                            None => PhysicalExtent::hole(take),
                        });
                        accumulated.precision =
                            accumulated.precision.worst(ExtentPrecision::Compressed);
                    }
                    pos += take;
                }
                None => {
                    // `physical_map` is advisory and returns no Result, so a
                    // hole degrades the answer rather than failing it: an
                    // extent with no device offset, and Synthetic precision so
                    // nobody reads it as "located".
                    let gap_end = self.next_segment_start(pos).unwrap_or(self.span).min(end);
                    accumulated
                        .extents
                        .push(PhysicalExtent::hole(gap_end - pos));
                    accumulated.precision = accumulated.precision.worst(ExtentPrecision::Synthetic);
                    pos = gap_end;
                }
            }
        }
        accumulated
    }
}

impl MemoryLayer for SegmentedLayer {
    fn min_address(&self) -> u64 {
        self.min_address
    }

    fn max_address(&self) -> u64 {
        self.max_address
    }

    /// Project `[offset, offset + length)` onto the acquisition source.
    ///
    /// An identity chunk yields an [`Encoding::Identity`] run clipped to the
    /// request, and consecutive chunks that are contiguous in *both* spaces are
    /// coalesced. An encoded chunk yields one [`Encoding::Encoded`] run
    /// covering the **whole** chunk, because that is what the encoding contract
    /// means: `mapped_length` stored bytes decoding, as a unit, to `length`
    /// bytes. Clipping such a run would describe a blob that decodes to fewer
    /// bytes than it does. A run may therefore begin below `offset` or end
    /// above `offset + length`; use [`MemoryLayer::is_valid`] rather than
    /// [`crate::layer::covered_len`] to ask whether the request was backed.
    fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        if offset > self.max_address {
            return Err(LayerError::OutOfRange {
                address: offset,
                max_address: self.max_address,
            });
        }
        let end = offset.saturating_add(length).min(self.span);

        let mut runs: Vec<MappedRange> = Vec::new();
        let mut pos = offset;
        while pos < end {
            let Some(index) = self.find_segment(pos) else {
                return Err(LayerError::Hole(self.hole_at(pos)));
            };
            let seg = self.segments[index];
            let chunk = self.chunk_at(seg, pos).map_err(LayerError::from_io)?;
            if !chunk.is_identity() {
                runs.push(MappedRange {
                    offset: chunk.memory_offset,
                    length: chunk.length,
                    mapped_offset: chunk.file_offset,
                    mapped_length: chunk.stored_len,
                    encoding: Encoding::Encoded,
                    source: BackingSource::Primary,
                    via: None,
                });
                pos = chunk.memory_offset.saturating_add(chunk.length);
                continue;
            }
            let within = pos - chunk.memory_offset;
            let take = (chunk.length - within).min(end - pos);
            let mapped_offset = chunk.file_offset + within;

            // Coalesce runs that are contiguous in BOTH spaces, so a caller
            // deriving scan sections from this gets the minimal list. Chunks
            // adjacent in memory but not in the file stay separate, which is
            // the distinction that matters — and is the whole reason a strided
            // run exists rather than being flattened into one extent.
            match runs.last_mut() {
                Some(prev)
                    if prev.encoding == Encoding::Identity
                        && prev.end() == pos
                        && prev.mapped_offset + prev.mapped_length == mapped_offset =>
                {
                    prev.length += take;
                    prev.mapped_length += take;
                }
                _ => runs.push(MappedRange::identity(pos, take, mapped_offset)),
            }
            pos += take;
        }
        Ok(runs)
    }

    fn layer_meta(&self) -> &LayerMeta {
        &self.meta
    }

    fn as_data_source(&self) -> &dyn DataSource {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::MemoryImageFormat;
    use crate::layer::{covered_len, HoleReason};
    use seance_core::data_source::{ByteSliceDataSource, DeviceImageSource, WindowSource};
    use seance_core::io::{read_capped, read_exact_or_fail};

    /// Backing bytes whose value encodes their own file offset, so a test can
    /// prove a read came from the offset it was meant to.
    ///
    /// Wrapped as a device image so `physical_map` reports exact offsets; a
    /// bare byte slice honestly reports "no device backing", which would make
    /// the projection assertions vacuous.
    fn backing(len: usize) -> Arc<dyn DataSource> {
        Arc::new(DeviceImageSource::new(Arc::new(ByteSliceDataSource::new(
            (0..len).map(|i| (i % 251) as u8).collect(),
        ))))
    }

    fn byte_at(file_offset: u64) -> u8 {
        (file_offset % 251) as u8
    }

    fn meta() -> LayerMeta {
        LayerMeta::new(MemoryImageFormat::Lime)
    }

    /// Three segments with a 0x1000-byte hole between the second and third,
    /// and a 0x2000-byte unmapped prefix below the first.
    ///
    /// memory 0x2000..0x3000 <- file 0x0000
    /// memory 0x3000..0x4000 <- file 0x8000   (memory-adjacent, file-disjoint)
    /// memory 0x5000..0x6000 <- file 0x1000   (after a hole at 0x4000)
    fn holed_layer() -> SegmentedLayer {
        SegmentedLayer::new(
            backing(0x1_0000),
            vec![
                Segment::new(0x0000, 0x2000, 0x1000),
                Segment::new(0x8000, 0x3000, 0x1000),
                Segment::new(0x1000, 0x5000, 0x1000),
            ],
            meta(),
        )
        .expect("a valid segment list")
    }

    // ── Valid image ─────────────────────────────────────────────────────────

    #[test]
    fn a_valid_segment_list_builds_a_correct_address_space() {
        let l = holed_layer();
        assert_eq!(l.min_address(), 0x2000);
        assert_eq!(l.max_address(), 0x5FFF);
        assert_eq!(l.size(), 0x6000, "size is the span of the address space");
        assert_eq!(l.mapped_len(), 0x3000, "only three pages were acquired");
        assert_eq!(l.segments().len(), 3);
    }

    #[test]
    fn reads_come_from_the_segments_file_offset_not_the_memory_address() {
        let l = holed_layer();
        let mut buf = [0u8; 4];
        // Memory 0x3000 is backed by file 0x8000, not file 0x3000.
        l.read_at(0x3000, &mut buf).unwrap();
        assert_eq!(buf[0], byte_at(0x8000));
        assert_eq!(buf[3], byte_at(0x8003));
        // Memory 0x5010 is backed by file 0x1010.
        l.read_at(0x5010, &mut buf).unwrap();
        assert_eq!(buf[0], byte_at(0x1010));
    }

    #[test]
    fn a_read_spanning_memory_adjacent_segments_stitches_the_right_bytes() {
        // 0x2000..0x4000 is contiguous in memory but comes from file 0x0000 and
        // file 0x8000. Getting this wrong is invisible unless the bytes differ.
        let l = holed_layer();
        let mut buf = vec![0u8; 0x2000];
        assert_eq!(l.read_at(0x2000, &mut buf).unwrap(), 0x2000);
        assert_eq!(buf[0], byte_at(0x0000));
        assert_eq!(buf[0x0FFF], byte_at(0x0FFF));
        assert_eq!(buf[0x1000], byte_at(0x8000));
        assert_eq!(buf[0x1FFF], byte_at(0x8FFF));
    }

    #[test]
    fn segments_may_arrive_unsorted_and_are_indexed_correctly() {
        // The fixture's third segment is the lowest file offset and the highest
        // memory address; if sorting were skipped the binary search would be
        // wrong for every lookup.
        let l = holed_layer();
        assert_eq!(l.segments()[0].memory_offset, 0x2000);
        assert_eq!(l.segments()[1].memory_offset, 0x3000);
        assert_eq!(l.segments()[2].memory_offset, 0x5000);
    }

    #[test]
    fn binary_search_is_correct_across_a_large_segment_list() {
        // 4096 one-page segments with a one-page hole between each, built in
        // reverse so the sort is doing real work.
        let count = 4096u64;
        let segments: Vec<Segment> = (0..count)
            .rev()
            .map(|i| Segment::new(i * 0x1000, i * 0x2000, 0x1000))
            .collect();
        let l = SegmentedLayer::new(backing(0x100), segments, meta()).unwrap();
        assert_eq!(l.mapped_len(), count * 0x1000);
        assert_eq!(l.size(), (count - 1) * 0x2000 + 0x1000);

        for i in [0u64, 1, 7, 1234, count - 1] {
            let addr = i * 0x2000;
            let runs = l.mapping(addr, 0x1000).expect("segment start is mapped");
            assert_eq!(runs.len(), 1);
            assert_eq!(runs[0].mapped_offset, i * 0x1000);
            if i + 1 < count {
                // The page immediately after each segment is a hole.
                let hole = l
                    .mapping(addr + 0x1000, 1)
                    .expect_err("the page after a segment is unmapped")
                    .hole()
                    .expect("a typed hole");
                assert_eq!(hole.address, addr + 0x1000);
                assert_eq!(hole.length, 0x1000);
            }
        }
    }

    // ── Holes ───────────────────────────────────────────────────────────────

    #[test]
    fn a_read_starting_in_a_hole_errors_with_the_exact_gap() {
        let l = holed_layer();
        let mut buf = [0u8; 16];
        let err = l.read_at(0x4000, &mut buf).expect_err("0x4000 is unmapped");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!(hole.address, 0x4000);
        assert_eq!(hole.length, 0x1000, "the gap runs to the next segment");
        assert_eq!(hole.reason, HoleReason::Unmapped);
    }

    #[test]
    fn a_read_below_the_first_segment_is_a_hole_not_eof() {
        let l = holed_layer();
        let mut buf = [0u8; 16];
        let err = l.read_at(0, &mut buf).expect_err("below min_address");
        let hole = MemoryHole::from_io(&err).unwrap();
        assert_eq!(hole.address, 0);
        assert_eq!(hole.length, 0x2000, "the gap runs up to the first segment");
    }

    #[test]
    fn a_read_spanning_a_gap_errors_rather_than_splicing_across_it() {
        // The defect this prevents: returning 0x1000 bytes of segment two
        // followed by segment three's bytes, presented as one contiguous
        // 0x2000-byte region of memory that never existed.
        let l = holed_layer();
        let mut buf = vec![0xFFu8; 0x2000];
        let err = l
            .read_at(0x3000, &mut buf)
            .expect_err("the range crosses the hole at 0x4000");
        let hole = MemoryHole::from_io(&err).unwrap();
        assert_eq!(hole.address, 0x4000);
        assert_eq!(hole.length, 0x1000);
        // The far side of the gap was never touched: segment three's bytes were
        // not spliced in behind the hole. The near side may have been written,
        // but `Err` carries no byte count, so no caller may treat any of it as
        // read.
        assert!(buf[0x1000..].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn a_structural_read_straddling_a_gap_fails_closed_with_the_hole_intact() {
        let l = holed_layer();
        let mut header = [0u8; 64];
        let err = read_exact_or_fail(l.as_data_source(), 0x3FE0, &mut header, "_EPROCESS")
            .expect_err("a header half in a hole must not parse");
        let hole = MemoryHole::from_io(&err).expect("the hole reaches the caller");
        assert_eq!(hole.address, 0x4000);
        // The 0x20 bytes before the gap are real; everything from the gap
        // onward was never fabricated, and the `Err` means the buffer is never
        // parsed as an `_EPROCESS` at all.
        assert!(header[0x20..].iter().all(|&b| b == 0));
    }

    #[test]
    fn best_effort_reads_stop_at_the_hole_instead_of_padding_over_it() {
        let l = holed_layer();
        // read_capped starts at 0, which is below the first segment, so it gets
        // nothing at all rather than a zero-filled 0x6000-byte "image".
        assert!(read_capped(l.as_data_source(), 0x6000).is_empty());
    }

    #[test]
    fn reads_above_the_top_of_the_space_are_eof() {
        let l = holed_layer();
        let mut buf = [0u8; 16];
        assert_eq!(l.read_at(0x6000, &mut buf).unwrap(), 0);
        assert_eq!(l.read_at(u64::MAX, &mut buf).unwrap(), 0);
    }

    #[test]
    fn a_read_is_clipped_at_the_top_of_the_space() {
        let l = holed_layer();
        let mut buf = vec![0u8; 0x1000];
        // 0x5F00..0x6000 exists; the rest of the request is past the end.
        assert_eq!(l.read_at(0x5F00, &mut buf).unwrap(), 0x100);
    }

    // ── mapping() ───────────────────────────────────────────────────────────

    #[test]
    fn mapping_projects_each_segment_separately() {
        let l = holed_layer();
        let runs = l.mapping(0x2800, 0x1000).expect("no gap in this range");
        assert_eq!(runs.len(), 2, "file-disjoint segments stay separate runs");
        assert_eq!(runs[0], MappedRange::identity(0x2800, 0x800, 0x800));
        assert_eq!(runs[1], MappedRange::identity(0x3000, 0x800, 0x8000));
        assert_eq!(covered_len(&runs), 0x1000);
        assert!(l.is_valid(0x2800, 0x1000));
    }

    #[test]
    fn mapping_coalesces_runs_contiguous_in_both_spaces() {
        // Two segments that are adjacent in memory AND in the file collapse to
        // one run, so a scan driver gets the minimal section list.
        let l = SegmentedLayer::new(
            backing(0x4000),
            vec![
                Segment::new(0x0000, 0x1000, 0x800),
                Segment::new(0x0800, 0x1800, 0x800),
            ],
            meta(),
        )
        .unwrap();
        let runs = l.mapping(0x1000, 0x1000).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0], MappedRange::identity(0x1000, 0x1000, 0x0000));
    }

    #[test]
    fn mapping_refuses_to_elide_a_gap() {
        let l = holed_layer();
        let err = l.mapping(0x3800, 0x2000).expect_err("crosses the hole");
        let hole = err.hole().expect("a typed hole");
        assert_eq!(hole.address, 0x4000);
        assert_eq!(hole.length, 0x1000);
        assert!(!l.is_valid(0x3800, 0x2000));
    }

    #[test]
    fn mapping_clips_at_the_top_and_rejects_addresses_above_it() {
        let l = holed_layer();
        let runs = l.mapping(0x5F00, 0x4000).expect("start is in range");
        assert_eq!(covered_len(&runs), 0x100);

        let err = l.mapping(0x6000, 1).expect_err("no such address");
        assert!(err.hole().is_none(), "past the end is not a hole");
        assert!(matches!(
            err,
            LayerError::OutOfRange {
                address: 0x6000,
                ..
            }
        ));
    }

    #[test]
    fn a_zero_length_mapping_is_empty_even_inside_a_hole() {
        let l = holed_layer();
        assert!(l.mapping(0x4000, 0).unwrap().is_empty());
    }

    // ── Truncated acquisition ───────────────────────────────────────────────

    #[test]
    fn a_segment_claiming_bytes_past_the_end_of_the_file_short_reads_honestly() {
        // The header says 0x2000 bytes at file offset 0; the file holds 0x1800.
        let l = SegmentedLayer::new(
            backing(0x1800),
            vec![Segment::new(0, 0, 0x2000)],
            meta().with_declared_size(0x2000),
        )
        .unwrap();
        let mut buf = vec![0u8; 0x2000];
        let got = l.read_at(0, &mut buf).unwrap();
        assert_eq!(got, 0x1800, "the honest count, not the declared one");
        // And a structural read over the truncated tail fails closed rather
        // than parsing the zeros that were never overwritten.
        let mut header = [0u8; 0x40];
        let err = read_exact_or_fail(l.as_data_source(), 0x1FE0, &mut header, "trailer")
            .expect_err("truncated evidence must not parse");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        // Truncation is not a hole: the segment list is right, the file is short.
        assert!(MemoryHole::from_io(&err).is_none());
    }

    // ── Malformed segment lists ─────────────────────────────────────────────

    #[test]
    fn an_empty_segment_list_is_refused() {
        let err = SegmentedLayer::new(backing(0x1000), Vec::new(), meta())
            .expect_err("no segments is a parse failure");
        assert!(matches!(err, LayerError::NoSegments(_)));
    }

    #[test]
    fn a_segment_list_above_the_cap_is_refused() {
        let segments = vec![Segment::new(0, 0, 1); MAX_SEGMENTS + 1];
        let err = SegmentedLayer::new(backing(0x100), segments, meta())
            .expect_err("a hostile header must not be honoured");
        assert!(matches!(
            err,
            LayerError::TooManySegments {
                cap: MAX_SEGMENTS,
                ..
            }
        ));
    }

    #[test]
    fn a_zero_length_segment_is_refused_and_does_not_panic() {
        let err = SegmentedLayer::new(
            backing(0x1000),
            vec![Segment::new(0, 0, 0x100), Segment::new(0x100, 0x200, 0)],
            meta(),
        )
        .expect_err("zero-length segments break the index");
        match err {
            LayerError::MalformedSegment { index, ref detail } => {
                assert_eq!(index, 1, "the caller's own index is named");
                assert!(detail.contains("zero length"));
            }
            other => panic!("unexpected error: {other}"),
        }
    }

    #[test]
    fn segments_whose_extents_overflow_are_refused_and_do_not_panic() {
        let err = SegmentedLayer::new(
            backing(0x1000),
            vec![Segment::new(0, u64::MAX - 4, 0x1000)],
            meta(),
        )
        .expect_err("memory extent overflow");
        assert!(matches!(err, LayerError::MalformedSegment { index: 0, .. }));

        let err = SegmentedLayer::new(
            backing(0x1000),
            vec![Segment::new(u64::MAX - 4, 0, 0x1000)],
            meta(),
        )
        .expect_err("file extent overflow");
        assert!(matches!(err, LayerError::MalformedSegment { index: 0, .. }));
    }

    #[test]
    fn overlapping_segments_are_refused_rather_than_silently_resolved() {
        let err = SegmentedLayer::new(
            backing(0x4000),
            vec![
                Segment::new(0x0000, 0x1000, 0x1000),
                Segment::new(0x2000, 0x1800, 0x1000),
            ],
            meta(),
        )
        .expect_err("two sets of bytes cannot share one address");
        assert!(matches!(
            err,
            LayerError::OverlappingSegments {
                first: 0,
                second: 1
            }
        ));
    }

    #[test]
    fn segments_sharing_a_start_address_are_refused() {
        let err = SegmentedLayer::new(
            backing(0x4000),
            vec![
                Segment::new(0x0000, 0x1000, 0x1000),
                Segment::new(0x2000, 0x1000, 0x0800),
            ],
            meta(),
        )
        .expect_err("duplicate start addresses overlap");
        assert!(matches!(err, LayerError::OverlappingSegments { .. }));
    }

    #[test]
    fn exactly_abutting_segments_are_accepted() {
        // `prev_end == next_start` is adjacency, not overlap.
        let l = SegmentedLayer::new(
            backing(0x4000),
            vec![
                Segment::new(0x0000, 0x1000, 0x1000),
                Segment::new(0x2000, 0x2000, 0x1000),
            ],
            meta(),
        )
        .expect("abutting segments are legal");
        assert_eq!(l.mapped_len(), 0x2000);
        assert_eq!(l.size(), 0x3000);
    }

    // ── physical_map ────────────────────────────────────────────────────────

    #[test]
    fn physical_map_locates_memory_addresses_in_the_acquisition_file() {
        // A LiME image sitting at offset 0x10_0000 inside a device image.
        let device = backing(0x20_0000);
        let lime: Arc<dyn DataSource> = Arc::new(WindowSource::new(device, 0x10_0000, 0x1_0000));
        let l = SegmentedLayer::new(
            lime,
            vec![
                Segment::new(0x0020, 0x0000, 0x1000),
                Segment::new(0x1040, 0x2000, 0x1000),
            ],
            meta(),
        )
        .unwrap();

        let map = l.physical_map(0x2000, 0x400);
        assert_eq!(map.precision, ExtentPrecision::Exact);
        assert_eq!(map.extents.len(), 1);
        assert_eq!(map.extents[0].device_offset, Some(0x10_0000 + 0x1040));
        assert_eq!(map.extents[0].length, 0x400);
    }

    #[test]
    fn physical_map_reports_a_hole_as_unlocated_rather_than_failing_or_lying() {
        let l = holed_layer();
        let map = l.physical_map(0x3F00, 0x1200);
        // 0x3F00..0x4000 mapped, 0x4000..0x5000 hole, 0x5000..0x5100 mapped.
        assert_eq!(map.extents.len(), 3);
        assert_eq!(map.extents[0].device_offset, Some(0x8F00));
        assert_eq!(map.extents[0].length, 0x100);
        assert_eq!(map.extents[1].device_offset, None);
        assert_eq!(map.extents[1].length, 0x1000);
        assert_eq!(map.extents[2].device_offset, Some(0x1000));
        assert_eq!(map.extents[2].length, 0x100);
        assert_eq!(map.precision, ExtentPrecision::Synthetic);
        assert_eq!(map.located_len(), 0x200);
    }

    #[test]
    fn physical_map_of_an_address_above_the_space_is_empty() {
        let l = holed_layer();
        assert!(l.physical_map(0x6000, 0x100).extents.is_empty());
        assert!(l.physical_map(0x2000, 0).extents.is_empty());
    }

    // ── Strided runs ────────────────────────────────────────────────────────

    /// A QEMU savevm's page interleave: 0x1000 bytes of page followed by the
    /// next page's 8-byte address word.
    const SAVEVM_CHUNK: u64 = 0x1000;
    const SAVEVM_STRIDE: u64 = 0x1008;

    #[test]
    fn an_ordinary_segment_is_exactly_one_chunk() {
        // The degenerate case has to stay exactly what it was, because every
        // reader except QEMU's produces only these.
        let s = Segment::new(0x100, 0x2000, 0x800);
        assert_eq!(s.chunk_count(), 1);
        assert!(s.is_contiguous());
        assert!(!s.is_encoded());
        assert_eq!(s.memory_end(), Some(0x2800));
        assert_eq!(s.file_end(), Some(0x900), "one chunk ends at offset+length");

        let chunk = s.chunk_containing(0x2400).expect("inside the run");
        assert_eq!(chunk.memory_offset, 0x2000);
        assert_eq!(chunk.file_offset, 0x100);
        assert_eq!(chunk.length, 0x800);
        assert!(chunk.is_identity());
        assert!(s.chunk_containing(0x2800).is_none(), "one past the end");
        assert!(s.chunk_containing(0x1FFF).is_none(), "below the start");
    }

    #[test]
    fn a_strided_run_reads_each_chunk_from_its_own_file_offset() {
        // The defect this exists for: a savevm writes an 8-byte address word
        // before every page, so page *n* lives at `file_offset + n * 0x1008`,
        // not at `file_offset + n * 0x1000`. Computing the source offset as a
        // distance from the run's start returns bytes — plausible ones, from
        // the wrong page — instead of failing.
        let pages = 4u64;
        let l = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::strided(
                0x40,
                0x8000,
                pages * SAVEVM_CHUNK,
                SAVEVM_CHUNK,
                SAVEVM_STRIDE,
            )],
            meta(),
        )
        .expect("a strided run is a valid segment list");

        assert_eq!(l.segments().len(), 1, "one run, not one segment per page");
        assert_eq!(l.mapped_len(), pages * SAVEVM_CHUNK);
        assert_eq!(l.min_address(), 0x8000);
        assert_eq!(l.max_address(), 0x8000 + pages * SAVEVM_CHUNK - 1);
        assert_eq!(l.size(), 0x8000 + pages * SAVEVM_CHUNK);

        for i in 0..pages {
            let mut buf = [0u8; 4];
            assert_eq!(l.read_at(0x8000 + i * SAVEVM_CHUNK, &mut buf).unwrap(), 4);
            let file_at = 0x40 + i * SAVEVM_STRIDE;
            assert_eq!(
                buf[0],
                byte_at(file_at),
                "page {i} came from the wrong offset"
            );
            assert_eq!(buf[3], byte_at(file_at + 3));
        }
    }

    #[test]
    fn a_read_across_a_strided_chunk_boundary_skips_the_interleaved_bytes() {
        // The eight bytes between two chunks are the acquisition format's, not
        // the guest's. Splicing them in would shift every byte after the
        // boundary by eight and still look like memory.
        let l = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::strided(
                0,
                0,
                2 * SAVEVM_CHUNK,
                SAVEVM_CHUNK,
                SAVEVM_STRIDE,
            )],
            meta(),
        )
        .unwrap();
        let mut buf = [0u8; 0x10];
        assert_eq!(l.read_at(0x0FF8, &mut buf).unwrap(), 0x10);
        for step in 0..8u64 {
            let at = step as usize;
            assert_eq!(buf[at], byte_at(0x0FF8 + step), "tail of chunk 0");
            assert_eq!(
                buf[8 + at],
                byte_at(SAVEVM_STRIDE + step),
                "head of chunk 1"
            );
        }
    }

    #[test]
    fn a_guest_far_above_the_old_page_ceiling_is_one_run_within_the_cap() {
        // The defect, stated as a size: one Segment per page put MAX_SEGMENTS
        // (1,048,576 runs) between the reader and any savevm above 4 GiB, so
        // every larger guest failed outright. As a strided run an 8 GiB guest
        // is a single segment, and the cap bounds runs — which is what it was
        // always meant to bound. Raising the cap instead would have replaced
        // the refusal with an allocation proportional to guest size.
        let pages = 2 * 1024 * 1024u64;
        let l = SegmentedLayer::new(
            backing(0x1000),
            vec![Segment::strided(
                0,
                0,
                pages * SAVEVM_CHUNK,
                SAVEVM_CHUNK,
                SAVEVM_STRIDE,
            )],
            meta(),
        )
        .expect("8 GiB of page-strided memory is one run, not two million");

        assert_eq!(l.segments().len(), 1);
        assert_eq!(l.mapped_len(), 8 * 1024 * 1024 * 1024);
        assert_eq!(l.size(), 8 * 1024 * 1024 * 1024);

        // The top page still projects to its own file offset, so the run is a
        // description of the whole guest and not just of its first chunk.
        let last = pages - 1;
        let runs = l
            .mapping(last * SAVEVM_CHUNK, SAVEVM_CHUNK)
            .expect("the top page is mapped");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].mapped_offset, last * SAVEVM_STRIDE);
        assert_eq!(runs[0].length, SAVEVM_CHUNK);
        assert!(l.is_valid(last * SAVEVM_CHUNK, SAVEVM_CHUNK));
    }

    #[test]
    fn mapping_over_a_strided_run_names_each_chunk_and_never_merges_them() {
        let l = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::strided(
                0x20,
                0,
                3 * SAVEVM_CHUNK,
                SAVEVM_CHUNK,
                SAVEVM_STRIDE,
            )],
            meta(),
        )
        .unwrap();
        let runs = l
            .mapping(0, 3 * SAVEVM_CHUNK)
            .expect("all three chunks are mapped");
        assert_eq!(runs.len(), 3, "chunks are not contiguous in the file");
        for (i, run) in runs.iter().enumerate() {
            let i = i as u64;
            assert_eq!(run.encoding, Encoding::Identity);
            assert_eq!(run.offset, i * SAVEVM_CHUNK);
            assert_eq!(run.length, SAVEVM_CHUNK);
            assert_eq!(run.mapped_offset, 0x20 + i * SAVEVM_STRIDE);
            assert_eq!(run.mapped_length, SAVEVM_CHUNK);
        }
        assert_eq!(covered_len(&runs), 3 * SAVEVM_CHUNK);
        assert!(l.is_valid(0, 3 * SAVEVM_CHUNK));
    }

    #[test]
    fn a_stride_equal_to_the_chunk_is_an_ordinary_contiguous_extent() {
        // Chunks that *are* file-adjacent still coalesce, so the strided model
        // degenerates to the old one rather than fragmenting every run list.
        let l = SegmentedLayer::new(
            backing(0x4000),
            vec![Segment::strided(0, 0x1000, 0x3000, 0x1000, 0x1000)],
            meta(),
        )
        .unwrap();
        let runs = l.mapping(0x1000, 0x3000).unwrap();
        assert_eq!(runs.len(), 1, "file-adjacent chunks coalesce");
        assert_eq!(runs[0], MappedRange::identity(0x1000, 0x3000, 0));

        let mut buf = vec![0u8; 0x3000];
        assert_eq!(l.read_at(0x1000, &mut buf).unwrap(), 0x3000);
        assert_eq!(buf[0x2FFF], byte_at(0x2FFF));
    }

    #[test]
    fn strided_runs_sort_and_reject_overlaps_over_their_whole_span() {
        // Sorting and overlap rejection are stated over the memory span, which
        // a strided run has like any other. Narrowing either to the first
        // chunk would let a second segment be accepted on top of the rest.
        let l = SegmentedLayer::new(
            backing(0x1_0000),
            vec![
                Segment::strided(0x2000, 0x8000, 0x2000, SAVEVM_CHUNK, SAVEVM_STRIDE),
                Segment::new(0x0000, 0x0000, 0x1000),
            ],
            meta(),
        )
        .expect("unsorted input is sorted here");
        assert_eq!(l.segments()[0].memory_offset, 0x0000);
        assert_eq!(l.segments()[1].memory_offset, 0x8000);

        let err = SegmentedLayer::new(
            backing(0x1_0000),
            vec![
                Segment::strided(0x2000, 0x8000, 0x2000, SAVEVM_CHUNK, SAVEVM_STRIDE),
                Segment::new(0x0000, 0x9000, 0x1000),
            ],
            meta(),
        )
        .expect_err("the second segment starts inside the strided run's second chunk");
        assert!(matches!(
            err,
            LayerError::OverlappingSegments {
                first: 0,
                second: 1
            }
        ));
    }

    #[test]
    fn a_hole_after_a_strided_run_is_measured_from_the_runs_true_end() {
        let l = SegmentedLayer::new(
            backing(0x1_0000),
            vec![
                Segment::strided(0, 0, 0x3000, SAVEVM_CHUNK, SAVEVM_STRIDE),
                Segment::new(0x8000, 0x5000, 0x1000),
            ],
            meta(),
        )
        .unwrap();

        let mut one = [0u8; 1];
        assert_eq!(
            l.read_at(0x2FFF, &mut one).unwrap(),
            1,
            "the run's last byte"
        );
        assert_eq!(one[0], byte_at(2 * SAVEVM_STRIDE + 0xFFF));

        let mut buf = [0u8; 16];
        let err = l.read_at(0x3000, &mut buf).expect_err("past the run");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!((hole.address, hole.length), (0x3000, 0x2000));
    }

    #[test]
    fn physical_map_locates_each_strided_chunk_at_its_own_device_offset() {
        let l = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::strided(
                0x100,
                0,
                0x2000,
                SAVEVM_CHUNK,
                SAVEVM_STRIDE,
            )],
            meta(),
        )
        .unwrap();
        // 0x0F00..0x1100 crosses a chunk boundary: the two halves are eight
        // bytes further apart on the device than they are in memory.
        let map = l.physical_map(0x0F00, 0x200);
        assert_eq!(map.precision, ExtentPrecision::Exact);
        assert_eq!(map.extents.len(), 2);
        assert_eq!(map.extents[0].device_offset, Some(0x100 + 0x0F00));
        assert_eq!(map.extents[0].length, 0x100);
        assert_eq!(map.extents[1].device_offset, Some(0x100 + SAVEVM_STRIDE));
        assert_eq!(map.extents[1].length, 0x100);
        assert_eq!(map.located_len(), 0x200);
    }

    // ── Encoded chunks ──────────────────────────────────────────────────────

    #[test]
    fn an_encoded_chunk_is_indexed_and_described_but_never_served_as_stored_bytes() {
        // A run-length page: one stored byte standing for a whole page, laid
        // out nine bytes apart because the format writes an address word before
        // each. The shared layer knows where they are and how far each decodes,
        // and says so through the mapping contract — but it must not hand the
        // caller a stored byte and call it a page, and it must not fabricate
        // the rest. Only the reader that chose the encoding can decode it.
        let l = SegmentedLayer::new(
            backing(0x100),
            vec![Segment::chunked(0x10, 0x4000, 0x3000, 0x1000, 1, 9)],
            meta(),
        )
        .expect("an encoded run is a valid segment list");
        assert_eq!(l.mapped_len(), 0x3000, "the pages are acquired");
        assert!(l.segments()[0].is_encoded());
        assert_eq!(l.segments()[0].chunk_count(), 3);
        assert_eq!(l.segments()[0].file_end(), Some(0x10 + 2 * 9 + 1));

        let runs = l.mapping(0x4400, 0x100).expect("the chunk is backed");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].encoding, Encoding::Encoded);
        assert_eq!(
            (runs[0].offset, runs[0].length),
            (0x4000, 0x1000),
            "an encoded run describes the whole unit it decodes to"
        );
        assert_eq!(runs[0].mapped_offset, 0x10);
        assert_eq!(runs[0].mapped_length, 1, "one stored byte");
        // Every chunk keeps its own stored bytes, one stride further on.
        assert_eq!(l.mapping(0x5000, 1).unwrap()[0].mapped_offset, 0x19);
        assert_eq!(l.mapping(0x6000, 1).unwrap()[0].mapped_offset, 0x22);
        assert!(l.is_valid(0x4400, 0x100));

        let mut buf = [0u8; 16];
        let err = l
            .read_at(0x4000, &mut buf)
            .expect_err("only the format reader can decode this");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("cannot decode"), "{err}");
        assert!(
            MemoryHole::from_io(&err).is_none(),
            "an encoded chunk is acquired memory, not a hole"
        );
        assert!(buf.iter().all(|&b| b == 0), "nothing was fabricated");
    }

    #[test]
    fn physical_map_of_an_encoded_chunk_is_compressed_precision_not_exact() {
        let l = SegmentedLayer::new(
            backing(0x100),
            vec![Segment::chunked(0x10, 0, 0x2000, 0x1000, 1, 9)],
            meta(),
        )
        .unwrap();
        let map = l.physical_map(0x1400, 0x100);
        assert_eq!(
            map.precision,
            ExtentPrecision::Compressed,
            "the position is known to the stored byte, not to the memory byte"
        );
        assert_eq!(map.extents.len(), 1);
        assert_eq!(map.extents[0].device_offset, Some(0x19));
        assert_eq!(map.extents[0].length, 0x100);
    }

    #[test]
    fn a_chunking_that_does_not_describe_its_own_run_is_refused() {
        // A trailing part-chunk has no defined source offset, and inventing one
        // would put real memory bytes at an address that is not theirs.
        let err = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::strided(0, 0, 0x2800, SAVEVM_CHUNK, SAVEVM_STRIDE)],
            meta(),
        )
        .expect_err("0x2800 is not a whole number of 0x1000-byte chunks");
        match err {
            LayerError::MalformedSegment { index, ref detail } => {
                assert_eq!(index, 0);
                assert!(detail.contains("whole number"), "{detail}");
            }
            other => panic!("unexpected error: {other}"),
        }

        // A stride below the stored chunk makes consecutive chunks overlap in
        // the file, so one of them would be read out of the other's bytes.
        let err = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::strided(0, 0, 0x2000, 0x1000, 0x800)],
            meta(),
        )
        .expect_err("chunks cannot overlap in the source");
        match err {
            LayerError::MalformedSegment { index, ref detail } => {
                assert_eq!(index, 0);
                assert!(detail.contains("overlap in the source"), "{detail}");
            }
            other => panic!("unexpected error: {other}"),
        }

        // A zero-length chunk describes nothing and would divide by zero in the
        // lookup.
        let err = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::chunked(0, 0, 0x1000, 0, 0x1000, 0x1000)],
            meta(),
        )
        .expect_err("a zero-length chunk describes nothing");
        assert!(matches!(err, LayerError::MalformedSegment { index: 0, .. }));

        let err = SegmentedLayer::new(
            backing(0x1_0000),
            vec![Segment::chunked(
                u64::MAX - 8,
                0,
                0x2000,
                0x1000,
                0x1000,
                0x1000,
            )],
            meta(),
        )
        .expect_err("the second chunk's source extent overflows");
        assert!(matches!(err, LayerError::MalformedSegment { index: 0, .. }));
    }

    // ── End-to-end over a synthetic LiME-shaped fixture ─────────────────────

    #[test]
    fn a_synthetic_lime_file_reads_back_through_the_layer() {
        // Build a real LiME byte stream: two 32-byte headers, each followed by
        // its payload, with a hole between the two physical ranges.
        fn lime_header(start: u64, end: u64) -> Vec<u8> {
            let mut h = Vec::with_capacity(32);
            h.extend_from_slice(&0x4C69_4D45u32.to_le_bytes());
            h.extend_from_slice(&1u32.to_le_bytes());
            h.extend_from_slice(&start.to_le_bytes());
            h.extend_from_slice(&end.to_le_bytes());
            h.extend_from_slice(&0u64.to_le_bytes());
            h
        }

        let mut file = Vec::new();
        file.extend_from_slice(&lime_header(0x0000, 0x0FFF));
        let first_payload_at = file.len() as u64;
        file.extend_from_slice(&[0xA1u8; 0x1000]);
        file.extend_from_slice(&lime_header(0x2000, 0x2FFF));
        let second_payload_at = file.len() as u64;
        file.extend_from_slice(&[0xB2u8; 0x1000]);

        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(file));
        let l = SegmentedLayer::new(
            source,
            vec![
                Segment::new(first_payload_at, 0x0000, 0x1000),
                Segment::new(second_payload_at, 0x2000, 0x1000),
            ],
            LayerMeta::new(MemoryImageFormat::Lime).with_declared_size(0x3000),
        )
        .unwrap();

        assert_eq!(l.size(), 0x3000);
        assert_eq!(l.mapped_len(), 0x2000);

        let mut page = vec![0u8; 0x1000];
        assert_eq!(l.read_at(0, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xA1));
        assert_eq!(l.read_at(0x2000, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xB2));

        // The physical hole LiME skipped is a hole here too, not zeros.
        let err = l.read_at(0x1000, &mut page).expect_err("unacquired range");
        let hole = MemoryHole::from_io(&err).unwrap();
        assert_eq!((hole.address, hole.length), (0x1000, 0x1000));
    }

    #[test]
    fn the_layer_is_usable_as_a_trait_object() {
        let l: Arc<dyn MemoryLayer> = Arc::new(holed_layer());
        assert_eq!(l.min_address(), 0x2000);
        assert!(l.is_valid(0x2000, 0x1000));
        assert!(!l.is_valid(0x4000, 1));
        assert_eq!(l.layer_meta().format(), Some(MemoryImageFormat::Lime));
    }
}
