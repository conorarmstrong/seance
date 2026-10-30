//! LiME — the Linux Memory Extractor's acquisition format.
//!
//! The simplest of the segment formats and the reference for the rest: a bare
//! sequence of `(header, payload)` pairs running to the end of the file, with
//! nothing in front of them and no index. Each 32-byte header is
//! `<IIQQQ` — magic, version, `start`, `end`, reserved — and is followed
//! immediately by `end - start + 1` bytes of physical memory. `end` is
//! **inclusive**, which is the one arithmetic trap in the format.
//!
//! LiME skips the physical ranges the kernel does not report as System RAM, so
//! the gaps between consecutive segments are MMIO windows and reserved regions
//! that were never memory. Those gaps become [`crate::layer::MemoryHole`]s, not
//! zeros; see that type for why.
//!
//! ## Where this is stricter than upstream
//!
//! Volatility's `layers/lime.py` rejects a segment whose `start` is *below* the
//! previous segment's `end` (`if start < maxaddr`), which lets `start == end` of
//! the previous segment through — a one-byte overlap in which two different
//! payloads claim the same physical address. Here a segment must start strictly
//! above the previous segment's last address, so an image that overlaps is
//! refused with the offending offset named rather than silently resolved.

use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_core::io::{read_exact_or_fail, IncompleteReason};

use crate::format::MemoryImageFormat;
use crate::layer::{LayerError, MAX_SEGMENTS};
use crate::meta::LayerMeta;
use crate::segmented::{Segment, SegmentedLayer};

use super::{u32_at, u64_at, Endian, FormatError};

const FORMAT: MemoryImageFormat = MemoryImageFormat::Lime;
const LE: Endian = Endian::Little;

/// `<IIQQQ`: magic, version, start, end, reserved.
pub const HEADER_LEN: u64 = 32;

/// `0x4C694D45`, which is the ASCII `EMiL` once written little-endian.
const MAGIC: u32 = 0x4C69_4D45;

/// The only header version LiME has ever shipped, and the only one upstream
/// accepts. A different version means a layout we have not seen, so we refuse
/// rather than parse this one's field offsets out of it.
const VERSION: u32 = 1;

/// A parsed LiME acquisition: the segment list its headers declare, plus what
/// the walk learned about the file's completeness.
#[derive(Debug, Clone)]
pub struct LimeImage {
    segments: Vec<Segment>,
    meta: LayerMeta,
}

impl LimeImage {
    /// Walk the header chain from offset 0 to the end of the source.
    ///
    /// # Errors
    ///
    /// - [`FormatError::NotThisFormat`] when the first header carries no LiME
    ///   magic, so a caller probing several readers can move on.
    /// - [`FormatError::Unsupported`] for a header version other than 1.
    /// - [`FormatError::Malformed`] for an inverted, overlapping or overflowing
    ///   segment range, or a mid-file header with no magic.
    /// - [`FormatError::Io`] when a header cannot be read in full. A header is
    ///   structural, so a short read is a refusal and never a parse of a
    ///   zero-padded buffer.
    ///
    /// A **payload** that the file cannot satisfy is not an error: the segment
    /// keeps its declared length and the image is marked
    /// [`IncompleteReason::ShortRead`] with the shortfall named, so the missing
    /// tail reads as a short read rather than as acquired zeros.
    pub fn parse(source: &dyn DataSource) -> Result<Self, FormatError> {
        let size = source.size();
        if size < HEADER_LEN {
            return Err(FormatError::not_this(
                FORMAT,
                format!("the source holds {size} byte(s), fewer than one {HEADER_LEN}-byte header"),
            ));
        }

        let mut meta = LayerMeta::new(FORMAT);
        let mut segments: Vec<Segment> = Vec::new();
        let mut offset = 0u64;
        // Last address claimed so far, so the next segment can be required to
        // start above it.
        let mut previous_end: Option<u64> = None;

        while offset < size {
            if size - offset < HEADER_LEN {
                // The file stops part-way through a header. Refusing the whole
                // image would throw away the segments already parsed correctly,
                // so the walk stops here and says so.
                meta.push_incomplete(
                    IncompleteReason::ShortRead,
                    format!(
                        "the acquisition ends {} byte(s) into a {HEADER_LEN}-byte LiME header at \
                         file offset {offset:#x}; any segments beyond it were not recovered",
                        size - offset
                    ),
                );
                break;
            }

            let mut header = [0u8; HEADER_LEN as usize];
            read_exact_or_fail(source, offset, &mut header, "LiME segment header")
                .map_err(|e| FormatError::io(FORMAT, "LiME segment header", e))?;

            let (magic, version, start, end) = decode_header(&header).ok_or_else(|| {
                FormatError::malformed(FORMAT, format!("header at {offset:#x} is under-length"))
            })?;

            if magic != MAGIC {
                return Err(if offset == 0 {
                    FormatError::not_this(
                        FORMAT,
                        format!("magic {magic:#010x} is not {MAGIC:#010x}"),
                    )
                } else {
                    FormatError::malformed(
                        FORMAT,
                        format!(
                            "the segment following the one at {:#x} should begin with a LiME \
                             header at file offset {offset:#x}, but the magic there is {magic:#010x}",
                            segments
                                .last()
                                .map(|s| s.memory_offset)
                                .unwrap_or_default(),
                        ),
                    )
                });
            }
            if version != VERSION {
                return Err(FormatError::unsupported(
                    FORMAT,
                    format!(
                        "header version {version} at file offset {offset:#x}; only version \
                         {VERSION} is defined"
                    ),
                ));
            }
            if end < start {
                return Err(FormatError::malformed(
                    FORMAT,
                    format!(
                        "the header at file offset {offset:#x} declares the inverted range \
                         {start:#x}..={end:#x}"
                    ),
                ));
            }
            if let Some(previous) = previous_end.filter(|last| start <= *last) {
                return Err(FormatError::malformed(
                    FORMAT,
                    format!(
                        "the header at file offset {offset:#x} starts at {start:#x}, at or below \
                         the previous segment's last address {previous:#x}; two payloads cannot \
                         hold the same physical address"
                    ),
                ));
            }

            // `end` is inclusive, so the length is one more than the difference.
            // The checked add is not decoration: `start = 0, end = u64::MAX`
            // is a legal-looking header that overflows a naive `end - start + 1`.
            let length = (end - start).checked_add(1).ok_or_else(|| {
                FormatError::malformed(
                    FORMAT,
                    format!(
                        "the header at file offset {offset:#x} claims the entire 64-bit address \
                         space ({start:#x}..={end:#x})"
                    ),
                )
            })?;

            let payload = offset + HEADER_LEN;
            let next = payload.checked_add(length).ok_or_else(|| {
                FormatError::malformed(
                    FORMAT,
                    format!(
                        "the segment at file offset {offset:#x} extends past the end of a 64-bit \
                         file ({length:#x} bytes at {payload:#x})"
                    ),
                )
            })?;

            if segments.len() == MAX_SEGMENTS {
                return Err(FormatError::layer(
                    FORMAT,
                    LayerError::TooManySegments {
                        count: MAX_SEGMENTS + 1,
                        cap: MAX_SEGMENTS,
                    },
                ));
            }
            segments.push(Segment::new(payload, start, length));
            previous_end = Some(end);

            if next > size {
                // The declared length is kept: trimming it here would erase the
                // evidence that the tool claimed bytes the file does not hold.
                // `SegmentedLayer` short-reads at the truncation point, so no
                // caller ever receives a fabricated byte from the missing tail.
                meta.push_incomplete(
                    IncompleteReason::ShortRead,
                    format!(
                        "the final segment declares {length:#x} bytes of physical memory at \
                         {start:#x} but the acquisition file holds only {:#x} of them",
                        size - payload
                    ),
                );
                break;
            }
            offset = next;
        }

        if segments.is_empty() {
            return Err(FormatError::malformed(
                FORMAT,
                "the header chain declared no segments".to_string(),
            ));
        }

        // The top of the physical address space the image describes, which is
        // not the size of the file holding it.
        let declared = segments
            .iter()
            .filter_map(|s| s.memory_end())
            .max()
            .unwrap_or(0);
        meta = meta.with_declared_size(declared);

        Ok(Self { segments, meta })
    }

    /// The segment list, in header order.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Metadata for the layer this image will become.
    pub fn layer_meta(&self) -> &LayerMeta {
        &self.meta
    }

    /// Bytes of physical memory the headers declare, summed across segments.
    /// Less than the span of the address space whenever LiME skipped a range.
    pub fn acquired_bytes(&self) -> u64 {
        self.segments
            .iter()
            .fold(0u64, |acc, s| acc.saturating_add(s.length))
    }

    /// Build the address space. `source` must be the same source [`parse`] read.
    ///
    /// [`parse`]: LimeImage::parse
    pub fn into_layer(self, source: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
        SegmentedLayer::new(source, self.segments, self.meta)
            .map_err(|e| FormatError::layer(FORMAT, e))
    }
}

fn decode_header(header: &[u8]) -> Option<(u32, u32, u64, u64)> {
    Some((
        u32_at(header, 0, LE)?,
        u32_at(header, 4, LE)?,
        u64_at(header, 8, LE)?,
        u64_at(header, 16, LE)?,
    ))
}

/// Parse `source` as a LiME image and return its address space.
pub fn open(source: Arc<dyn DataSource>) -> Result<SegmentedLayer, FormatError> {
    let image = LimeImage::parse(&*source)?;
    image.into_layer(source)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{HoleReason, MemoryHole, MemoryLayer};
    use seance_core::data_source::ByteSliceDataSource;
    use std::io;

    /// A 32-byte LiME header. `end` is inclusive, as on disk.
    fn header(magic: u32, version: u32, start: u64, end: u64) -> Vec<u8> {
        let mut h = Vec::with_capacity(HEADER_LEN as usize);
        h.extend_from_slice(&magic.to_le_bytes());
        h.extend_from_slice(&version.to_le_bytes());
        h.extend_from_slice(&start.to_le_bytes());
        h.extend_from_slice(&end.to_le_bytes());
        h.extend_from_slice(&0u64.to_le_bytes());
        h
    }

    /// A whole LiME file: `(physical_start, payload_len, fill_byte)` per segment.
    fn image(segments: &[(u64, u64, u8)]) -> Vec<u8> {
        let mut file = Vec::new();
        for &(start, len, fill) in segments {
            file.extend_from_slice(&header(MAGIC, VERSION, start, start + len - 1));
            file.extend(std::iter::repeat_n(fill, len as usize));
        }
        file
    }

    fn source(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes))
    }

    // ── Valid image ─────────────────────────────────────────────────────────

    #[test]
    fn a_valid_image_yields_the_declared_segments_and_reads_back() {
        // Two acquired ranges with an unacquired MMIO window between them.
        let layer = open(source(image(&[
            (0x0000, 0x1000, 0xA1),
            (0x3000, 0x2000, 0xB2),
        ])))
        .expect("a well-formed LiME image");

        assert_eq!(layer.min_address(), 0x0000);
        assert_eq!(layer.max_address(), 0x4FFF);
        assert_eq!(layer.size(), 0x5000, "the span of the address space");
        assert_eq!(layer.mapped_len(), 0x3000, "only three pages were acquired");
        assert_eq!(layer.layer_meta().declared_size(), Some(0x5000));
        assert_eq!(layer.layer_meta().format(), Some(MemoryImageFormat::Lime));
        assert!(layer.layer_meta().incomplete().is_empty());

        // Payloads land at the physical address their header declared, from the
        // file offset just past that header.
        let mut page = vec![0u8; 0x1000];
        assert_eq!(layer.read_at(0x0000, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xA1));
        assert_eq!(layer.read_at(0x3800, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0xB2));
    }

    #[test]
    fn the_range_lime_skipped_is_a_hole_and_never_zeros() {
        let layer = open(source(image(&[
            (0x0000, 0x1000, 0xA1),
            (0x3000, 0x1000, 0xB2),
        ])))
        .unwrap();

        let mut buf = vec![0xEEu8; 0x800];
        let err = layer
            .read_at(0x1000, &mut buf)
            .expect_err("an unacquired physical range must not read as zeros");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!(hole.address, 0x1000);
        assert_eq!(hole.length, 0x2000);
        assert_eq!(hole.reason, HoleReason::Unmapped);
        assert!(buf.iter().all(|&b| b == 0xEE), "the buffer was not touched");
    }

    #[test]
    fn the_inclusive_end_is_decoded_as_an_inclusive_end() {
        // The trap in the format: `end` is the LAST byte, so a 0x1000-byte
        // segment beginning at 0 declares `end = 0xFFF`, not `0x1000`. An
        // off-by-one here shortens or lengthens every segment in the image.
        let parsed = LimeImage::parse(&*source(image(&[(0x2000, 0x1000, 0x5A)]))).unwrap();
        assert_eq!(parsed.segments().len(), 1);
        assert_eq!(parsed.segments()[0].memory_offset, 0x2000);
        assert_eq!(parsed.segments()[0].length, 0x1000);
        assert_eq!(parsed.segments()[0].file_offset, HEADER_LEN);
        assert_eq!(parsed.acquired_bytes(), 0x1000);
    }

    #[test]
    fn many_segments_are_walked_in_order() {
        let spec: Vec<(u64, u64, u8)> = (0..64u64)
            .map(|i| (i * 0x2000, 0x1000, (i % 251) as u8))
            .collect();
        let parsed = LimeImage::parse(&*source(image(&spec))).unwrap();
        assert_eq!(parsed.segments().len(), 64);
        assert_eq!(parsed.acquired_bytes(), 64 * 0x1000);
        // Each header sits immediately after the previous payload.
        for (i, seg) in parsed.segments().iter().enumerate() {
            let expected = (i as u64 + 1) * HEADER_LEN + i as u64 * 0x1000;
            assert_eq!(seg.file_offset, expected, "segment {i}");
        }
    }

    // ── Truncated image ─────────────────────────────────────────────────────

    #[test]
    fn a_truncated_final_payload_is_reported_incomplete_and_reads_short() {
        // The header claims 0x2000 bytes; the acquisition was cut off after
        // 0x800 of them, which is what happens when a capture is interrupted.
        let mut file = image(&[(0x0000, 0x1000, 0xA1)]);
        file.extend_from_slice(&header(MAGIC, VERSION, 0x4000, 0x5FFF));
        file.extend(std::iter::repeat_n(0xC3u8, 0x800));

        let parsed = LimeImage::parse(&*source(file.clone())).expect("the parse still succeeds");
        assert_eq!(parsed.segments().len(), 2);
        assert_eq!(
            parsed.segments()[1].length,
            0x2000,
            "the declared length is kept; trimming it would erase the discrepancy"
        );
        let incomplete = parsed.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::ShortRead);
        assert!(incomplete[0].detail.contains("0x800"));

        // And the layer serves the 0x800 bytes that exist, then stops. It does
        // not pad the missing 0x1800.
        let layer = open(source(file)).unwrap();
        let mut buf = vec![0u8; 0x2000];
        assert_eq!(layer.read_at(0x4000, &mut buf).unwrap(), 0x800);
        assert!(buf[..0x800].iter().all(|&b| b == 0xC3));

        // A structural read over the truncation point fails closed rather than
        // parsing the zeros that were never overwritten.
        let mut structure = [0u8; 0x40];
        let err = read_exact_or_fail(layer.as_data_source(), 0x47E0, &mut structure, "list entry")
            .expect_err("truncated evidence must not parse");
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(
            MemoryHole::from_io(&err).is_none(),
            "truncation is not a hole"
        );
    }

    #[test]
    fn a_trailing_partial_header_is_reported_rather_than_parsed_or_ignored() {
        let mut file = image(&[(0x0000, 0x1000, 0xA1)]);
        file.extend_from_slice(&header(MAGIC, VERSION, 0x2000, 0x2FFF)[..19]);

        let parsed = LimeImage::parse(&*source(file)).expect("the first segment is intact");
        assert_eq!(parsed.segments().len(), 1);
        let incomplete = parsed.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::ShortRead);
        assert!(incomplete[0].detail.contains("19 byte(s)"));
    }

    #[test]
    fn a_truncated_first_header_is_refused_outright() {
        // Nothing was recovered, so there is no image — only a claim of one.
        let short = header(MAGIC, VERSION, 0, 0xFFF)[..20].to_vec();
        let err = LimeImage::parse(&*source(short)).expect_err("must not parse");
        assert!(err.is_not_this_format());

        // Even a source that is exactly the magic and nothing else.
        let err =
            LimeImage::parse(&*source(MAGIC.to_le_bytes().to_vec())).expect_err("must not parse");
        assert!(err.is_not_this_format());
    }

    #[test]
    fn a_source_that_dribbles_bytes_is_not_mistaken_for_a_truncated_image() {
        let parsed = // DribbleSource returns at most seven bytes per call, as a windowed or
        // container-backed source legitimately does. The header read must loop
        // rather than treat the dribble as truncation.
        LimeImage::parse(&seance_core::test_support::DribbleSource::new(
            image(&[(0, 0x1000, 0x7E), (0x1000, 0x1000, 0x7F)]),
            7,
        ))
        .expect("all the bytes are there, just not in one read");
        assert_eq!(parsed.segments().len(), 2);
        assert!(parsed.layer_meta().incomplete().is_empty());
    }

    // ── Malformed headers ───────────────────────────────────────────────────

    #[test]
    fn a_foreign_magic_is_declined_rather_than_reported_as_damage() {
        let mut file = header(0xDEAD_BEEF, VERSION, 0, 0xFFF);
        file.resize(0x2000, 0);
        let err = LimeImage::parse(&*source(file)).expect_err("not a LiME image");
        assert!(err.is_not_this_format());
    }

    #[test]
    fn an_unsupported_version_fails_closed_with_the_version_named() {
        let mut file = header(MAGIC, 7, 0, 0xFFF);
        file.resize(0x2000, 0);
        let err = LimeImage::parse(&*source(file)).expect_err("version 7 is not defined");
        assert!(matches!(err, FormatError::Unsupported { .. }));
        assert!(err.to_string().contains('7'));
    }

    #[test]
    fn an_inverted_range_does_not_panic_and_is_refused() {
        let mut file = header(MAGIC, VERSION, 0xFFFF, 0x10);
        file.resize(0x2000, 0);
        let err = LimeImage::parse(&*source(file)).expect_err("end below start");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("inverted"));
    }

    #[test]
    fn a_range_spanning_the_whole_address_space_does_not_overflow() {
        // `end - start + 1` is u64::MAX + 1. A naive reader wraps to zero here
        // and produces a zero-length segment.
        let mut file = header(MAGIC, VERSION, 0, u64::MAX);
        file.resize(0x2000, 0);
        let err = LimeImage::parse(&*source(file)).expect_err("cannot be represented");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("entire 64-bit address space"));
    }

    #[test]
    fn a_payload_extending_past_a_64_bit_file_does_not_overflow() {
        let mut file = header(MAGIC, VERSION, 0, u64::MAX - 1);
        file.resize(0x2000, 0);
        let err = LimeImage::parse(&*source(file)).expect_err("file extent overflows");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn segments_that_overlap_in_physical_memory_are_refused() {
        // The second segment starts one byte below the first one's end. Upstream
        // accepts the exactly-equal case; both are two payloads claiming one
        // physical address, so both are refused here.
        let mut file = header(MAGIC, VERSION, 0x1000, 0x1FFF);
        file.extend(std::iter::repeat_n(0xA1u8, 0x1000));
        file.extend_from_slice(&header(MAGIC, VERSION, 0x1FFF, 0x2FFF));
        file.extend(std::iter::repeat_n(0xB2u8, 0x1001));

        let err = LimeImage::parse(&*source(file)).expect_err("overlapping segments");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("same physical address"));
    }

    #[test]
    fn segments_that_run_backwards_are_refused() {
        let mut file = header(MAGIC, VERSION, 0x4000, 0x4FFF);
        file.extend(std::iter::repeat_n(0xA1u8, 0x1000));
        file.extend_from_slice(&header(MAGIC, VERSION, 0x1000, 0x1FFF));
        file.extend(std::iter::repeat_n(0xB2u8, 0x1000));

        let err = LimeImage::parse(&*source(file)).expect_err("descending segments");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_missing_magic_on_a_later_header_is_damage_not_a_declined_probe() {
        let mut file = image(&[(0x0000, 0x1000, 0xA1)]);
        file.extend_from_slice(&header(0x0BAD_F00D, VERSION, 0x2000, 0x2FFF));
        file.extend(std::iter::repeat_n(0xB2u8, 0x1000));

        let err = LimeImage::parse(&*source(file)).expect_err("the chain is broken");
        assert!(
            !err.is_not_this_format(),
            "the first header proved this is a LiME image; the break is damage"
        );
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_zero_length_segment_is_impossible_because_end_is_inclusive() {
        // start == end is a single byte, the smallest legal segment, and must
        // not be mistaken for an empty one.
        let mut file = header(MAGIC, VERSION, 0x1000, 0x1000);
        file.push(0x42);
        let parsed = LimeImage::parse(&*source(file.clone())).expect("one byte is a segment");
        assert_eq!(parsed.segments()[0].length, 1);

        let layer = open(source(file)).unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(layer.read_at(0x1000, &mut byte).unwrap(), 1);
        assert_eq!(byte[0], 0x42);
    }

    #[test]
    fn an_empty_source_is_declined_without_panicking() {
        let err = LimeImage::parse(&*source(Vec::new())).expect_err("nothing to parse");
        assert!(err.is_not_this_format());
    }
}
