//! AVML — Microsoft's *Acquire Volatile Memory for Linux*.
//!
//! An AVML file is a sequence of **blocks**, each a 32-byte header
//! (`<IIQQQ`: magic, version, `start`, `end`, padding) followed by a
//! [Snappy framing-format] stream holding that block's `end - start` bytes of
//! physical memory, followed by eight further bytes before the next block.
//! `end` is **inclusive**, exactly as in LiME: the two formats share a header
//! shape and agree on this. Both take their ranges from `/proc/iomem`, which
//! reports inclusive ranges (`00001000-0009fbff : System RAM`), and copy them
//! through unchanged.
//!
//! This module previously documented and implemented `end` as *exclusive*. That
//! was wrong, and it made every real AVML capture unreadable: the byte count
//! came out one short, which is never page-aligned, and the frame walk then
//! decoded more bytes than the block declared and refused the image as
//! malformed. It was invisible for as long as the only test inputs were
//! fixtures this crate built for itself, because they were written with the
//! same wrong convention they were read back with. Found by opening a capture
//! taken with AVML 0.14.0 from a live Ubuntu host.
//!
//! Inside the stream, each frame is a 4-byte header (a type byte and a 24-bit
//! little-endian length) and then, for the two data types, a 4-byte checksum
//! followed by the frame body:
//!
//! | type | meaning |
//! |---|---|
//! | `0xFF` | stream identifier; the body must be `sNaPpY` |
//! | `0x00` | Snappy-compressed data, at most 64 KiB decompressed |
//! | `0x01` | uncompressed data |
//! | `0x02`–`0x7F` | reserved **unskippable** — refuse the image |
//! | `0x80`–`0xFE` | reserved skippable — ignored |
//!
//! ## The checksum, which upstream does not verify
//!
//! Volatility's `layers/avml.py` reads the checksum and throws it away
//! (`# frame_crc = ...`, `# TODO: Verify CRC`), so a frame whose bytes were
//! corrupted in storage or transit decompresses to plausible-looking memory and
//! is served as evidence. **Here every frame is verified before a single byte of
//! it is returned, and a mismatch is a hard error**, never a warning and never a
//! degraded read.
//!
//! There is nothing to transcribe from upstream for this, because upstream never
//! wrote it. The framing is Snappy's own, so the checksum is the **masked
//! CRC-32C of the uncompressed data**: `crc32c` with the Castagnoli polynomial,
//! then `(sum >> 15 | sum << 17) + 0xA282EAD8`. `snap` does not export a
//! checksum helper, so it is implemented here — and pinned by a known-answer
//! vector (`crc32c("123456789") == 0xE3069283`) plus round-trips against
//! `snap`'s own frame encoder, because getting the mask or the polynomial wrong
//! would reject every real AVML capture.
//!
//! ## Why this format needs its own layer
//!
//! Every other segment format is byte-for-byte on disk, so it reduces to a
//! [`SegmentedLayer`] and nothing more. A compressed AVML frame cannot be
//! addressed into: the bytes for one physical address only exist after the whole
//! frame is decoded. [`AvmlLayer`] therefore keeps the validated segment index a
//! `SegmentedLayer` provides — sorting, overlap rejection, bounds and hole
//! sizing — and adds the decode, the verification and the
//! [`Encoding::Encoded`] mapping runs on top.
//!
//! [Snappy framing-format]: https://github.com/google/snappy/blob/main/framing_format.txt

use std::collections::HashMap;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use seance_core::data_source::{DataSource, ExtentPrecision, PhysicalExtent, PhysicalMap};
use seance_core::io::{read_exact_or_fail, read_full, IncompleteReason};

use crate::format::MemoryImageFormat;
use crate::layer::{
    BackingSource, Encoding, LayerError, MappedRange, MemoryHole, MemoryLayer, MAX_SEGMENTS,
};
use crate::meta::LayerMeta;
use crate::segmented::{Segment, SegmentedLayer};

use super::{u32_at, u64_at, Endian, FormatError};

const FORMAT: MemoryImageFormat = MemoryImageFormat::Avml;
const LE: Endian = Endian::Little;

/// `<IIQQQ`: magic, version, start, end, padding.
pub const BLOCK_HEADER_LEN: u64 = 32;
/// Bytes between the end of a block's frame stream and the next block header.
const BLOCK_TRAILER_LEN: u64 = 8;
/// `0x4C4D5641`, which is the ASCII `AVML` once written little-endian.
const MAGIC: u32 = 0x4C4D_5641;
/// The only version whose block layout this reader implements, matching
/// upstream. Version 1 exists but is a different layout.
const VERSION: u32 = 2;

/// Type byte plus a 24-bit little-endian length.
const FRAME_HEADER_LEN: u64 = 4;
/// The masked CRC-32C that precedes every data frame's body.
const FRAME_CRC_LEN: u64 = 4;
const FRAME_STREAM_IDENTIFIER: u8 = 0xFF;
const FRAME_COMPRESSED: u8 = 0x00;
const FRAME_UNCOMPRESSED: u8 = 0x01;
const STREAM_IDENTIFIER_LEN: usize = 6;
const STREAM_IDENTIFIER_BODY: &[u8; STREAM_IDENTIFIER_LEN] = b"sNaPpY";
/// The framing format caps one frame's uncompressed data at 64 KiB, which is
/// also the bound on every decode allocation this module makes.
const MAX_FRAME_DECODED: u64 = 65_536;
/// A Snappy block preamble is a varint of the uncompressed length, at most five
/// bytes because the length is a `u32`.
const SNAPPY_PREAMBLE_MAX: usize = 5;

/// How a frame's bytes are stored, and what they must check against.
#[derive(Debug, Clone, Copy)]
struct Codec {
    compressed: bool,
    /// Bytes of frame body on disk: the frame payload minus its checksum.
    stored_len: u64,
    /// The masked CRC-32C the stream declares for the *decoded* bytes.
    masked_crc: u32,
}

/// One frame: where its decoded bytes live in the physical address space, and
/// how to get them back.
#[derive(Debug, Clone, Copy)]
struct Frame {
    segment: Segment,
    codec: Codec,
}

/// A parsed AVML acquisition: the frame table its block headers and Snappy
/// streams declare, plus what the walk learned about the file's completeness.
#[derive(Debug, Clone)]
pub struct AvmlImage {
    frames: Vec<Frame>,
    meta: LayerMeta,
}

impl AvmlImage {
    /// Walk every block header and every frame within it.
    ///
    /// Frame bodies are **not** decoded here — only their headers, checksums and
    /// declared lengths are read, so opening a multi-gigabyte capture does not
    /// decompress it. Verification happens when the bytes are actually served,
    /// which is the only point at which serving unverified bytes would be
    /// possible.
    ///
    /// # Errors
    ///
    /// - [`FormatError::NotThisFormat`] when the first block carries no AVML
    ///   magic.
    /// - [`FormatError::Unsupported`] for a version other than 2.
    /// - [`FormatError::Malformed`] for an inverted block range, a frame that
    ///   decodes to more than its block declares, a malformed stream
    ///   identifier, or a reserved unskippable frame type.
    /// - [`FormatError::Io`] when a header, checksum or stream identifier
    ///   cannot be read in full.
    ///
    /// A stream that simply **stops** — the common shape of an interrupted
    /// acquisition — is not an error: the frames recovered so far are kept and
    /// the image is marked [`IncompleteReason::ShortRead`] with the file offset
    /// named. Upstream instead spins forever here, because its frame loop is
    /// `while decompressed_len <= expected_length` guarded only by an `if` with
    /// no `else`.
    pub fn parse(source: &dyn DataSource) -> Result<Self, FormatError> {
        let size = source.size();
        if size < BLOCK_HEADER_LEN {
            return Err(FormatError::not_this(
                FORMAT,
                format!(
                    "the source holds {size} byte(s), fewer than one {BLOCK_HEADER_LEN}-byte \
                     block header"
                ),
            ));
        }

        let mut meta = LayerMeta::new(FORMAT);
        let mut frames: Vec<Frame> = Vec::new();
        let mut offset = 0u64;
        let mut blocks = 0u64;
        let mut compressed_frames = 0u64;

        'blocks: while offset < size {
            if size - offset < BLOCK_HEADER_LEN {
                meta.push_incomplete(
                    IncompleteReason::ShortRead,
                    format!(
                        "the acquisition ends {} byte(s) into a {BLOCK_HEADER_LEN}-byte AVML \
                         block header at file offset {offset:#x}; any blocks beyond it were not \
                         recovered",
                        size - offset
                    ),
                );
                break;
            }

            let mut header = [0u8; BLOCK_HEADER_LEN as usize];
            read_exact_or_fail(source, offset, &mut header, "AVML block header")
                .map_err(|e| FormatError::io(FORMAT, "AVML block header", e))?;
            let (magic, version, start, end) = decode_block_header(&header).ok_or_else(|| {
                FormatError::malformed(FORMAT, format!("block header at {offset:#x} is short"))
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
                            "the block at file offset {offset:#x} should begin with the AVML \
                             magic, but carries {magic:#010x}"
                        ),
                    )
                });
            }
            if version != VERSION {
                return Err(FormatError::unsupported(
                    FORMAT,
                    format!(
                        "block version {version} at file offset {offset:#x}; only version \
                         {VERSION} has this layout"
                    ),
                ));
            }
            if end < start {
                return Err(FormatError::malformed(
                    FORMAT,
                    format!(
                        "the block at file offset {offset:#x} declares the inverted range \
                         {start:#x}..{end:#x}"
                    ),
                ));
            }
            // `end` is INCLUSIVE, so the byte count is one more than the
            // difference. AVML copies its ranges verbatim out of
            // `/proc/iomem`, which reports them inclusively -- the first block
            // of an x86 capture reads `00001000-0009fbff : System RAM` there
            // and `0x1000..=0x9efff` here. Reading it as exclusive makes every
            // block one byte short, which is also never page-aligned, and the
            // frame walk below then decodes more bytes than the block claims
            // and refuses the image. See the module docs.
            let declared = end - start + 1;
            if declared == 0 {
                return Err(FormatError::malformed(
                    FORMAT,
                    format!("the block at file offset {offset:#x} declares an empty range"),
                ));
            }
            blocks += 1;

            let mut cursor = offset + BLOCK_HEADER_LEN;
            let mut produced = 0u64;

            while produced < declared {
                if size.saturating_sub(cursor) < FRAME_HEADER_LEN {
                    meta.push_incomplete(
                        IncompleteReason::ShortRead,
                        format!(
                            "the frame stream of the block covering {start:#x}..{end:#x} stops at \
                             file offset {cursor:#x} after {produced:#x} of {declared:#x} bytes"
                        ),
                    );
                    break 'blocks;
                }

                let mut frame_header = [0u8; FRAME_HEADER_LEN as usize];
                read_exact_or_fail(source, cursor, &mut frame_header, "snappy frame header")
                    .map_err(|e| FormatError::io(FORMAT, "snappy frame header", e))?;
                let kind = frame_header[0];
                let frame_len = u64::from(frame_header[1])
                    | u64::from(frame_header[2]) << 8
                    | u64::from(frame_header[3]) << 16;
                let payload_at = cursor + FRAME_HEADER_LEN;

                match kind {
                    FRAME_STREAM_IDENTIFIER => {
                        if frame_len != STREAM_IDENTIFIER_LEN as u64 {
                            return Err(FormatError::malformed(
                                FORMAT,
                                format!(
                                    "the stream identifier at file offset {cursor:#x} declares \
                                     {frame_len} bytes, not {STREAM_IDENTIFIER_LEN}"
                                ),
                            ));
                        }
                        let mut body = [0u8; STREAM_IDENTIFIER_LEN];
                        read_exact_or_fail(
                            source,
                            payload_at,
                            &mut body,
                            "snappy stream identifier",
                        )
                        .map_err(|e| FormatError::io(FORMAT, "snappy stream identifier", e))?;
                        if &body != STREAM_IDENTIFIER_BODY {
                            return Err(FormatError::malformed(
                                FORMAT,
                                format!(
                                    "the stream identifier at file offset {payload_at:#x} is \
                                     {body:02x?}, not {STREAM_IDENTIFIER_BODY:?}"
                                ),
                            ));
                        }
                    }

                    FRAME_COMPRESSED | FRAME_UNCOMPRESSED => {
                        if frame_len <= FRAME_CRC_LEN {
                            return Err(FormatError::malformed(
                                FORMAT,
                                format!(
                                    "the data frame at file offset {cursor:#x} declares \
                                     {frame_len} bytes, too few for a {FRAME_CRC_LEN}-byte \
                                     checksum and a body"
                                ),
                            ));
                        }
                        match payload_at.checked_add(frame_len) {
                            Some(frame_end) if frame_end <= size => {}
                            _ => {
                                meta.push_incomplete(
                                    IncompleteReason::ShortRead,
                                    format!(
                                        "the frame at file offset {cursor:#x} declares \
                                         {frame_len:#x} bytes but the acquisition ends at \
                                         {size:#x}; it and everything after it were not recovered"
                                    ),
                                );
                                break 'blocks;
                            }
                        }

                        let mut checksum = [0u8; FRAME_CRC_LEN as usize];
                        read_exact_or_fail(
                            source,
                            payload_at,
                            &mut checksum,
                            "snappy frame checksum",
                        )
                        .map_err(|e| FormatError::io(FORMAT, "snappy frame checksum", e))?;
                        let masked_crc = u32::from_le_bytes(checksum);

                        let body_at = payload_at + FRAME_CRC_LEN;
                        let stored_len = frame_len - FRAME_CRC_LEN;
                        let compressed = kind == FRAME_COMPRESSED;

                        // A compressed frame states its decoded length in the
                        // Snappy block preamble, so the segment table can be
                        // built without decompressing the capture.
                        let decoded_len = if compressed {
                            let mut preamble = [0u8; SNAPPY_PREAMBLE_MAX];
                            let got = read_full(source, body_at, &mut preamble);
                            snappy_block_len(&preamble[..got]).ok_or_else(|| {
                                FormatError::malformed(
                                    FORMAT,
                                    format!(
                                        "the compressed frame at file offset {body_at:#x} has no \
                                         readable length preamble"
                                    ),
                                )
                            })?
                        } else {
                            stored_len
                        };

                        if decoded_len == 0 || decoded_len > MAX_FRAME_DECODED {
                            return Err(FormatError::malformed(
                                FORMAT,
                                format!(
                                    "the frame at file offset {cursor:#x} declares {decoded_len:#x} \
                                     decoded bytes; the framing format allows 1..={MAX_FRAME_DECODED:#x}"
                                ),
                            ));
                        }
                        if produced.saturating_add(decoded_len) > declared {
                            return Err(FormatError::malformed(
                                FORMAT,
                                format!(
                                    "the frames of the block covering {start:#x}..{end:#x} decode \
                                     to more than the {declared:#x} bytes it declares"
                                ),
                            ));
                        }
                        if frames.len() == MAX_SEGMENTS {
                            return Err(FormatError::layer(
                                FORMAT,
                                LayerError::TooManySegments {
                                    count: MAX_SEGMENTS + 1,
                                    cap: MAX_SEGMENTS,
                                },
                            ));
                        }

                        let memory_offset = start.checked_add(produced).ok_or_else(|| {
                            FormatError::malformed(
                                FORMAT,
                                format!(
                                    "the frame at file offset {cursor:#x} sits past the end of the \
                                     64-bit address space"
                                ),
                            )
                        })?;
                        frames.push(Frame {
                            segment: Segment::new(body_at, memory_offset, decoded_len),
                            codec: Codec {
                                compressed,
                                stored_len,
                                masked_crc,
                            },
                        });
                        if compressed {
                            compressed_frames += 1;
                        }
                        produced += decoded_len;
                    }

                    0x02..=0x7F => {
                        // The framing format reserves these for constructs a
                        // reader must understand. Skipping one would silently
                        // drop or misplace memory.
                        return Err(FormatError::malformed(
                            FORMAT,
                            format!(
                                "the frame at file offset {cursor:#x} has reserved unskippable \
                                 type {kind:#04x}"
                            ),
                        ));
                    }

                    _ => {
                        // 0x80..=0xFE are reserved skippable; the format says to
                        // step over them, which is what the cursor advance does.
                    }
                }

                let next_frame = cursor
                    .checked_add(FRAME_HEADER_LEN)
                    .and_then(|c| c.checked_add(frame_len));
                cursor = match next_frame {
                    Some(next) => next,
                    None => {
                        return Err(FormatError::malformed(
                            FORMAT,
                            format!("the frame at file offset {cursor:#x} runs past a 64-bit file"),
                        ))
                    }
                };
            }

            let next_block = cursor.checked_add(BLOCK_TRAILER_LEN);
            offset = match next_block {
                Some(next) => next,
                None => {
                    return Err(FormatError::malformed(
                        FORMAT,
                        format!("the block at file offset {offset:#x} runs past a 64-bit file"),
                    ))
                }
            };
        }

        if frames.is_empty() {
            return Err(FormatError::malformed(
                FORMAT,
                "no frames of physical memory were recovered".to_string(),
            ));
        }

        let declared_size = frames
            .iter()
            .filter_map(|f| f.segment.memory_end())
            .max()
            .unwrap_or(0);
        meta = meta
            .with_declared_size(declared_size)
            .with_note("blocks", blocks)
            .with_note("frames", frames.len() as u64)
            .with_note("compressed_frames", compressed_frames);

        Ok(Self { frames, meta })
    }

    /// The decoded extents the frames cover, in file order.
    pub fn segments(&self) -> Vec<Segment> {
        self.frames.iter().map(|f| f.segment).collect()
    }

    /// How many Snappy frames the walk found.
    pub fn frame_count(&self) -> usize {
        self.frames.len()
    }

    /// How many of them are compressed rather than stored.
    pub fn compressed_frame_count(&self) -> usize {
        self.frames.iter().filter(|f| f.codec.compressed).count()
    }

    /// Bytes of physical memory the frames decode to, summed.
    pub fn acquired_bytes(&self) -> u64 {
        self.frames
            .iter()
            .fold(0u64, |acc, f| acc.saturating_add(f.segment.length))
    }

    /// Metadata for the layer this image will become.
    pub fn layer_meta(&self) -> &LayerMeta {
        &self.meta
    }

    /// Build the address space. `source` must be the same source
    /// [`parse`](AvmlImage::parse) read.
    pub fn into_layer(self, source: Arc<dyn DataSource>) -> Result<AvmlLayer, FormatError> {
        let segments: Vec<Segment> = self.frames.iter().map(|f| f.segment).collect();
        let codecs: HashMap<u64, Codec> = self
            .frames
            .iter()
            .map(|f| (f.segment.file_offset, f.codec))
            .collect();
        // The segment index is a real `SegmentedLayer`, so sorting, overlap
        // rejection, bounds and hole sizing are the shared implementation and
        // not a second copy of them.
        let index = SegmentedLayer::new(source, segments, self.meta)
            .map_err(|e| FormatError::layer(FORMAT, e))?;
        Ok(AvmlLayer {
            index,
            codecs,
            decoded: Mutex::new(None),
        })
    }
}

/// Parse `source` as an AVML image and return its physical address space.
pub fn open(source: Arc<dyn DataSource>) -> Result<AvmlLayer, FormatError> {
    let image = AvmlImage::parse(&*source)?;
    image.into_layer(source)
}

fn decode_block_header(header: &[u8]) -> Option<(u32, u32, u64, u64)> {
    Some((
        u32_at(header, 0, LE)?,
        u32_at(header, 4, LE)?,
        u64_at(header, 8, LE)?,
        u64_at(header, 16, LE)?,
    ))
}

/// The uncompressed length a Snappy block states in its varint preamble.
///
/// `None` if the varint is unterminated within the bytes given or is longer
/// than the five bytes a `u32` length can occupy.
fn snappy_block_len(preamble: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    for (index, &byte) in preamble.iter().take(SNAPPY_PREAMBLE_MAX).enumerate() {
        value |= u64::from(byte & 0x7F) << (7 * index);
        if byte & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// A physical address space over an AVML capture.
///
/// Reads decode and **verify** the frame they land in before returning a byte of
/// it. Addresses AVML never captured are [`MemoryHole`]s, exactly as for any
/// other segment format.
#[derive(Debug)]
pub struct AvmlLayer {
    /// The validated, sorted frame extents. Its `file_offset` is the frame body
    /// on disk, which for a compressed frame is *not* addressable directly.
    index: SegmentedLayer,
    codecs: HashMap<u64, Codec>,
    /// The most recently decoded frame.
    ///
    /// Not an optimisation in the ordinary sense: without it, walking a
    /// structure eight bytes at a time would decompress and re-verify a 64 KiB
    /// frame for every field read.
    decoded: Mutex<Option<(u64, Arc<Vec<u8>>)>>,
}

impl AvmlLayer {
    /// The frame extents, sorted by physical address.
    pub fn segments(&self) -> &[Segment] {
        self.index.segments()
    }

    /// Bytes of physical memory the capture holds, summed across frames.
    /// Smaller than [`DataSource::size`] whenever AVML skipped a range.
    pub fn mapped_len(&self) -> u64 {
        self.index.mapped_len()
    }

    /// The acquisition file the frames live in.
    pub fn inner(&self) -> &Arc<dyn DataSource> {
        self.index.inner()
    }

    fn find(&self, address: u64) -> Option<Segment> {
        let segments = self.index.segments();
        let index = segments.partition_point(|s| s.memory_offset <= address);
        if index == 0 {
            return None;
        }
        let segment = segments[index - 1];
        if address - segment.memory_offset < segment.length {
            Some(segment)
        } else {
            None
        }
    }

    fn next_start(&self, address: u64) -> Option<u64> {
        let segments = self.index.segments();
        let index = segments.partition_point(|s| s.memory_offset <= address);
        segments.get(index).map(|s| s.memory_offset)
    }

    fn hole_at(&self, address: u64) -> MemoryHole {
        let span = self.index.size();
        let end = self.next_start(address).unwrap_or(span);
        MemoryHole::unmapped(address, end.saturating_sub(address))
    }

    /// Decode and verify the frame backing `segment`, returning its bytes.
    ///
    /// The checksum is checked on **every** decode, including cache misses after
    /// an eviction, so no path exists on which unverified bytes reach a caller.
    fn frame_bytes(&self, segment: Segment) -> io::Result<Arc<Vec<u8>>> {
        if let Some((_, bytes)) = self.cached().filter(|(at, _)| *at == segment.file_offset) {
            return Ok(bytes);
        }

        let codec = self
            .codecs
            .get(&segment.file_offset)
            .copied()
            .ok_or_else(|| {
                invalid(FormatError::malformed(
                    FORMAT,
                    format!(
                        "the frame at file offset {:#x} has no recorded encoding",
                        segment.file_offset
                    ),
                ))
            })?;

        let mut stored = vec![0u8; codec.stored_len as usize];
        read_exact_or_fail(
            &**self.index.inner(),
            segment.file_offset,
            &mut stored,
            "AVML frame body",
        )?;

        let decoded = if codec.compressed {
            snap::raw::Decoder::new()
                .decompress_vec(&stored)
                .map_err(|e| {
                    invalid(FormatError::malformed(
                        FORMAT,
                        format!(
                            "the compressed frame at file offset {:#x} could not be decoded: {e}",
                            segment.file_offset
                        ),
                    ))
                })?
        } else {
            stored
        };

        let computed = crc32c_masked(&decoded);
        if computed != codec.masked_crc {
            // Upstream would have served these bytes. They failed the integrity
            // check the format itself carries, so they are not evidence.
            return Err(invalid(FormatError::malformed(
                FORMAT,
                format!(
                    "the frame at file offset {:#x} failed its CRC-32C: the stream declares \
                     {:#010x}, the {} decoded byte(s) compute {computed:#010x}",
                    segment.file_offset,
                    codec.masked_crc,
                    decoded.len()
                ),
            )));
        }
        if decoded.len() as u64 != segment.length {
            return Err(invalid(FormatError::malformed(
                FORMAT,
                format!(
                    "the frame at file offset {:#x} decoded to {} bytes, not the {} its preamble \
                     declared",
                    segment.file_offset,
                    decoded.len(),
                    segment.length
                ),
            )));
        }

        let bytes = Arc::new(decoded);
        self.store(segment.file_offset, bytes.clone());
        Ok(bytes)
    }

    fn cached(&self) -> Option<(u64, Arc<Vec<u8>>)> {
        // A poisoned lock means a panic elsewhere, not corrupt data; the cache
        // is still usable and refusing every read would be worse.
        let guard = match self.decoded.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.clone()
    }

    fn store(&self, at: u64, bytes: Arc<Vec<u8>>) {
        let mut guard = match self.decoded.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some((at, bytes));
    }
}

fn invalid(err: FormatError) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

impl DataSource for AvmlLayer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        let span = self.index.size();
        if buf.is_empty() || offset >= span {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(span - offset);
        let end = offset + want;

        let mut pos = offset;
        let mut written = 0usize;
        while pos < end {
            let Some(segment) = self.find(pos) else {
                return Err(self.hole_at(pos).into_io());
            };
            let within = pos - segment.memory_offset;
            let take = (segment.length - within).min(end - pos) as usize;
            // `frame_bytes` guarantees the decoded length equals the segment
            // length, so this slice is in range.
            let bytes = self.frame_bytes(segment)?;
            let from = within as usize;
            buf[written..written + take].copy_from_slice(&bytes[from..from + take]);
            written += take;
            pos += take as u64;
        }
        Ok(written)
    }

    fn size(&self) -> u64 {
        self.index.size()
    }

    fn get_underlying_path(&self) -> Option<PathBuf> {
        self.index.get_underlying_path()
    }

    fn open_sibling(&self, suffix: &str) -> Option<Arc<dyn DataSource>> {
        self.index.open_sibling(suffix)
    }

    fn physical_map(&self, offset: u64, len: u64) -> PhysicalMap {
        let span = self.index.size();
        let mut accumulated = PhysicalMap::empty(ExtentPrecision::Exact);
        if len == 0 || offset >= span {
            return accumulated;
        }
        let end = offset.saturating_add(len).min(span);
        let mut pos = offset;
        while pos < end {
            match self.find(pos) {
                Some(segment) => {
                    let within = pos - segment.memory_offset;
                    let take = (segment.length - within).min(end - pos);
                    match self.codecs.get(&segment.file_offset) {
                        // A stored frame really is byte-for-byte on disk.
                        Some(codec) if !codec.compressed => {
                            let sub = self
                                .index
                                .inner()
                                .physical_map(segment.file_offset + within, take);
                            // `absorb` rather than `extend`: an inner map's auxiliary source
                            // indices are meaningful only against its own table.
                            accumulated.absorb(sub);
                        }
                        // A compressed frame is located to the frame, not to the
                        // byte, which is exactly what `Compressed` means.
                        _ => {
                            let sub = self.index.inner().physical_map(segment.file_offset, 1);
                            // An inner extent backed by an auxiliary source
                            // cannot be named through this projection, which
                            // carries no source table of its own. Report it as
                            // unlocated rather than as an offset into the image,
                            // where that offset would mean something else.
                            let located = sub
                                .extents
                                .first()
                                .filter(|e| !e.is_auxiliary())
                                .and_then(|e| e.device_offset);
                            accumulated.extents.push(match located {
                                Some(offset) => PhysicalExtent::device(offset, take),
                                None => PhysicalExtent::hole(take),
                            });
                            accumulated.precision =
                                accumulated.precision.worst(ExtentPrecision::Compressed);
                        }
                    }
                    pos += take;
                }
                None => {
                    let gap_end = self.next_start(pos).unwrap_or(span).min(end);
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

impl MemoryLayer for AvmlLayer {
    fn min_address(&self) -> u64 {
        self.index.min_address()
    }

    fn max_address(&self) -> u64 {
        self.index.max_address()
    }

    /// Project onto the acquisition file.
    ///
    /// A **stored** frame yields ordinary [`Encoding::Identity`] runs, clipped
    /// to the request. A **compressed** frame yields one
    /// [`Encoding::Encoded`] run describing the *whole* frame, because that is
    /// what the encoding contract means: `mapped_length` bytes at
    /// `mapped_offset` decode, as a single unit, to `length` bytes. Clipping
    /// such a run to a sub-range would describe a blob that decodes to fewer
    /// bytes than it does, which is how a caller ends up slicing at the wrong
    /// place. A run may therefore begin below `offset` or end above
    /// `offset + length`; use [`MemoryLayer::is_valid`] rather than
    /// [`crate::layer::covered_len`] to ask whether the request was fully
    /// backed.
    fn mapping(&self, offset: u64, length: u64) -> Result<Vec<MappedRange>, LayerError> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let max_address = self.index.max_address();
        if offset > max_address {
            return Err(LayerError::OutOfRange {
                address: offset,
                max_address,
            });
        }
        let end = offset.saturating_add(length).min(self.index.size());

        let mut runs = Vec::new();
        let mut pos = offset;
        while pos < end {
            let Some(segment) = self.find(pos) else {
                return Err(LayerError::Hole(self.hole_at(pos)));
            };
            match self.codecs.get(&segment.file_offset) {
                Some(codec) if !codec.compressed => {
                    let within = pos - segment.memory_offset;
                    let take = (segment.length - within).min(end - pos);
                    runs.push(MappedRange::identity(
                        pos,
                        take,
                        segment.file_offset + within,
                    ));
                    pos += take;
                }
                Some(codec) => {
                    runs.push(MappedRange {
                        offset: segment.memory_offset,
                        length: segment.length,
                        mapped_offset: segment.file_offset,
                        mapped_length: codec.stored_len,
                        encoding: Encoding::Encoded,
                        source: BackingSource::Primary,
                        via: None,
                    });
                    pos = segment.memory_offset + segment.length;
                }
                None => {
                    // A segment with no codec cannot happen: both come from the
                    // same frame table. Reporting a hole would be a lie about
                    // the evidence, so this surfaces as the internal fault it is.
                    return Err(LayerError::Io(invalid(FormatError::malformed(
                        FORMAT,
                        format!(
                            "the frame at file offset {:#x} has no recorded encoding",
                            segment.file_offset
                        ),
                    ))));
                }
            }
        }
        Ok(runs)
    }

    /// Whether every byte of the range is backed.
    ///
    /// Answered from the frame index rather than from `mapping`'s coverage,
    /// because an `Encoded` run deliberately describes more than was asked for.
    fn is_valid(&self, offset: u64, length: u64) -> bool {
        self.index.is_valid(offset, length)
    }

    fn layer_meta(&self) -> &LayerMeta {
        self.index.layer_meta()
    }

    fn as_data_source(&self) -> &dyn DataSource {
        self
    }
}

// ── Masked CRC-32C ──────────────────────────────────────────────────────────

/// The Castagnoli polynomial, reflected — CRC-32C, as Snappy's framing format
/// requires. This is **not** the CRC-32 of zlib/PNG (`0xEDB88320` reflected);
/// using that one would reject every real AVML capture.
const CRC32C_POLYNOMIAL: u32 = 0x82F6_3B78;

const fn crc32c_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0usize;
    while index < 256 {
        let mut value = index as u32;
        let mut bit = 0;
        while bit < 8 {
            value = if value & 1 != 0 {
                (value >> 1) ^ CRC32C_POLYNOMIAL
            } else {
                value >> 1
            };
            bit += 1;
        }
        table[index] = value;
        index += 1;
    }
    table
}

static CRC32C_TABLE: [u32; 256] = crc32c_table();

/// CRC-32C of `data`.
fn crc32c(data: &[u8]) -> u32 {
    let mut crc = u32::MAX;
    for &byte in data {
        let index = ((crc ^ u32::from(byte)) & 0xFF) as usize;
        crc = (crc >> 8) ^ CRC32C_TABLE[index];
    }
    !crc
}

/// The masked form Snappy stores, which rotates the sum away from the data it
/// covers so a checksum embedded in its own stream cannot be self-consistent.
fn crc32c_masked(data: &[u8]) -> u32 {
    let sum = crc32c(data);
    (sum.wrapping_shr(15) | sum.wrapping_shl(17)).wrapping_add(0xA282_EAD8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{backed_len, covered_len, HoleReason};
    use seance_core::data_source::{ByteSliceDataSource, DeviceImageSource};
    use std::io::Write;

    fn source(bytes: Vec<u8>) -> Arc<dyn DataSource> {
        Arc::new(ByteSliceDataSource::new(bytes))
    }

    /// Snappy-frame `payload` with the same encoder a real AVML capture used.
    ///
    /// Using `snap`'s own encoder rather than hand-built frames is the point: if
    /// this module's masked CRC-32C, its varint reader or its frame walk were
    /// wrong, an independently produced stream would not read back.
    fn frames(payload: &[u8]) -> Vec<u8> {
        let mut encoder = snap::write::FrameEncoder::new(Vec::new());
        encoder.write_all(payload).expect("in-memory write");
        match encoder.into_inner() {
            Ok(bytes) => bytes,
            Err(e) => panic!("frame encoding failed: {}", e.error()),
        }
    }

    /// One AVML block: header, frame stream, trailer.
    fn block(start: u64, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&MAGIC.to_le_bytes());
        out.extend_from_slice(&VERSION.to_le_bytes());
        out.extend_from_slice(&start.to_le_bytes());
        // `end` is INCLUSIVE, so the last byte's address, not one past it.
        // This helper wrote `start + len` until 2026-08-04, which is why every
        // test here passed against a reader that had the same convention
        // backwards: the fixtures were built wrong and read back wrong, and the
        // two errors cancelled. Only a capture this crate did not write exposed
        // it.
        out.extend_from_slice(&(start + payload.len() as u64 - 1).to_le_bytes());
        out.extend_from_slice(&0u64.to_le_bytes());
        out.extend_from_slice(&frames(payload));
        out.extend_from_slice(&0u64.to_le_bytes());
        out
    }

    /// Highly compressible bytes, which the encoder stores as `0x00` frames.
    fn compressible(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| seed.wrapping_add((i / 64) as u8))
            .collect()
    }

    /// High-entropy bytes, which the encoder gives up on and stores as `0x01`
    /// frames — the other half of the frame-type matrix.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x2545_F491_4F6C_DD1Du64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                (state >> 24) as u8
            })
            .collect()
    }

    /// Offset of the first data frame's header within a block.
    fn first_data_frame_at() -> u64 {
        // Header, then the 10-byte stream identifier frame.
        BLOCK_HEADER_LEN + FRAME_HEADER_LEN + STREAM_IDENTIFIER_BODY.len() as u64
    }

    // ── The checksum ────────────────────────────────────────────────────────

    #[test]
    fn the_checksum_matches_the_published_crc32c_check_value() {
        // The known-answer vector for CRC-32C. Getting the polynomial wrong
        // here would reject every AVML capture ever made, so it is pinned
        // rather than assumed.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(b""), 0);
        // And the mask is Snappy's, not an identity.
        assert_eq!(crc32c_masked(b""), 0xA282_EAD8);
        assert_ne!(crc32c_masked(b"123456789"), crc32c(b"123456789"));
    }

    #[test]
    fn the_checksum_agrees_with_the_encoder_that_wrote_the_stream() {
        // The real cross-check: `snap` wrote these frames and put its own
        // masked CRC-32C in them, and the whole image reads back only if this
        // module computes the identical value.
        let payload = compressible(0x4000, 0x30);
        let layer = open(source(block(0, &payload))).expect("a stream snap itself produced");
        let mut out = vec![0u8; payload.len()];
        assert_eq!(layer.read_at(0, &mut out).unwrap(), payload.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn the_snappy_length_preamble_is_decoded_as_a_varint() {
        assert_eq!(snappy_block_len(&[0x00]), Some(0));
        assert_eq!(snappy_block_len(&[0x7F]), Some(127));
        assert_eq!(snappy_block_len(&[0x80, 0x01]), Some(128));
        assert_eq!(snappy_block_len(&[0x80, 0x80, 0x04]), Some(65_536));
        // Unterminated, and longer than a u32 length can be.
        assert_eq!(snappy_block_len(&[0x80, 0x80]), None);
        assert_eq!(snappy_block_len(&[0x80; 5]), None);
        assert_eq!(snappy_block_len(&[]), None);
    }

    // ── Valid images ────────────────────────────────────────────────────────

    #[test]
    fn a_valid_compressed_capture_reads_back_byte_for_byte() {
        let payload = compressible(0x8000, 0x11);
        let parsed = AvmlImage::parse(&*source(block(0x1000, &payload))).expect("a valid capture");

        assert_eq!(parsed.acquired_bytes(), payload.len() as u64);
        assert_eq!(parsed.compressed_frame_count(), parsed.frame_count());
        assert_eq!(parsed.layer_meta().declared_size(), Some(0x1000 + 0x8000));

        let layer = open(source(block(0x1000, &payload))).unwrap();
        assert_eq!(layer.min_address(), 0x1000);
        assert_eq!(layer.max_address(), 0x1000 + 0x8000 - 1);
        assert_eq!(layer.mapped_len(), 0x8000);

        let mut out = vec![0u8; payload.len()];
        assert_eq!(layer.read_at(0x1000, &mut out).unwrap(), payload.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn an_uncompressed_frame_is_read_and_verified_like_any_other() {
        let payload = incompressible(0x2000);
        let parsed = AvmlImage::parse(&*source(block(0, &payload))).expect("a valid capture");
        assert_eq!(
            parsed.compressed_frame_count(),
            0,
            "high-entropy data is stored, not compressed"
        );

        let layer = open(source(block(0, &payload))).unwrap();
        let mut out = vec![0u8; payload.len()];
        assert_eq!(layer.read_at(0, &mut out).unwrap(), payload.len());
        assert_eq!(out, payload);
    }

    #[test]
    fn a_capture_spanning_more_than_one_frame_stitches_them_correctly() {
        // Over 64 KiB, so the encoder emits several frames and a read across a
        // frame boundary has to decode two of them.
        let payload = compressible(0x2_8000, 0x77);
        let layer = open(source(block(0, &payload))).unwrap();
        assert!(layer.segments().len() >= 3, "several frames");

        let mut out = vec![0u8; 0x100];
        // Straddle the first frame boundary at 64 KiB.
        layer.read_at(0xFF80, &mut out).unwrap();
        assert_eq!(out, payload[0xFF80..0xFF80 + 0x100]);

        // And the whole capture in one read.
        let mut whole = vec![0u8; payload.len()];
        assert_eq!(layer.read_at(0, &mut whole).unwrap(), payload.len());
        assert_eq!(whole, payload);
    }

    #[test]
    fn several_blocks_become_one_address_space_with_the_gap_as_a_hole() {
        let first = compressible(0x1000, 0x40);
        let second = compressible(0x1000, 0x90);
        let mut file = block(0x0000, &first);
        file.extend_from_slice(&block(0x3000, &second));

        let parsed = AvmlImage::parse(&*source(file.clone())).expect("two blocks");
        assert_eq!(parsed.layer_meta().to_json()["notes"]["blocks"], 2);

        let layer = open(source(file)).unwrap();
        assert_eq!(layer.size(), 0x4000, "the span of the address space");
        assert_eq!(layer.mapped_len(), 0x2000, "what was acquired");

        let mut page = vec![0u8; 0x1000];
        layer.read_at(0x3000, &mut page).unwrap();
        assert_eq!(page, second);

        // The range AVML skipped is a hole, not 0x2000 fabricated zeros.
        let mut buf = vec![0xEEu8; 0x40];
        let err = layer
            .read_at(0x1000, &mut buf)
            .expect_err("unacquired range");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!((hole.address, hole.length), (0x1000, 0x2000));
        assert_eq!(hole.reason, HoleReason::Unmapped);
        assert!(buf.iter().all(|&b| b == 0xEE));
        assert!(!layer.is_valid(0x1000, 1));
        assert!(layer.is_valid(0x3000, 0x1000));
    }

    #[test]
    fn a_compressed_frame_maps_as_an_encoded_run_over_the_whole_frame() {
        let payload = compressible(0x1000, 0x21);
        let layer = open(source(block(0, &payload))).unwrap();

        let runs = layer.mapping(0x400, 0x100).expect("mapped");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].encoding, Encoding::Encoded);
        assert_eq!(
            runs[0].offset, 0,
            "the whole frame, not the requested slice"
        );
        assert_eq!(runs[0].length, 0x1000);
        assert_eq!(
            runs[0].mapped_offset,
            first_data_frame_at() + FRAME_HEADER_LEN + FRAME_CRC_LEN
        );
        assert!(
            runs[0].mapped_length < runs[0].length,
            "compression is visible in the mapping"
        );
        // Coverage over-reports for an encoded run, which is why is_valid does
        // not use it.
        assert!(covered_len(&runs) > 0x100);
        assert!(layer.is_valid(0x400, 0x100));
    }

    /// The `is_valid` override must agree with the trait's definition of it.
    ///
    /// This layer answers `is_valid` from its frame index rather than from
    /// `mapping`, which is an optimisation — no run list is built — and the
    /// trait defines the answer as `backed_len` over `mapping`. Two independent
    /// paths to one answer can drift, and a drift here is invisible: the index
    /// would say a page is present while a read through `mapping` refuses it,
    /// or the reverse, and only one of them reaches the examiner.
    ///
    /// Probes deliberately straddle frame boundaries and the top of the image,
    /// because those are where a whole-frame projection and a byte-exact index
    /// are most likely to disagree.
    #[test]
    fn the_is_valid_override_agrees_with_backed_len_over_mapping() {
        // Two compressed frames, then a gap, then a stored one.
        let mut file = block(0x0000, &compressible(0x1000, 1));
        file.extend_from_slice(&block(0x1000, &compressible(0x1000, 2)));
        file.extend_from_slice(&block(0x3000, &incompressible(0x1000)));
        let layer = open(source(file)).unwrap();

        let definition = |offset: u64, len: u64| match layer.mapping(offset, len) {
            Ok(runs) => backed_len(&runs, offset, len) == len,
            Err(_) => false,
        };

        for &(offset, len) in &[
            (0u64, 1u64),
            (0, 0x1000),
            (0x400, 0x100),   // inside one frame
            (0x0FF0, 0x20),   // across two present frames
            (0x1FF0, 0x20),   // from a present frame into the gap
            (0x2000, 0x10),   // wholly inside the gap
            (0x2FF0, 0x20),   // from the gap into a present frame
            (0x3000, 0x1000), // the stored frame, exactly
            (0x3FF0, 0x20),   // off the top of the image
            (0x9000, 0x10),   // well above the top
        ] {
            assert_eq!(
                layer.is_valid(offset, len),
                definition(offset, len),
                "is_valid disagreed with backed_len over mapping at \
                 offset {offset:#x} len {len:#x}"
            );
        }
    }

    #[test]
    fn a_stored_frame_maps_as_an_identity_run_clipped_to_the_request() {
        let payload = incompressible(0x1000);
        let layer = open(source(block(0, &payload))).unwrap();

        let runs = layer.mapping(0x400, 0x100).expect("mapped");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].encoding, Encoding::Identity);
        assert_eq!(runs[0].offset, 0x400);
        assert_eq!(runs[0].length, 0x100);
        assert_eq!(runs[0].mapped_length, 0x100);
        assert_eq!(covered_len(&runs), 0x100);
    }

    #[test]
    fn mapping_refuses_to_elide_a_gap_and_rejects_addresses_above_the_top() {
        let mut file = block(0x0000, &compressible(0x1000, 1));
        file.extend_from_slice(&block(0x3000, &compressible(0x1000, 2)));
        let layer = open(source(file)).unwrap();

        let err = layer.mapping(0x800, 0x3000).expect_err("crosses the hole");
        let hole = err.hole().expect("a typed hole");
        assert_eq!((hole.address, hole.length), (0x1000, 0x2000));

        let err = layer.mapping(0x4000, 1).expect_err("no such address");
        assert!(err.hole().is_none(), "past the end is not a hole");
        assert!(matches!(err, LayerError::OutOfRange { .. }));
        assert!(layer.mapping(0x1000, 0).unwrap().is_empty());
    }

    #[test]
    fn physical_map_reports_a_compressed_frame_at_compression_unit_precision() {
        let payload = compressible(0x1000, 0x33);
        let device: Arc<dyn DataSource> = Arc::new(DeviceImageSource::new(Arc::new(
            ByteSliceDataSource::new(block(0, &payload)),
        )));
        let parsed = AvmlImage::parse(&*device).unwrap();
        let layer = parsed.into_layer(device).unwrap();

        let map = layer.physical_map(0x100, 0x80);
        assert_eq!(map.precision, ExtentPrecision::Compressed);
        assert_eq!(map.extents.len(), 1);
        assert_eq!(map.extents[0].length, 0x80);
        assert_eq!(
            map.extents[0].device_offset,
            Some(first_data_frame_at() + FRAME_HEADER_LEN + FRAME_CRC_LEN),
            "located to the frame that holds the address"
        );
    }

    #[test]
    fn physical_map_reports_a_stored_frame_exactly_and_a_hole_as_unlocated() {
        let mut file = block(0x0000, &incompressible(0x1000));
        file.extend_from_slice(&block(0x3000, &incompressible(0x1000)));
        let device: Arc<dyn DataSource> = Arc::new(DeviceImageSource::new(Arc::new(
            ByteSliceDataSource::new(file),
        )));
        let parsed = AvmlImage::parse(&*device).unwrap();
        let layer = parsed.into_layer(device).unwrap();

        let exact = layer.physical_map(0x200, 0x100);
        assert_eq!(exact.precision, ExtentPrecision::Exact);
        assert_eq!(exact.extents.len(), 1);
        assert_eq!(exact.extents[0].length, 0x100);

        let across = layer.physical_map(0x0F00, 0x2200);
        assert_eq!(across.precision, ExtentPrecision::Synthetic);
        let unlocated: u64 = across
            .extents
            .iter()
            .filter(|e| e.device_offset.is_none())
            .map(|e| e.length)
            .sum();
        assert_eq!(unlocated, 0x2000, "the whole gap is reported as unlocated");
    }

    // ── The checksum is enforced ────────────────────────────────────────────

    #[test]
    fn a_frame_whose_checksum_does_not_match_its_bytes_is_refused() {
        // Upstream reads this checksum and discards it, so a corrupted frame is
        // served as evidence. Here it must be an error at read time.
        let payload = compressible(0x1000, 0x55);
        let mut file = block(0, &payload);
        let crc_at = (first_data_frame_at() + FRAME_HEADER_LEN) as usize;
        file[crc_at] ^= 0xFF;

        let layer = open(source(file)).expect("the frame table is still readable");
        let mut out = vec![0u8; 0x100];
        let err = layer
            .read_at(0, &mut out)
            .expect_err("bytes that fail their own integrity check are not evidence");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("CRC-32C"));
        // And it is not a hole: "corrupt" and "never captured" are different
        // claims and must not collapse into one.
        assert!(MemoryHole::from_io(&err).is_none());
    }

    #[test]
    fn a_corrupted_compressed_body_never_yields_bytes() {
        let payload = compressible(0x1000, 0x66);
        let mut file = block(0, &payload);
        let body_at = (first_data_frame_at() + FRAME_HEADER_LEN + FRAME_CRC_LEN) as usize;
        // Damage the middle of the compressed body, past its length preamble.
        file[body_at + 8] ^= 0xA5;

        let layer = open(source(file)).expect("the frame table is still readable");
        let mut out = vec![0u8; 0x100];
        let err = layer.read_at(0, &mut out).expect_err("corrupt frame");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(out.iter().all(|&b| b == 0), "no bytes were handed back");
    }

    #[test]
    fn every_read_of_a_frame_is_verified_not_just_the_first() {
        // Two frames alternating evicts the single-entry cache, so the second
        // read of the first frame decodes and re-verifies rather than trusting
        // a previous result.
        let payload = compressible(0x2_0000, 0x12);
        let layer = open(source(block(0, &payload))).unwrap();
        let mut out = vec![0u8; 0x40];
        for address in [0u64, 0x1_8000, 0, 0x1_8000, 0] {
            layer.read_at(address, &mut out).unwrap();
            assert_eq!(out, payload[address as usize..address as usize + 0x40]);
        }
    }

    // ── Truncated captures ──────────────────────────────────────────────────

    /// File offset of the body of frame `index`, from a parse of the whole file.
    fn frame_body_at(file: &[u8], index: usize) -> u64 {
        let parsed = AvmlImage::parse(&*source(file.to_vec())).expect("the whole file parses");
        assert!(
            parsed.frame_count() > index,
            "the fixture needs more frames"
        );
        parsed.segments()[index].file_offset
    }

    #[test]
    fn a_capture_cut_off_mid_frame_is_reported_incomplete_rather_than_short() {
        let payload = compressible(0x2_0000, 0x88);
        let full = block(0, &payload);
        // Four bytes into the second frame's body: its header and checksum are
        // present, the data it declares is not.
        let mut cut = full.clone();
        cut.truncate(frame_body_at(&full, 1) as usize + 4);

        let parsed = AvmlImage::parse(&*source(cut.clone())).expect("the first frame is intact");
        assert_eq!(parsed.frame_count(), 1);
        let incomplete = parsed.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert_eq!(incomplete[0].reason, IncompleteReason::ShortRead);
        assert!(incomplete[0].detail.contains("not recovered"));
        assert!(parsed.acquired_bytes() < payload.len() as u64);

        // What survived still reads correctly; the rest is simply not in the
        // address space rather than fabricated zeros inside it.
        let layer = open(source(cut)).unwrap();
        let mut out = vec![0u8; 0x1000];
        layer.read_at(0, &mut out).unwrap();
        assert_eq!(out, payload[..0x1000]);
        assert_eq!(layer.size(), layer.mapped_len(), "no interior gap");
    }

    #[test]
    fn a_capture_cut_off_mid_frame_header_is_reported_incomplete() {
        let payload = compressible(0x1_8000, 0x99);
        let full = block(0, &payload);
        // Two bytes into the second frame's four-byte header.
        let header_at = frame_body_at(&full, 1) - FRAME_HEADER_LEN - FRAME_CRC_LEN;
        let mut cut = full.clone();
        cut.truncate(header_at as usize + 2);

        let parsed = AvmlImage::parse(&*source(cut)).expect("the first frame is intact");
        assert_eq!(parsed.frame_count(), 1);
        let incomplete = parsed.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert!(incomplete[0].detail.contains("stops at"));
    }

    #[test]
    fn trailing_bytes_shorter_than_a_block_header_are_reported() {
        let mut file = block(0, &compressible(0x1000, 0x11));
        file.extend_from_slice(&[0u8; 9]);
        let parsed = AvmlImage::parse(&*source(file)).expect("the block is intact");
        let incomplete = parsed.layer_meta().incomplete();
        assert_eq!(incomplete.len(), 1);
        assert!(incomplete[0].detail.contains("9 byte(s)"));
    }

    #[test]
    fn a_source_too_short_for_a_block_header_is_declined() {
        let err = AvmlImage::parse(&*source(vec![0u8; 20])).expect_err("nothing to parse");
        assert!(err.is_not_this_format());
        let err = AvmlImage::parse(&*source(Vec::new())).expect_err("empty");
        assert!(err.is_not_this_format());
    }

    #[test]
    fn a_block_header_with_no_frames_after_it_is_refused() {
        let mut file = MAGIC.to_le_bytes().to_vec();
        file.extend_from_slice(&VERSION.to_le_bytes());
        file.extend_from_slice(&0u64.to_le_bytes());
        file.extend_from_slice(&0x1000u64.to_le_bytes());
        file.extend_from_slice(&0u64.to_le_bytes());
        let err = AvmlImage::parse(&*source(file)).expect_err("no memory was recovered");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    // ── Malformed headers and frames ────────────────────────────────────────

    #[test]
    fn a_foreign_magic_is_declined_rather_than_reported_as_damage() {
        let mut file = block(0, &compressible(0x400, 1));
        file[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        let err = AvmlImage::parse(&*source(file)).expect_err("not an AVML image");
        assert!(err.is_not_this_format());
    }

    #[test]
    fn an_unsupported_version_fails_closed_with_the_version_named() {
        let mut file = block(0, &compressible(0x400, 1));
        file[4..8].copy_from_slice(&1u32.to_le_bytes());
        let err = AvmlImage::parse(&*source(file)).expect_err("version 1 is a different layout");
        assert!(matches!(err, FormatError::Unsupported { .. }));
        assert!(err.to_string().contains('1'));
    }

    #[test]
    fn an_inverted_block_range_does_not_panic_and_is_refused() {
        let mut file = block(0, &compressible(0x400, 1));
        file[8..16].copy_from_slice(&0x9000u64.to_le_bytes());
        file[16..24].copy_from_slice(&0x1000u64.to_le_bytes());
        let err = AvmlImage::parse(&*source(file)).expect_err("end below start");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("inverted"));
    }

    #[test]
    fn an_empty_block_range_is_refused() {
        let mut file = block(0, &compressible(0x400, 1));
        file[16..24].copy_from_slice(&0u64.to_le_bytes());
        let err = AvmlImage::parse(&*source(file)).expect_err("a block covering nothing");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_block_whose_frames_decode_past_its_declared_range_is_refused() {
        // The header claims a 0x100-byte range but the stream holds 0x1000
        // bytes of memory, so the extra would land outside the block's own
        // physical range and overlap whatever comes next.
        let mut file = block(0, &compressible(0x1000, 1));
        file[16..24].copy_from_slice(&0x100u64.to_le_bytes());
        let err = AvmlImage::parse(&*source(file)).expect_err("frames exceed the block");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("decode to more than"));
    }

    #[test]
    fn a_reserved_unskippable_frame_type_is_refused_rather_than_stepped_over() {
        // Skipping one would drop or misplace memory with nothing to say so.
        let mut file = block(0, &compressible(0x1000, 1));
        file[first_data_frame_at() as usize] = 0x40;
        let err = AvmlImage::parse(&*source(file)).expect_err("unskippable frame");
        assert!(matches!(err, FormatError::Malformed { .. }));
        assert!(err.to_string().contains("unskippable"));
    }

    #[test]
    fn a_malformed_stream_identifier_is_refused() {
        let mut file = block(0, &compressible(0x400, 1));
        file[(BLOCK_HEADER_LEN + FRAME_HEADER_LEN) as usize] = b'X';
        let err = AvmlImage::parse(&*source(file)).expect_err("not sNaPpY");
        assert!(matches!(err, FormatError::Malformed { .. }));

        let mut file = block(0, &compressible(0x400, 1));
        file[(BLOCK_HEADER_LEN + 1) as usize] = 0x09; // declared length 9, not 6
        let err = AvmlImage::parse(&*source(file)).expect_err("wrong identifier length");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_data_frame_too_short_to_hold_a_checksum_is_refused() {
        let mut file = block(0, &compressible(0x400, 1));
        let at = first_data_frame_at() as usize;
        file[at + 1] = 0x02;
        file[at + 2] = 0x00;
        file[at + 3] = 0x00;
        let err = AvmlImage::parse(&*source(file)).expect_err("no room for a checksum");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_frame_declaring_more_than_the_framing_format_allows_is_refused() {
        // A stored frame claiming 0x20_0000 decoded bytes: above the 64 KiB the
        // format permits, and the bound that keeps a decode allocation finite.
        let mut file = block(0, &incompressible(0x400));
        let at = first_data_frame_at() as usize;
        file[at] = FRAME_UNCOMPRESSED;
        file[at + 1] = 0x04;
        file[at + 2] = 0x00;
        file[at + 3] = 0x20;
        // Give the file enough bytes that the frame is not simply truncated.
        file.resize(0x21_0000, 0);
        let err = AvmlImage::parse(&*source(file)).expect_err("above the frame cap");
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn a_second_block_with_a_broken_header_is_damage_not_a_declined_probe() {
        let mut file = block(0x0000, &compressible(0x1000, 1));
        let mut second = block(0x3000, &compressible(0x1000, 2));
        second[0..4].copy_from_slice(&0u32.to_le_bytes());
        file.extend_from_slice(&second);

        let err = AvmlImage::parse(&*source(file)).expect_err("the chain is broken");
        assert!(!err.is_not_this_format());
        assert!(matches!(err, FormatError::Malformed { .. }));
    }

    #[test]
    fn blocks_that_claim_the_same_physical_address_are_refused_by_the_layer() {
        let mut file = block(0x0000, &compressible(0x2000, 1));
        file.extend_from_slice(&block(0x1000, &compressible(0x2000, 2)));
        let err = open(source(file)).expect_err("two frames cannot hold one address");
        assert!(matches!(err, FormatError::Layer { .. }));
    }

    #[test]
    fn reads_above_the_top_of_the_space_are_eof_and_not_holes() {
        let layer = open(source(block(0, &compressible(0x1000, 1)))).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(layer.read_at(0x1000, &mut buf).unwrap(), 0);
        assert_eq!(layer.read_at(u64::MAX, &mut buf).unwrap(), 0);
        assert_eq!(layer.read_at(0, &mut []).unwrap(), 0);
    }

    #[test]
    fn a_read_is_clipped_at_the_top_of_the_space() {
        let payload = compressible(0x1000, 0x44);
        let layer = open(source(block(0, &payload))).unwrap();
        let mut buf = vec![0u8; 0x800];
        assert_eq!(layer.read_at(0xF00, &mut buf).unwrap(), 0x100);
        assert_eq!(buf[..0x100], payload[0xF00..]);
    }

    #[test]
    fn the_layer_is_usable_as_a_trait_object() {
        let layer: Arc<dyn MemoryLayer> =
            Arc::new(open(source(block(0x2000, &compressible(0x1000, 1)))).unwrap());
        assert_eq!(layer.min_address(), 0x2000);
        assert_eq!(layer.max_address(), 0x2FFF);
        assert_eq!(layer.layer_meta().format(), Some(MemoryImageFormat::Avml));
        let mut buf = [0u8; 8];
        assert_eq!(layer.as_data_source().read_at(0x2000, &mut buf).unwrap(), 8);
    }
}
