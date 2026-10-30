//! Writing a memory layer out as a raw, address-aligned file — the equivalent of
//! Volatility's `layerwriter` — together with the **hole manifest** that says
//! which of the written bytes were never acquired.
//!
//! # Why the manifest is not optional
//!
//! A raw file has to put *something* at every offset, so the unacquired parts
//! of a sparse image (the MMIO windows a LiME capture skips, the pages a crash
//! dump never held, the address a hibernation file did not save) are written as
//! zero bytes. Those zeros are fabricated. Without a record of where they are,
//! the exported file is byte-identical to a capture in which the suspect's
//! machine really held zeros there, and every tool the examiner runs over it
//! afterwards — a hash, a carve, a string search, another framework's plugins —
//! treats them as evidence. [`MemoryHole`] exists in this crate to stop exactly
//! that inside Séance; this module is where the bytes leave Séance, so the
//! distinction leaves with them, as a list of `(start, length, reason)`.
//!
//! # Plan first, then write, and refuse a disagreement
//!
//! [`plan_export`] walks the layer's own geometry (its [`MemoryLayer::mapping`])
//! and states the holes before a byte is written. [`write_export`] then streams
//! the backed ranges through [`DataSource::read_at`] and the holes as zeros. A
//! read that fails inside a range the plan called backed is **not** filled: the
//! write stops with [`ExportError::Unplanned`], because the manifest already
//! handed out would then be wrong about that range, and a file whose manifest
//! understates its holes is worse than no file.
//!
//! # Bounded
//!
//! The writer holds one [`EXPORT_CHUNK`] buffer; the planner asks the layer
//! about one [`PLAN_WINDOW`] at a time and keeps at most [`MAX_MANIFEST_HOLES`]
//! holes (adjacent holes with the same reason are merged). A geometry with
//! more holes than that is refused rather than truncated: a manifest that
//! stops listing holes part-way through reads as a file that has none after
//! that point.
//!
//! [`DataSource::read_at`]: seance_core::data_source::DataSource::read_at

use std::io::{self, Write};

use serde_json::{json, Value};

use crate::layer::{HoleReason, LayerError, MemoryHole, MemoryLayer, MAX_SEGMENTS};

/// Bytes read from the layer (or written as fill) per step of the writer.
pub const EXPORT_CHUNK: usize = 1 << 20;

/// How much address space the planner asks the layer to project at once.
pub const PLAN_WINDOW: u64 = 256 << 20;

/// The most holes a manifest will list before the export is refused.
pub const MAX_MANIFEST_HOLES: usize = MAX_SEGMENTS;

/// The value every fill byte takes. Stated in the manifest so nobody has to
/// assume it.
pub const FILL_BYTE: u8 = 0;

/// One range of the exported file that holds fill, not acquired bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExportHole {
    /// First layer address of the hole. Equal to its offset in the file minus
    /// the plan's `start`.
    pub start: u64,
    /// Number of fill bytes.
    pub length: u64,
    /// Why nothing was there.
    pub reason: HoleReason,
}

impl ExportHole {
    fn end(&self) -> u64 {
        self.start.saturating_add(self.length)
    }
}

/// What an export of `[start, end)` will contain, established before writing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportPlan {
    /// First layer address written; file offset 0 holds it.
    pub start: u64,
    /// One past the last layer address written.
    pub end: u64,
    /// Every unacquired range inside `[start, end)`, ascending.
    pub holes: Vec<ExportHole>,
}

impl ExportPlan {
    /// Bytes the file will hold.
    pub fn total_bytes(&self) -> u64 {
        self.end - self.start
    }

    /// Bytes that are fill.
    pub fn hole_bytes(&self) -> u64 {
        self.holes.iter().map(|h| h.length).sum()
    }

    /// Bytes read from the acquisition.
    pub fn backed_bytes(&self) -> u64 {
        self.total_bytes() - self.hole_bytes()
    }

    /// The manifest an examiner keeps beside the file.
    ///
    /// `file_offset` is repeated on every hole so the file can be checked
    /// without doing the subtraction, and the `statement` is the sentence to
    /// read aloud: how much of the file is fill, and that fill is not evidence.
    pub fn manifest_json(&self) -> Value {
        let holes: Vec<Value> = self
            .holes
            .iter()
            .map(|h| {
                json!({
                    "start": h.start,
                    "file_offset": h.start - self.start,
                    "length": h.length,
                    "reason": h.reason.as_str(),
                })
            })
            .collect();
        json!({
            "kind": "seance.layer_export.manifest",
            "version": 1,
            "start": self.start,
            "end": self.end,
            "addressing": "file offset = layer address - start; one byte per address",
            "total_bytes": self.total_bytes(),
            "backed_bytes": self.backed_bytes(),
            "hole_bytes": self.hole_bytes(),
            "hole_count": self.holes.len(),
            "fill_byte": FILL_BYTE,
            "holes": holes,
            "statement": self.statement(),
        })
    }

    /// The manifest's plain-language summary.
    pub fn statement(&self) -> String {
        let head = format!(
            "This file holds {} bytes of layer address space {:#x}..{:#x}, one byte per \
             address.",
            self.total_bytes(),
            self.start,
            self.end
        );
        if self.holes.is_empty() {
            return format!(
                "{head} No range in it was unacquired: every byte was read from the acquisition."
            );
        }
        format!(
            "{head} {} bytes in {} range(s) were not acquired and are written as 0x{:02x} \
             fill; they are listed under holes and say nothing about what the machine held \
             there. {} bytes were read from the acquisition.",
            self.hole_bytes(),
            self.holes.len(),
            FILL_BYTE,
            self.backed_bytes()
        )
    }
}

/// Why an export could not be planned or written.
#[derive(Debug, thiserror::Error)]
pub enum ExportError {
    /// The requested range is empty or lies outside the layer.
    #[error("the requested range {start:#x}..{end:#x} is not inside the layer's address space")]
    Range { start: u64, end: u64 },
    /// The layer could not describe its own geometry.
    #[error("the layer could not state its geometry: {0}")]
    Geometry(LayerError),
    /// More holes than [`MAX_MANIFEST_HOLES`].
    #[error("the layer has more than {cap} holes; a manifest that stopped listing them would understate what the file lacks, so the export is refused")]
    TooManyHoles { cap: usize },
    /// A range the plan called backed could not be read.
    #[error("address {address:#x} was planned as acquired but could not be read ({detail}); the export stopped rather than fill a range its manifest calls acquired")]
    Unplanned { address: u64, detail: String },
    /// The sink refused bytes.
    #[error("writing the export failed: {0}")]
    Sink(io::Error),
}

/// State the holes of `[start, end)` in `layer` without writing anything.
///
/// `end = None` means the top of the layer. The range must lie inside the
/// layer's address space; a request that runs past it is refused rather than
/// clipped, so the size of the file is always the size that was asked for.
pub fn plan_export(
    layer: &dyn MemoryLayer,
    start: u64,
    end: Option<u64>,
) -> Result<ExportPlan, ExportError> {
    let top = layer.max_address().saturating_add(1);
    let end = end.unwrap_or(top);
    if start < layer.min_address() || end <= start || end > top {
        return Err(ExportError::Range { start, end });
    }

    let mut holes: Vec<ExportHole> = Vec::new();
    let mut pos = start;
    while pos < end {
        let window_end = end.min(pos.saturating_add(PLAN_WINDOW));
        match layer.mapping(pos, window_end - pos) {
            Ok(runs) => {
                gaps_in(&runs, pos, window_end, &mut holes)?;
                pos = window_end;
            }
            Err(LayerError::Hole(hole)) => {
                // Layers that refuse at their first hole (a segmented layer
                // does) are asked again for the part before it, which they can
                // answer, and the hole itself is taken from the refusal.
                let before = hole.address.min(window_end);
                if before > pos {
                    let runs = layer
                        .mapping(pos, before - pos)
                        .map_err(ExportError::Geometry)?;
                    gaps_in(&runs, pos, before, &mut holes)?;
                }
                if hole.address >= window_end {
                    pos = window_end;
                    continue;
                }
                let hole_start = hole.address.max(pos);
                let hole_end = hole.address.saturating_add(hole.length).min(end);
                if hole_end <= hole_start {
                    // A hole that does not advance would loop forever: a fault
                    // in the layer, reported rather than skipped.
                    return Err(ExportError::Geometry(LayerError::Hole(hole)));
                }
                push_hole(&mut holes, hole_start, hole_end - hole_start, hole.reason)?;
                pos = hole_end;
            }
            Err(err) => return Err(ExportError::Geometry(err)),
        }
    }
    Ok(ExportPlan { start, end, holes })
}

/// Record every part of `[from, to)` that `runs` do not back.
///
/// A layer may answer a window with short runs rather than a refusal (a
/// [`crate::physical::PhysicalLayer`] with a declared geometry does); what no
/// run covers was not acquired.
fn gaps_in(
    runs: &[crate::layer::MappedRange],
    from: u64,
    to: u64,
    holes: &mut Vec<ExportHole>,
) -> Result<(), ExportError> {
    let mut reached = from;
    for run in runs {
        if reached >= to {
            break;
        }
        if run.offset > reached {
            let gap_end = run.offset.min(to);
            push_hole(holes, reached, gap_end - reached, HoleReason::Unmapped)?;
            reached = gap_end;
        }
        reached = reached.max(run.end().min(to));
    }
    if reached < to {
        push_hole(holes, reached, to - reached, HoleReason::Unmapped)?;
    }
    Ok(())
}

/// Append a hole, merging it into the last one when they touch and share a
/// reason, and refusing past [`MAX_MANIFEST_HOLES`].
fn push_hole(
    holes: &mut Vec<ExportHole>,
    start: u64,
    length: u64,
    reason: HoleReason,
) -> Result<(), ExportError> {
    if length == 0 {
        return Ok(());
    }
    if let Some(last) = holes.last_mut() {
        if last.end() == start && last.reason == reason {
            last.length += length;
            return Ok(());
        }
    }
    if holes.len() >= MAX_MANIFEST_HOLES {
        return Err(ExportError::TooManyHoles {
            cap: MAX_MANIFEST_HOLES,
        });
    }
    holes.push(ExportHole {
        start,
        length,
        reason,
    });
    Ok(())
}

/// Stream the plan's range of `layer` to `out`, returning the bytes written.
///
/// Acquired ranges are read in [`EXPORT_CHUNK`] steps; holes are written as
/// [`FILL_BYTE`]. A read that fails, or ends early, inside a range the plan
/// called acquired stops the write with [`ExportError::Unplanned`]: the bytes
/// already written are a fragment, and the caller must say so.
pub fn write_export<W: Write>(
    layer: &dyn MemoryLayer,
    plan: &ExportPlan,
    out: &mut W,
) -> Result<u64, ExportError> {
    let mut buf = vec![0u8; EXPORT_CHUNK];
    let mut written = 0u64;
    let mut pos = plan.start;
    for hole in &plan.holes {
        written += copy_backed(layer, pos, hole.start, &mut buf, out)?;
        written += write_fill(hole.length, &mut buf, out)?;
        pos = hole.end();
    }
    written += copy_backed(layer, pos, plan.end, &mut buf, out)?;
    Ok(written)
}

fn copy_backed<W: Write>(
    layer: &dyn MemoryLayer,
    from: u64,
    to: u64,
    buf: &mut [u8],
    out: &mut W,
) -> Result<u64, ExportError> {
    let source = layer.as_data_source();
    let mut pos = from;
    while pos < to {
        let want = (to - pos).min(buf.len() as u64) as usize;
        let got = match source.read_at(pos, &mut buf[..want]) {
            Ok(0) => {
                return Err(ExportError::Unplanned {
                    address: pos,
                    detail: "the layer ended before the planned range did".to_string(),
                })
            }
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => {
                let detail = match MemoryHole::from_io(&err) {
                    Some(hole) => format!("{} bytes {}", hole.length, hole.reason),
                    None => err.to_string(),
                };
                return Err(ExportError::Unplanned {
                    address: pos,
                    detail,
                });
            }
        };
        out.write_all(&buf[..got]).map_err(ExportError::Sink)?;
        pos += got as u64;
    }
    Ok(to.saturating_sub(from))
}

fn write_fill<W: Write>(length: u64, buf: &mut [u8], out: &mut W) -> Result<u64, ExportError> {
    buf.fill(FILL_BYTE);
    let mut left = length;
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        out.write_all(&buf[..n]).map_err(ExportError::Sink)?;
        left -= n as u64;
    }
    Ok(length)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::physical::PhysicalLayer;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use std::sync::Arc;

    fn pattern(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i % 251) as u8 + 1).collect()
    }

    fn sparse() -> PhysicalLayer {
        // 0x5000 addressable; 0x1000..0x2000 and 0x3000..0x3800 never acquired.
        PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(pattern(0x5000))))
            .expect("non-empty")
            .with_backed(vec![(0, 0x1000), (0x2000, 0x1000), (0x3800, 0x1800)])
    }

    #[test]
    fn the_plan_names_every_unacquired_range_and_nothing_else() {
        let plan = plan_export(&sparse(), 0, None).expect("plans");
        assert_eq!(plan.start, 0);
        assert_eq!(plan.end, 0x5000);
        assert_eq!(
            plan.holes,
            vec![
                ExportHole {
                    start: 0x1000,
                    length: 0x1000,
                    reason: HoleReason::Unmapped
                },
                ExportHole {
                    start: 0x3000,
                    length: 0x800,
                    reason: HoleReason::Unmapped
                },
            ]
        );
        assert_eq!(plan.hole_bytes(), 0x1800);
        assert_eq!(plan.backed_bytes(), 0x3800);
    }

    #[test]
    fn a_flat_layer_plans_no_holes() {
        let flat = PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(pattern(0x3000))))
            .expect("non-empty");
        let plan = plan_export(&flat, 0, None).expect("plans");
        assert!(plan.holes.is_empty());
        assert_eq!(plan.backed_bytes(), 0x3000);
    }

    #[test]
    fn the_file_is_address_aligned_with_acquired_bytes_and_fill_where_the_plan_says() {
        let layer = sparse();
        let plan = plan_export(&layer, 0, None).expect("plans");
        let mut out = Vec::new();
        let written = write_export(&layer, &plan, &mut out).expect("writes");
        assert_eq!(written, 0x5000);
        assert_eq!(out.len(), 0x5000);
        let source = pattern(0x5000);
        assert_eq!(&out[..0x1000], &source[..0x1000]);
        assert!(out[0x1000..0x2000].iter().all(|b| *b == FILL_BYTE));
        assert_eq!(&out[0x2000..0x3000], &source[0x2000..0x3000]);
        assert!(out[0x3000..0x3800].iter().all(|b| *b == FILL_BYTE));
        assert_eq!(&out[0x3800..], &source[0x3800..]);
    }

    #[test]
    fn a_sub_range_is_planned_and_written_relative_to_its_start() {
        let layer = sparse();
        let plan = plan_export(&layer, 0x0800, Some(0x3400)).expect("plans");
        assert_eq!(plan.total_bytes(), 0x2c00);
        assert_eq!(
            plan.holes,
            vec![
                ExportHole {
                    start: 0x1000,
                    length: 0x1000,
                    reason: HoleReason::Unmapped
                },
                ExportHole {
                    start: 0x3000,
                    length: 0x400,
                    reason: HoleReason::Unmapped
                },
            ]
        );
        let mut out = Vec::new();
        write_export(&layer, &plan, &mut out).expect("writes");
        assert_eq!(out.len(), 0x2c00);
        assert_eq!(&out[..0x800], &pattern(0x5000)[0x800..0x1000]);
    }

    #[test]
    fn a_range_outside_the_layer_is_refused_not_clipped() {
        let layer = sparse();
        assert!(matches!(
            plan_export(&layer, 0x4000, Some(0x6000)),
            Err(ExportError::Range { .. })
        ));
        assert!(matches!(
            plan_export(&layer, 0x2000, Some(0x2000)),
            Err(ExportError::Range { .. })
        ));
    }

    /// A layer whose geometry says "all backed" but whose read fails at one
    /// address: the write must stop there, not fill it.
    #[derive(Debug)]
    struct LiesAboutGeometry(PhysicalLayer);
    impl DataSource for LiesAboutGeometry {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
            if offset <= 0x2000 && offset + buf.len() as u64 > 0x2000 && offset < 0x2000 {
                let n = (0x2000 - offset) as usize;
                return self.0.read_at(offset, &mut buf[..n]);
            }
            if offset == 0x2000 {
                return Err(MemoryHole::unmapped(0x2000, 0x1000).into_io());
            }
            self.0.read_at(offset, buf)
        }
        fn size(&self) -> u64 {
            self.0.size()
        }
    }
    impl MemoryLayer for LiesAboutGeometry {
        fn min_address(&self) -> u64 {
            0
        }
        fn max_address(&self) -> u64 {
            self.0.max_address()
        }
        fn mapping(
            &self,
            offset: u64,
            length: u64,
        ) -> Result<Vec<crate::layer::MappedRange>, LayerError> {
            self.0.mapping(offset, length)
        }
        fn layer_meta(&self) -> &crate::meta::LayerMeta {
            self.0.layer_meta()
        }
        fn as_data_source(&self) -> &dyn DataSource {
            self
        }
    }

    #[test]
    fn a_read_failure_inside_a_planned_backed_range_stops_the_write() {
        let layer = LiesAboutGeometry(
            PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(pattern(0x4000))))
                .expect("non-empty"),
        );
        let plan = plan_export(&layer, 0, None).expect("plans");
        assert!(plan.holes.is_empty());
        let mut out = Vec::new();
        match write_export(&layer, &plan, &mut out) {
            Err(ExportError::Unplanned { address, .. }) => assert_eq!(address, 0x2000),
            other => panic!("expected Unplanned at 0x2000, got {other:?}"),
        }
    }

    /// A segmented layer refuses a mapping at its first hole instead of
    /// returning short runs; the plan must step over each one.
    #[test]
    fn a_layer_that_refuses_at_holes_is_planned_hole_by_hole() {
        use crate::segmented::{Segment, SegmentedLayer};
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(pattern(0x3000)));
        let layer = SegmentedLayer::new(
            data,
            vec![
                Segment::new(0x0, 0x1000, 0x1000),
                Segment::new(0x1000, 0x3000, 0x2000),
            ],
            crate::meta::LayerMeta::new(crate::format::MemoryImageFormat::Lime),
        )
        .expect("valid segments");
        let plan = plan_export(&layer, layer.min_address(), None).expect("plans");
        assert_eq!(
            plan.holes,
            vec![ExportHole {
                start: 0x2000,
                length: 0x1000,
                reason: HoleReason::Unmapped
            }]
        );
        let mut out = Vec::new();
        write_export(&layer, &plan, &mut out).expect("writes");
        assert_eq!(out.len() as u64, plan.total_bytes());
    }

    /// The decode seam the API uses: a LiME file is decoded by the same reader
    /// the ingest runs, and its geometry reaches the plan.
    #[test]
    fn a_decoded_lime_capture_exports_with_its_gaps_as_holes() {
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
        for (start, fill) in [(0x0000u64, 0xA1u8), (0x2000, 0xB2), (0x4000, 0xC3)] {
            file.extend_from_slice(&lime_header(start, start + 0xFFF));
            file.extend_from_slice(&[fill; 0x1000]);
        }
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(file));
        let layer =
            crate::module::open_physical_layer(crate::format::MemoryImageFormat::Lime, &source)
                .expect("a well-formed LiME file decodes");
        let plan = plan_export(layer.as_ref(), 0, None).expect("plans");
        assert_eq!(plan.end, 0x5000);
        assert_eq!(
            plan.holes,
            vec![
                ExportHole {
                    start: 0x1000,
                    length: 0x1000,
                    reason: HoleReason::Unmapped
                },
                ExportHole {
                    start: 0x3000,
                    length: 0x1000,
                    reason: HoleReason::Unmapped
                },
            ]
        );
        let mut out = Vec::new();
        write_export(layer.as_ref(), &plan, &mut out).expect("writes");
        assert!(out[..0x1000].iter().all(|b| *b == 0xA1));
        assert!(out[0x1000..0x2000].iter().all(|b| *b == FILL_BYTE));
        assert!(out[0x2000..0x3000].iter().all(|b| *b == 0xB2));
        assert!(out[0x4000..0x5000].iter().all(|b| *b == 0xC3));
    }

    #[test]
    fn the_manifest_states_the_fill_the_holes_and_the_totals() {
        let plan = plan_export(&sparse(), 0, None).expect("plans");
        let m = plan.manifest_json();
        assert_eq!(m["start"], 0);
        assert_eq!(m["end"], 0x5000);
        assert_eq!(m["total_bytes"], 0x5000);
        assert_eq!(m["hole_bytes"], 0x1800);
        assert_eq!(m["backed_bytes"], 0x3800);
        assert_eq!(m["fill_byte"], 0);
        assert_eq!(m["hole_count"], 2);
        assert_eq!(m["holes"][1]["start"], 0x3000);
        assert_eq!(m["holes"][1]["file_offset"], 0x3000);
        assert_eq!(m["holes"][1]["length"], 0x800);
        assert_eq!(m["holes"][1]["reason"], "unmapped");
        assert!(m["statement"]
            .as_str()
            .expect("statement")
            .contains("were not acquired"));
    }
}
