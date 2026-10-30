//! Parse LVM2 text metadata and map a logical volume onto its physical volume.
//!
//! LVM2 stores a human-readable text description of the volume group in the PV
//! label area. That text is enough to recover which physical extents back each
//! logical volume, so a `/dev/vg/lv` seized as a raw PV image (or as a
//! reconstructed RAID device) can be read as the filesystem it holds. This parser
//! handles the linear/single-stripe case — one PV per segment — which covers the
//! overwhelming majority of real deployments. A genuinely striped segment
//! (`stripe_count > 1`) is **recognised and refused**, not silently mapped to its
//! first stripe, so the reader never returns the wrong bytes for a striped LV.
//!
//! The text format is the one `vgcfgbackup` emits: block structure in `{ }`,
//! `key = value` lines, and arrays in `[ ]` that may be wrapped across several
//! lines (which [`collapse_arrays`] rejoins before parsing).

use std::collections::BTreeMap;

/// A physical volume within the group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvmPv {
    pub name: String,
    /// First usable extent's offset from the start of the PV device, in sectors.
    pub pe_start_sectors: u64,
}

/// One segment of a logical volume: a contiguous run of LV extents mapped to a
/// contiguous run of PV extents.
///
/// `stripe_pv`/`stripe_start_extent` are the segment's **first** stripe. A
/// linear or single-stripe segment (`stripe_count == 1`) is mapped by those two;
/// a genuinely striped segment (`stripe_count > 1`) round-robins extents across
/// several PVs and is NOT mapped by [`LvmVg::map_lv_offset`] — it is refused
/// rather than silently mismapped to the first stripe (which would return the
/// wrong bytes for every extent not on that PV).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvmSegment {
    pub start_extent: u64,
    pub extent_count: u64,
    pub stripe_pv: String,
    pub stripe_start_extent: u64,
    /// Number of stripes this segment spreads across (1 = linear).
    pub stripe_count: u64,
}

/// A logical volume: an ordered list of segments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvmLv {
    pub name: String,
    pub segments: Vec<LvmSegment>,
}

/// A parsed volume group.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LvmVg {
    pub name: String,
    /// Extent size in sectors.
    pub extent_size_sectors: u64,
    pub pvs: Vec<LvmPv>,
    pub lvs: Vec<LvmLv>,
}

impl LvmVg {
    /// Extent size in bytes. Cannot overflow: [`parse_metadata`] refuses a group
    /// whose declared extent size does not survive the conversion to bytes.
    pub fn extent_bytes(&self) -> u64 {
        self.extent_size_sectors * 512
    }

    /// Map a byte offset within logical volume `lv_name` to `(pv_name, pv_byte)`
    /// — the byte offset within that PV's device image. Returns `None` if the LV
    /// is unknown or the offset is past its end.
    pub fn map_lv_offset(&self, lv_name: &str, offset: u64) -> Option<(String, u64)> {
        let lv = self.lvs.iter().find(|l| l.name == lv_name)?;
        let ebytes = self.extent_bytes();
        if ebytes == 0 {
            // Corrupt/hostile metadata with extent_size = 0; refuse rather than
            // divide by zero. (Also rejected at parse; this is belt-and-braces.)
            return None;
        }
        let lv_extent = offset / ebytes;
        let intra = offset % ebytes;
        for seg in &lv.segments {
            let seg_end = seg.start_extent + seg.extent_count;
            if lv_extent >= seg.start_extent && lv_extent < seg_end {
                // A multi-stripe segment interleaves extents across PVs; mapping
                // it as if it were linear would return the wrong bytes. Refuse.
                if seg.stripe_count > 1 {
                    return None;
                }
                let pv = self.pvs.iter().find(|p| p.name == seg.stripe_pv)?;
                let pv_extent = seg.stripe_start_extent + (lv_extent - seg.start_extent);
                let pv_byte = pv.pe_start_sectors * 512 + pv_extent * ebytes + intra;
                return Some((pv.name.clone(), pv_byte));
            }
        }
        None
    }
}

/// Parse LVM2 text metadata into a [`LvmVg`]. Returns `None` if no volume group
/// with an extent size can be found.
pub fn parse_metadata(text: &str) -> Option<LvmVg> {
    // Block stack of names, so context is "what are we inside?".
    let mut stack: Vec<String> = Vec::new();
    let mut vg_name: Option<String> = None;
    let mut extent_size: Option<u64> = None;
    let mut pvs: BTreeMap<String, LvmPv> = BTreeMap::new();
    let mut lvs: BTreeMap<String, LvmLv> = BTreeMap::new();
    // Scratch for the segment currently being read.
    let mut seg: SegScratch = SegScratch::default();

    // Real `vgcfgbackup` output wraps arrays across several lines:
    //     stripes = [
    //         "pv0", 0
    //     ]
    // Collapse newlines *inside* `[ ]` to spaces first, so the whole array
    // reaches the line parser on one line. Then normalise braces onto their own
    // lines (the compact `pv0 { pe_start = 0 }` form and the one-key-per-line
    // form both then parse). Order matters: arrays use `[]`, blocks use `{}`.
    let collapsed = collapse_arrays(text);
    let normalized = collapsed.replace('{', " {\n").replace('}', "\n}\n");
    for raw in normalized.lines() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(name) = line.strip_suffix('{') {
            let name = name.trim().trim_end_matches('=').trim().to_string();
            // A segment block closes the previous segment's scratch.
            stack.push(name);
            continue;
        }
        if line == "}" {
            // Closing a segmentN block: commit the scratch to its LV.
            if let Some(top) = stack.last() {
                if is_segment_block(top) {
                    if let Some(committed) = seg.take() {
                        // The LV name is two levels up: lv_name { segmentN { } }.
                        if let Some(lv_name) = stack.iter().rev().nth(1).cloned() {
                            lvs.entry(lv_name.clone())
                                .or_insert_with(|| LvmLv {
                                    name: lv_name,
                                    segments: Vec::new(),
                                })
                                .segments
                                .push(committed);
                        }
                    }
                }
            }
            stack.pop();
            // The VG is the outermost named block.
            if stack.is_empty() {
                // done
            }
            continue;
        }

        // key = value lines.
        let (key, value) = match line.split_once('=') {
            Some((k, v)) => (k.trim(), v.trim()),
            None => continue,
        };
        let context = stack.last().map(|s| s.as_str()).unwrap_or("");

        // The first named block is the VG.
        if vg_name.is_none() && stack.len() == 1 {
            vg_name = stack.first().cloned();
        }

        match key {
            "extent_size" if stack.len() == 1 => {
                extent_size = value
                    .trim_end_matches(&[' ', '#'][..])
                    .split_whitespace()
                    .next()
                    .and_then(|n| n.parse().ok());
            }
            "pe_start" => {
                if in_pv_block(&stack) {
                    let pv = context.to_string();
                    let v: u64 = value
                        .split_whitespace()
                        .next()
                        .and_then(|n| n.parse().ok())
                        .unwrap_or(0);
                    pvs.entry(pv.clone())
                        .or_insert_with(|| LvmPv {
                            name: pv,
                            pe_start_sectors: 0,
                        })
                        .pe_start_sectors = v;
                }
            }
            "start_extent" if is_segment_block(context) => {
                seg.start_extent = value.split_whitespace().next().and_then(|n| n.parse().ok());
            }
            "extent_count" if is_segment_block(context) => {
                seg.extent_count = value.split_whitespace().next().and_then(|n| n.parse().ok());
            }
            "stripe_count" if is_segment_block(context) => {
                seg.stripe_count = value.split_whitespace().next().and_then(|n| n.parse().ok());
            }
            "stripes" if is_segment_block(context) => {
                // `stripes = [ "pv0", 12, "pv1", 0 ]` — one (pv, start_extent)
                // pair per stripe. Record the first pair (used for a linear map)
                // AND the number of pairs, so a genuinely striped segment is
                // recognised rather than mapped as if it were only its first PV.
                let inner = value.trim_start_matches('[').trim_end_matches(']');
                let fields: Vec<&str> = inner.split(',').map(|s| s.trim()).collect();
                seg.stripe_pairs = Some(fields.len() / 2);
                if let Some(pv) = fields.first() {
                    seg.stripe_pv = Some(pv.trim_matches('"').to_string());
                }
                if let Some(ext) = fields.get(1) {
                    seg.stripe_start_extent = ext.parse().ok();
                }
            }
            _ => {}
        }
    }

    // A zero extent size is not a usable volume group — every extent-to-byte
    // calculation would divide by it. Treat metadata that declares one as not a
    // VG rather than returning a group that panics on first use. A size that
    // cannot be expressed in bytes is refused for the same reason: the metadata
    // is untrusted text, and `extent_bytes()` must not wrap to a plausible value.
    let extent_size_sectors = extent_size?;
    if extent_size_sectors == 0 || extent_size_sectors > u64::MAX / 512 {
        return None;
    }
    Some(LvmVg {
        name: vg_name?,
        extent_size_sectors,
        pvs: pvs.into_values().collect(),
        lvs: lvs.into_values().collect(),
    })
}

/// Scratch for a segment being parsed.
#[derive(Default)]
struct SegScratch {
    start_extent: Option<u64>,
    extent_count: Option<u64>,
    stripe_pv: Option<String>,
    stripe_start_extent: Option<u64>,
    /// Declared `stripe_count`, if the segment stated one.
    stripe_count: Option<u64>,
    /// Number of `(pv, offset)` pairs actually seen in `stripes`.
    stripe_pairs: Option<usize>,
}

impl SegScratch {
    /// Take the scratch as a segment if complete, resetting it either way.
    fn take(&mut self) -> Option<LvmSegment> {
        // The stripe count is the declared value when present, else the number
        // of stripe pairs seen, else 1 — so a striped segment is recognised even
        // if `stripe_count` was absent, from the pair count alone.
        let stripe_count = self
            .stripe_count
            .or_else(|| self.stripe_pairs.map(|n| n as u64))
            .unwrap_or(1)
            .max(1);
        let out = match (
            self.start_extent,
            self.extent_count,
            self.stripe_pv.take(),
            self.stripe_start_extent,
        ) {
            (Some(s), Some(c), Some(pv), Some(se)) => Some(LvmSegment {
                start_extent: s,
                extent_count: c,
                stripe_pv: pv,
                stripe_start_extent: se,
                stripe_count,
            }),
            _ => None,
        };
        *self = SegScratch::default();
        out
    }
}

/// Collapse newlines that fall inside `[ ... ]` into spaces, so a line-wrapped
/// array (as `vgcfgbackup` emits) reaches the line parser whole.
fn collapse_arrays(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut depth = 0i32;
    for ch in text.chars() {
        match ch {
            '[' => {
                depth += 1;
                out.push(ch);
            }
            ']' => {
                depth = (depth - 1).max(0);
                out.push(ch);
            }
            '\n' | '\r' if depth > 0 => out.push(' '),
            _ => out.push(ch),
        }
    }
    out
}

fn strip_comment(line: &str) -> &str {
    match line.find('#') {
        Some(i) => &line[..i],
        None => line,
    }
}

fn is_segment_block(name: &str) -> bool {
    name.starts_with("segment") && name.len() > 7 && name[7..].chars().all(|c| c.is_ascii_digit())
}

fn in_pv_block(stack: &[String]) -> bool {
    stack.len() >= 2 && stack[stack.len() - 2] == "physical_volumes"
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
vg0 {
    id = "abc"
    seqno = 3
    extent_size = 8192		# 4 Megabytes
    physical_volumes {
        pv0 {
            id = "pv-id"
            device = "/dev/sda1"
            pe_start = 2048
            pe_count = 25599
        }
    }
    logical_volumes {
        root {
            id = "lv-id"
            segment_count = 1
            segment1 {
                start_extent = 0
                extent_count = 100
                type = "striped"
                stripe_count = 1
                stripes = [ "pv0", 5 ]
            }
        }
    }
}
"#;

    #[test]
    fn parses_vg_pv_and_lv() {
        let vg = parse_metadata(SAMPLE).unwrap();
        assert_eq!(vg.name, "vg0");
        assert_eq!(vg.extent_size_sectors, 8192);
        assert_eq!(vg.extent_bytes(), 8192 * 512);
        assert_eq!(vg.pvs.len(), 1);
        assert_eq!(vg.pvs[0].name, "pv0");
        assert_eq!(vg.pvs[0].pe_start_sectors, 2048);
        assert_eq!(vg.lvs.len(), 1);
        let lv = &vg.lvs[0];
        assert_eq!(lv.name, "root");
        assert_eq!(lv.segments.len(), 1);
        assert_eq!(lv.segments[0].start_extent, 0);
        assert_eq!(lv.segments[0].extent_count, 100);
        assert_eq!(lv.segments[0].stripe_pv, "pv0");
        assert_eq!(lv.segments[0].stripe_start_extent, 5);
    }

    #[test]
    fn maps_lv_offset_to_pv_byte() {
        let vg = parse_metadata(SAMPLE).unwrap();
        let ebytes = vg.extent_bytes();
        // Offset 0 in the LV → pe_start + stripe_start_extent (5) * extent_bytes.
        let (pv, byte) = vg.map_lv_offset("root", 0).unwrap();
        assert_eq!(pv, "pv0");
        assert_eq!(byte, 2048 * 512 + 5 * ebytes);
        // An offset one extent + 100 bytes in → pv extent 6, intra 100.
        let (_, byte) = vg.map_lv_offset("root", ebytes + 100).unwrap();
        assert_eq!(byte, 2048 * 512 + 6 * ebytes + 100);
    }

    #[test]
    fn offset_past_lv_end_is_none() {
        let vg = parse_metadata(SAMPLE).unwrap();
        let past = vg.extent_bytes() * 100; // LV has 100 extents (0..99)
        assert!(vg.map_lv_offset("root", past).is_none());
    }

    #[test]
    fn unknown_lv_is_none() {
        let vg = parse_metadata(SAMPLE).unwrap();
        assert!(vg.map_lv_offset("nonexistent", 0).is_none());
    }

    #[test]
    fn multi_segment_lv_maps_each_segment() {
        let meta = r#"
vg1 {
    extent_size = 2048
    physical_volumes {
        pv0 { pe_start = 384 }
    }
    logical_volumes {
        data {
            segment1 {
                start_extent = 0
                extent_count = 10
                stripes = [ "pv0", 0 ]
            }
            segment2 {
                start_extent = 10
                extent_count = 10
                stripes = [ "pv0", 50 ]
            }
        }
    }
}
"#;
        let vg = parse_metadata(meta).unwrap();
        let lv = &vg.lvs[0];
        assert_eq!(lv.segments.len(), 2);
        let ebytes = vg.extent_bytes();
        // First segment: lv extent 0 → pv extent 0.
        let (_, b0) = vg.map_lv_offset("data", 0).unwrap();
        assert_eq!(b0, 384 * 512);
        // Second segment: lv extent 10 → pv extent 50.
        let (_, b1) = vg.map_lv_offset("data", 10 * ebytes).unwrap();
        assert_eq!(b1, 384 * 512 + 50 * ebytes);
    }

    #[test]
    fn garbage_returns_none() {
        assert!(parse_metadata("not lvm metadata at all").is_none());
    }

    /// Metadata declaring extent_size = 0 must be rejected, not returned as a VG
    /// that divides by zero on the first offset mapping.
    #[test]
    fn zero_extent_size_is_refused() {
        let meta = r#"
vg {
    extent_size = 0
    physical_volumes { pv0 { pe_start = 0 } }
    logical_volumes {
        lv0 { segment1 { start_extent = 0 extent_count = 1 stripes = [ "pv0", 0 ] } }
    }
}
"#;
        assert!(
            parse_metadata(meta).is_none(),
            "extent_size 0 is not a usable VG"
        );
    }

    /// An extent size whose byte value cannot be expressed in 64 bits is refused
    /// at parse, so `extent_bytes()` can never wrap to a small, plausible number
    /// that every later offset calculation would then trust.
    #[test]
    fn an_extent_size_that_overflows_in_bytes_is_refused() {
        let meta = r#"
vg {
    extent_size = 18446744073709551615
    physical_volumes { pv0 { pe_start = 0 } }
    logical_volumes {
        lv0 { segment1 { start_extent = 0 extent_count = 1 stripes = [ "pv0", 0 ] } }
    }
}
"#;
        assert!(
            parse_metadata(meta).is_none(),
            "an extent size that overflows in bytes is not a usable VG"
        );
    }

    /// Real `vgcfgbackup` output: a preamble before the VG, quoted-string arrays
    /// for `status`/`flags`, and — the trap — a `stripes` array **wrapped across
    /// lines**. The single-line synthetic fixtures never exercised this, and the
    /// old parser saw only `stripes = [` and mapped nothing.
    #[test]
    fn parses_real_vgcfgbackup_shaped_metadata_with_wrapped_arrays() {
        let meta = r#"
# Generated by LVM2 version 2.03.11
contents = "Text Format Volume Group"
version = 1

vg0 {
	id = "aaaa-bbbb"
	seqno = 4
	format = "lvm2"
	status = ["RESIZEABLE", "READ", "WRITE"]
	flags = []
	extent_size = 8192
	max_lv = 0

	physical_volumes {
		pv0 {
			id = "pv-aaaa"
			device = "/dev/loop0"
			status = ["ALLOCATABLE"]
			flags = []
			dev_size = 204800
			pe_start = 2048
			pe_count = 24
		}
	}

	logical_volumes {
		root {
			id = "lv-aaaa"
			status = ["READ", "WRITE", "VISIBLE"]
			flags = []
			creation_host = "box"
			segment_count = 1

			segment1 {
				start_extent = 0
				extent_count = 24
				type = "striped"
				stripe_count = 1

				stripes = [
					"pv0", 3
				]
			}
		}
	}
}
"#;
        let vg = parse_metadata(meta).expect("real-shaped metadata parses");
        assert_eq!(vg.name, "vg0");
        assert_eq!(vg.pvs.len(), 1);
        assert_eq!(vg.pvs[0].pe_start_sectors, 2048);
        let seg = &vg.lvs[0].segments[0];
        assert_eq!(seg.stripe_pv, "pv0");
        assert_eq!(
            seg.stripe_start_extent, 3,
            "wrapped stripes array must parse"
        );
        assert_eq!(seg.stripe_count, 1);
        // And the mapping works: LV extent 0 -> pv0 extent 3.
        let (_, byte) = vg.map_lv_offset("root", 0).unwrap();
        assert_eq!(byte, 2048 * 512 + 3 * vg.extent_bytes());
    }

    /// A genuinely striped LV (`stripe_count = 2`, two `(pv, offset)` pairs). The
    /// old parser read only the first pair and would have mapped every extent to
    /// pv0 — wrong for the half that live on pv1. It must be recognised as
    /// multi-stripe and refused, not silently mismapped.
    #[test]
    fn multi_stripe_segment_is_recognised_and_refused_not_mismapped() {
        let meta = r#"
vg0 {
    extent_size = 8192
    physical_volumes {
        pv0 { pe_start = 2048 pe_count = 100 }
        pv1 { pe_start = 2048 pe_count = 100 }
    }
    logical_volumes {
        data {
            segment1 {
                start_extent = 0
                extent_count = 100
                type = "striped"
                stripe_count = 2
                stripes = [
                    "pv0", 0,
                    "pv1", 0
                ]
            }
        }
    }
}
"#;
        let vg = parse_metadata(meta).unwrap();
        let seg = &vg.lvs[0].segments[0];
        assert_eq!(seg.stripe_count, 2, "two stripe pairs => stripe_count 2");
        // Mapping refuses rather than returning the wrong (pv0-only) bytes.
        assert!(
            vg.map_lv_offset("data", 0).is_none(),
            "a multi-stripe segment must not be linearly mapped"
        );
    }

    /// Even with `stripe_count` absent, two stripe pairs mean multi-stripe.
    #[test]
    fn stripe_count_is_inferred_from_the_pair_count_when_absent() {
        let meta = r#"
vg {
    extent_size = 1
    physical_volumes {
        pv0 { pe_start = 0 }
        pv1 { pe_start = 0 }
    }
    logical_volumes {
        lv0 {
            segment1 {
                start_extent = 0
                extent_count = 10
                stripes = [ "pv0", 0, "pv1", 0 ]
            }
        }
    }
}
"#;
        let vg = parse_metadata(meta).unwrap();
        assert_eq!(vg.lvs[0].segments[0].stripe_count, 2);
    }
}
