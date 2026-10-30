//! Examiner-supplied patterns over an address space, and what one costs.
//!
//! # Why this is here and not in a plugin
//!
//! Three things search memory for what an examiner brought: the Windows tier's
//! per-process stage, the same tier's sweep of the kernel's own space, and
//! [`ImagePatternScan`] below — which searches an **image's own** address space
//! and is the only route available for a blob with no page tables at all: a
//! reconstructed hibernation file, a swap area, a capture whose operating
//! system could not be profiled.
//!
//! They share the planning, the ceilings and the coverage arithmetic. One
//! definition of those, here, beside the scanner they drive; a second would
//! drift, and two numbers for one fact from one tool is indefensible.
//!
//! # What a pattern set is
//!
//! A [`Scanner`] and the words that have to travel with its results. This
//! crate knows how to search an address space and deliberately does not know
//! what a YARA rule is: the registration site has both and supplies the engine.

use std::ops::Range;
use std::sync::Arc;

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::module::{ForensicsModule, InputCapability, ModuleError};
use serde_json::{json, Value};

use crate::format::MemoryImageFormat;
use crate::scan::{
    derive_sections, derive_sections_in, scan_planned, Hit, RefusedChunk, ScanConfig, ScanError,
    Scanner, ScannerDiagnostics, SectionPlan,
};
use crate::MemoryLayer;

/// Matches one space's scan will report before it stops.
///
/// A pattern whose string is four common bytes matches millions of times in a
/// process's memory. The ceiling keeps that from becoming the record, and
/// firing it is reported as a truncated scan rather than as a match count.
pub const MAX_HITS_PER_SPACE: usize = 100_000;

/// Matches a record carries as individual rows.
///
/// Past this the counts stay exact — in total and per pattern — and only the
/// per-match detail stops.
pub const MAX_RECORDED_MATCHES: usize = 10_000;

/// Mapped regions one space's plan will hold.
pub const MAX_SECTIONS_PER_SPACE: usize = 262_144;

/// Bytes of one address space one pass will read before it stops.
///
/// Eight gibibytes is far above any process on a real machine — the largest
/// mapped total in the Windows 11 corpus capture is under 700 MiB — and finite,
/// which is what a scan driven by a pattern an examiner wrote needs to be
/// inside an ingest. A whole image is bounded by
/// [`PatternCaps::max_bytes_per_space`] in its own right, which a caller
/// scanning one raises.
pub const MAX_BYTES_PER_SPACE: u64 = 8 * 1024 * 1024 * 1024;

/// The ceilings one pass observes, and the chunk geometry it reads with.
#[derive(Debug, Clone)]
pub struct PatternCaps {
    /// Chunking, overlap and the per-space hit ceiling.
    pub scan: ScanConfig,
    /// Bytes one space's pass will read before it stops.
    pub max_bytes_per_space: u64,
    /// Mapped regions one plan will hold.
    pub max_sections_per_space: usize,
    /// Matches a record carries as individual rows. The totals stay exact.
    pub max_recorded_matches: usize,
}

impl Default for PatternCaps {
    fn default() -> Self {
        Self {
            scan: ScanConfig {
                max_hits: MAX_HITS_PER_SPACE,
                ..ScanConfig::default()
            },
            max_bytes_per_space: MAX_BYTES_PER_SPACE,
            max_sections_per_space: MAX_SECTIONS_PER_SPACE,
            max_recorded_matches: MAX_RECORDED_MATCHES,
        }
    }
}

/// What a regular expression over an address space is, and is not.
///
/// Published on every result of a regex pattern set, for the same reason YARA's
/// chunk-scoped condition is: the semantics an examiner brings from `grep` are
/// not the semantics they get here, and two of the differences change what an
/// empty result means.
pub const REGEX_SCOPE: &str = concat!(
    "The pattern was matched against RAW BYTES, not text. It is byte-oriented and ",
    "Unicode-unaware, so `.` is one byte rather than one character and a pattern written in ",
    "ASCII does not match the same characters stored as UTF-16 -- which is how most strings ",
    "in a Windows process are stored: a search for `Password` will not find the same text ",
    "held as UTF-16, where every character is followed by a zero byte, unless the pattern ",
    "says so. A match is found within one CHUNK of the ",
    "address space at a time: a regular expression has no bounded match length, so a match ",
    "spanning a chunk boundary is not guaranteed to be found, and the result says so on ",
    "itself. A zero-length match is not reported at all.",
);

/// One thing an examiner asked to be looked for, and the engine that looks.
///
/// Held as a trait object rather than a rule set, so this crate knows how to
/// search an address space without knowing what a YARA rule is. The wiring that
/// has both — `seance_api`'s module registration — supplies the scanner, and a
/// regular expression arrives here the same way a rule set does.
#[derive(Clone, Debug)]
pub struct PatternSet {
    /// Stable kind, for the record: `yara`, `regex`.
    pub kind: &'static str,
    /// What the examiner named, in their words: a rule path, a pattern.
    pub source: String,
    /// Pattern names, indexed by [`Hit::pattern_id`].
    pub pattern_names: Vec<String>,
    /// The engine.
    pub scanner: Arc<dyn Scanner>,
    /// What the engine has to say that its hits cannot: a chunk it refused, a
    /// pattern that matched with no address. `None` for an engine that can do
    /// neither.
    pub diagnostics: Option<Arc<dyn ScannerDiagnostics>>,
    /// A caveat that must travel with every result of this set — for YARA, that
    /// a rule's condition was evaluated over one chunk of the address space
    /// rather than over an image.
    pub scope_note: Option<String>,
}

impl PatternSet {
    /// The pattern a hit's id refers to.
    ///
    /// An id with no name behind it is reported as the id rather than as the
    /// first pattern in the set: a match attributed to the wrong rule is worse
    /// than a match attributed to none.
    pub fn pattern_name(&self, id: u32) -> String {
        self.pattern_names
            .get(id as usize)
            .cloned()
            .unwrap_or_else(|| format!("pattern #{id}"))
    }

    pub fn to_json(&self) -> Value {
        json!({
            "kind": self.kind,
            "source": self.source,
            "patterns": self.pattern_names,
            "pattern_count": self.pattern_names.len(),
            "scanner": self.scanner.name(),
            "match_length_bounded": self.scanner.max_match_len().is_some(),
            "scope_note": self.scope_note,
        })
    }
}

/// What one pass over one address space did.
#[derive(Debug, Clone, Default)]
pub struct SpaceScan {
    /// Mapped regions the pass covered, after touching ones were merged.
    pub sections: usize,
    /// Distinct bytes examined.
    pub bytes_scanned: u64,
    /// Bytes inside the planned regions that were mapped and would not read.
    ///
    /// **This is the number that means evidence may have been missed.**
    pub unreadable_bytes: u64,
    /// Bytes the pass spanned and never asked to read: address space between
    /// the planned regions, and address space inside one with no page behind
    /// it.
    ///
    /// Kept apart from the figure above because nothing could have been found
    /// in either. Committed user memory is described by an allocation, so
    /// address space outside every allocation is not a gap in coverage — and a
    /// reserved region inside one held no page to search.
    pub unmapped_bytes: u64,
    /// Bytes above a ceiling that fired: planned and never asked for, whether
    /// mapped or not. Named by `capped`, and never part of `unreadable_bytes`
    /// (MEM-041).
    pub not_searched_bytes: u64,
    /// Regions the layer would not describe, so nothing in them was planned.
    pub ranges_unplannable: usize,
    /// Matches, in ascending address order.
    pub hits: Vec<Hit>,
    /// Whether the pass stopped at a ceiling.
    pub truncated: bool,
    /// Which ceiling, and the address from which nothing was examined.
    pub capped: Option<String>,
    /// Whether a match could span a chunk boundary undetected — always true for
    /// an engine whose match length is unbounded, which YARA's is.
    pub pattern_may_exceed_overlap: bool,
}

impl SpaceScan {
    /// Whether the pass examined every byte it planned to.
    ///
    /// Unmapped address space does not count against it: the question is
    /// whether anything that existed went unread.
    pub fn is_complete(&self) -> bool {
        !self.truncated
            && self.capped.is_none()
            && self.unreadable_bytes == 0
            && self.ranges_unplannable == 0
    }

    pub fn to_json(&self) -> Value {
        json!({
            "sections": self.sections,
            "bytes_scanned": self.bytes_scanned,
            "unreadable_bytes": self.unreadable_bytes,
            "unmapped_bytes": self.unmapped_bytes,
            "not_searched_bytes": self.not_searched_bytes,
            "not_searched_bytes_meaning":
                "Planned bytes above the ceiling named in `capped`, which were never asked for; \
                 some may be unmapped. Not counted in `unreadable_bytes` or `unmapped_bytes`.",
            "unmapped_bytes_meaning":
                "Address space this pass spanned and never read: between the regions it was \
                 planned over, or inside one with no page behind it. Nothing could have been \
                 found in either -- and where the regions are a process's allocations, \
                 committed user memory is described by one of them -- so this is not coverage \
                 the scan lost. `unreadable_bytes` is the figure that means evidence may have \
                 been missed.",
            "ranges_unplannable": self.ranges_unplannable,
            "matches": self.hits.len(),
            "truncated": self.truncated,
            "capped": self.capped,
            "pattern_may_exceed_overlap": self.pattern_may_exceed_overlap,
            "complete": self.is_complete(),
        })
    }
}

/// Keep sections until `budget` bytes are accounted for.
///
/// Returns what is kept and, when the budget ran out, the address from which
/// nothing was examined. A section is split rather than dropped whole: the
/// bytes below the ceiling were searched and saying otherwise would understate
/// the coverage as badly as claiming the rest.
pub fn trim_to_budget(sections: &[Range<u64>], budget: u64) -> (Vec<Range<u64>>, Option<u64>) {
    let mut kept = Vec::with_capacity(sections.len());
    let mut spent = 0u64;
    for section in sections {
        let remaining = budget.saturating_sub(spent);
        if remaining == 0 {
            return (kept, Some(section.start));
        }
        let len = section.end.saturating_sub(section.start);
        if len <= remaining {
            spent = spent.saturating_add(len);
            kept.push(section.clone());
            continue;
        }
        let cut = section.start.saturating_add(remaining);
        kept.push(section.start..cut);
        return (kept, Some(cut));
    }
    (kept, None)
}

/// Scan the mapped memory inside `ranges` of `layer` for one pattern set.
///
/// `ranges` are the regions that mean something — a process's allocations —
/// and the probe of each one is what keeps reserved address space from being
/// read. They may arrive in any order and may touch: touching regions are
/// merged, because the chunk overlap is suppressed at a section end and an
/// invented boundary would lose a match lying across it. Attribution is
/// therefore by address, never by which section produced a hit.
pub fn scan_space(
    layer: &dyn MemoryLayer,
    ranges: &[Range<u64>],
    set: &PatternSet,
    budget: u64,
    caps: &PatternCaps,
) -> SpaceScan {
    let mut sections: Vec<Range<u64>> = Vec::new();
    let mut unplannable = 0usize;
    let mut sections_capped = false;
    let mut probe_stopped: Option<u64> = None;

    for range in ranges {
        if sections.len() >= caps.max_sections_per_space {
            sections_capped = true;
            break;
        }
        match derive_sections_in(layer, range.clone(), &caps.scan) {
            Ok(plan) => {
                if let Some(at) = plan.truncated_at {
                    probe_stopped = Some(probe_stopped.map_or(at, |x: u64| x.min(at)));
                }
                sections.extend(plan.sections);
            }
            // One region the layer will not describe must not cost the others.
            // Counted, and the count travels with the result.
            Err(_) => unplannable += 1,
        }
    }

    scan_sections(
        layer,
        sections,
        unplannable,
        sections_capped,
        probe_stopped,
        set,
        budget,
        caps,
    )
}

/// Scan every mapped byte of `layer`, wherever it is.
///
/// The whole-layer form of [`scan_space`], for a space with no allocation list
/// to plan from: the kernel's own, which is upstream's `yarascan` rather than
/// its `vadyarascan`.
///
/// Not expressible as one range handed to [`scan_space`]. A 64-bit space's last
/// addressable byte is `u64::MAX`, and `Range<u64>` has no exclusive end above
/// it; `derive_sections` carries the top as a `u128` for exactly that reason,
/// and a caller that tried to build the range itself would either overflow or
/// refuse the whole scan.
pub fn scan_whole_layer(
    layer: &dyn MemoryLayer,
    set: &PatternSet,
    budget: u64,
    caps: &PatternCaps,
) -> Result<SpaceScan, ScanError> {
    let plan = derive_sections(layer, &caps.scan)?;
    Ok(scan_sections(
        layer,
        plan.sections,
        0,
        false,
        plan.truncated_at,
        set,
        budget,
        caps,
    ))
}

/// Scan a section list, whichever way it was derived.
#[allow(clippy::too_many_arguments)]
fn scan_sections(
    layer: &dyn MemoryLayer,
    sections: Vec<Range<u64>>,
    unplannable: usize,
    sections_capped: bool,
    probe_stopped: Option<u64>,
    set: &PatternSet,
    budget: u64,
    caps: &PatternCaps,
) -> SpaceScan {
    let merged = SectionPlan::over(sections);
    let (kept, budget_stop) = trim_to_budget(&merged.sections, budget);
    let plan = SectionPlan::over(kept);
    let sections_count = plan.sections.len();

    let outcome = match scan_planned(layer, set.scanner.as_ref(), &plan, &caps.scan) {
        Ok(outcome) => outcome,
        // A configuration or layer failure that makes the pass meaningless.
        // Reported as a pass that examined nothing, with the reason, rather
        // than as a pass that found nothing.
        Err(err) => {
            return SpaceScan {
                sections: sections_count,
                ranges_unplannable: unplannable,
                capped: Some(format!(
                    "this space was not searched: {err}. Nothing here is a statement about what \
                     is in it."
                )),
                truncated: true,
                ..SpaceScan::default()
            };
        }
    };

    let unreadable = outcome
        .unread_bytes
        .saturating_sub(outcome.unmapped_bytes)
        .saturating_sub(outcome.not_searched_bytes);
    let mut capped: Option<String> = None;
    if let Some(at) = budget_stop {
        capped = Some(format!(
            "the byte ceiling of {budget} fired at {at:#x}; the mapped memory above it was not \
             searched"
        ));
    }
    if sections_capped {
        capped = Some(format!(
            "{} region(s) of this space were planned and the ceiling of {} fired, so the \
             allocations after it were not searched",
            sections_count, caps.max_sections_per_space
        ));
    }
    if let Some(at) = probe_stopped {
        capped = Some(format!(
            "enumerating the mapped memory of this space stopped at {at:#x}, so what lies above \
             that was not searched"
        ));
    }
    if outcome.truncated {
        capped = Some(format!(
            "the match ceiling of {} fired, so this space was searched up to the last match \
             reported and no further",
            caps.scan.max_hits
        ));
    }

    SpaceScan {
        sections: sections_count,
        bytes_scanned: outcome.bytes_scanned,
        unreadable_bytes: unreadable,
        unmapped_bytes: outcome.unmapped_bytes,
        not_searched_bytes: outcome.not_searched_bytes,
        ranges_unplannable: unplannable,
        hits: outcome.hits,
        truncated: outcome.truncated || sections_capped || budget_stop.is_some(),
        capped,
        pattern_may_exceed_overlap: outcome.pattern_may_exceed_overlap,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::MemoryImageFormat;
    use crate::meta::LayerMeta;
    use crate::physical::PhysicalLayer;
    use crate::scan::SingleStringScanner;
    use crate::segmented::{Segment, SegmentedLayer};
    use seance_core::data_source::{ByteSliceDataSource, DataSource};

    const NEEDLE: &[u8] = b"FORENSIC-W11";

    /// Bytes with `NEEDLE` written at each offset given.
    fn image(len: usize, at: &[usize]) -> Vec<u8> {
        let mut bytes = vec![b'.'; len];
        for offset in at {
            bytes[*offset..offset + NEEDLE.len()].copy_from_slice(NEEDLE);
        }
        bytes
    }

    fn flat(bytes: Vec<u8>) -> PhysicalLayer {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        PhysicalLayer::raw(source).expect("a non-empty image is a physical layer")
    }

    /// A layer with a genuine hole: bytes at `0..0x100`, nothing at
    /// `0x100..0x200`, bytes again at `0x200..0x300`.
    fn holed(bytes: Vec<u8>) -> SegmentedLayer {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        SegmentedLayer::new(
            source,
            vec![Segment::new(0, 0, 0x100), Segment::new(0x100, 0x200, 0x100)],
            LayerMeta::new(MemoryImageFormat::Lime),
        )
        .expect("two disjoint segments")
    }

    /// A set of one fixed needle, with no engine diagnostics: the scanner
    /// cannot refuse a chunk and cannot match without an address.
    fn needle_set() -> PatternSet {
        PatternSet {
            kind: "regex",
            source: "FORENSIC-W11".to_string(),
            pattern_names: vec!["marker".to_string()],
            scanner: Arc::new(SingleStringScanner::new("needle", NEEDLE).expect("valid needle")),
            diagnostics: None,
            scope_note: None,
        }
    }

    /// One region, as a slice. Written this way rather than inline because
    /// `&[a..b]` reads to clippy as a range-filled array.
    fn one(range: Range<u64>) -> Vec<Range<u64>> {
        Vec::from([range])
    }

    // ── The whole-image scan ────────────────────────────────────────────

    /// An image record of the shape the container stage emits: the decoded
    /// space as the data source, the format on the metadata.
    fn image_record(bytes: Vec<u8>, format: MemoryImageFormat) -> Artifact {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(source),
            json!({
                "type": "MemoryImage",
                "subtype": "memory_image",
                "image_format": format.as_str(),
            }),
        )
    }

    fn scan_of(record: &Artifact, sets: Vec<PatternSet>) -> Vec<Artifact> {
        ImagePatternScan::new(sets)
            .expect("a non-empty set list")
            .process(record)
            .expect("a readable image")
    }

    /// **A pattern is found in the image's own space, at an address in it.**
    #[test]
    fn a_match_in_an_image_is_reported_at_its_address_in_that_image() {
        let record = image_record(image(0x400, &[0x120]), MemoryImageFormat::Lime);
        let out = scan_of(&record, vec![needle_set()]);

        assert_eq!(out.len(), 1, "one record per image");
        let md = &out[0].metadata;
        assert_eq!(md["record_type"], "MemoryImagePatternScan");
        assert_eq!(md["matches_total"], 1);
        assert_eq!(md["matches"][0]["address"], 0x120);
        assert_eq!(md["matches"][0]["address_hex"], "0x120");
        assert_eq!(md["matches"][0]["pattern"], "marker");
        assert_eq!(md["matches_by_pattern"]["marker"], 1);
        assert_eq!(md["content_complete"], json!(true));
        assert_eq!(out[0].parent_id, Some(record.id));
    }

    /// **What an offset in the record means is stated per format**, because for
    /// a hibernation file it is nothing like an offset in the file on the disk
    /// image an examiner would correlate against.
    #[test]
    fn the_record_says_what_an_address_in_it_is_for_this_format() {
        for (format, must_say) in [
            (
                MemoryImageFormat::WindowsHibernation,
                "not an offset in `hiberfil.sys`",
            ),
            (MemoryImageFormat::WindowsCrashDump64, "run table"),
            (MemoryImageFormat::Lime, "segment map"),
            (
                MemoryImageFormat::Raw,
                "only
if that declaration is true",
            ),
        ] {
            let record = image_record(image(0x400, &[0x120]), format);
            let out = scan_of(&record, vec![needle_set()]);
            let meaning = out[0].metadata["offset_meaning"]
                .as_str()
                .expect("every record says what its addresses are");
            let wanted = must_say.replace('\n', " ");
            assert!(meaning.contains(&wanted), "{}: {meaning}", format.as_str());
        }
    }

    /// **A scan that matched nothing says what that does and does not mean.**
    #[test]
    fn no_match_over_an_image_is_not_reported_as_nothing_to_find() {
        let record = image_record(vec![b'.'; 0x400], MemoryImageFormat::Lime);
        let out = scan_of(&record, vec![needle_set()]);
        let statement = out[0].metadata["statement"].as_str().expect("a statement");
        assert!(
            statement.contains("No match is not the same as nothing to find"),
            "{statement}"
        );
        assert_eq!(out[0].metadata["matches_total"], 0);
        assert_eq!(out[0].metadata["content_complete"], json!(true));
    }

    /// **A match here is not attributed to a process, and the record says so.**
    /// An image's own space has no allocations, and a row that implied one
    /// would be read as a finding about a process nobody examined.
    #[test]
    fn a_match_over_an_image_claims_no_process_and_no_allocation() {
        let record = image_record(image(0x400, &[0x120]), MemoryImageFormat::Lime);
        let out = scan_of(&record, vec![needle_set()]);
        let row = &out[0].metadata["matches"][0];
        assert!(row.get("pid").is_none());
        assert!(row.get("region").is_none());
        assert!(out[0].metadata["statement"]
            .as_str()
            .is_some_and(|s| s.contains("are NOT established here")));
    }

    /// **With nothing named there is no module.** A module that is registered,
    /// reports success and searches for nothing reads as "searched, nothing
    /// found"; absence of the module is visible in the module list.
    #[test]
    fn an_empty_pattern_list_builds_no_module_at_all() {
        assert!(ImagePatternScan::new(Vec::new()).is_none());
        let scan = ImagePatternScan::new(vec![needle_set()]).expect("one set is a module");
        assert_eq!(scan.sets().len(), 1);
        assert_eq!(scan.id(), "plugin.memory.pattern_scan");
    }

    /// An artifact that is not a memory image record is not claimed, and a
    /// decode failure is not scanned: there is no address space behind it, and
    /// a scan of nothing must not be reported as a scan that found nothing.
    #[test]
    fn only_a_decoded_image_record_is_scanned() {
        let scan = ImagePatternScan::new(vec![needle_set()]).expect("a module");

        let other = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "SomethingElse"}),
        );
        assert!(scan.process(&other).expect("not claimed").is_empty());

        let failed = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "MemoryImage", "decode_failed": true}),
        );
        assert!(scan.process(&failed).expect("not scanned").is_empty());
    }

    /// An image record with no decoded space is a pipeline defect, not an
    /// image that holds nothing: it is refused rather than reported as clean.
    #[test]
    fn an_image_record_with_no_address_space_is_refused() {
        let scan = ImagePatternScan::new(vec![needle_set()]).expect("a module");
        let record = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "MemoryImage", "image_format": "lime"}),
        );
        let err = scan.process(&record).expect_err("no space is a refusal");
        assert!(
            format!("{err}").contains("no decoded address space"),
            "{err}"
        );
    }

    /// **A note an examiner reads must be readable.** It is written as wrapped
    /// source, and a wrapped string literal whose continuations are lost
    /// renders as prose with runs of spaces in it — which is how this one first
    /// shipped. No control characters either: these travel in JSON and reach a
    /// screen.
    #[test]
    fn the_regex_scope_note_renders_as_prose() {
        assert!(
            !REGEX_SCOPE.contains("  "),
            "a run of spaces means a line continuation was lost: {REGEX_SCOPE:?}"
        );
        assert!(
            !REGEX_SCOPE.chars().any(|c| c.is_control()),
            "a control character in prose that reaches a screen: {REGEX_SCOPE:?}"
        );
        assert!(REGEX_SCOPE.ends_with('.'));
        // And it says the two things that change what an empty result means.
        assert!(REGEX_SCOPE.contains("RAW BYTES"));
        assert!(REGEX_SCOPE.contains("UTF-16"));
    }

    /// Small chunks, so a boundary can be exercised without a 16 MiB fixture.
    fn caps(chunk_size: u64) -> PatternCaps {
        PatternCaps {
            scan: ScanConfig {
                chunk_size,
                ..ScanConfig::default()
            },
            ..PatternCaps::default()
        }
    }

    /// **Only the regions handed in are searched.** The scan is planned from the
    /// allocation list and from nothing else, so a match outside every allocation
    /// is not something this scan can produce.
    #[test]
    fn a_match_outside_every_region_is_not_found() {
        let layer = flat(image(0x400, &[0x40, 0x340]));
        let pass = scan_space(&layer, &one(0x0..0x100), &needle_set(), u64::MAX, &caps(64));

        let addresses: Vec<u64> = pass.hits.iter().map(|hit| hit.address).collect();
        assert_eq!(addresses, vec![0x40], "0x340 is outside the only region");
        assert_eq!(pass.bytes_scanned, 0x100);
        assert!(pass.is_complete());
    }

    /// Regions arrive in any order, and the address space between them is neither
    /// searched nor counted against the coverage: nothing could have been there.
    #[test]
    fn the_space_between_two_regions_is_not_evidence_that_was_missed() {
        let layer = flat(image(0x400, &[0x10, 0x210]));
        let pass = scan_space(
            &layer,
            &[0x200..0x300, 0x0..0x100],
            &needle_set(),
            u64::MAX,
            &caps(64),
        );

        let addresses: Vec<u64> = pass.hits.iter().map(|hit| hit.address).collect();
        assert_eq!(
            addresses,
            vec![0x10, 0x210],
            "ascending, whatever the input order"
        );
        assert_eq!(pass.bytes_scanned, 0x200);
        assert_eq!(
            pass.unmapped_bytes, 0x100,
            "the address space between the two regions, which the scan never asked to read"
        );
        assert_eq!(
            pass.unreadable_bytes, 0,
            "nothing that existed went unread, which is the only figure that means evidence was \
             possibly missed"
        );
        assert!(pass.is_complete());
    }

    /// **Two regions that touch are merged, so a match across their boundary is
    /// still found.** The chunk overlap is suppressed at a section end, so an
    /// invented boundary at 0x100 would lose this match silently — which is the
    /// failure a caller cannot see and cannot test for in their own output.
    #[test]
    fn a_match_across_the_boundary_between_two_touching_regions_is_found() {
        // The needle starts four bytes below 0x100 and ends above it.
        let layer = flat(image(0x400, &[0xFC]));
        let pass = scan_space(
            &layer,
            &[0x0..0x100, 0x100..0x200],
            &needle_set(),
            u64::MAX,
            &caps(64),
        );
        assert_eq!(
            pass.hits.iter().map(|h| h.address).collect::<Vec<_>>(),
            vec![0xFC]
        );
        assert_eq!(pass.sections, 1, "the touching pair is one section");
    }

    /// A region that is reserved rather than mapped costs a probe, not a read: the
    /// hole inside it is never read, so it cannot come back as bytes that would not
    /// read.
    #[test]
    fn a_hole_inside_a_region_is_never_read_and_is_not_unreadable_bytes() {
        let layer = holed(image(0x200, &[0x10, 0x110]));
        // One region spanning the hole: 0..0x300 in the layer's address space.
        let pass = scan_space(&layer, &one(0x0..0x300), &needle_set(), u64::MAX, &caps(64));

        // The second needle sits at layer address 0x210 (file offset 0x110).
        assert_eq!(
            pass.hits.iter().map(|h| h.address).collect::<Vec<_>>(),
            vec![0x10, 0x210]
        );
        assert_eq!(pass.bytes_scanned, 0x200, "both segments and nothing else");
        assert_eq!(pass.unmapped_bytes, 0x100, "the hole");
        assert_eq!(pass.unreadable_bytes, 0, "the hole was never read");
        assert!(pass.is_complete(), "a hole is not incompleteness");
    }

    #[test]
    fn the_byte_ceiling_names_the_address_it_fired_at() {
        let layer = flat(image(0x400, &[0x10, 0x210]));
        let pass = scan_space(&layer, &one(0x0..0x400), &needle_set(), 0x100, &caps(64));

        assert_eq!(
            pass.hits.iter().map(|h| h.address).collect::<Vec<_>>(),
            vec![0x10],
            "the match above the ceiling was never looked for"
        );
        assert!(pass.truncated);
        let capped = pass.capped.clone().expect("a ceiling that fired says so");
        assert!(capped.contains("0x100"), "{capped}");
        assert!(!pass.is_complete(), "a scan that stopped is not complete");
    }

    #[test]
    fn a_budget_of_nothing_searches_nothing_and_says_where_it_stopped() {
        let layer = flat(image(0x400, &[0x10]));
        let pass = scan_space(&layer, &one(0x0..0x400), &needle_set(), 0, &caps(64));
        assert!(pass.hits.is_empty());
        assert_eq!(pass.bytes_scanned, 0);
        assert!(pass.truncated);
        assert!(pass.capped.is_some());
    }

    #[test]
    fn the_section_ceiling_is_reported_rather_than_silently_dropping_allocations() {
        let layer = flat(image(0x400, &[0x10, 0x210]));
        let ranges = [0x0..0x100, 0x200..0x300];
        let mut caps = caps(64);
        caps.max_sections_per_space = 1;
        let pass = scan_space(&layer, &ranges, &needle_set(), u64::MAX, &caps);

        assert_eq!(
            pass.hits.iter().map(|h| h.address).collect::<Vec<_>>(),
            vec![0x10]
        );
        assert!(pass.truncated);
        assert!(pass
            .capped
            .as_deref()
            .is_some_and(|c| c.contains("ceiling of 1")));
    }

    #[test]
    fn the_match_ceiling_reports_a_truncated_scan_rather_than_a_match_count() {
        let layer = flat(image(0x400, &[0x10, 0x110, 0x210]));
        let mut caps = caps(0x400);
        caps.scan.max_hits = 2;
        let pass = scan_space(&layer, &one(0x0..0x400), &needle_set(), u64::MAX, &caps);

        assert_eq!(pass.hits.len(), 2);
        assert!(pass.truncated);
        assert!(pass
            .capped
            .as_deref()
            .is_some_and(|c| c.contains("match ceiling")));
        // MEM-041: every byte of this image reads, so none is unreadable; the
        // bytes past the second match were not searched, and say so.
        assert_eq!(pass.unreadable_bytes, 0);
        assert!(pass.not_searched_bytes > 0);
        assert_eq!(pass.bytes_scanned + pass.not_searched_bytes, 0x400);
    }

    #[test]
    fn a_capped_pass_over_a_hole_keeps_unsearched_bytes_out_of_unreadable() {
        let mut bytes = image(0x300, &[0x10, 0x20]);
        bytes[0x200..0x300].fill(b'.');
        let layer = holed(bytes);
        let mut caps = caps(0x300);
        caps.scan.max_hits = 1;
        let pass = scan_space(&layer, &one(0x0..0x300), &needle_set(), u64::MAX, &caps);
        assert!(pass.truncated);
        assert_eq!(pass.unreadable_bytes, 0, "{pass:?}");
        assert_eq!(pass.unmapped_bytes, 0, "the hole lies above the stop");
        assert!(pass.not_searched_bytes > 0x100, "{pass:?}");
    }

    #[test]
    fn a_budget_splits_a_section_rather_than_dropping_it_whole() {
        let (kept, stopped) = trim_to_budget(&one(0x0..0x1000), 0x400);
        assert_eq!(kept, vec![0x0..0x400]);
        assert_eq!(
            stopped,
            Some(0x400),
            "the address nothing above was examined"
        );
    }

    #[test]
    fn a_budget_that_covers_everything_stops_nowhere() {
        let (kept, stopped) = trim_to_budget(&[0x0..0x100, 0x200..0x300], 0x1000);
        assert_eq!(kept, vec![0x0..0x100, 0x200..0x300]);
        assert_eq!(stopped, None);
    }

    #[test]
    fn a_budget_exhausted_on_a_boundary_names_the_next_sections_start() {
        let (kept, stopped) = trim_to_budget(&[0x0..0x100, 0x200..0x300], 0x100);
        assert_eq!(kept, vec![0x0..0x100]);
        assert_eq!(
            stopped,
            Some(0x200),
            "the next region's start, not the last one's end: the bytes between were never in the \
             plan"
        );
    }

    /// An id with no pattern behind it is reported as the id. Naming the first
    /// pattern in the set would attribute a match to the wrong rule.
    #[test]
    fn an_unknown_pattern_id_is_reported_as_the_id_and_not_as_the_first_pattern() {
        let set = needle_set();
        assert_eq!(set.pattern_name(0), "marker");
        assert_eq!(set.pattern_name(7), "pattern #7");
    }

    /// An engine whose match length is unbounded — YARA's is — cannot guarantee a
    /// match spanning a chunk boundary is found, and the pass says so.
    #[test]
    fn an_unbounded_pattern_length_is_declared_on_every_pass() {
        #[derive(Debug)]
        struct Unbounded;
        impl Scanner for Unbounded {
            fn name(&self) -> &str {
                "unbounded"
            }
            fn max_match_len(&self) -> Option<u64> {
                None
            }
            fn scan_chunk(
                &self,
                _chunk: &[u8],
                _base: u64,
                _sink: &mut dyn FnMut(crate::scan::Hit) -> crate::scan::ScanControl,
            ) {
            }
        }
        let set = PatternSet {
            kind: "yara",
            source: "rules.yar".to_string(),
            pattern_names: vec!["r".to_string()],
            scanner: Arc::new(Unbounded),
            diagnostics: None,
            scope_note: None,
        };
        let layer = flat(image(0x400, &[]));
        let pass = scan_space(&layer, &one(0x0..0x400), &set, u64::MAX, &caps(64));
        assert!(pass.pattern_may_exceed_overlap);
        let json = pass.to_json();
        assert_eq!(json["pattern_may_exceed_overlap"], serde_json::json!(true));
    }
}

// ── The whole-image scan ────────────────────────────────────────────────────

/// Offsets recorded against an image, in the words the format allows.
///
/// A match is reported at an address in the image's **own** decoded space, and
/// what that address *is* differs by format. An examiner correlating a match
/// against the evidence file needs to be told which, because for one format the
/// two are the same number and for another they are nothing like it.
fn offset_meaning(format: MemoryImageFormat) -> &'static str {
    match format {
        MemoryImageFormat::WindowsHibernation => {
            "A PHYSICAL MEMORY ADDRESS in the reconstructed image, not an offset in \
             `hiberfil.sys`. The file holds these pages Xpress-compressed, so the two numbers \
             are unrelated: a match reported here cannot be found at the same offset in the \
             file on the disk image."
        }
        MemoryImageFormat::WindowsCrashDump32 | MemoryImageFormat::WindowsCrashDump64 => {
            "A physical memory address, as the dump's own run table maps it. The dump's header \
             and its bitmap or run table sit in front of the pages, so this is not an offset in \
             the dump file."
        }
        MemoryImageFormat::Lime
        | MemoryImageFormat::Avml
        | MemoryImageFormat::ElfCore
        | MemoryImageFormat::QemuSaveVm
        | MemoryImageFormat::VmwareSnapshot => {
            "A physical memory address, as this format's segment map places it. The format \
             stores segments with headers between them, so this is not an offset in the file."
        }
        MemoryImageFormat::Raw => {
            "An offset in the image as the case declared it. Nothing in the bytes of a raw \
             capture identifies it as memory at all, so this is a physical memory address only \
             if that declaration is true -- and if the file is something else a flat blob was \
             searched, which is still a fact about those bytes and no more."
        }
    }
}

/// Examiner-supplied patterns over an image's **own** address space.
///
/// Upstream's `yarascan` over the physical layer rather than over a process's:
/// the route for a capture with no page tables to plan from, which is every
/// reconstructed hibernation file, every swap area, and every acquisition whose
/// operating system could not be profiled. It runs beside the per-process scan
/// rather than instead of it — a match in a process's own space carries the
/// allocation that held it and this one cannot, so the two answer different
/// questions about the same bytes.
///
/// # Registered only when something was named
///
/// Constructed from the pattern sets the registration site built, so a
/// deployment that named no rules and no pattern does not carry this module at
/// all. A module that is registered, reports success and searches for nothing
/// is the shape this codebase keeps finding: absence of the module is visible
/// in the module list, a silent no-op is not.
#[derive(Debug)]
pub struct ImagePatternScan {
    sets: Vec<PatternSet>,
    caps: PatternCaps,
}

/// The record type this module emits.
pub const IMAGE_PATTERN_SCAN_RECORD: &str = "MemoryImagePatternScan";

impl ImagePatternScan {
    /// Scan every image for `sets`.
    ///
    /// Returns `None` for an empty set list, because there is then nothing to
    /// search for and a module that searches for nothing must not be
    /// registered. The caller registers what it gets.
    pub fn new(sets: Vec<PatternSet>) -> Option<Self> {
        (!sets.is_empty()).then_some(Self {
            sets,
            caps: PatternCaps {
                // A whole image is the one space where the per-space ceiling is
                // routinely the wrong shape: a 16 GiB capture is ordinary. The
                // ceiling is raised to the image-wide one rather than removed,
                // and a scan that reaches it says so with the address.
                max_bytes_per_space: 512 * 1024 * 1024 * 1024,
                ..PatternCaps::default()
            },
        })
    }

    /// The same, with the ceilings a caller chooses.
    pub fn with_caps(sets: Vec<PatternSet>, caps: PatternCaps) -> Option<Self> {
        Self::new(sets).map(|scan| Self { caps, ..scan })
    }

    /// Patterns this module searches for.
    pub fn sets(&self) -> &[PatternSet] {
        &self.sets
    }
}

impl ForensicsModule for ImagePatternScan {
    fn id(&self) -> &str {
        "plugin.memory.pattern_scan"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // The container stage emits the decoded image as a ParsedRecord, and
        // that record carries the decoded address space. This module reads that
        // and nothing else: it never re-detects a format that has already been
        // decoded, and never scans the *file* when a decoded space exists.
        vec![ArtifactType::ParsedRecord]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        if !crate::analysis::is_memory_image_record(artifact) {
            return Ok(Vec::new());
        }
        // A decode failure carries the same record type so an examiner sees it.
        // There is no address space behind it, and a scan of nothing must not
        // be reported as a scan that found nothing.
        if artifact
            .metadata
            .get("decode_failed")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }
        let Some(source) = artifact.data.as_ref() else {
            return Err(crate::module::refused(
                "the memory image record carries no decoded address space, so an examiner's \
                 patterns were not searched for in it"
                    .to_string(),
            ));
        };
        let layer = crate::analysis::physical_layer_for(source, artifact)?;

        let format = artifact
            .metadata
            .get("image_format")
            .and_then(|v| v.as_str())
            .and_then(crate::format::parse_format_name)
            .unwrap_or(MemoryImageFormat::Raw);

        let mut passes: Vec<SpaceScan> = Vec::new();
        let mut rows: Vec<Value> = Vec::new();
        let mut total: u64 = 0;
        let mut by_pattern: std::collections::BTreeMap<String, u64> =
            std::collections::BTreeMap::new();
        let mut rows_capped = false;
        let mut refused_chunks: Vec<(String, RefusedChunk)> = Vec::new();
        let mut without_address: Vec<(String, String)> = Vec::new();

        for set in &self.sets {
            let pass = match scan_whole_layer(
                layer.as_ref(),
                set,
                self.caps.max_bytes_per_space,
                &self.caps,
            ) {
                Ok(pass) => pass,
                // The space will not enumerate at all. Stated, and not rendered
                // as a space that was searched and held nothing.
                Err(err) => {
                    passes.push(SpaceScan {
                        truncated: true,
                        capped: Some(format!(
                            "this image's address space could not be enumerated, so it was not \
                             searched: {err}"
                        )),
                        ..SpaceScan::default()
                    });
                    continue;
                }
            };
            for hit in &pass.hits {
                let pattern = set.pattern_name(hit.pattern_id);
                total = total.saturating_add(1);
                *by_pattern.entry(pattern.clone()).or_insert(0) += 1;
                if rows.len() >= self.caps.max_recorded_matches {
                    rows_capped = true;
                    continue;
                }
                rows.push(json!({
                    "pattern": pattern,
                    "pattern_kind": set.kind,
                    "address": hit.address,
                    // Exact beside the number: a JSON number is an IEEE double,
                    // and an address above 2^53 reaches a client rounded.
                    "address_hex": format!("{:#x}", hit.address),
                    "length": hit.length,
                }));
            }
            if let Some(diagnostics) = &set.diagnostics {
                for chunk in diagnostics.take_refused_chunks() {
                    refused_chunks.push((set.source.clone(), chunk));
                }
                for pattern in diagnostics.take_matched_without_address() {
                    without_address.push((set.source.clone(), pattern));
                }
            }
            passes.push(pass);
        }

        let bytes_scanned = passes
            .iter()
            .fold(0u64, |acc, p| acc.saturating_add(p.bytes_scanned));
        let complete =
            passes.iter().all(SpaceScan::is_complete) && !rows_capped && refused_chunks.is_empty();

        let mut incomplete: Vec<Value> = Vec::new();
        if rows_capped {
            incomplete.push(json!({
                "reason": "cap_reached",
                "detail": format!(
                    "{total} match(es) were found and {} are listed individually; the totals \
                     are exact and the rows are a sample.",
                    rows.len()
                ),
            }));
        }
        for pass in &passes {
            if let Some(capped) = &pass.capped {
                incomplete.push(json!({"reason": "cap_reached", "detail": capped}));
            }
            if pass.unreadable_bytes > 0 {
                incomplete.push(json!({
                    "reason": "short_read",
                    "detail": format!(
                        "{} byte(s) of this image were mapped and would not read, so they were \
                         not searched.",
                        pass.unreadable_bytes
                    ),
                }));
            }
        }
        for (set, chunk) in &refused_chunks {
            incomplete.push(json!({
                "reason": "unresolved_structure",
                "detail": format!(
                    "the engine for {set} refused {} byte(s) at {:#x}: {}. Those bytes were \
                     read and not searched.",
                    chunk.bytes, chunk.address, chunk.detail
                ),
            }));
        }

        let statement = if total == 0 {
            format!(
                "No match for {} pattern(s) in {bytes_scanned} byte(s) of this image's own \
                 address space. No match is not the same as nothing to find: it is this \
                 pattern set, over the memory this capture holds and this build could read.",
                self.sets
                    .iter()
                    .map(|s| s.pattern_names.len())
                    .sum::<usize>()
            )
        } else {
            format!(
                "{total} match(es) in {bytes_scanned} byte(s) of this image's own address \
                 space. Each is reported at an address in that space; a match's process and \
                 the allocation that held it are NOT established here -- the per-process scan \
                 is what answers that, and it needs an address space this image may not have."
            )
        };

        let mut value = json!({
            "type": IMAGE_PATTERN_SCAN_RECORD,
            "record_type": IMAGE_PATTERN_SCAN_RECORD,
            "name": format!("Pattern scan over the image ({} match(es))", total),
            "image_format": format.as_str(),
            "offset_meaning": offset_meaning(format),
            "patterns": self.sets.iter().map(PatternSet::to_json).collect::<Vec<_>>(),
            "scope_notes": self.sets.iter().filter_map(|s| s.scope_note.clone())
                .collect::<Vec<_>>(),
            "matches": rows,
            "matches_total": total,
            "matches_recorded": rows.len(),
            "matches_by_pattern": by_pattern.iter()
                .map(|(k, v)| (k.clone(), json!(v))).collect::<serde_json::Map<_, _>>(),
            "rows_capped": rows_capped,
            "passes": passes.iter().map(SpaceScan::to_json).collect::<Vec<_>>(),
            "bytes_scanned": bytes_scanned,
            "refused_chunks": refused_chunks.iter().map(|(set, chunk)| json!({
                "pattern_set": set,
                "address": chunk.address,
                "address_hex": format!("{:#x}", chunk.address),
                "bytes": chunk.bytes,
                "detail": chunk.detail,
            })).collect::<Vec<_>>(),
            "matched_without_address": without_address.iter().map(|(set, pattern)| json!({
                "pattern_set": set,
                "pattern": pattern,
            })).collect::<Vec<_>>(),
            "statement": statement,
            "content_complete": complete,
            "content_incomplete": !complete,
            "incomplete": incomplete,
        });
        if !complete {
            if let Some(obj) = value.as_object_mut() {
                obj.insert(
                    "content_incomplete_reason".into(),
                    json!("this image was not searched in full; see `incomplete`"),
                );
            }
        }

        Ok(vec![Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            value,
        )
        .with_parent(artifact.id)])
    }
}
