#![forbid(unsafe_code)]
//! # Séance Memory
//!
//! The memory-forensics foundation: the layer contract, the leaf physical
//! layer, the shared segment machinery every acquisition format reduces to, the
//! metadata carried up a layer chain, and content detection of the acquisition
//! formats themselves.
//!
//! This is phase 1 of the memory programme. It contains no address translation,
//! no symbols and no analysis; it contains the part everything above it stands
//! on, and the invariants that make the rest trustworthy.
//!
//! ## The one idea
//!
//! **Every memory layer is a [`seance_core::data_source::DataSource`].** A
//! memory address is an offset; a layer is a thing you can `read_at`. That
//! single decision is why memory evidence needs almost no new plumbing: the
//! moment an image is wrapped in a layer, `read_capped`, `read_full`,
//! `read_exact_or_fail`, `SourceCursor`, `CachingDataSource`, the hasher, the
//! 358-signature carving engine, the search indexer and the API content
//! resolver all work over it unchanged.
//!
//! [`layer::MemoryLayer`] is the supertrait carrying the one thing `DataSource`
//! cannot express: how a logical range projects onto the layer beneath, and
//! where it does not project at all.
//!
//! ## The one invariant
//!
//! **An unmapped memory region is an error, never zeros.**
//!
//! Volatility 3 offers `read(..., pad=True)`, which fabricates zero bytes for
//! regions it cannot map. Under Séance's rules that is evidence fabrication: a
//! page that was swapped out, smeared during acquisition, or simply never
//! captured becomes byte-identical to a page the suspect's machine genuinely
//! zeroed, and the fabricated bytes then flow into hashes, carving, search and
//! reports with no record that they were invented. "This buffer was wiped" and
//! "we never had this buffer" are opposite conclusions and must never render
//! the same.
//!
//! So a layer read has three outcomes, kept strictly apart:
//!
//! | Condition | Result |
//! |---|---|
//! | Range fully mapped | `Ok(n)` with acquired bytes |
//! | Offset above the top of the address space | `Ok(0)` — genuine EOF |
//! | Any unmapped byte inside the range | `Err` carrying a [`layer::MemoryHole`] |
//!
//! `Err` rather than `Ok(0)` is the whole trick: it means the existing Séance
//! helpers already behave correctly with no changes of their own, and a
//! memory-aware caller can recover the exact unmapped range with
//! [`layer::MemoryHole::from_io`] and stamp an honest
//! [`seance_core::io::IncompleteReason`] onto the artifact.
//!
//! ## What is here
//!
//! - [`layer`] — [`layer::MemoryLayer`], [`layer::MappedRange`],
//!   [`layer::MemoryHole`], [`layer::LayerError`].
//! - [`physical`] — [`physical::PhysicalLayer`], flat physical memory over any
//!   `DataSource` (offset == physical address).
//! - [`segmented`] — [`segmented::SegmentedLayer`], the sorted, binary-searched
//!   run list that LiME, ELF core, crash dumps, VMware and Xen all reduce to.
//!   Each format reader only produces a segment list; the lookup, the bounds
//!   and the hole semantics are written once, here.
//! - [`meta`] — [`meta::LayerMeta`], the facts a layer knows about itself,
//!   inherited down a chain.
//! - [`format`] — [`format::MemoryImageFormat`], [`format::detect`], and
//!   [`format::DECLARABLE_FORMAT_NAMES`] with [`format::parse_format_name`]:
//!   the one table of names an examiner may declare an image as, exported so
//!   the API can refuse an unrecognised declaration with 400 instead of keeping
//!   a second copy of the list that drifts from this one.
//! - [`formats`] — the per-format readers that turn an image header into that
//!   segment list. Each produces only the list; the lookup, the bounds and the
//!   hole semantics are [`segmented::SegmentedLayer`]'s, written once.
//! - [`binding`] — the build binding: what *this* kernel build declares, and
//!   how a stage says what it needs. A structure member absent because this
//!   build never had it is [`binding::Field::NotDeclared`] — an answer — and
//!   never an error. Written once here because Linux carries 231 such branches,
//!   macOS varies across 129 symbol packs, and the Windows tier has already
//!   lost eight analysis stages to a single member proved fatally in a
//!   pre-flight that no Windows XP code path reaches.
//!
//! ## What is deliberately not here
//!
//! Phase 1 stops at "the bytes are addressable and honest about their gaps".
//! Deferred, with the phase that owns each:
//!
//! - **Non-linear (encoded) segments.** [`layer::Encoding::Encoded`] exists in
//!   the mapping contract because AVML's snappy frames and QEMU's compressed
//!   pages need it, but no phase-1 layer produces one, and there is no decode
//!   path yet.
//! - **Address translation.** Virtual address spaces, the Intel/PAE/x64/LA57
//!   page-table walk, ARM64, and the swap layer.
//! - **The scan-only padded read.** `read_for_scan`, which returns fabricated
//!   regions alongside the bytes so a hit landing inside one can be discarded,
//!   belongs with the scan driver.
//! - **Symbols, objects and the `ForensicsModule` wiring.** Separate crates.

pub mod analysis;
pub mod binding;
pub mod btf;
pub mod btf_isf;
pub mod export;
pub mod format;
pub mod formats;
pub mod isf_files;
pub mod kallsyms;
pub mod layer;
pub mod meta;
pub mod module;
pub mod object;
pub mod patterns;
pub mod physical;
pub mod recognise;
/// Which address spaces map a given physical offset, and where in each.
pub mod reverse;
pub mod scan;
pub mod segmented;
pub mod stage_records;
pub mod translate;

pub use analysis::{
    analysed_stamp, is_memory_image_record, MemoryAnalysis, MemoryAnalysisModule,
    MEMORY_IMAGE_RECORD,
};
pub use binding::{
    first_member, first_type, BindError, BoundMember, BoundType, BuildBinding, Evidence, Field,
    Found, MemberSet, MemberSpec, MemberUse, Necessity, StageId, TypeSpec, TypeUse,
    MEMORY_STAGE_MANIFEST_RECORD,
};
pub use format::{detect, parse_format_name, MemoryImageFormat, DECLARABLE_FORMAT_NAMES};
pub use formats::avml::{AvmlImage, AvmlLayer};
pub use formats::crash::{CrashDump, CrashDumpKind};
pub use formats::lime::LimeImage;
pub use formats::FormatError;
pub use layer::{
    backed_len, covered_len, BackingSource, Encoding, HoleReason, LayerError, MappedRange,
    MemoryHole, MemoryLayer, MAX_SEGMENTS,
};
pub use meta::{Architecture, Incomplete, LayerMeta};
pub use module::{open_physical_layer, undeclared_memory_hint, MemoryImageModule};
pub use patterns::{PatternCaps, PatternSet, SpaceScan};
pub use physical::PhysicalLayer;
pub use segmented::{Segment, SegmentedLayer};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_core::io::read_exact_or_fail;
    use std::sync::Arc;

    /// A LiME acquisition, end to end: detect the format from the bytes, build
    /// the segment list a phase-2 reader would produce, and prove that the
    /// resulting layer reads acquired memory correctly and refuses the gap.
    #[test]
    fn a_lime_image_goes_from_bytes_to_an_honest_address_space() {
        fn header(start: u64, end: u64) -> Vec<u8> {
            let mut h = Vec::with_capacity(32);
            h.extend_from_slice(&0x4C69_4D45u32.to_le_bytes()); // "EMiL"
            h.extend_from_slice(&1u32.to_le_bytes());
            h.extend_from_slice(&start.to_le_bytes());
            h.extend_from_slice(&end.to_le_bytes());
            h.extend_from_slice(&0u64.to_le_bytes());
            h
        }

        // Physical 0x0000..0x1000 and 0x3000..0x4000 were captured; the range
        // between them is an MMIO window LiME skipped.
        let mut file = header(0x0000, 0x0FFF);
        let first_payload = file.len() as u64;
        file.extend_from_slice(&[0x11u8; 0x1000]);
        file.extend_from_slice(&header(0x3000, 0x3FFF));
        let second_payload = file.len() as u64;
        file.extend_from_slice(&[0x22u8; 0x1000]);

        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(file));
        assert_eq!(detect(&*source), MemoryImageFormat::Lime);

        let layer = SegmentedLayer::new(
            source,
            vec![
                Segment::new(first_payload, 0x0000, 0x1000),
                Segment::new(second_payload, 0x3000, 0x1000),
            ],
            LayerMeta::new(MemoryImageFormat::Lime).with_declared_size(0x4000),
        )
        .expect("a well-formed LiME segment list");

        // The address space spans 0x4000 but only 0x2000 was acquired, and both
        // numbers are reachable so a report cannot imply a complete capture.
        assert_eq!(layer.size(), 0x4000);
        assert_eq!(layer.mapped_len(), 0x2000);

        let mut page = vec![0u8; 0x1000];
        assert_eq!(layer.read_at(0x3000, &mut page).unwrap(), 0x1000);
        assert!(page.iter().all(|&b| b == 0x22));

        // The skipped window is a hole, not 0x2000 fabricated zero bytes.
        let err = layer
            .read_at(0x1000, &mut page)
            .expect_err("unacquired memory must not read as zeros");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!((hole.address, hole.length), (0x1000, 0x2000));
        assert_eq!(hole.reason, HoleReason::Unmapped);
    }

    /// A raw dump: no magic, so nothing claims it, and the examiner-declared
    /// path produces a flat space with no holes anywhere.
    #[test]
    fn a_declared_raw_image_is_flat_and_hole_free() {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0x5A; 0x8000]));
        let format = detect(&*source);
        assert_eq!(format, MemoryImageFormat::Raw);
        assert!(
            !format.is_content_detected(),
            "raw memory can only be declared, never detected"
        );

        let layer = PhysicalLayer::raw(source).expect("non-empty");
        assert_eq!(layer.min_address(), 0);
        assert_eq!(layer.max_address(), 0x7FFF);
        assert!(layer.is_valid(0, 0x8000));

        let mut buf = [0u8; 0x40];
        read_exact_or_fail(layer.as_data_source(), 0x7000, &mut buf, "probe").unwrap();
        assert!(buf.iter().all(|&b| b == 0x5A));
    }

    /// Layer metadata composes down a chain: a segmented image over a physical
    /// leaf, with the leaf's discovered facts visible from the top.
    #[test]
    fn metadata_composes_down_a_two_layer_chain() {
        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 0x2000]));
        let leaf = PhysicalLayer::new(
            source.clone(),
            LayerMeta::new(MemoryImageFormat::WindowsCrashDump64)
                .with_architecture(Architecture::X64)
                .with_note("directory_table_base", 0x1a_b000u64),
        )
        .unwrap();

        let leaf_meta = Arc::new(leaf.layer_meta().clone());
        let upper = SegmentedLayer::new(
            source,
            vec![Segment::new(0x1000, 0x0000, 0x1000)],
            LayerMeta::default().with_parent(leaf_meta).with_incomplete(
                seance_core::io::IncompleteReason::CapReached,
                "run list truncated at the segment cap",
            ),
        )
        .unwrap();

        let meta = upper.layer_meta();
        assert_eq!(meta.architecture(), Some(Architecture::X64));
        assert!(meta.note("directory_table_base").is_some());
        assert_eq!(meta.chain_depth(), 2);
        let json = meta.to_json();
        assert_eq!(json["architecture"], "x64");
        assert_eq!(json["incomplete"][0]["reason"], "cap_reached");
    }
}
