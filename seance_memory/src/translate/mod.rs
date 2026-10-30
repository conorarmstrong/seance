//! Address translation: turning a virtual address into a physical one by
//! walking the hardware page tables the suspect's machine was using.
//!
//! Everything a memory-forensics plugin does above this point — every process
//! list, every registry hive read out of RAM, every injected-code finding —
//! rests on the arithmetic in [`walk`]. A page-table walk that is subtly wrong
//! does not crash and does not look wrong; it returns a physical address that
//! is 4 KiB out, or one that belongs to another process, and everything read
//! through it parses perfectly into a false answer. That is why this module is
//! parameter-driven ([`spec`]) rather than mode-by-mode, why every failure is a
//! named reason rather than a null, and why the tests build page tables by
//! hand.
//!
//! ## The three pieces
//!
//! - [`spec`] — [`PagingSpec`], the per-(mode, OS) parameter table: entry size,
//!   MAXPHYADDR, MAXVIRTADDR, the level list, and what a non-present entry
//!   means under Windows' conventions.
//! - [`walk`] — [`PageWalk`], the walk itself, plus [`Translation`] and the
//!   [`TranslateError`] vocabulary that keeps "absent", "paged out",
//!   "shared/prototype", "table unreadable" and "suppressed" apart.
//! - [`virt`] — [`VirtualLayer`], an address space as an ordinary
//!   [`seance_core::data_source::DataSource`], with [`cache`] the bounded,
//!   shareable memo of page-table entries underneath it.
//!
//! ## What is supported
//!
//! | Mode | Levels | Page sizes |
//! |---|---|---|
//! | Intel 32-bit, no PAE | PD, PT | 4 KiB, 4 MiB |
//! | Intel PAE | PDPT (4 entries), PD, PT | 4 KiB, 2 MiB |
//! | Intel IA-32e (x86-64) | PML4, PDPT, PD, PT | 4 KiB, 2 MiB, 1 GiB |
//! | Intel IA-32e with LA57 | PML5, PML4, PDPT, PD, PT | 4 KiB, 2 MiB, 1 GiB |
//! | ARM64 (VMSAv8-64), 4 KiB granule | up to L0, L1, L2, L3 by `TxSZ` | 4 KiB, 2 MiB (L2 block), 1 GiB (L1 block) |
//! | ARM64, 16 KiB granule | up to L0 (2 entries), L1, L2, L3 | 16 KiB, 32 MiB (L2 block) |
//! | ARM64, 64 KiB granule | up to L1 (64 entries), L2, L3 | 64 KiB, 512 MiB (L2 block) |
//!
//! The paging **depth** is `CR4.LA57`, which is register state and appears in
//! no raw dump, so it is never assumed here: it is declared by the profiler
//! that built the address space, and an image whose depth could not be
//! established is refused rather than walked at a guessed one. The Linux tier
//! establishes it by walking the kernel's own tables at each candidate depth
//! and requiring the banner to translate back to the physical address it was
//! found at; nothing in this crate infers it.
//!
//! ARM64 is the same discipline with more register state. The granule
//! (`TCR_EL1.TG0`/`TG1`), the width of each regime (`T0SZ`/`T1SZ`, which fixes
//! the start level) and the two roots (`TTBR0_EL1`/`TTBR1_EL1`) are all
//! declared through [`PagingMode::Arm64`] and an [`Arm64Regime`], and **each
//! regime is its own [`VirtualLayer`]**: the kernel's space is a TTBR1 layer
//! whose addresses have every bit above the width set, a process is a TTBR0
//! layer over its own root, and an address from the other regime is refused as
//! non-canonical rather than walked through the wrong tables. How an entry
//! ends the walk — Intel's `PS` bit against ARM64's type bit, a large page's
//! PAT bit against a block's `nT` — is one [`LeafRule`] per level applied by
//! [`PagingSpec::classify`], which both the upward walk and the downward
//! enumeration consult; no walker holds the shape of an architecture.
//!
//! A regime can also be built from a recorded `TCR_EL1` value
//! ([`Arm64Regime::from_tcr_el1`]), which reads the granule, width, `IPS`,
//! top-byte-ignore, hierarchical-permission and walk-disable fields for the
//! regime asked about; `DS = 1` (FEAT_LPA2) is decoded for the 16 KiB granule
//! (52-bit widths, output-address bits 51:50 in descriptor bits 9:8, a 64 GiB level-1
//! block, a `TTBRn_EL1` whose bits 5:2 are address bits 51:48) and refused by name under a
//! 4 or 64 KiB granule. A regime built
//! that way enforces what the register says: an output address above `IPS` is
//! an Address size fault, refused with the entry verbatim; a tagged pointer
//! translates when `TBIn` is set and is non-canonical when it is not; and the
//! hierarchical `PXNTable`/`UXNTable` bits are folded into `no_execute` unless
//! `HPDn` is set. A regime built with [`Arm64Regime::new`] enforces 48 bits of
//! output address, never untags, and folds the table bits (without FEAT_HPDS
//! the hardware always applies them).
//!
//! The ARM64 synthetic tables are written from the descriptor layout in ARM
//! DDI 0487 D8.3, with every expected address worked by hand. The 4 KiB core
//! has since agreed with an independent walker on every leaf of four real
//! (QEMU-emulated, not hardware) AArch64 trees — `tests/arm64_mmushell_real_test.rs`,
//! `VALIDATION.md` `MEM-ARM-1`; and, since 2026-10-20, on every leaf of a real
//! 16 KiB-granule Debian kernel and a 64 KiB-granule Ubuntu kernel booted under
//! QEMU TCG (`tests/arm64_16k_real_test.rs`, `tests/arm64_64k_real_test.rs`,
//! `MEM-ARM-5`, `MEM-ARM-6`). The IPS fault and the hierarchical execute-never
//! rule have no real descriptor to meet and are pinned on synthetic tables only.
//!
//! Under [`PteSemantics::Windows`], transition PTEs resolve (a standby-list
//! page is real evidence, still in RAM), software PTEs are decoded into a
//! pagefile number and offset instead of being flattened into "absent", and
//! prototype PTEs are followed into the section object's prototype array, so a
//! shared or file-backed page that is still resident reads as the bytes it is
//! rather than as a hole. The answer records that it came from a section
//! ([`TranslationPath`]), because "resident" and "private to this process" are
//! different claims. A consumer holding the address space as
//! `Arc<dyn MemoryLayer>` reaches that answer through
//! [`crate::layer::MemoryLayer::as_virtual`]; there is no other route, because a
//! successful read says the bytes were acquired and nothing about whose they
//! are.
//!
//! Under [`PteSemantics::Linux`], an entry the hardware rejects is separated
//! into "nothing was ever mapped here" (`pte_none`, and `_PAGE_PROTNONE`, which
//! Linux counts as present) and "the kernel moved this page's contents out and
//! recorded where" — a `swp_entry_t`, reported as
//! [`TranslateError::LinuxSwapEntry`] with the entry verbatim.
//!
//! ## What is deliberately not here
//!
//! - **ARM64 beyond a 48-bit output address.** FEAT_LPA and FEAT_LPA2 press
//!   descriptor bits 15:12 (64 KiB) and 49:48 (4 and 16 KiB) into service as
//!   output-address bits 51:48; whether they are on is `TCR_EL1.DS` or the
//!   PE's ID registers, state no image records. A descriptor with those bits
//!   set is refused as one whose frame cannot be stated, never masked — but an
//!   LPA2 frame above 2^50 whose bits 49:48 are clear carries its high bits in
//!   9:8, which the non-LPA2 reading takes as shareability, so it is read as a
//!   48-bit frame and cannot be detected from the entry alone — which is why
//!   `TCR_EL1.DS = 1` under a 16 KiB granule is the one case decoded, not guessed at: a
//!   regime built from a recorded register that says so reads the descriptors as LPA2
//!   (`tests/arm64_16k_lpa2_real_test.rs`, `VALIDATION.md` `MEM-ARM-7`). The
//!   same features permit a block one level higher than the base
//!   architecture does — a 4 KiB level 0 (512 GiB) and a 16 KiB level 1
//!   (64 GiB) under LPA2, a 64 KiB level 1 (4 TiB) under LPA — and a valid
//!   descriptor with the type bit clear at such a level is either that block
//!   or a reserved encoding, with nothing in the image to say which; it is
//!   refused as undecodable ([`EntryKind::Unnameable`]), and **not** reported
//!   as not present, because the region may be mapped. Nor is a 52-bit *virtual* regime
//!   accepted without `DS = 1` ([`Arm64Regime::new`] bounds the width at 48; only a
//!   recorded `TCR_EL1` with `DS = 1` under a 16 KiB granule widens it to 52), and an LPA2
//!   regime under a 4 KiB granule (a level above the four this build walks) or a 64 KiB
//!   one is refused. `APTable` (bits 62:61) is not read, because no access
//!   permission of any level is reported by this crate; that is a decided
//!   limit (2026-10-20), not an open one.
//! - **ARM64 Linux swap-entry *classification*.** On x86-64 the crate
//!   separates "never mapped" from "the kernel moved this out"; on arm64 it
//!   cannot, because the present-invalid marker moved between bit 58 and bit
//!   11 across kernel series and each position is a swap-offset bit under
//!   the other layout. A non-valid arm64 entry is reported as absent with the
//!   entry verbatim — see [`PagingSpec::classify_invalid`].
//! - **ARM64 Windows conventions, for what two builds share.** Under [`PteSemantics::Windows`] an
//!   ARM64 spec reads a descriptor whose valid bit is clear as Windows 11 builds 28000 and 26300 both
//!   lay it out (Microsoft's PDBs, checked against two QEMU-emulated captures, `MEM-ARM-8` and
//!   `MEM-ARM-11`): bit 10 is `Prototype` (named, never followed: the prototype field is `ProtoIndex`
//!   at bits 53:12 on 28000 and `ProtoAddress` at bits 63:16 on 26300, so it is not decoded to an
//!   address), bit 11 `Transition` (the page is on the standby or modified list and is read, as on
//!   x64), and `PageFileHigh` at bits 63:32, the offset in the pagefile. **No pagefile index is
//!   stated:** `PageFileLow` is at bits 17:14 on 28000 and bits 9:6 on 26300, a spec is not told
//!   the build, and the first reading named pagefile 0 for entries of pagefile 1. Other builds
//!   were not read. A valid descriptor's bits 10 and 11 stay the access flag and nG, and the
//!   uniform-table heuristic — observed on x64 — does not fire.
//! - **Linux swap-entry *decoding*.** The classification above is as far as it
//!   goes: which swap area and which page within it are read from bit positions
//!   that are a property of the kernel **source**, and they have moved three
//!   times on x86-64. The obvious selector does not work — the L1TF inversion
//!   was backported below 4.19, so a kernel's own version string cannot say
//!   which layout built it — and nothing else in an image states it. See
//!   [`PteSemantics::Linux`].
//! - **Resolving a swapped page into a pagefile layer.** For Windows the
//!   translation says which pagefile and which offset; supplying that pagefile
//!   and reading it is a layer above this one. Until it exists, a paged-out
//!   address is a [`crate::layer::HoleReason::SwappedOut`] hole and never
//!   zeros. There is no Linux equivalent, because there is no decoded location
//!   to give one.
//!
//! [`PagingSpec`]: spec::PagingSpec
//! [`PagingSpec::classify`]: spec::PagingSpec::classify
//! [`PagingSpec::classify_invalid`]: spec::PagingSpec::classify_invalid
//! [`PagingMode::Arm64`]: spec::PagingMode::Arm64
//! [`Arm64Regime`]: spec::Arm64Regime
//! [`Arm64Regime::new`]: spec::Arm64Regime::new
//! [`Arm64Regime::from_tcr_el1`]: spec::Arm64Regime::from_tcr_el1
//! [`LeafRule`]: spec::LeafRule
//! [`PteSemantics::Windows`]: spec::PteSemantics::Windows
//! [`PteSemantics::Bare`]: spec::PteSemantics::Bare
//! [`PteSemantics::Linux`]: spec::PteSemantics::Linux
//! [`PageWalk`]: walk::PageWalk
//! [`Translation`]: walk::Translation
//! [`TranslateError`]: walk::TranslateError
//! [`TranslateError::LinuxSwapEntry`]: walk::TranslateError::LinuxSwapEntry
//! [`VirtualLayer`]: virt::VirtualLayer

pub mod cache;
/// Every mapping an address space holds, walked downward through the tables.
pub mod enumerate;
pub mod spec;
/// The hand-built page-table fixtures the upward walk and the downward
/// enumeration share, so the two cannot be tested against different images.
#[cfg(test)]
pub(crate) mod test_image;
pub mod virt;
pub mod walk;

/// ARM64 translation, proved against hand-written tables with hand-worked
/// expected addresses. In its own module because the fixture provenance —
/// synthetic, from the ARM ARM, with no capture to check against — is a fact
/// the file states once at its head.
#[cfg(test)]
mod arm64_tests;

pub use cache::{TableCache, TableShape, ENTRIES_PER_SHARD, TABLE_CACHE_SHARDS};
pub use enumerate::{
    Blindness, EnumerateCap, EnumerateLimits, EnumerateOutcome, MappingRun, MappingSink,
    RootParity, RunVia, SinkFlow, MAX_PROTOTYPE_HOPS_PER_SPACE, MAX_RUNS_PER_SPACE,
    MAX_TABLES_PER_SPACE,
};
pub use spec::{
    mask_bits, Arm64Granule, Arm64Regime, EntryKind, InvalidEntry, LeafRule, PageLevel, PagingMode,
    PagingSpec, PteSemantics, Ttbr, ARM64_MAX_VA_BITS, ARM64_MIN_VA_BITS, PAGE_OFFSET_BITS,
};
pub use virt::{SwapFile, VirtualLayer};
pub use walk::{
    unresolved_span, PageWalk, TranslateError, Translation, TranslationPath, TranslationPolicy,
    UNIFORM_TABLE_BYTES,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layer::{HoleReason, MemoryHole, MemoryLayer};
    use crate::physical::PhysicalLayer;
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::io::read_exact_or_fail;
    use std::sync::Arc;

    /// A whole x86-64 kernel address space, end to end: build the page tables a
    /// Windows kernel would have, wrap them in a layer, and prove that the
    /// primitives Séance already had behave correctly over virtual memory with
    /// no memory-specific code of their own.
    #[test]
    fn an_address_space_composes_with_the_primitives_seance_already_had() {
        const PML4: u64 = 0x1000;
        const PDPT: u64 = 0x2000;
        const PD: u64 = 0x3000;
        const PT: u64 = 0x4000;

        let mut bytes = vec![0u8; 0x10_0000];
        {
            let mut put = |table: u64, index: u64, value: u64| {
                let at = (table + index * 8) as usize;
                bytes[at..at + 8].copy_from_slice(&value.to_le_bytes());
            };
            // Kernel space: PML4 index 256 is the first index of the upper half.
            put(PML4, 256, PDPT | 1);
            put(PDPT, 0, PD | 1);
            put(PD, 0, PT | 1);
            put(PT, 0, 0x8000 | 1);
            // The next page is in a pagefile, not in this evidence item.
            put(PT, 1, (1u64 << 1) | (0x77u64 << 32));
        }
        // A recognisable structure at the start of the mapped page.
        bytes[0x8000..0x8008].copy_from_slice(&0xDEAD_BEEF_0000_0001u64.to_le_bytes());

        let physical: Arc<dyn MemoryLayer> =
            Arc::new(PhysicalLayer::raw(Arc::new(ByteSliceDataSource::new(bytes))).unwrap());
        let space = VirtualLayer::new(
            physical,
            PML4,
            PagingSpec::new(PagingMode::Intel32e, PteSemantics::Windows)
                .with_win8_pagefile_layout(false),
        )
        .expect("a usable directory table base");

        // A typed read of a kernel structure, through the shared helper.
        let mut field = [0u8; 8];
        read_exact_or_fail(
            space.as_data_source(),
            0xFFFF_8000_0000_0000,
            &mut field,
            "_EPROCESS.UniqueProcessId",
        )
        .expect("the page is mapped and acquired");
        assert_eq!(u64::from_le_bytes(field), 0xDEAD_BEEF_0000_0001);

        // The neighbouring page is on the suspect's disk. The helper refuses to
        // parse it, and the reason survives all the way to the caller.
        let err = read_exact_or_fail(
            space.as_data_source(),
            0xFFFF_8000_0000_1000,
            &mut field,
            "_EPROCESS.UniqueProcessId",
        )
        .expect_err("a paged-out structure must not parse");
        let hole = MemoryHole::from_io(&err).expect("a typed hole");
        assert_eq!(hole.reason, HoleReason::SwappedOut);
        assert_eq!(hole.to_json()["reason"], "swapped_out");

        // And the precise disk location is recoverable for an examiner who does
        // have the pagefile.
        match space.translate(0xFFFF_8000_0000_1000).unwrap_err() {
            TranslateError::SwappedOut {
                swap_index,
                swap_offset,
                ..
            } => {
                assert_eq!(swap_index, Some(1));
                assert_eq!(swap_offset, 0x77 << 12);
            }
            other => panic!("expected SwappedOut, got {other:?}"),
        }

        // Layer metadata carries the claim the whole address space rests on.
        let json = space.layer_meta().to_json();
        assert_eq!(json["notes"]["paging_mode"], "intel32e");
        assert_eq!(json["notes"]["directory_table_base"], PML4);
        assert_eq!(space.uniform_tables_suppressed(), 0);
    }
}
