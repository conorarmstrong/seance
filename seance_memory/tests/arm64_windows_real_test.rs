//! The ARM64 translation core, under Windows conventions, against the page tables of a real
//! **Windows 11 ARM64** kernel (build 28000, 4 KiB granule, 47-bit regimes), compared leaf for
//! leaf with a walker written independently of this crate (`winarm_28000_qemu/digest.py`).
//!
//! # Evidence
//!
//! Captured 2026-10-23 on this host: the Windows 11 ARM64 install under `qemu-system-aarch64`
//! 10.0.11 (TCG, `-machine virt -cpu max -m 6G`, from the 2026-08 install in `winarm/`), booted to
//! the lock screen, RAM written by QMP `dump-guest-memory` and flattened by `elf2raw.py`, the
//! translation registers read through the gdbstub (`forensic_corpora/winarm_28000_qemu/`).
//! **QEMU-emulated, not ARM64 hardware.**
//!
//! # Ground truth
//!
//! | register | value |
//! |---|---|
//! | `TCR_EL1` | `0x0000_0695_b551_3511` (`T0SZ = T1SZ = 17`, 4 KiB both, `IPS = 5`, `HPD0`, `HA`) |
//! | `TTBR1_EL1` | `0x09c0_0001_4dbd_d800` (a 256-entry level 0 in the upper half of a shared page) |
//!
//! The software-PTE layout (`_MMPTE_TRANSITION`, `_MMPTE_PROTOTYPE`, `_MMPTE_SOFTWARE`) comes from
//! Microsoft's own PDB for the kernel the capture holds (`ntkrnlmp.pdb` GUID
//! `0382994831D35A1367EF9CC7C56B3F26`, age 1, converted by Volatility's `pdbconv`;
//! `forensic_corpora/winarm_symbols/`). The independent walker applies those positions and
//! nothing else of this crate.
//!
//! # Running it
//!
//! `SEANCE_WINARM_28000` names the directory holding `mem.raw`. Unset, the tests skip.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::layer::MemoryLayer;
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::translate::{
    Arm64Regime, PagingMode, PagingSpec, PteSemantics, TranslateError, Ttbr, VirtualLayer,
};
use seance_memory::{LayerMeta, MemoryImageFormat};

const CORPUS_VAR: &str = "SEANCE_WINARM_28000";
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 6 << 30;
const TCR: u64 = 0x0000_0695_b551_3511;
const TTBR1: u64 = 0x09c0_0001_4dbd_d800;

fn space(dump: &Path) -> VirtualLayer {
    let source = FileDataSource::new(dump.to_path_buf()).expect("the corpus gate proved the dump");
    let physical: Arc<dyn MemoryLayer> = Arc::new(
        SegmentedLayer::new(
            Arc::new(source),
            vec![Segment::new(RAM_BASE, RAM_BASE, RAM_LEN)],
            LayerMeta::new(MemoryImageFormat::Raw),
        )
        .expect("one 6 GiB segment at 0x4000_0000"),
    );
    let regime = Arm64Regime::from_tcr_el1(TCR, Ttbr::Ttbr1).expect("the recorded TCR_EL1");
    VirtualLayer::new(
        physical,
        TTBR1,
        PagingSpec::new(PagingMode::Arm64(regime), PteSemantics::Windows)
            .with_win8_pagefile_layout(true),
    )
    .expect("the recorded TTBR1")
}

/// Every entry kind, over 240 addresses drawn by a random descent of the real kernel half
/// (`winarm_28000_qemu/samples.py`, seed 28000, so aliased and self-mapped regions are sampled
/// too) and translated by the independent walker: valid pages and 2 MiB blocks, transition
/// pages (valid clear, bit 11 set), pagefile entries, prototype entries and absent ones.
///
/// Whole-space enumeration is not compared: the kernel half holds a self-map (index 83) and six
/// 512 GiB regions that alias, which is some 813 million leaves, and the enumerator refuses at its
/// run cap and says so (`Blindness::Capped`).
#[test]
fn every_sampled_kernel_address_agrees_with_an_independent_walker() {
    let Some(dump) = corpus::file(CORPUS_VAR, "mem.raw") else {
        return;
    };
    let space = space(&dump);
    let samples: &[(u64, &str, u64, u64, u64)] = include!("winarm_28000_samples.in");
    let mut kinds = BTreeMap::<&str, u32>::new();
    for &(va, kind, a, size, entry) in samples {
        *kinds.entry(kind).or_default() += 1;
        let got = space.translate(va);
        match (kind, got) {
            ("page" | "block" | "transition", Ok(t)) => {
                assert_eq!((t.phys, t.run_len), (a, size), "{kind} {va:#x}")
            }
            (
                "pagefile",
                Err(TranslateError::SwappedOut {
                    entry: e,
                    swap_offset,
                    ..
                }),
            ) => {
                assert_eq!((e, swap_offset), (entry, (entry >> 32) << 12), "{va:#x}")
            }
            ("prototype", Err(TranslateError::PrototypePte { .. })) => {}
            (
                "absent",
                Err(TranslateError::NotPresent {
                    level, entry: e, ..
                }),
            ) => {
                assert_eq!((level as u64, e), (a, entry), "{va:#x}")
            }
            (_, other) => panic!("{kind} {va:#x}: {other:?}"),
        }
    }
    assert_eq!(kinds.len(), 6, "{kinds:?}");
}

/// One real entry of each software kind, each found by the independent walker and classified by
/// the PDB layout alone.
#[test]
fn a_real_transition_pagefile_and_prototype_entry_are_each_named() {
    let Some(dump) = corpus::file(CORPUS_VAR, "mem.raw") else {
        return;
    };
    let space = space(&dump);
    // 0x1bd73f808: valid clear, Protection 4, transition set, frame 0x1bd73f000.
    let t = space
        .translate(0xffff_ca89_1320_5123)
        .expect("a transition page is recovered");
    assert_eq!(t.phys, 0x1_bd73_f123);
    assert_eq!(t.run_len, 0x1000);
    // 0x3ba520000000: PageFileLow 0, PageFileHigh 0x3ba5 (bit 29 is Reserved1). No index is stated: PageFileLow
    // is at bits 17:14 on this build and 9:6 on build 26300 (`arm64_windows_26300_real_test.rs`).
    match space.translate(0xffff_8081_dc52_9000) {
        Err(TranslateError::SwappedOut {
            swap_index: None,
            swap_offset,
            entry,
            ..
        }) => {
            assert_eq!(entry, 0x3ba5_2000_0000);
            assert_eq!(swap_offset, 0x3ba5 << 12);
        }
        other => panic!("expected a pagefile location, got {other:?}"),
    }
    // 0x122840445400: Prototype set, ProtoIndex in bits 53:12, not followed.
    match space.translate(0xffff_950a_c027_1000) {
        Err(TranslateError::PrototypePte { .. }) => {}
        other => panic!("expected an unfollowed prototype PTE, got {other:?}"),
    }
}
