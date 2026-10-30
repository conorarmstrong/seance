//! The ARM64 translation core, under Windows conventions, against the page tables of a second real **Windows 11 ARM64**
//! kernel (build 26300.9457, 4 KiB granule, 47-bit regimes) (`MEM-043`, `MEM-ARM-11`), compared with walkers written
//! independently of this crate, and what that build's own PDB says about a pagefile entry.
//!
//! # Evidence
//!
//! Microsoft's `Windows11_client_arm64_en-us_26300_9457.iso`, installed unattended (`autounattend.xml`: the
//! `LabConfig` bypasses, `Windows 11 Pro`, a local account) under `qemu-system-aarch64` 10.2.1 TCG (`-M virt,gic-version=3
//! -cpu cortex-a76 -smp 8 -m 6144`, edk2 firmware, NVMe disk, no network device), left at the first-logon "Still working
//! on a few things" screen, paused, RAM written by `pmemsave 0x40000000` and the registers read through the gdbstub
//! (`forensic_corpora/lab_winarm64/`). **QEMU-emulated, not ARM64 hardware.** The earlier capture, build 28000, is
//! `arm64_windows_real_test.rs`.
//!
//! | register | value |
//! |---|---|
//! | `TCR_EL1` | `0x0000_0695_b551_3511` (`T0SZ = T1SZ = 17`, 4 KiB both, `IPS = 5`, `HA`) |
//! | `TTBR0_EL1` | `0x0040_0000_400a_1000` (a 256-entry level 0 in the lower half of a shared page) |
//! | `TTBR1_EL1` | `0x0040_0000_400a_1800` (the upper half of that page) |
//!
//! The kernel is `ntkrnlmp.pdb` GUID `7A9F162A39E89C67CD02CF2126D51A65` age 1 (read from its `RSDS` record in the capture,
//! fetched from the symbol server, converted by Volatility's `pdbconv`). On it `_MMPTE_SOFTWARE.PageFileLow` is bits 9:6
//! and `PageFileHigh` bits 63:32; build 28000's is bits 17:14 and 63:32; `_MMPTE_PROTOTYPE` is `ProtoAddress` at 63:16
//! here and `ProtoIndex` at 53:12 there. `Prototype` (bit 10), `Transition` (bit 11) and `PageFileHigh` agree.
//!
//! # What the capture showed
//!
//! * **Séance named the wrong pagefile.** It read the pagefile index from bits 17:14 on any ARM64 Windows image, the one
//!   position build 28000 had. On this kernel those bits are zero in every pagefile entry, and `PageFileLow` is 1 in
//!   some: `swap_index: Some(0)` for an entry the kernel put in its second paging file. The index is now not stated on
//!   ARM64, as on an x64 image of unknown build; the offset, which did not move, is.
//! * Table descriptors carry `APTable[0] = 1` and `NSTable = 1` (bits 63:59 are `0x14`) on 48 of the 52 valid kernel
//!   level-0 entries and both user ones, and the self-map and three others carry none. This is the first real
//!   `APTable` bit met; the crate does not report access permissions, so it has nothing to fold it into
//!   (a decided limit), and no `XNTable` bit is set on either Windows build.
//! * The kernel half holds a self-map and five 512 GiB regions that alias, which is some 813 million leaves by path;
//!   whole-space enumeration refuses at its run cap and says so.
//!
//! # Running it
//!
//! `SEANCE_WINARM_26300` names the directory holding `mem.raw` (6 GiB, file offset 0 is physical `0x4000_0000`). Unset,
//! the tests skip. The samples are `winarm_26300_samples.in`, drawn by `scripts/oracle/winarm_walk_ram.py`.

use std::collections::BTreeMap;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::layer::MemoryLayer;
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::translate::{
    Arm64Regime, Blindness, EnumerateLimits, MappingRun, MappingSink, PageWalk, PagingMode,
    PagingSpec, PteSemantics, SinkFlow, TranslateError, Ttbr, VirtualLayer,
};
use seance_memory::{LayerMeta, MemoryImageFormat};

const CORPUS_VAR: &str = "SEANCE_WINARM_26300";
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 6 << 30;
const TCR: u64 = 0x0000_0695_b551_3511;
const TTBR0: u64 = 0x0040_0000_400a_1000;
const TTBR1: u64 = 0x0040_0000_400a_1800;

fn physical(dump: &Path) -> Arc<dyn MemoryLayer> {
    let source = FileDataSource::new(dump.to_path_buf()).expect("the corpus gate proved the dump");
    Arc::new(
        SegmentedLayer::new(
            Arc::new(source),
            vec![Segment::new(0, RAM_BASE, RAM_LEN)],
            LayerMeta::new(MemoryImageFormat::Raw),
        )
        .expect("one 6 GiB segment at 0x4000_0000"),
    )
}

fn space(dump: &Path, ttbr: Ttbr, register: u64) -> VirtualLayer {
    let regime = Arm64Regime::from_tcr_el1(TCR, ttbr).expect("the recorded TCR_EL1");
    VirtualLayer::new(
        physical(dump),
        register,
        PagingSpec::new(PagingMode::Arm64(regime), PteSemantics::Windows)
            .with_win8_pagefile_layout(true),
    )
    .expect("the recorded TTBR")
}

/// splitmix64's finaliser, the same function the independent walker used.
fn mix(x: u64) -> u64 {
    let mut x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

#[derive(Default)]
struct Leaves {
    by_size: BTreeMap<u64, u64>,
    digest: u64,
    blind: Vec<String>,
}

impl MappingSink for Leaves {
    fn run(&mut self, run: &MappingRun) -> SinkFlow {
        let mut offset = 0;
        while offset < run.len {
            let (va, pa) = (run.va_start + offset, run.phys_start + offset);
            *self.by_size.entry(run.page_bytes).or_default() += 1;
            self.digest = self
                .digest
                .wrapping_add(mix(va) ^ mix(pa.wrapping_add(run.page_bytes)));
            offset += run.page_bytes;
        }
        SinkFlow::Continue
    }

    fn blind(&mut self, blindness: &Blindness) -> SinkFlow {
        self.blind.push(format!("{blindness:?}"));
        SinkFlow::Continue
    }
}

/// One whole-space enumeration, with its outcome.
fn enumerate(
    dump: &Path,
    ttbr: Ttbr,
    register: u64,
) -> (Leaves, seance_memory::translate::EnumerateOutcome) {
    let space = space(dump, ttbr, register);
    let cache = space.table_cache();
    let suppressed = AtomicU64::new(0);
    let walk = PageWalk::new(
        &**space.physical(),
        space.spec(),
        cache,
        space.policy(),
        &suppressed,
    );
    let limits = EnumerateLimits {
        coalesce: false,
        ..EnumerateLimits::default()
    };
    let mut leaves = Leaves::default();
    let outcome = walk.enumerate(space.dtb(), &limits, &mut leaves);
    (leaves, outcome)
}

fn dump() -> Option<std::path::PathBuf> {
    corpus::file(CORPUS_VAR, "mem.raw")
}

/// The process tree of the capture: 83 4 KiB pages and 12 tables below the root, the answer of
/// `scripts/oracle/arm64_walk.py --granule 12` (digest `0xe89dd0eb5dad96fb`, no anomaly, no non-zero invalid descriptor).
#[test]
fn the_user_half_agrees_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    let (leaves, outcome) = enumerate(&dump, Ttbr::Ttbr0, TTBR0);
    assert!(leaves.blind.is_empty(), "{:?}", leaves.blind);
    assert!(outcome.is_complete(), "{outcome:?}");
    assert_eq!(outcome.tables_read, 13, "the root and its 12 tables");
    assert_eq!(leaves.by_size, BTreeMap::from([(0x1000, 83)]));
    assert_eq!(leaves.digest, 0xe89d_d0eb_5dad_96fb);
}

/// The kernel half cannot be listed whole: a self-map and five 512 GiB regions that alias. The enumeration stops at
/// its run cap, names the cap and the top indices it did not finish, and reports no leaf it did not read.
#[test]
fn the_kernel_half_is_refused_at_its_run_cap_and_says_so() {
    let Some(dump) = dump() else { return };
    let (leaves, outcome) = enumerate(&dump, Ttbr::Ttbr1, TTBR1);
    assert!(!outcome.is_complete(), "{outcome:?}");
    assert_eq!(
        format!("{:?}", outcome.caps_reached),
        "[Runs]",
        "{outcome:?}"
    );
    assert!(!outcome.incomplete_top_indices.is_empty());
    assert_eq!(outcome.runs, leaves.by_size.values().sum::<u64>());
}

/// 240 addresses drawn by a random descent of the real kernel half and translated by the independent walker
/// (`scripts/oracle/winarm_walk_ram.py`, seed 26300): valid pages and 2 MiB blocks, transition pages, pagefile entries,
/// prototype entries and absent ones.
#[test]
fn every_sampled_kernel_address_agrees_with_an_independent_walker() {
    let Some(dump) = dump() else { return };
    let space = space(&dump, Ttbr::Ttbr1, TTBR1);
    let samples: &[(u64, &str, u64, u64, u64)] = include!("winarm_26300_samples.in");
    let mut kinds = BTreeMap::<&str, u32>::new();
    for &(va, kind, a, size, entry) in samples {
        *kinds.entry(kind).or_default() += 1;
        match (kind, space.translate(va)) {
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
            ) => assert_eq!((e, swap_offset), (entry, (entry >> 32) << 12), "{va:#x}"),
            ("prototype", Err(TranslateError::PrototypePte { .. })) => {}
            (
                "absent",
                Err(TranslateError::NotPresent {
                    level, entry: e, ..
                }),
            ) => assert_eq!((level as u64, e), (a, entry), "{va:#x}"),
            (_, other) => panic!("{kind} {va:#x}: {other:?}"),
        }
    }
    assert_eq!(kinds.len(), 6, "{kinds:?}");
}

/// Four real pagefile entries whose `PageFileLow` (bits 9:6 on this build, by its PDB) is 1. Reading bits 17:14, as
/// build 28000's layout has it, named pagefile 0 for each; the index is now not stated, and the offset is.
#[test]
fn a_pagefile_entry_is_not_given_the_pagefile_index_of_another_build() {
    let Some(dump) = dump() else { return };
    let space = space(&dump, Ttbr::Ttbr1, TTBR1);
    for (va, entry) in [
        (0xffff_c881_f931_4000u64, 0x3f1e_d800_0040u64),
        (0xffff_c881_f917_0000, 0x3f25_f400_0040),
        (0xffff_c881_f8fb_8000, 0x3f1f_6c00_0040),
        (0xffff_c881_f92f_9000, 0x3f1e_ca00_0040),
    ] {
        assert_eq!((entry >> 6) & 0xf, 1, "the entry's own PageFileLow");
        match space.translate(va) {
            Err(TranslateError::SwappedOut {
                entry: e,
                swap_index,
                swap_offset,
                ..
            }) => {
                assert_eq!(e, entry, "{va:#x}");
                assert_eq!(swap_offset, (entry >> 32) << 12, "{va:#x}");
                assert_eq!(swap_index, None, "{va:#x}: no pagefile is named");
            }
            other => panic!("{va:#x}: expected a pagefile location, got {other:?}"),
        }
    }
}

/// Bits 63:59 of every valid table descriptor of the two level-0 tables, read straight from the file.
#[test]
fn the_real_table_descriptors_carry_aptable_and_nstable() {
    let Some(dump) = dump() else { return };
    let mut file = std::fs::File::open(dump).expect("open the capture");
    let mut tally = |root: u64| {
        let mut by_attr = BTreeMap::<String, u32>::new();
        for i in 0..256u64 {
            let mut b = [0u8; 8];
            file.seek(SeekFrom::Start(root - RAM_BASE + 8 * i)).unwrap();
            file.read_exact(&mut b).unwrap();
            let d = u64::from_le_bytes(b);
            if d & 1 == 1 {
                assert_eq!(d & 2, 2, "level 0 holds tables only");
                *by_attr.entry(format!("{:#x}", d >> 59)).or_default() += 1;
            }
        }
        by_attr
    };
    assert_eq!(
        tally(0x400a_1000),
        BTreeMap::from([("0x14".to_string(), 2)])
    );
    assert_eq!(
        tally(0x400a_1800),
        BTreeMap::from([("0x0".to_string(), 4), ("0x14".to_string(), 48)])
    );
}
