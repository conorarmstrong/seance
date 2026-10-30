//! The ARM64 translation core against the page tables of FreeBSD, NetBSD and HelenOS (`MEM-043`): three more QEMU
//! guests of the MMUShell dataset, walked from the translation-table base registers QEMU recorded and compared leaf by
//! leaf with an independent walker.
//!
//! # Evidence
//!
//! The MMUShell dataset (Oliveri & Balzarotti, "In the Land of MMUs", ACM TOPS 2022), `aarch64/freebsd.7z`,
//! `aarch64/netbsd.7z` and `aarch64/helenos.7z` (the dataset tar is `forensic_corpora/mmushell_dataset/mmushell_dataset.tar`,
//! provenance beside it). Each holds a RAM dump that its yaml places at physical `0x4000_0000` (4 GiB for the BSDs, 1 GiB
//! for HelenOS) and a `.regs` pickle of every `TCR_EL1`, `TTBR0_EL1` and `TTBR1_EL1` value QEMU saw; the pickle was read
//! without unpickling it (`forensic_corpora/mmushell_aarch64/regs_read.py`). **QEMU-emulated machines, not ARM64
//! hardware**; the tables are the guest kernels' own (FreeBSD's `pmap`, NetBSD's, HelenOS's), the first non-Linux ones this
//! crate has met.
//!
//! The independent answer is `scripts/oracle/arm64_walk.py --granule 12`, a stage-1 walker written from ARM DDI 0487
//! D8 without reference to this crate: leaf counts by size, the order-independent digest over `(va, pa, size)`, 16 spot
//! translations and the faults each tree gives (two at every depth the walk can stop at). It also counts the table
//! descriptors with attribute bits 63:59 set and the non-zero invalid descriptors. **No table descriptor in any of the
//! seven trees sets an `APTable`, `XNTable` or `PXNTable` bit. HelenOS's kernel root has 510 invalid descriptors
//! that are not zero** (`0x41d0a002`: the valid bit clear, the next-table address and bit 1 left in place), and two of
//! the faults pinned below stop at one: the first real non-zero invalid descriptors this crate has met outside a Linux
//! swap or `PROT_NONE` entry, and the entry the fault reports is the descriptor as written.
//!
//! # Running it
//!
//! `SEANCE_MMUSHELL_AARCH64` names a directory holding the extracted archives, `freebsd/freebsd.dump`,
//! `netbsd/netbsd.dump` and `helenos/helenos.dump`. Unset, every test here skips.
//!
//! # Registers (the latest the run recorded, `TCR_EL1` with the TTBR0 walk enabled)
//!
//! | OS | `TCR_EL1` | kernel `TTBR1_EL1` | process or boot `TTBR0_EL1` |
//! |---|---|---|---|
//! | FreeBSD | `0x14_b510_3510` | `0x1_3040_5000` | `0x1_3844_5000` (17,953 pages) |
//! | NetBSD | `0x12_b510_3510` | `0x1_3760_1000` | `0x01bb_0001_3d1d_0000` (ASID `0x1bb`, 3,360 pages) |
//! | HelenOS | `0x15_b510_3510` | `0x4000_4000` (529,649 pages) | `0x7fff_f000` (boot map: 7,167 pages, 1,099 2 MiB and 512 1 GiB blocks), `0x0005_0000_7c06_a000` |
//!
//! FreeBSD's last `TTBR0_EL1` is its kernel root again and several others walk to garbage (stale tables); the process
//! tree used maps pages and has only zero or valid entries. NetBSD's `TCR_EL1` also appears with `EPD0` set
//! (`0x12b5103590`, late in the run), which disables the `TTBR0` walk; the value with it clear is used. rCore (25
//! memory fragments), Barrelfish (a reserved `TG1` encoding) and Embox (`TCR_EL1 = 0x4000`: `TG0` = 64 KiB with
//! `T0SZ` = 0, outside the architecture's range) are in the dataset and not used here.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::layer::MemoryLayer;
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::translate::{
    Arm64Granule, Arm64Regime, Blindness, EnumerateLimits, MappingRun, MappingSink, PageWalk,
    PagingMode, PagingSpec, PteSemantics, SinkFlow, TranslateError, Ttbr, VirtualLayer,
};
use seance_memory::{LayerMeta, MemoryImageFormat};

const CORPUS_VAR: &str = "SEANCE_MMUSHELL_AARCH64";

/// Each yaml's `memspace.ram[0]` starts at `0x4000_0000`, file offset 0; the length is the dump's (4 GiB for FreeBSD
/// and NetBSD, 1 GiB for HelenOS).
const RAM_BASE: u64 = 0x4000_0000;

fn bits(value: u64, high: u32, low: u32) -> u64 {
    (value >> low) & ((1u64 << (high - low + 1)) - 1)
}

/// The regime a recorded `TCR_EL1` selects for one TTBR, through the crate's
/// own decoder ([`Arm64Regime::from_tcr_el1`]); the field-by-field reading it
/// must agree with is spelled out in the test below.
fn regime_from_tcr(tcr: u64, ttbr: Ttbr) -> Arm64Regime {
    Arm64Regime::from_tcr_el1(tcr, ttbr)
        .unwrap_or_else(|e| panic!("TCR_EL1 {tcr:#x} {ttbr:?} refused: {e}"))
}

fn physical(dump: &Path) -> Arc<dyn MemoryLayer> {
    let source =
        FileDataSource::new(dump.to_path_buf()).expect("the corpus gate proved the dump exists");
    let ram_len = std::fs::metadata(dump).expect("dump metadata").len();
    let layer = SegmentedLayer::new(
        Arc::new(source),
        vec![Segment::new(0, RAM_BASE, ram_len)],
        LayerMeta::new(MemoryImageFormat::Raw),
    )
    .expect("one 4 GiB segment at 0x4000_0000");
    Arc::new(layer)
}

fn space(dump: &Path, tcr: u64, ttbr: Ttbr, register: u64) -> VirtualLayer {
    let spec = PagingSpec::new(
        PagingMode::Arm64(regime_from_tcr(tcr, ttbr)),
        PteSemantics::Linux,
    );
    VirtualLayer::new(physical(dump), register, spec)
        .unwrap_or_else(|e| panic!("TTBR {register:#x} refused: {e}"))
}

/// splitmix64's finaliser, the same function the independent walker used.
fn mix(x: u64) -> u64 {
    let mut x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    x ^ (x >> 31)
}

/// Every leaf the crate's own downward walk reports, one entry per page or
/// block, and every blindness.
#[derive(Default)]
struct Leaves {
    by_size: BTreeMap<u64, u64>,
    digest: u64,
    blind: Vec<String>,
}

impl MappingSink for Leaves {
    fn run(&mut self, run: &MappingRun) -> SinkFlow {
        assert!(
            run.page_bytes > 0 && run.len.is_multiple_of(run.page_bytes),
            "{run:?}"
        );
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

struct Expected {
    /// Leaves by size: 4 KiB pages, 2 MiB blocks, 1 GiB blocks.
    pages: u64,
    blocks_2m: u64,
    blocks_1g: u64,
    digest: u64,
    /// `(va, pa, size of the page or block it lies in)`.
    spots: &'static [(u64, u64, u64)],
    /// `(va, index of the level whose descriptor is invalid, that descriptor,
    /// its physical address)`.
    faults: &'static [(u64, u8, u64, u64)],
}

fn check(dump: &Path, tcr: u64, ttbr: Ttbr, register: u64, expected: &Expected) {
    let space = space(dump, tcr, ttbr, register);

    for &(va, pa, size) in expected.spots {
        let t = space
            .translate(va)
            .unwrap_or_else(|e| panic!("{va:#x} should translate to {pa:#x}: {e}"));
        assert_eq!(t.phys, pa, "{va:#x}");
        assert_eq!(t.run_len, size, "{va:#x}: page or block size");
    }

    for &(va, level, entry, entry_pa) in expected.faults {
        match space.translate(va) {
            Err(TranslateError::NotPresent {
                level: l,
                entry: e,
                entry_pa: at,
                ..
            }) => assert_eq!(
                (l, e, at),
                (level, entry, entry_pa),
                "{va:#x}: (level, entry, entry address)"
            ),
            other => panic!("{va:#x} should fault at level {level}: {other:?}"),
        }
    }

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
    assert!(leaves.blind.is_empty(), "{:?}", leaves.blind);
    assert!(outcome.is_complete(), "{outcome:?}");

    let want: BTreeMap<u64, u64> = [
        (0x1000, expected.pages),
        (0x20_0000, expected.blocks_2m),
        (0x4000_0000, expected.blocks_1g),
    ]
    .into_iter()
    .filter(|&(_, n)| n > 0)
    .collect();
    assert_eq!(leaves.by_size, want, "leaves by size");
    assert_eq!(
        leaves.digest, expected.digest,
        "digest over every leaf's (va, pa, size) disagrees with the independent walker"
    );
}

fn dump(os: &str) -> Option<std::path::PathBuf> {
    corpus::file(CORPUS_VAR, &format!("{os}/{os}.dump"))
}

const FREEBSD_TCR: u64 = 0x14_b510_3510;
const NETBSD_TCR: u64 = 0x12_b510_3510;
const HELENOS_TCR: u64 = 0x15_b510_3510;

/// The recorded `TCR_EL1` values decode to the regimes the manual gives them: 4 KiB granule, 48-bit, in both halves.
#[test]
fn the_recorded_tcr_values_select_4k_regimes_of_48_bits() {
    for tcr in [FREEBSD_TCR, NETBSD_TCR, HELENOS_TCR] {
        for ttbr in [Ttbr::Ttbr0, Ttbr::Ttbr1] {
            let regime = regime_from_tcr(tcr, ttbr);
            assert_eq!(regime.granule(), Arm64Granule::Kb4, "{tcr:#x}");
            assert_eq!(regime.va_bits(), 48, "{tcr:#x} {ttbr:?}");
            assert!(!regime.walks_disabled());
        }
        assert_eq!(bits(tcr, 15, 14), 0b00, "TG0: 4K");
        assert_eq!(bits(tcr, 31, 30), 0b10, "TG1: 4K");
        assert_eq!(64 - bits(tcr, 5, 0), 48, "T0SZ");
        assert_eq!(64 - bits(tcr, 21, 16), 48, "T1SZ");
        assert_eq!(bits(tcr, 59, 59), 0, "DS: no LPA2");
    }
    // FreeBSD programs a 44-bit IPS, NetBSD a 40-bit one, HelenOS a 48-bit one.
    assert_eq!(regime_from_tcr(FREEBSD_TCR, Ttbr::Ttbr1).ips_bits(), 44);
    assert_eq!(regime_from_tcr(NETBSD_TCR, Ttbr::Ttbr1).ips_bits(), 40);
    assert_eq!(regime_from_tcr(HELENOS_TCR, Ttbr::Ttbr1).ips_bits(), 48);
}

/// Embox's recorded `TCR_EL1` is `0x4000` while its `SCTLR` has the MMU on: `TG0` = 64 KiB with `T0SZ` = 0, a 64-bit
/// input address the 64 KiB granule does not support (its minimum `T0SZ` is 16, or 12 with a 52-bit VA). The crate
/// refuses it and says why, rather than guess what the emulator did with it.
#[test]
fn a_recorded_tcr_with_a_64k_granule_and_a_zero_t0sz_is_refused_not_guessed() {
    let err = Arm64Regime::from_tcr_el1(0x4000, Ttbr::Ttbr0)
        .expect_err("T0SZ = 0 at 64 KiB must be refused");
    assert!(err.to_string().contains("wider than 48 bits"), "{err}");
}

#[test]
fn freebsd_kernel_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("freebsd") else { return };
    check(
        &dump,
        FREEBSD_TCR,
        Ttbr::Ttbr1,
        0x1_3040_5000,
        &Expected {
            pages: 71633,
            blocks_2m: 524,
            blocks_1g: 3,
            digest: 0x969f7ec1250fec60,
            spots: FREEBSD_TTBR1_SPOTS,
            faults: FREEBSD_TTBR1_FAULTS,
        },
    );
}

#[test]
fn freebsd_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("freebsd") else { return };
    check(
        &dump,
        FREEBSD_TCR,
        Ttbr::Ttbr0,
        0x1_3844_5000,
        &Expected {
            pages: 17953,
            blocks_2m: 0,
            blocks_1g: 0,
            digest: 0x4f58a5066c6e2725,
            spots: FREEBSD_TTBR0_SPOTS,
            faults: FREEBSD_TTBR0_FAULTS,
        },
    );
}

#[test]
fn netbsd_kernel_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("netbsd") else { return };
    check(
        &dump,
        NETBSD_TCR,
        Ttbr::Ttbr1,
        0x1_3760_1000,
        &Expected {
            pages: 26822,
            blocks_2m: 514,
            blocks_1g: 3,
            digest: 0x1d18bd8829008a7a,
            spots: NETBSD_TTBR1_SPOTS,
            faults: NETBSD_TTBR1_FAULTS,
        },
    );
}

#[test]
fn netbsd_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("netbsd") else { return };
    check(
        &dump,
        NETBSD_TCR,
        Ttbr::Ttbr0,
        0x01bb_0001_3d1d_0000,
        &Expected {
            pages: 3360,
            blocks_2m: 0,
            blocks_1g: 0,
            digest: 0xfcb3119d97b15ab1,
            spots: NETBSD_TTBR0_SPOTS,
            faults: NETBSD_TTBR0_FAULTS,
        },
    );
}

/// HelenOS's kernel root holds 510 invalid descriptors that are not zero; the faults pinned here include two that
/// stop at one, and the entry reported is the descriptor as written.
#[test]
fn helenos_kernel_tables_agree_with_an_independent_walker_on_every_leaf_and_report_a_non_zero_invalid_descriptor_as_written(
) {
    let Some(dump) = dump("helenos") else { return };
    check(
        &dump,
        HELENOS_TCR,
        Ttbr::Ttbr1,
        0x4000_4000,
        &Expected {
            pages: 529649,
            blocks_2m: 0,
            blocks_1g: 0,
            digest: 0x75f7d6062e1b8b65,
            spots: HELENOS_TTBR1_SPOTS,
            faults: HELENOS_TTBR1_FAULTS,
        },
    );
}

#[test]
fn helenos_boot_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("helenos") else { return };
    check(
        &dump,
        HELENOS_TCR,
        Ttbr::Ttbr0,
        0x7fff_f000,
        &Expected {
            pages: 7167,
            blocks_2m: 1099,
            blocks_1g: 512,
            digest: 0x56bb8fbccf32f4d2,
            spots: HELENOS_TTBR0_BOOT_SPOTS,
            faults: HELENOS_TTBR0_BOOT_FAULTS,
        },
    );
}

#[test]
fn helenos_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("helenos") else { return };
    check(
        &dump,
        HELENOS_TCR,
        Ttbr::Ttbr0,
        0x0005_0000_7c06_a000,
        &Expected {
            pages: 1010,
            blocks_2m: 0,
            blocks_1g: 0,
            digest: 0x598e5e81793a16ef,
            spots: HELENOS_TTBR0_SPOTS,
            faults: HELENOS_TTBR0_FAULTS,
        },
    );
}

const FREEBSD_TTBR1_SPOTS: &[(u64, u64, u64)] = &[
    (0xffff000063aef885, 0x4012cef885, 0x1000),
    (0xffff000061673752, 0x4010873752, 0x1000),
    (0xffff0000678bc345, 0x4016abc345, 0x1000),
    (0xffff000063283a28, 0x4012483a28, 0x1000),
    (0xffff00006f3cd0fa, 0x401e5cd0fa, 0x1000),
    (0xffff00006dc470b6, 0x401ce470b6, 0x1000),
    (0xffff00006e7ee0d0, 0x401d9ee0d0, 0x1000),
    (0xffff00006b88004b, 0x401aa8004b, 0x1000),
    (0xffff0000661a3c32, 0x40153a3c32, 0x1000),
    (0xffff0000626326ee, 0x40118326ee, 0x1000),
    (0xffff00006efecd81, 0x401e1ecd81, 0x1000),
    (0xffff0000414fc0ed, 0x1382fc0ed, 0x1000),
    (0xffff00006bdb9718, 0x401afb9718, 0x1000),
    (0xffff00006d3b7e03, 0x401c5b7e03, 0x1000),
    (0xffff00004035cfdd, 0x44936fdd, 0x1000),
    (0xffff00006da2d775, 0x401cc2d775, 0x1000),
];

const FREEBSD_TTBR1_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffff7634587fd280, 0, 0x0, 0x130405760),
    (0xffff7004ad45f23d, 0, 0x0, 0x130405700),
    (0xfffffd7a501fc6f4, 1, 0x0, 0x130408f48),
    (0xfffffd733bb42d9d, 1, 0x0, 0x130408e60),
    (0xffff006e52dd34d6, 2, 0x0, 0x131a5d4b0),
    (0xffff004db2867e2f, 2, 0x0, 0x1319daca0),
    (0xffff000041d3a000, 3, 0x0, 0x400779d0),
    (0xffff000041e99000, 3, 0x0, 0x400784c8),
];

const FREEBSD_TTBR0_SPOTS: &[(u64, u64, u64)] = &[
    (0x5132885, 0x5132885, 0x1000),
    (0x4813752, 0x4813752, 0x1000),
    (0x60a6345, 0x60a6345, 0x1000),
    (0x4f17a28, 0x4f17a28, 0x1000),
    (0x7f6a0fa, 0x7f6a0fa, 0x1000),
    (0x79880b6, 0x79880b6, 0x1000),
    (0x7c720d0, 0x7c720d0, 0x1000),
    (0x709704b, 0x709704b, 0x1000),
    (0x5adfc32, 0x5adfc32, 0x1000),
    (0x4c036ee, 0x4c036ee, 0x1000),
    (0x7e72d81, 0x7e72d81, 0x1000),
    (0x43a00ed, 0x43a00ed, 0x1000),
    (0x71e5718, 0x71e5718, 0x1000),
    (0x7764e03, 0x7764e03, 0x1000),
    (0x4045fdd, 0x4045fdd, 0x1000),
    (0x7902775, 0x7902775, 0x1000),
];

const FREEBSD_TTBR0_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0x7634587fd280, 0, 0x0, 0x138445760),
    (0x7004ad45f23d, 0, 0x0, 0x138445700),
    (0x6e52dd34d6, 1, 0x0, 0x138444dc8),
    (0x4db2867e2f, 1, 0x0, 0x1384449b0),
    (0x3e29000, 2, 0x0, 0x131afe0f8),
    (0x138860000, 2, 0x0, 0x138443e20),
    (0x13845e000, 3, 0x0, 0x1384422f0),
    (0x138401000, 3, 0x0, 0x138442008),
];

const NETBSD_TTBR1_SPOTS: &[(u64, u64, u64)] = &[
    (0xffff8000009c0f9c, 0x43c0f9c, 0x1000),
    (0xffff8000041690e8, 0x7b690e8, 0x1000),
    (0xffffffc063d6ac79, 0x13da82c79, 0x1000),
    (0xffffffc06343edd9, 0x134636dd9, 0x1000),
    (0xffff8000000a1011, 0x1385d1011, 0x1000),
    (0xffff800001934e40, 0x5334e40, 0x1000),
    (0xffff8000007a5885, 0x41a5885, 0x1000),
    (0xffff8000037f8752, 0x71f8752, 0x1000),
    (0xffffffc0633e1345, 0x134696345, 0x1000),
    (0xffff800003216a28, 0x6c16a28, 0x1000),
    (0xffff8000035000fa, 0x6f000fa, 0x1000),
    (0xffffffc0036770b6, 0x13f92c0b6, 0x1000),
    (0xffff8000029250d0, 0x63250d0, 0x1000),
    (0xffffffc063b9004b, 0x13e6f604b, 0x1000),
    (0xffff80000136dc32, 0x4d6dc32, 0x1000),
    (0xffff8000004916ee, 0x13be916ee, 0x1000),
];

const NETBSD_TTBR1_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffffd81ff8130c42, 0, 0x0, 0x137601d80),
    (0xffff0edeb9d179e0, 0, 0x0, 0x1376010e8),
    (0xffffffe5810d2e30, 1, 0x0, 0x137605cb0),
    (0xffff804e27e125a4, 1, 0x0, 0x1376079c0),
    (0xffffffc002f53000, 2, 0x0, 0x1376060b8),
    (0xffffffc002d53000, 2, 0x0, 0x1376060b0),
    (0xffffffc063132000, 3, 0x0, 0x13dd20990),
    (0xffffffc062f28000, 3, 0x0, 0x13f171940),
];

const NETBSD_TTBR0_SPOTS: &[(u64, u64, u64)] = &[
    (0xf9152243df9c, 0x135579f9c, 0x1000),
    (0xf9152331c0e8, 0x139eb50e8, 0x1000),
    (0xf91523c86c79, 0x13cef4c79, 0x1000),
    (0xf91523be8dd9, 0x13d1eadd9, 0x1000),
    (0xf915220fa011, 0x138882011, 0x1000),
    (0xf915226d8e40, 0x139215e40, 0x1000),
    (0xf915223d3885, 0x135577885, 0x1000),
    (0xf91523171752, 0x13a0cb752, 0x1000),
    (0xf91523bc7345, 0x13e6b3345, 0x1000),
    (0xf915230afa28, 0x139bdca28, 0x1000),
    (0xf915231120fa, 0x13a23e0fa, 0x1000),
    (0xf9152371e0b6, 0x13ceb50b6, 0x1000),
    (0xf9152299c0d0, 0x139c170d0, 0x1000),
    (0xf91523c4e04b, 0x13ce0804b, 0x1000),
    (0xf915225f8c32, 0x13909fc32, 0x1000),
    (0xf915223656ee, 0x1354e26ee, 0x1000),
];

const NETBSD_TTBR0_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xd81ff8130c42, 0, 0x0, 0x13d1d0d80),
    (0xedeb9d179e0, 0, 0x0, 0x13d1d00e8),
    (0xffe5810d2e30, 1, 0x0, 0x13d20dcb0),
    (0x6e52dd34d6, 1, 0x0, 0x13d20fdc8),
    (0xf91522c32000, 2, 0x0, 0x13d1bb8b0),
    (0xf91523f32000, 2, 0x0, 0x13d1bb8f8),
    (0xf91522836000, 3, 0x0, 0x139cad1b0),
    (0xf9152283a000, 3, 0x0, 0x139cad1d0),
];

const HELENOS_TTBR1_SPOTS: &[(u64, u64, u64)] = &[
    (0xffffffffa116a885, 0x6116a885, 0x1000),
    (0xffffffff8ed8b752, 0x4ed8b752, 0x1000),
    (0xffffffffbffd2345, 0x7ffd2345, 0x1000),
    (0xffffffff9ce0da28, 0x5ce0da28, 0x1000),
    (0xfffffffffd85c0fa, 0xbd85c0fa, 0x1000),
    (0xfffffffff1c2c0b6, 0xb1c2c0b6, 0x1000),
    (0xfffffffff79600d0, 0xb79600d0, 0x1000),
    (0xffffffffdfdf604b, 0x9fdf604b, 0x1000),
    (0xffffffffb4708c32, 0x74708c32, 0x1000),
    (0xffffffff96b816ee, 0x56b816ee, 0x1000),
    (0xfffffffffb951d81, 0xbb951d81, 0x1000),
    (0xffffffff85f2b0ed, 0x45f2b0ed, 0x1000),
    (0xffffffffe27b7718, 0xa27b7718, 0x1000),
    (0xffffffffed7ace03, 0xad7ace03, 0x1000),
    (0xffff0000008a1fdd, 0x409b3fdd, 0x1000),
    (0xfffffffff0b5d775, 0xb0b5d775, 0x1000),
];

const HELENOS_TTBR1_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffff7634587fd280, 0, 0x41df5002, 0x40004760),
    (0xffff7004ad45f23d, 0, 0x41de9002, 0x40004700),
    (0xffffffe5810d2e30, 1, 0x0, 0x40005cb0),
    (0xffff006e52dd34d6, 1, 0x0, 0x41f0ddc8),
    (0xffff00000167f000, 2, 0x0, 0x41f0e058),
    (0xffff000001695000, 2, 0x0, 0x41f0e058),
    (0xffff00000157b000, 3, 0x0, 0x7c089bd8),
    (0xffff0000015da000, 3, 0x0, 0x7c089ed0),
];

const HELENOS_TTBR0_BOOT_SPOTS: &[(u64, u64, u64)] = &[
    (0x416b9885, 0x416b9885, 0x1000),
    (0x3ee33752, 0x3ee33752, 0x1000),
    (0x69139345, 0x69139345, 0x1000),
    (0x401b5a28, 0x401b5a28, 0x1000),
    (0x7ffeb0fa, 0x7ffeb0fa, 0x1000),
    (0x7f6fd0b6, 0x7f6fd0b6, 0x1000),
    (0x7fe6f0d0, 0x7fe6f0d0, 0x1000),
    (0x7baa004b, 0x7baa004b, 0x1000),
    (0x68858c32, 0x68858c32, 0x1000),
    (0x4002b6ee, 0x4002b6ee, 0x1000),
    (0x7ff6fd81, 0x7ff6fd81, 0x1000),
    (0x1d10ed, 0x1d10ed, 0x1000),
    (0x7bb47718, 0x7bb47718, 0x1000),
    (0x7cdc0659, 0x7cdc0659, 0x200000),
    (0x23fdd, 0x23fdd, 0x1000),
    (0x7f6ba775, 0x7f6ba775, 0x1000),
];

const HELENOS_TTBR0_BOOT_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0x7634587fd280, 0, 0x0, 0x7ffff760),
    (0x7004ad45f23d, 0, 0x0, 0x7ffff700),
    (0x6e52dd34d6, 1, 0x0, 0x7fffedc8),
    (0x4db2867e2f, 1, 0x0, 0x7fffe9b0),
    (0x317000, 2, 0x0, 0x7fffd008),
    (0x517000, 2, 0x0, 0x7fffd010),
    (0x0, 3, 0x0, 0x7fffc000),
    (0x0, 3, 0x0, 0x7fffc000),
];

const HELENOS_TTBR0_SPOTS: &[(u64, u64, u64)] = &[
    (0xc6b300, 0x40a25300, 0x1000),
    (0x1076f9c, 0x40e30f9c, 0x1000),
    (0x12710e8, 0x4102b0e8, 0x1000),
    (0x1239c79, 0x40ff3c79, 0x1000),
    (0x1208dd9, 0x40fc2dd9, 0x1000),
    (0x45e011, 0x40218011, 0x1000),
    (0xe85e40, 0x40c3fe40, 0x1000),
    (0xa20885, 0x407da885, 0x1000),
    (0xfe6752, 0x40da0752, 0x1000),
    (0x1205345, 0x40fbf345, 0x1000),
    (0xfa8a28, 0x40d62a28, 0x1000),
    (0xfc60fa, 0x40d800fa, 0x1000),
    (0x113a0b6, 0x40ef40b6, 0x1000),
    (0xf4b0d0, 0x40d050d0, 0x1000),
    (0x122b04b, 0x40fe504b, 0x1000),
    (0xdf5c32, 0x40bafc32, 0x1000),
];

const HELENOS_TTBR0_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0x6ee6afbd67f9, 0, 0x0, 0x7c06a6e8),
    (0xd81ff8130c42, 0, 0x0, 0x7c06ad80),
    (0xffe5810d2e30, 1, 0x0, 0x7c11ccb0),
    (0x6e52dd34d6, 1, 0x0, 0x7c118dc8),
    (0x619000, 2, 0x0, 0x7c119018),
    (0x7a7000, 2, 0x0, 0x7c119018),
    (0xe8f000, 3, 0x0, 0x7c7b9478),
    (0xc85000, 3, 0x0, 0x7c225428),
];
