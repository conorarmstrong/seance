//! The ARM64 translation core against real **LPA2** page tables (`TCR_EL1.DS = 1`, a 52-bit
//! regime) of a 16 KiB-granule Linux guest, compared address by address with a walker written
//! independently of this crate (`scripts/oracle/arm64_walk.py`).
//!
//! # Evidence
//!
//! Captured 2026-10-22 on this host by `qemu-system-aarch64` 10.2.1 (TCG, `-M virt -cpu max -m
//! 512`; `-cpu max` offers FEAT_LPA2, which the sibling capture withheld with `lpa2=off`),
//! booting Debian trixie's `linux-image-6.12.107+deb13-arm64-16k-unsigned` with a busybox
//! initramfs, paused over QMP, RAM saved with `pmemsave 0x40000000 512M`, and the translation
//! registers read through the gdbstub (`forensic_corpora/arm64_16k_lpa2_qemu/SOURCE.md`, which
//! records the recipe, `run.sh` and `gdbregs.py`). **QEMU-emulated, not ARM64 hardware.**
//!
//! # Ground truth
//!
//! | register | value |
//! |---|---|
//! | `TCR_EL1` | `0x0950_01f6_754c_b50c` |
//! | `TTBR1_EL1` | `0x0014_0000_41f5_4001` (ASID `0x14`, `CnP`) |
//! | `TTBR0_EL1` | `0x0000_0000_441f_6401` (init's `pgd`, `CnP`) |
//!
//! `TCR_EL1` decodes to `TG0 = 0b10` and `TG1 = 0b01` (both 16 KiB), `T0SZ = T1SZ = 12` (52-bit
//! regimes: level 0 holds 32 entries above three full levels), `IPS = 0b110` (52-bit) and
//! `DS = 1`.
//!
//! # The independent answer, and what it does not exercise
//!
//! The walker was first run on the non-LPA2 sibling capture and reproduced its pinned counts
//! and digest exactly (35,417 pages and 8 blocks, digest `0x742b_d1b6_db01_7400`), then run on
//! these tables. Every leaf it found has output-address bits 51:48 clear, so **the evidence does
//! not exercise the high address bits**: it shows that a DS = 1 tree of this shape (a 52-bit
//! virtual width, a 32-entry start level, descriptors whose bits 9:8 are address bits and not
//! shareability) is walked leaf for leaf, and nothing about a frame above 2^48, which the
//! synthetic tests in `translate/arm64_tests.rs` pin from the manual only.
//!
//! # Running it
//!
//! `SEANCE_ARM64_16K_LPA2` names the directory holding `mem.raw` (physical
//! `0x4000_0000..0x6000_0000`). Unset, the tests skip and say so; set to a directory without
//! the dump, they panic.

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

const CORPUS_VAR: &str = "SEANCE_ARM64_16K_LPA2";

/// `-M virt` RAM: `0x4000_0000`, 512 MiB, file offset 0.
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 512 << 20;

/// Read through the gdbstub with the guest paused (`regs.py` in the capture
/// recipe).
const TCR: u64 = 0x0950_01f6_754c_b50c;
const TTBR1: u64 = 0x0014_0000_41f5_4001;
const TTBR0: u64 = 0x441f_6401;

fn bits(value: u64, high: u32, low: u32) -> u64 {
    (value >> low) & ((1u64 << (high - low + 1)) - 1)
}

fn regime_from_tcr(tcr: u64, ttbr: Ttbr) -> Arm64Regime {
    Arm64Regime::from_tcr_el1(tcr, ttbr)
        .unwrap_or_else(|e| panic!("TCR_EL1 {tcr:#x} {ttbr:?} refused: {e}"))
}

fn physical(dump: &Path) -> Arc<dyn MemoryLayer> {
    let source =
        FileDataSource::new(dump.to_path_buf()).expect("the corpus gate proved the dump exists");
    let layer = SegmentedLayer::new(
        Arc::new(source),
        vec![Segment::new(0, RAM_BASE, RAM_LEN)],
        LayerMeta::new(MemoryImageFormat::Raw),
    )
    .expect("one 512 MiB segment at 0x4000_0000");
    Arc::new(layer)
}

fn space(dump: &Path, ttbr: Ttbr, register: u64) -> VirtualLayer {
    let spec = PagingSpec::new(
        PagingMode::Arm64(regime_from_tcr(TCR, ttbr)),
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
    /// 16 KiB pages (level 3).
    pages: u64,
    /// 32 MiB blocks (level 2).
    blocks_32m: u64,
    digest: u64,
    /// `(va, pa, size of the page or block it lies in)`.
    spots: &'static [(u64, u64, u64)],
    /// `(va, depth of the invalid descriptor (0 is the first level walked, as in
    /// the 4 KiB sibling test), that descriptor, its physical
    /// address)`.
    faults: &'static [(u64, u8, u64, u64)],
}

fn check(dump: &Path, ttbr: Ttbr, register: u64, expected: &Expected) {
    let space = space(dump, ttbr, register);

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

    let want: BTreeMap<u64, u64> = [(0x4000, expected.pages), (0x200_0000, expected.blocks_32m)]
        .into_iter()
        .filter(|&(_, n)| n > 0)
        .collect();
    assert_eq!(leaves.by_size, want, "leaves by size");
    assert_eq!(
        leaves.digest, expected.digest,
        "digest over every leaf's (va, pa, size) disagrees with the independent walker"
    );
}

/// The recorded `TCR_EL1` builds 16 KiB LPA2 regimes of 52 bits, with the field values read by
/// hand from the manual. No corpus needed: the value is the evidence.
#[test]
fn the_recorded_tcr_selects_16k_lpa2_regimes_of_52_bits() {
    for ttbr in [Ttbr::Ttbr0, Ttbr::Ttbr1] {
        let regime = regime_from_tcr(TCR, ttbr);
        assert_eq!(regime.granule(), Arm64Granule::Kb16, "{ttbr:?}");
        assert_eq!(regime.va_bits(), 52, "{ttbr:?}");
        assert_eq!(regime.ips_bits(), 52, "{ttbr:?}");
        assert!(regime.lpa2(), "{ttbr:?}");
        assert!(regime.tbi(), "TBI0 = TBI1 = 1");
        assert!(!regime.walks_disabled());
    }
    assert_eq!(bits(TCR, 15, 14), 0b10, "TG0: 16K");
    assert_eq!(bits(TCR, 31, 30), 0b01, "TG1: 16K");
    assert_eq!(64 - bits(TCR, 5, 0), 52, "T0SZ");
    assert_eq!(64 - bits(TCR, 21, 16), 52, "T1SZ");
    assert_eq!(bits(TCR, 59, 59), 1, "DS: LPA2");
    assert_eq!(bits(TCR, 34, 32), 0b110, "IPS: 52-bit");
}

fn dump() -> Option<std::path::PathBuf> {
    corpus::file(CORPUS_VAR, "mem.raw")
}

#[test]
fn the_lpa2_kernel_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    check(
        &dump,
        Ttbr::Ttbr1,
        TTBR1,
        &Expected {
            pages: 35418,
            blocks_32m: 8,
            digest: 0x89e4_7ee7_3731_7a67,
            spots: KERNEL_SPOTS,
            faults: KERNEL_FAULTS,
        },
    );
}

#[test]
fn the_lpa2_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    check(
        &dump,
        Ttbr::Ttbr0,
        TTBR0,
        &Expected {
            pages: 91,
            blocks_32m: 0,
            digest: 0xeb34_87c3_5655_afe1,
            spots: PROCESS_SPOTS,
            faults: PROCESS_FAULTS,
        },
    );
}

/// An address above the 52-bit width of the regime, in either half, is refused rather than
/// wrapped into the tables.
#[test]
fn a_non_canonical_address_is_refused_in_both_52_bit_regimes() {
    let Some(dump) = dump() else { return };
    let process = space(&dump, Ttbr::Ttbr0, TTBR0);
    assert!(matches!(
        process.translate(1 << 52),
        Err(TranslateError::NonCanonical { .. })
    ));
    let kernel = space(&dump, Ttbr::Ttbr1, TTBR1);
    assert!(matches!(
        kernel.translate(0xffef_ffff_ffff_f000),
        Err(TranslateError::NonCanonical { .. })
    ));
}

const KERNEL_SPOTS: &[(u64, u64, u64)] = &[
    (0xfff00000089970cb, 0x489970cb, 0x4000),
    (0xfff000000409dbb9, 0x4409dbb9, 0x4000),
    (0xfff0000010533607, 0x50533607, 0x4000),
    (0xfff00000078bc3b7, 0x478bc3b7, 0x4000),
    (0xfff000001fb51c60, 0x5fb51c60, 0x4000),
    (0xfff000001cc4780c, 0x5cc4780c, 0x4000),
    (0xfff000001e397f76, 0x5e397f76, 0x4000),
    (0xfff00000184b9dd5, 0x584b9dd5, 0x4000),
    (0xfff000000d6fec3f, 0x4d6fec3f, 0x4000),
    (0xfff000000601dd8d, 0x4601dd8d, 0x4000),
    (0xfff000001f391c01, 0x5f391c01, 0x4000),
    (0xfff0000001d07ad4, 0x41d07ad4, 0x4000),
    (0xfff0000018f2a517, 0x58f2a517, 0x4000),
    (0xfff000001bb242c0, 0x5bb242c0, 0x4000),
    (0xfff000000022b545, 0x4022b545, 0x4000),
    (0xfff000001c810ccc, 0x5c810ccc, 0x4000),
    (0xfff00000110b97cb, 0x510b97cb, 0x4000),
    (0xfff000000ea425f0, 0x4ea425f0, 0x4000),
    (0xfff00000068acf79, 0x468acf79, 0x4000),
    (0xfff000001450ea95, 0x5450ea95, 0x4000),
    (0xfff0000001f53607, 0x41f53607, 0x4000),
    (0xfff00000016d984c, 0x416d984c, 0x4000),
    (0xfff0000001a0e6d4, 0x41a0e6d4, 0x4000),
    (0xfff000000096e45f, 0x4096e45f, 0x4000),
];
const KERNEL_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xfffc965a815a47c5, 0, 0x0, 0x41f540c8),
    (0xffff5e0408d6af57, 0, 0x0, 0x41f540f0),
    (0xfffffac6e1ea24c4, 1, 0x0, 0x4277bd60),
    (0xfff064c6fb695ffb, 1, 0x0, 0x5ffff260),
    (0xfff00000206ec000, 2, 0x0, 0x5fff8080),
    (0xfff0000020778000, 2, 0x0, 0x5fff8080),
    (0xffffd53206a70000, 3, 0x0, 0x427854e0),
    (0xffffd53204a68000, 3, 0x0, 0x427814d0),
];
const PROCESS_SPOTS: &[(u64, u64, u64)] = &[
    (0x44412d, 0x427cc12d, 0x4000),
    (0x5a30cb, 0x5fcab0cb, 0x4000),
    (0x421bb9, 0x427a9bb9, 0x4000),
    (0x483607, 0x5fd0b607, 0x4000),
    (0x43c3b7, 0x427c43b7, 0x4000),
    (0x57dc60, 0x5fc85c60, 0x4000),
    (0x56780c, 0x5fc6f80c, 0x4000),
    (0x573f76, 0x5fc7bf76, 0x4000),
    (0x4c1dd5, 0x5fd49dd5, 0x4000),
    (0x46ac3f, 0x427f2c3f, 0x4000),
    (0x431d8d, 0x427b9d8d, 0x4000),
    (0x579c01, 0x5fc81c01, 0x4000),
    (0x40fad4, 0x5fd87ad4, 0x4000),
    (0x4c6517, 0x5fd4e517, 0x4000),
    (0x54c2c0, 0x5fc542c0, 0x4000),
    (0x403545, 0x5fd93545, 0x4000),
    (0x5dcccc, 0x42284ccc, 0x4000),
    (0x4897cb, 0x5fd117cb, 0x4000),
    (0x4765f0, 0x427fe5f0, 0x4000),
    (0x434f79, 0x427bcf79, 0x4000),
    (0x4a2a95, 0x5fd2aa95, 0x4000),
    (0x5bb607, 0x5fcc3607, 0x4000),
    (0x40984c, 0x5fd8184c, 0x4000),
    (0x5966d4, 0x5fc9e6d4, 0x4000),
];
const PROCESS_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0x11ad5da711448, 0, 0x0, 0x441f6410),
    (0x7c4867af027bc, 0, 0x0, 0x441f6478),
    (0x2ec4bab9f87f, 1, 0x0, 0x445b5760),
    (0x774673f7ba8e, 1, 0x0, 0x445b7ba0),
    (0x7fffb005c000, 2, 0x0, 0x4472fec0),
    (0x7fffd5b54000, 2, 0x0, 0x4472ff50),
    (0x7fffaf05c000, 3, 0x0, 0x447460b8),
    (0x7fffaf054000, 3, 0x0, 0x447460a8),
];
