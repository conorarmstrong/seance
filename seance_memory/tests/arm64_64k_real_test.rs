//! The ARM64 translation core against real 64 KiB-granule page tables: a
//! Linux guest's kernel and process hierarchies, walked from the translation
//! registers read off the paused machine, and compared address by address
//! with a walker written independently of this crate.
//!
//! # Evidence
//!
//! Captured 2026-10-20 on this host by `qemu-system-aarch64` 10.2.1 (TCG, `-M
//! virt -cpu max,lpa2=off -m 512`), booting Ubuntu noble's own
//! `linux-image-unsigned-6.8.0-71-generic-64k` (`CONFIG_ARM64_64K_PAGES`)
//! with a busybox initramfs. The guest was paused over QMP, RAM saved with
//! `pmemsave 0x40000000 512M`, and `TCR_EL1` / `TTBR0_EL1` / `TTBR1_EL1` read
//! through QEMU's gdbstub. Provenance, package hashes and the exact command
//! line are in `forensic_corpora/arm64_64k_qemu/SOURCE.md` and
//! `documentation/VALIDATION.md` `MEM-ARM-6`.
//!
//! **This is a QEMU-emulated machine, not ARM64 hardware.** The page tables
//! are the guest kernel's own; the translation regime around them is QEMU's
//! model of the architecture. Before this and its 16 KiB sibling, every 16 and
//! 64 KiB test was a synthetic table written from the same reading of the
//! manual the code implements.
//!
//! # Running it
//!
//! `SEANCE_ARM64_64K` names the directory holding `mem.raw` (file offset 0 is
//! physical `0x4000_0000`). Unset, the corpus tests skip.
//!
//! # Ground truth
//!
//! | register | value |
//! |---|---|
//! | `TCR_EL1` | `0x0150_01f5_f550_7510` |
//! | `TTBR1_EL1` | `0x001a_0000_428a_0001` (ASID `0x1a`, `CnP`) |
//! | `TTBR0_EL1` | `0x001a_0000_400e_c801` (init's `pgd`, ASID `0x1a`, `CnP`) |
//!
//! `TCR_EL1` decodes to `TG0 = 0b01` and `TG1 = 0b11` (both 64 KiB), `T0SZ =
//! T1SZ = 16` (48-bit regimes of three levels, level 1 holding 64 entries),
//! `IPS = 0b101` (48-bit), `TBI0 = TBI1 = 1`, `DS = 0`.
//!
//! # The independent answer
//!
//! Every expected value was produced by a Python stage-1 walker written from
//! ARM DDI 0487 D8 (VMSAv8-64, 64 KiB granule, `DS = 0`: level 1 and 2 tables
//! or a 512 MiB block at level 2, level 3 a 64 KiB page, bits 15:12 of a
//! descriptor RES0 without FEAT_LPA) without reference to this crate's walker.
//! It found no reserved encoding, no descriptor with bits 15:12 set and no
//! unreadable table. The counts and the order-independent digest over `(va,
//! pa, size)` below are its output, as are the spot translations and the
//! faults.
//!
//! # What this evidence does not exercise
//!
//! A 64 KiB block (the kernel mapped everything with 64 KiB pages, so the
//! only leaf size is 64 KiB); FEAT_LPA output addresses above 48 bits; any
//! non-zero invalid descriptor; hierarchical `APTable` / `XNTable`; hardware
//! access/dirty management.

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

const CORPUS_VAR: &str = "SEANCE_ARM64_64K";

/// `-M virt` RAM: `0x4000_0000`, 512 MiB, file offset 0.
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 512 << 20;

/// Read through the gdbstub with the guest paused (`regs.py` in the capture
/// recipe).
const TCR: u64 = 0x0150_01f5_f550_7510;
const TTBR1: u64 = 0x001a_0000_428a_0001;
const TTBR0: u64 = 0x001a_0000_400e_c801;

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
    /// 64 KiB pages (level 3).
    pages: u64,
    /// 512 MiB blocks (level 2).
    blocks_512m: u64,
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

    let want: BTreeMap<u64, u64> = [
        (0x1_0000, expected.pages),
        (0x2000_0000, expected.blocks_512m),
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

/// The recorded `TCR_EL1` builds 64 KiB regimes of 48 bits, with the field
/// values read by hand from the manual. No corpus needed: the value is the
/// evidence.
#[test]
fn the_recorded_tcr_selects_64k_regimes_of_48_bits() {
    for ttbr in [Ttbr::Ttbr0, Ttbr::Ttbr1] {
        let regime = regime_from_tcr(TCR, ttbr);
        assert_eq!(regime.granule(), Arm64Granule::Kb64, "{ttbr:?}");
        assert_eq!(regime.va_bits(), 48, "{ttbr:?}");
        assert_eq!(regime.ips_bits(), 48, "{ttbr:?}");
        assert!(regime.tbi(), "TBI0 = TBI1 = 1");
        assert!(!regime.hierarchical_permissions_disabled());
        assert!(!regime.walks_disabled());
    }
    // The fields read by hand, so the decoder is checked against the manual
    // rather than against itself. TG0 and TG1 encode 64 KiB differently.
    assert_eq!(bits(TCR, 15, 14), 0b01, "TG0: 64K");
    assert_eq!(bits(TCR, 31, 30), 0b11, "TG1: 64K");
    assert_eq!(64 - bits(TCR, 5, 0), 48, "T0SZ");
    assert_eq!(64 - bits(TCR, 21, 16), 48, "T1SZ");
    assert_eq!(bits(TCR, 59, 59), 0, "DS: no LPA2");
    assert_eq!(bits(TCR, 34, 32), 0b101, "IPS: 48-bit");
    assert_eq!(bits(TCR, 37, 37), 1, "TBI0");
    assert_eq!(bits(TCR, 38, 38), 1, "TBI1");
}

fn dump() -> Option<std::path::PathBuf> {
    corpus::file(CORPUS_VAR, "mem.raw")
}

#[test]
fn the_64k_kernel_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    check(
        &dump,
        Ttbr::Ttbr1,
        TTBR1,
        &Expected {
            pages: 13203,
            blocks_512m: 0,
            digest: 0xc837_3daf_6f15_716b,
            spots: KERNEL_SPOTS,
            faults: KERNEL_FAULTS,
        },
    );
}

#[test]
fn the_64k_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    check(
        &dump,
        Ttbr::Ttbr0,
        TTBR0,
        &Expected {
            pages: 26,
            blocks_512m: 0,
            digest: 0xe405_543d_d4e2_6e36,
            spots: PROCESS_SPOTS,
            faults: PROCESS_FAULTS,
        },
    );
}

/// Top-byte-ignore on both sides, against the recorded `TBI0 = TBI1 = 1`.
/// A tagged pointer translates as its untagged form, user and kernel alike
/// (bit 55 still selects the register).
#[test]
fn tagged_pointers_translate_as_untagged_ones_under_tbi0_and_tbi1() {
    let Some(dump) = dump() else { return };
    let kernel = space(&dump, Ttbr::Ttbr1, TTBR1);
    for &(va, pa, _) in KERNEL_SPOTS.iter().take(8) {
        let tagged = (va & 0x00ff_ffff_ffff_ffff) | (0x2a << 56);
        assert_eq!(kernel.translate(tagged).expect("TBI1 = 1").phys, pa);
    }
    let process = space(&dump, Ttbr::Ttbr0, TTBR0);
    for &(va, pa, _) in PROCESS_SPOTS.iter().take(8) {
        let tagged = va | (0x2a << 56);
        assert_eq!(process.translate(tagged).expect("TBI0 = 1").phys, pa);
    }
}

/// An address that fits the 48-bit regime's table but not its canonical form
/// is refused, not wrapped: the walk must not mistake bit 48 of a user
/// address for a table index.
#[test]
fn a_non_canonical_address_is_refused_in_both_regimes() {
    let Some(dump) = dump() else { return };
    let process = space(&dump, Ttbr::Ttbr0, TTBR0);
    assert!(matches!(
        process.translate(1 << 48),
        Err(TranslateError::NonCanonical { .. })
    ));
    let kernel = space(&dump, Ttbr::Ttbr1, TTBR1);
    assert!(matches!(
        kernel.translate(0xfffe_ffff_ffff_f000),
        Err(TranslateError::NonCanonical { .. })
    ));
}

const KERNEL_SPOTS: &[(u64, u64, u64)] = &[
    (0xffff00000899e408, 0x4899e408, 0x10000),
    (0xffff800093d48858, 0x4013d48858, 0x10000),
    (0xffffac9874cb7520, 0x43ab7520, 0x10000),
    (0xffffac9871893450, 0x40693450, 0x10000),
    (0xffff00000409a280, 0x4409a280, 0x10000),
    (0xffff000010530fa8, 0x50530fa8, 0x10000),
    (0xffff0000078b0b68, 0x478b0b68, 0x10000),
    (0xffff00001fb50d00, 0x5fb50d00, 0x10000),
    (0xffffac98715b04b0, 0x403b04b0, 0x10000),
    (0xffff00001cc4c328, 0x5cc4c328, 0x10000),
    (0xffff00001e396ee0, 0x5e396ee0, 0x10000),
    (0xffff8000991ad818, 0x40191ad818, 0x10000),
    (0xffff0000184b0ed8, 0x584b0ed8, 0x10000),
    (0xffffac9873227180, 0x42027180, 0x10000),
    (0xffff00000d6fe030, 0x4d6fe030, 0x10000),
    (0xffff00000601fdd8, 0x4601fdd8, 0x10000),
    (0xffff00001f397750, 0x5f397750, 0x10000),
    (0xffff000001d0b0f8, 0x41d0b0f8, 0x10000),
    (0xffff000018f27630, 0x58f27630, 0x10000),
    (0xffff00001bb27000, 0x5bb27000, 0x10000),
    (0xffff80009647eb50, 0x401647eb50, 0x10000),
    (0xffffac9871719458, 0x40519458, 0x10000),
    (0xffffac9871c10b00, 0x40a10b00, 0x10000),
    (0xffff00000022d510, 0x4022d510, 0x10000),
];

const KERNEL_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffffffc00bc60000, 2, 0x0, 0x5ff65e30),
    (0xffffffc01feb0000, 2, 0x0, 0x5ff6ff58),
    (0xfffffc3620000000, 1, 0x0, 0x43ac0d88),
    (0xffffffee00000000, 1, 0x0, 0x43acfb80),
    (0xfffffef560000000, 1, 0x0, 0x43acbd58),
    (0xffff033340000000, 1, 0x0, 0x5ffdccd0),
    (0xffff800260000000, 1, 0x0, 0x43e50098),
    (0xfffffe8b60000000, 1, 0x0, 0x43aca2d8),
    (0xffffffbfee7f0000, 2, 0x0, 0x43ad73f8),
    (0xffffffc011800000, 2, 0x0, 0x5ff68c00),
    (0xffff838b80000000, 1, 0x0, 0x43e5e2e0),
    (0xffff03de60000000, 1, 0x0, 0x5ffdf798),
    (0xffffffbff3800000, 2, 0x0, 0x43ad9c00),
    (0xffffac9860da0000, 2, 0x0, 0x5ffe06d0),
    (0xffffffc01a9f0000, 2, 0x0, 0x5ff6d4f8),
    (0xffffffbfedf20000, 2, 0x0, 0x43ad6f90),
];

const PROCESS_SPOTS: &[(u64, u64, u64)] = &[
    (0x440fa8, 0x5e1c0fa8, 0x10000),
    (0x5a0b68, 0x5e5d0b68, 0x10000),
    (0x420d00, 0x5e170d00, 0x10000),
    (0x4804b0, 0x5e4a04b0, 0x10000),
    (0x43c328, 0x5e1bc328, 0x10000),
    (0x576ee0, 0x5e5a6ee0, 0x10000),
    (0x56d818, 0x5e59d818, 0x10000),
    (0x5c0ed8, 0x5e5f0ed8, 0x10000),
    (0x4c7180, 0x5e4f7180, 0x10000),
    (0x46e030, 0x5e1fe030, 0x10000),
    (0x5dfdd8, 0x4339fdd8, 0x10000),
    (0x477750, 0x5e487750, 0x10000),
    (0x40b0f8, 0x5e14b0f8, 0x10000),
    (0x587630, 0x5e5b7630, 0x10000),
    (0x597000, 0x5e5c7000, 0x10000),
    (0x49eb50, 0x5e4ceb50, 0x10000),
    (0x549458, 0x5e579458, 0x10000),
    (0x5b0b00, 0x5e5e0b00, 0x10000),
    (0xffffffa5d510, 0x4321d510, 0x10000),
    (0x453330, 0x5e1d3330, 0x10000),
    (0x415f28, 0x5e155f28, 0x10000),
    (0x5e97c0, 0x434697c0, 0x10000),
    (0x4a3de0, 0x5e4d3de0, 0x10000),
    (0x4baa50, 0x5e4eaa50, 0x10000),
];

const PROCESS_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffffe0120000, 2, 0x0, 0x43220090),
    (0xfe9ad7140000, 2, 0x0, 0x4338b8a0),
    (0xffffe1d70000, 2, 0x0, 0x43220eb8),
    (0x21640000000, 1, 0x0, 0x431f8590),
    (0xfdb080000000, 1, 0x0, 0x43236c20),
    (0xfd1320000000, 1, 0x0, 0x432344c8),
    (0xfffff6490000, 2, 0x0, 0x4322b248),
    (0xfff660000000, 1, 0x0, 0x4323fd98),
    (0xffffe1380000, 2, 0x0, 0x432209c0),
    (0xfe9acfb70000, 2, 0x0, 0x43387db8),
    (0xfffff6a60000, 2, 0x0, 0x4322b530),
    (0x8ed0000, 2, 0x0, 0x43274768),
    (0xff59a0000000, 1, 0x0, 0x4323d668),
    (0x3c7a0000000, 1, 0x0, 0x431ff1e8),
    (0xfe9ad2840000, 2, 0x0, 0x43389420),
    (0xfe9ad5150000, 2, 0x0, 0x4338a8a8),
];
