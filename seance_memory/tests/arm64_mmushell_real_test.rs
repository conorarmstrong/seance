//! The ARM64 translation core against real AArch64 page tables: two QEMU
//! guests' kernel and process hierarchies, walked from the translation-table
//! base registers QEMU recorded, and compared address by address with a walker
//! written independently of this crate.
//!
//! # Evidence
//!
//! The MMUShell dataset (Oliveri & Balzarotti, "In the Land of MMUs", ACM TOPS
//! 2022, doi:10.1145/3528102), fetched from EURECOM S3 on 2026-09-24; its
//! provenance is `forensic_corpora/mmushell_dataset/PROVENANCE.md`. Two
//! archives are used, `aarch64/linux.7z` and `aarch64/linux_debian.7z`. Each
//! holds a 4 GiB `linux.dump` that `Linux.yaml` places at physical
//! `0x4000_0000..=0x1_3fff_ffff` (file offset 0 is physical `0x4000_0000`), and
//! a `linux.regs` recording every `TCR_EL1` / `TTBR0_EL1` / `TTBR1_EL1` /
//! `SCTLR` value QEMU saw, with first and last timestamps.
//!
//! **These are QEMU-emulated machines, not ARM64 hardware.** The page tables
//! are the guest kernels' own, written by Linux; the translation regime around
//! them is QEMU's model of the architecture.
//!
//! # Running it
//!
//! `SEANCE_MMUSHELL_AARCH64` names a directory holding the two extracted
//! archives, one subdirectory each:
//!
//! ```text
//! $SEANCE_MMUSHELL_AARCH64/linux/linux.dump     (from aarch64/linux.7z)
//! $SEANCE_MMUSHELL_AARCH64/debian/linux.dump    (from aarch64/linux_debian.7z)
//! ```
//!
//! Unset, every corpus test here skips and says so; set to a directory that
//! lacks either dump, it panics. `.regs` is a Python pickle and is never read
//! by this file: the register values below were read from it once, outside
//! the build, with `python3 -m pickletools` and a reader that interprets the
//! opcode stream symbolically (it imports and calls nothing; the one
//! `collections.defaultdict(dict)` it contains is modelled as a plain `dict`).
//!
//! # Ground truth
//!
//! The register values in force at the end of each run — the value with the
//! latest last-seen timestamp:
//!
//! | dump   | `TCR_EL1`             | `TTBR1_EL1`           | `TTBR0_EL1` used here |
//! |--------|-----------------------|-----------------------|-----------------------|
//! | linux  | `0x32_b559_3519`      | `0xe6_0000_4075_5000` | `0x1_39de_0000`       |
//! | debian | `0x40_0032_b550_3510` | `0x42e_0000_412e_e000`| `0x1_3d14_2000`       |
//!
//! Both `TCR_EL1` values decode to `TG1 = TG0 = 4 KiB`, `A1 = 1` (the ASID is
//! in `TTBR1_EL1[63:48]`), `IPS = 0b010` (40-bit), `TBI0 = 1`, `TBI1 = 0`,
//! `HA = HD = 0`, `DS = 0` (no LPA2). `linux` has `T0SZ = T1SZ = 25` (39-bit
//! regimes, three levels from level 1); `debian` has `T0SZ = T1SZ = 16`
//! (48-bit, four levels from level 0). `ID_AA64MMFR0_EL1 = 0x1124` in both
//! `Linux.yaml`: `PARange = 0b0100` (44-bit).
//!
//! `linux`'s last `TTBR0_EL1` (`0x1_39de_0000`, last seen at 40.245 s of a
//! 40.35 s run) is a live process. `debian`'s last one (`0x1_3a5f_c000`, at
//! 142.798 s) and the eleven before it walk to nothing — short-lived tasks
//! whose tables were torn down — so the process regime used is
//! `0x1_3d14_2000`, the latest with mappings (last seen at 141.047 s).
//!
//! # The independent answer
//!
//! Every expected value was produced by a Python stage-1 walker written from
//! ARM DDI 0487 D8 (VMSAv8-64, 4 KiB granule, `DS = 0`) without reference to
//! this crate's walker. It enumerated every valid leaf of each tree; the
//! counts and the order-independent digest over `(va, pa, size)` of every leaf
//! below are its output, as are the spot translations (a random interior
//! address in randomly chosen leaves at each level) and the faults (addresses
//! whose walk meets an invalid descriptor, with the level, entry and entry
//! address the architecture says it stops at).
//!
//! # What this evidence does not exercise
//!
//! 16 KiB and 64 KiB granules; FEAT_LPA / LPA2 (`DS = 0`, `IPS` 40-bit, no
//! descriptor has bits 49:48 set); 52-bit VAs; any non-zero invalid descriptor
//! (no swap or `PROT_NONE` entries exist in these four trees); hierarchical
//! `APTable` / `XNTable` (no
//! table descriptor sets bits 63:59); hardware access/dirty management
//! (`HA = HD = 0`); an output address above `IPS`.

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

/// `Linux.yaml` `memspace.ram[0]`: `0x4000_0000..=0x1_3fff_ffff`, file offset 0.
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 4 << 30;

/// `linux.regs` of `aarch64/linux.7z`: the only non-zero `TCR_EL1` (first and
/// last seen 0.109 s), and the `TTBR1_EL1` / `TTBR0_EL1` last seen latest
/// (40.245409 s and 40.245413 s of a 40.353774 s run).
const LINUX_TCR: u64 = 0x32_b559_3519;
const LINUX_TTBR1: u64 = 0xe6_0000_4075_5000;
const LINUX_TTBR0: u64 = 0x1_39de_0000;

/// `linux.regs` of `aarch64/linux_debian.7z`: the `TCR_EL1` last seen latest
/// (6.672927 s; also recorded, 0x0 and the firmware's 0x2_8080_3518), the
/// `TTBR1_EL1` last seen latest (142.798348 s of a 147.638999 s run), and the
/// latest `TTBR0_EL1` that maps anything (last seen 141.046501 s).
const DEBIAN_TCR: u64 = 0x40_0032_b550_3510;
const DEBIAN_TTBR1: u64 = 0x42e_0000_412e_e000;
const DEBIAN_TTBR0: u64 = 0x1_3d14_2000;

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
    let layer = SegmentedLayer::new(
        Arc::new(source),
        vec![Segment::new(0, RAM_BASE, RAM_LEN)],
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

/// Both recorded `TCR_EL1` values build a regime, with the widths the
/// architecture gives them. No corpus needed: the values are the evidence.
#[test]
fn the_recorded_tcr_values_select_4k_regimes_of_39_and_48_bits() {
    for (tcr, bits_expected) in [(LINUX_TCR, 39u8), (DEBIAN_TCR, 48u8)] {
        for ttbr in [Ttbr::Ttbr0, Ttbr::Ttbr1] {
            let regime = regime_from_tcr(tcr, ttbr);
            assert_eq!(regime.granule(), Arm64Granule::Kb4, "{tcr:#x}");
            assert_eq!(regime.va_bits(), bits_expected, "{tcr:#x} {ttbr:?}");
            assert_eq!(regime.ips_bits(), 40, "{tcr:#x}");
            assert_eq!(regime.tbi(), ttbr == Ttbr::Ttbr0, "TBI0 = 1, TBI1 = 0");
            assert!(!regime.hierarchical_permissions_disabled());
            assert!(!regime.walks_disabled());
        }
        // The fields read by hand, so the decoder is checked against the
        // manual rather than against itself.
        assert_eq!(bits(tcr, 15, 14), 0b00, "TG0: 4K");
        assert_eq!(bits(tcr, 31, 30), 0b10, "TG1: 4K");
        assert_eq!(64 - bits(tcr, 5, 0), u64::from(bits_expected), "T0SZ");
        assert_eq!(64 - bits(tcr, 21, 16), u64::from(bits_expected), "T1SZ");
        assert_eq!(bits(tcr, 59, 59), 0, "DS: no LPA2");
        assert_eq!(bits(tcr, 34, 32), 0b010, "IPS: 40-bit");
        assert_eq!(bits(tcr, 37, 37), 1, "TBI0");
        assert_eq!(bits(tcr, 38, 38), 0, "TBI1");
        assert_eq!(bits(tcr, 22, 22), 1, "A1: the ASID is in TTBR1");
    }
}

fn dump(sub: &str) -> Option<std::path::PathBuf> {
    corpus::file(CORPUS_VAR, &format!("{sub}/linux.dump"))
}

#[test]
fn linux_kernel_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("linux") else { return };
    check(
        &dump,
        LINUX_TCR,
        Ttbr::Ttbr1,
        LINUX_TTBR1,
        &Expected {
            pages: 2383,
            blocks_2m: 544,
            blocks_1g: 3,
            digest: 0x83e6_56a4_6f56_dcb2,
            spots: LINUX_TTBR1_SPOTS,
            faults: LINUX_TTBR1_FAULTS,
        },
    );
}

#[test]
fn linux_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("linux") else { return };
    check(
        &dump,
        LINUX_TCR,
        Ttbr::Ttbr0,
        LINUX_TTBR0,
        &Expected {
            pages: 264,
            blocks_2m: 0,
            blocks_1g: 0,
            digest: 0xd3df_37ee_6690_d7e1,
            spots: LINUX_TTBR0_SPOTS,
            faults: LINUX_TTBR0_FAULTS,
        },
    );
}

#[test]
fn debian_kernel_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("debian") else { return };
    check(
        &dump,
        DEBIAN_TCR,
        Ttbr::Ttbr1,
        DEBIAN_TTBR1,
        &Expected {
            pages: 6125,
            blocks_2m: 1183,
            blocks_1g: 2,
            digest: 0x92c0_32f5_f061_b79b,
            spots: DEBIAN_TTBR1_SPOTS,
            faults: DEBIAN_TTBR1_FAULTS,
        },
    );
}

#[test]
fn debian_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump("debian") else { return };
    check(
        &dump,
        DEBIAN_TCR,
        Ttbr::Ttbr0,
        DEBIAN_TTBR0,
        &Expected {
            pages: 1159,
            blocks_2m: 0,
            blocks_1g: 0,
            digest: 0x2337_3004_f024_d9ad,
            spots: DEBIAN_TTBR0_SPOTS,
            faults: DEBIAN_TTBR0_FAULTS,
        },
    );
}

/// Top-byte-ignore, against the recorded `TCR_EL1.TBI0 = 1` / `TBI1 = 0`,
/// with both regimes built from that register value.
///
/// With `TBI1 = 0` a kernel address whose top byte is not all ones faults on
/// the hardware, and the crate refuses it as non-canonical. With `TBI0 = 1`
/// the hardware ignores a user pointer's top byte and translates
/// `0x2a00_0000_0043_d080` exactly as `0x43_d080`, and so does the crate.
/// (Until 2026-09-26 the second half was a pinned limit, MEM-043: the crate
/// refused the tagged user pointer.)
#[test]
fn a_tagged_user_pointer_translates_under_tbi0_and_a_tagged_kernel_pointer_faults_under_tbi1_clear()
{
    let Some(dump) = dump("linux") else { return };
    let kernel = space(&dump, LINUX_TCR, Ttbr::Ttbr1, LINUX_TTBR1);
    let (va, _, _) = LINUX_TTBR1_SPOTS[0];
    let tagged = (va & 0x00ff_ffff_ffff_ffff) | (0x2a << 56);
    assert!(matches!(
        kernel.translate(tagged),
        Err(TranslateError::NonCanonical { .. })
    ));

    let process = space(&dump, LINUX_TCR, Ttbr::Ttbr0, LINUX_TTBR0);
    for &(va, pa, _) in LINUX_TTBR0_SPOTS {
        assert_eq!(process.translate(va).expect("untagged").phys, pa);
        let tagged = va | (0x2a << 56);
        assert_eq!(
            process
                .translate(tagged)
                .unwrap_or_else(|e| panic!("TBI0 = 1: {tagged:#x} must translate: {e}"))
                .phys,
            pa,
            "{tagged:#x}"
        );
    }
}

const LINUX_TTBR1_SPOTS: &[(u64, u64, u64)] = &[
    (0xffffffc0769dc720, 0xb69dc720, 0x40000000),
    (0xffffffc0e3996220, 0x123996220, 0x40000000),
    (0xffffffc0af102040, 0xef102040, 0x40000000),
    (0xffffffc034b101c0, 0x74b101c0, 0x200000),
    (0xffffffc026a24f80, 0x66a24f80, 0x200000),
    (0xffffffc028258948, 0x68258948, 0x200000),
    (0xffffffc03497a6d8, 0x7497a6d8, 0x200000),
    (0xffffffc01b5e1960, 0x5b5e1960, 0x200000),
    (0xffffffc00374c550, 0x4374c550, 0x200000),
    (0xffffffc01dc4d520, 0x5dc4d520, 0x200000),
    (0xffffffc0167053c8, 0x567053c8, 0x200000),
    (0xffffffc00061cc88, 0x4061cc88, 0x1000),
    (0xffffff80085bad30, 0x405bad30, 0x1000),
    (0xffffffc0006ba3c0, 0x406ba3c0, 0x1000),
    (0xffffffc0006978c0, 0x406978c0, 0x1000),
    (0xffffffc00060a580, 0x4060a580, 0x1000),
    (0xffffffc0001efe90, 0x401efe90, 0x1000),
    (0xffffffc00019dd70, 0x4019dd70, 0x1000),
    (0xffffffc0001d47a8, 0x401d47a8, 0x1000),
    (0xffffff80087243c0, 0x407243c0, 0x1000),
    (0xffffff80080d40b8, 0x400d40b8, 0x1000),
    (0xffffffc00079ff98, 0x4079ff98, 0x1000),
    (0xffffff80084e1720, 0x404e1720, 0x1000),
];

const LINUX_TTBR1_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffffffa5f0626000, 0, 0x0, 0x407554b8),
    (0xffffffbffef53000, 0, 0x0, 0x407557f8),
    (0xffffffd8bb265000, 0, 0x0, 0x40755b10),
    (0xffffffdaa6ba6000, 0, 0x0, 0x40755b50),
    (0xfffffff2ecbf2000, 0, 0x0, 0x40755e58),
    (0xffffff8d613e6000, 0, 0x0, 0x407551a8),
    (0xffffff8006a50000, 1, 0x0, 0x13fffe1a8),
    (0xffffff800806c000, 2, 0x0, 0x13fffd360),
    (0xffffff801764a000, 1, 0x0, 0x13fffe5d8),
    (0xffffff80088ce000, 2, 0x0, 0x13b180670),
    (0xffffff80087ce000, 2, 0x0, 0x13fffbe70),
    (0xffffff800704d000, 1, 0x0, 0x13fffe1c0),
    (0xffffff8008893000, 2, 0x0, 0x13b180498),
    (0xffffff80095b1000, 1, 0x0, 0x13fffe250),
    (0xffffff802b0eb000, 1, 0x0, 0x13fffeac0),
    (0xffffff800939f000, 1, 0x0, 0x13fffe248),
];

const LINUX_TTBR0_SPOTS: &[(u64, u64, u64)] = &[
    (0x43d080, 0x13bf82080, 0x1000),
    (0x7fa196d118, 0x13bfa4118, 0x1000),
    (0x477390, 0x13fe35390, 0x1000),
    (0x47e4f8, 0x13bf164f8, 0x1000),
    (0x7fa19257d8, 0x13ff517d8, 0x1000),
    (0x49e748, 0x13bf38748, 0x1000),
    (0x46b3e8, 0x13fe003e8, 0x1000),
    (0x7fa19498a8, 0x13bf0a8a8, 0x1000),
    (0x464ae8, 0x13bf79ae8, 0x1000),
    (0x40d960, 0x13ff12960, 0x1000),
    (0x488fd8, 0x13bf20fd8, 0x1000),
    (0x4ae9f8, 0x13bfc09f8, 0x1000),
];

const LINUX_TTBR0_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0x6ad5f9f000, 0, 0x0, 0x139de0d58),
    (0x67c2af7000, 0, 0x0, 0x139de0cf8),
    (0x4881083000, 0, 0x0, 0x139de0910),
    (0x4dd000, 2, 0x0, 0x139dee6e8),
    (0x536000, 2, 0x0, 0x139dee9b0),
    (0x7fd229b000, 2, 0x0, 0x139e884d8),
    (0x180a4f6000, 0, 0x0, 0x139de0300),
    (0x1a8f000, 1, 0x0, 0x139e8f068),
    (0x2384000, 1, 0x0, 0x139e8f088),
    (0x2658d25000, 0, 0x0, 0x139de04c8),
    (0x6cb0436000, 0, 0x0, 0x139de0d90),
    (0x3c2000, 1, 0x0, 0x139e8f008),
    (0x7fb8042000, 1, 0x0, 0x139de3e00),
    (0x563000, 2, 0x0, 0x139deeb18),
    (0x7fcf0ee000, 1, 0x0, 0x139e193c0),
    (0x21be6000, 1, 0x0, 0x139e8f868),
];

const DEBIAN_TTBR1_SPOTS: &[(u64, u64, u64)] = &[
    (0xffff800053ee3e70, 0x93ee3e70, 0x40000000),
    (0xffff80008645b728, 0xc645b728, 0x40000000),
    (0xffff8000ef648e80, 0x12f648e80, 0x200000),
    (0xffff80002cf1aec0, 0x6cf1aec0, 0x200000),
    (0xffff8000ccfbc7d0, 0x10cfbc7d0, 0x200000),
    (0xffff7e00033c74a0, 0x1379c74a0, 0x200000),
    (0xffff80002905a5e8, 0x6905a5e8, 0x200000),
    (0xffff80003262a6e8, 0x7262a6e8, 0x200000),
    (0xffff0000143a6ea8, 0x40143a6ea8, 0x200000),
    (0xffff8000ced91888, 0x10ed91888, 0x200000),
    (0xffff000009543d10, 0x13fad5d10, 0x1000),
    (0xffff000008919a30, 0x40919a30, 0x1000),
    (0xffff000009512748, 0x13faa4748, 0x1000),
    (0xffff00000a5817f8, 0x138f1d7f8, 0x1000),
    (0xffff000000d2bde0, 0x13b977de0, 0x1000),
    (0xffff000000b0fcc8, 0x133853cc8, 0x1000),
    (0xffff000009791c08, 0x13ed24c08, 0x1000),
    (0xffff00000a9a1378, 0x13b65b378, 0x1000),
    (0xffff00000939e9a8, 0x13f9309a8, 0x1000),
    (0xffff8000f87e7eb8, 0x1387e7eb8, 0x1000),
    (0xffff000009ab8190, 0x13eab8190, 0x1000),
    (0xffff8000f8464140, 0x138464140, 0x1000),
];

const DEBIAN_TTBR1_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffff98dc04eeb000, 0, 0x0, 0x412ee988),
    (0xffff969a6b446000, 0, 0x0, 0x412ee968),
    (0xffff4d70ed2de000, 0, 0x0, 0x412ee4d0),
    (0xffff2428f30f8000, 0, 0x0, 0x412ee240),
    (0xffff00003783b000, 2, 0x0, 0x13fffdde0),
    (0xffffc3307e7ac000, 0, 0x0, 0x412eec30),
    (0xffff95ee7697f000, 0, 0x0, 0x412ee958),
    (0xffff00002eff2000, 2, 0x0, 0x13fffdbb8),
    (0xffff000044ebc000, 1, 0x0, 0x13fffe008),
    (0xffff000009083000, 3, 0x0, 0x13fff9418),
    (0xffff7dffc1e66000, 2, 0x0, 0x41266078),
    (0xffff00000a740000, 3, 0x0, 0x13c89ba00),
    (0xffff000009cb2000, 3, 0x0, 0x138ecc590),
    (0xffff0000016dd000, 2, 0x0, 0x13fffd058),
    (0xffff000009934000, 3, 0x0, 0x13ee889a0),
    (0xffff000001e90000, 2, 0x0, 0x13fffd078),
];

const DEBIAN_TTBR0_SPOTS: &[(u64, u64, u64)] = &[
    (0xffff83ffc000, 0x13206f000, 0x1000),
    (0xaaaab9a31cc0, 0x130adccc0, 0x1000),
    (0xaaaab9a2e588, 0x13932e588, 0x1000),
    (0xffff84034a90, 0x13247fa90, 0x1000),
    (0xffff83f8ae38, 0x13442ce38, 0x1000),
    (0xaaaab9a33718, 0x130af1718, 0x1000),
    (0xffff83f32150, 0x1334e5150, 0x1000),
    (0xffff83ef3500, 0x133509500, 0x1000),
    (0xaaaab9982d80, 0x1308dad80, 0x1000),
    (0xffff83f22360, 0x13911b360, 0x1000),
    (0xffff83eff380, 0x13f6ee380, 0x1000),
    (0xffff83f92fb8, 0x134434fb8, 0x1000),
];

const DEBIAN_TTBR0_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xaaaabb4f8000, 2, 0x0, 0x13cbebed0),
    (0xaaaaac56e000, 2, 0x0, 0x13cbebb10),
    (0xaaaab4521000, 2, 0x0, 0x13cbebd10),
    (0xaaaac87de000, 2, 0x0, 0x13a120218),
    (0xaaaad6869000, 2, 0x0, 0x13a1205a0),
    (0x8d0191c13000, 0, 0x0, 0x13d1428d0),
    (0xffffa1ab6000, 2, 0x0, 0x133a74868),
    (0xffff83e36000, 3, 0x0, 0x13ac8f1b0),
    (0xcd1b5df44000, 0, 0x0, 0x13d142cd0),
    (0x4abb9fbaf000, 0, 0x0, 0x13d1424a8),
    (0x209e1e253000, 0, 0x0, 0x13d142208),
    (0xfa8c67b97000, 0, 0x0, 0x13d142fa8),
    (0x40f551a50000, 0, 0x0, 0x13d142408),
    (0xffff83bbd000, 3, 0x0, 0x13cbedde8),
    (0xffff532e1000, 1, 0x0, 0x13c1effe8),
    (0xffff83bfe000, 3, 0x0, 0x13cbedff0),
];
