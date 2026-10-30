//! The ARM64 translation core against real 16 KiB-granule page tables: a
//! Linux guest's kernel and process hierarchies, walked from the translation
//! registers read off the paused machine, and compared address by address
//! with a walker written independently of this crate.
//!
//! # Evidence
//!
//! Captured 2026-10-20 on this host by `qemu-system-aarch64` 10.2.1 (TCG, `-M
//! virt -cpu max,lpa2=off -m 512`), booting Debian trixie's own
//! `linux-image-6.12.107+deb13-arm64-16k-unsigned` (`CONFIG_ARM64_16K_PAGES`)
//! with a busybox initramfs. The guest was paused over QMP, RAM saved with
//! `pmemsave 0x40000000 512M`, and `TCR_EL1` / `TTBR0_EL1` / `TTBR1_EL1` read
//! through QEMU's gdbstub. Provenance, package hashes and the exact command
//! line are in `forensic_corpora/arm64_16k_qemu/SOURCE.md` and
//! `documentation/VALIDATION.md` `MEM-ARM-5`.
//!
//! **This is a QEMU-emulated machine, not ARM64 hardware.** The page tables
//! are the guest kernel's own, written by Linux; the translation regime around
//! them is QEMU's model of the architecture. It is the first 16 KiB-granule
//! evidence the crate has met: before it, every 16 and 64 KiB test was a
//! synthetic table written from the same reading of the manual the code
//! implements.
//!
//! # Running it
//!
//! `SEANCE_ARM64_16K` names the directory holding `mem.raw` (physical
//! `0x4000_0000..0x6000_0000`, file offset 0 is physical `0x4000_0000`).
//! Unset, the corpus tests skip and say so; set to a directory without the
//! dump, they panic.
//!
//! # Ground truth
//!
//! | register | value |
//! |---|---|
//! | `TCR_EL1` | `0x0150_01f5_7551_b511` |
//! | `TTBR1_EL1` | `0x001a_0000_41f5_4001` (ASID `0x1a`, `CnP`) |
//! | `TTBR0_EL1` | `0x0000_0000_480a_8001` (init's `pgd`, `CnP`) |
//!
//! `TCR_EL1` decodes to `TG0 = 0b10` and `TG1 = 0b01` (both 16 KiB), `T0SZ =
//! T1SZ = 17` (47-bit regimes of three levels, level 1 holding 2048 entries),
//! `IPS = 0b101` (48-bit), `TBI0 = TBI1 = 1`, `DS = 0`. The kernel was built
//! with `VA_BITS_52` and fell back to 47 bits because `lpa2=off` withheld the
//! feature, which is how a non-LPA2 16 KiB capture was obtained.
//!
//! # The independent answer
//!
//! Every expected value was produced by a Python stage-1 walker written from
//! ARM DDI 0487 D8 (VMSAv8-64, 16 KiB granule, `DS = 0`: level 1 is table
//! only, level 2 a 32 MiB block or a table, level 3 a 16 KiB page) without
//! reference to this crate's walker. It enumerated every valid leaf of each
//! tree and found no reserved encoding, no descriptor with bits 49:48 set and
//! no table pointer outside RAM; the counts and the order-independent digest
//! over `(va, pa, size)` below are its output, as are the spot translations
//! (a random interior address in randomly chosen leaves) and the faults
//! (slots whose descriptor is invalid, with the level, descriptor and
//! descriptor address the architecture says the walk stops at).
//!
//! # What this evidence does not exercise
//!
//! The 64 KiB granule; FEAT_LPA / LPA2 (`arm64_16k_lpa2_real_test.rs` is the capture
//! that does); any non-zero invalid descriptor (no swap or
//! `PROT_NONE` entry exists in these trees); hierarchical `APTable` /
//! `XNTable` as a *cause* of execute-never (table descriptors here do set `PXNTable` and
//! `UXNTable`, 26 of the kernel's 28 and 6 of the process's, but every leaf below them already
//! carries its own bit, so the rule is never what decides: see
//! `execute_never_agrees_with_the_independent_walker_on_every_leaf_of_both_trees`); hardware
//! access/dirty management (`HA = HD = 0`); an output address above 40 bits.

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

const CORPUS_VAR: &str = "SEANCE_ARM64_16K";

/// `-M virt` RAM: `0x4000_0000`, 512 MiB, file offset 0.
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 512 << 20;

/// Read through the gdbstub with the guest paused (`regs.py` in the capture
/// recipe).
const TCR: u64 = 0x0150_01f5_7551_b511;
const TTBR1: u64 = 0x001a_0000_41f5_4001;
const TTBR0: u64 = 0x480a_8001;

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

/// The recorded `TCR_EL1` builds 16 KiB regimes of 47 bits, with the field
/// values read by hand from the manual. No corpus needed: the value is the
/// evidence.
#[test]
fn the_recorded_tcr_selects_16k_regimes_of_47_bits() {
    for ttbr in [Ttbr::Ttbr0, Ttbr::Ttbr1] {
        let regime = regime_from_tcr(TCR, ttbr);
        assert_eq!(regime.granule(), Arm64Granule::Kb16, "{ttbr:?}");
        assert_eq!(regime.va_bits(), 47, "{ttbr:?}");
        assert_eq!(regime.ips_bits(), 48, "{ttbr:?}");
        assert!(regime.tbi(), "TBI0 = TBI1 = 1");
        assert!(!regime.hierarchical_permissions_disabled());
        assert!(!regime.walks_disabled());
    }
    // The fields read by hand, so the decoder is checked against the manual
    // rather than against itself. TG0 and TG1 encode 16 KiB differently.
    assert_eq!(bits(TCR, 15, 14), 0b10, "TG0: 16K");
    assert_eq!(bits(TCR, 31, 30), 0b01, "TG1: 16K");
    assert_eq!(64 - bits(TCR, 5, 0), 47, "T0SZ");
    assert_eq!(64 - bits(TCR, 21, 16), 47, "T1SZ");
    assert_eq!(bits(TCR, 59, 59), 0, "DS: no LPA2");
    assert_eq!(bits(TCR, 34, 32), 0b101, "IPS: 48-bit");
    assert_eq!(bits(TCR, 37, 37), 1, "TBI0");
    assert_eq!(bits(TCR, 38, 38), 1, "TBI1");
}

fn dump() -> Option<std::path::PathBuf> {
    corpus::file(CORPUS_VAR, "mem.raw")
}

#[test]
fn the_16k_kernel_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    check(
        &dump,
        Ttbr::Ttbr1,
        TTBR1,
        &Expected {
            pages: 35417,
            blocks_32m: 8,
            digest: 0x742b_d1b6_db01_7400,
            spots: KERNEL_SPOTS,
            faults: KERNEL_FAULTS,
        },
    );
}

#[test]
fn the_16k_process_tables_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    check(
        &dump,
        Ttbr::Ttbr0,
        TTBR0,
        &Expected {
            pages: 90,
            blocks_32m: 0,
            digest: 0x41b4_c02a_c781_e505,
            spots: PROCESS_SPOTS,
            faults: PROCESS_FAULTS,
        },
    );
}

/// Leaves the walk reports as no-execute, one count per page or block.
#[derive(Default)]
struct NoExecute {
    leaves: u64,
    no_execute: u64,
}

impl MappingSink for NoExecute {
    fn run(&mut self, run: &MappingRun) -> SinkFlow {
        let n = run.len / run.page_bytes;
        self.leaves += n;
        if run.no_execute {
            self.no_execute += n;
        }
        SinkFlow::Continue
    }

    fn blind(&mut self, blindness: &Blindness) -> SinkFlow {
        panic!("a blind spot in a tree the independent walker read whole: {blindness:?}");
    }
}

/// The recorded tables set `PXNTable` and `UXNTable` on 26 of the kernel's 28 table descriptors (`0x1800_0000_5fff_c003`:
/// bits 60 and 59) and `PXNTable` on 6 process ones, with `TCR_EL1.HPD0 = HPD1 = 0`, so the hierarchical bits apply.
/// The independent walker (`arm64_walk.py`) ORs them into every leaf below as the manual says (PXN under `TTBR1`, UXN
/// under `TTBR0`) and counts the leaves that end up no-execute: 34,313 of 35,425 kernel leaves and 6 of 90 process
/// ones, none of them made so by a table descriptor alone (every leaf under an `XNTable` already has its own bit). The
/// crate reports the same counts, so folding the table bits in changes nothing the leaves did not already say here.
#[test]
fn execute_never_agrees_with_the_independent_walker_on_every_leaf_of_both_trees() {
    let Some(dump) = dump() else { return };
    for (ttbr, register, leaves, no_execute) in [
        (Ttbr::Ttbr1, TTBR1, 35_425u64, 34_313u64),
        (Ttbr::Ttbr0, TTBR0, 90, 6),
    ] {
        let space = space(&dump, ttbr, register);
        let suppressed = AtomicU64::new(0);
        let walk = PageWalk::new(
            &**space.physical(),
            space.spec(),
            space.table_cache(),
            space.policy(),
            &suppressed,
        );
        let limits = EnumerateLimits {
            coalesce: false,
            ..EnumerateLimits::default()
        };
        let mut sink = NoExecute::default();
        let outcome = walk.enumerate(space.dtb(), &limits, &mut sink);
        assert!(outcome.is_complete(), "{outcome:?}");
        assert_eq!(
            (sink.leaves, sink.no_execute),
            (leaves, no_execute),
            "{ttbr:?}: leaves and no-execute leaves"
        );
    }
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

/// An address that fits the 47-bit regime's table but not its canonical form
/// is refused, not wrapped: the walk must not mistake bit 47 of a user
/// address for a table index.
#[test]
fn a_non_canonical_address_is_refused_in_both_regimes() {
    let Some(dump) = dump() else { return };
    let process = space(&dump, Ttbr::Ttbr0, TTBR0);
    assert!(matches!(
        process.translate(1 << 47),
        Err(TranslateError::NonCanonical { .. })
    ));
    let kernel = space(&dump, Ttbr::Ttbr1, TTBR1);
    assert!(matches!(
        kernel.translate(0xffff_7fff_ffff_f000),
        Err(TranslateError::NonCanonical { .. })
    ));
}

const KERNEL_SPOTS: &[(u64, u64, u64)] = &[
    (0xffff8000089970c8, 0x489970c8, 0x4000),
    (0xffff80000409dbb8, 0x4409dbb8, 0x4000),
    (0xffff800010533600, 0x50533600, 0x4000),
    (0xffff8000078bc3b0, 0x478bc3b0, 0x4000),
    (0xffff80001fb51c60, 0x5fb51c60, 0x4000),
    (0xffff80001cc47808, 0x5cc47808, 0x4000),
    (0xffff80001e397f70, 0x5e397f70, 0x4000),
    (0xffff8000184b9dd0, 0x584b9dd0, 0x4000),
    (0xffff80000d6fec38, 0x4d6fec38, 0x4000),
    (0xffff80000601dd88, 0x4601dd88, 0x4000),
    (0xffff80001f391c00, 0x5f391c00, 0x4000),
    (0xffff800001d07ad0, 0x41d07ad0, 0x4000),
    (0xffff800018f2a510, 0x58f2a510, 0x4000),
    (0xffff80001bb242c0, 0x5bb242c0, 0x4000),
    (0xffff80000022b540, 0x4022b540, 0x4000),
    (0xffff80001c810cc8, 0x5c810cc8, 0x4000),
    (0xffff8000110b97c8, 0x510b97c8, 0x4000),
    (0xffff80000ea425f0, 0x4ea425f0, 0x4000),
    (0xffff8000068acf78, 0x468acf78, 0x4000),
    (0xffff80001450ea90, 0x5450ea90, 0x4000),
    (0xffff800001f53600, 0x41f53600, 0x4000),
    (0xffff8000016d9848, 0x416d9848, 0x4000),
    (0xffff800001a0e6d0, 0x41a0e6d0, 0x4000),
    (0xffff80000096e458, 0x4096e458, 0x4000),
];

const KERNEL_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xfffffffad8000000, 1, 0x0, 0x4267eb60),
    (0xffffffbfc0910000, 2, 0x0, 0x5ff99220),
    (0xffffffbfc0c18000, 2, 0x0, 0x5ff99830),
    (0xffffffb81c000000, 1, 0x0, 0x5ff9e070),
    (0xfffffffb36000000, 1, 0x0, 0x4267ecd8),
    (0xffff8008f6000000, 1, 0x0, 0x5fffe3d8),
    (0xffffffbfbfd44000, 2, 0x0, 0x5630fa88),
    (0xffffec52cc000000, 1, 0x0, 0x42778b30),
    (0xffffffbae8000000, 1, 0x0, 0x5ff9eba0),
    (0xffffffbd7a000000, 1, 0x0, 0x5ff9f5e8),
    (0xffffffffc1dc4000, 2, 0x0, 0x446d7b88),
    (0xffffc0067a000000, 1, 0x0, 0x441ed9e8),
    (0xffffffb164000000, 1, 0x0, 0x5ff9c590),
    (0xfffffff0ec000000, 1, 0x0, 0x4267c3b0),
    (0xffffffffff0e8000, 2, 0x0, 0x426821d0),
    (0xfffffffffe248000, 2, 0x0, 0x42680490),
];

const PROCESS_SPOTS: &[(u64, u64, u64)] = &[
    (0x444128, 0x427d0128, 0x4000),
    (0x5a30c8, 0x4012f0c8, 0x4000),
    (0x421bb8, 0x427adbb8, 0x4000),
    (0x483600, 0x4000f600, 0x4000),
    (0x43c3b0, 0x427c83b0, 0x4000),
    (0x57dc60, 0x40109c60, 0x4000),
    (0x567808, 0x400f3808, 0x4000),
    (0x573f70, 0x400fff70, 0x4000),
    (0x4c1dd0, 0x4004ddd0, 0x4000),
    (0x46ac38, 0x427f6c38, 0x4000),
    (0x431d88, 0x427bdd88, 0x4000),
    (0x579c00, 0x40105c00, 0x4000),
    (0x40fad0, 0x5fe0bad0, 0x4000),
    (0x4c6510, 0x40052510, 0x4000),
    (0x54c2c0, 0x400d82c0, 0x4000),
    (0x403540, 0x5ff93540, 0x4000),
    (0x5d8cc8, 0x40164cc8, 0x4000),
    (0x4897c8, 0x400157c8, 0x4000),
    (0x4765f0, 0x400025f0, 0x4000),
    (0x434f78, 0x427c0f78, 0x4000),
    (0x4a2a90, 0x4002ea90, 0x4000),
    (0x5b7600, 0x40143600, 0x4000),
    (0x409848, 0x5fe05848, 0x4000),
    (0x5926d0, 0x4011e6d0, 0x4000),
];

const PROCESS_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0x512000000, 1, 0x0, 0x44729448),
    (0x7ffbec000000, 1, 0x0, 0x444fafb0),
    (0x7ff0a2000000, 1, 0x0, 0x444f8288),
    (0x7fffeda44000, 2, 0x0, 0x44483488),
    (0x7ff164000000, 1, 0x0, 0x444f8590),
    (0x187000000000, 0, 0x0, 0x480a8c38),
    (0x7ffc1c000000, 1, 0x0, 0x444fb070),
    (0x7fffedc14000, 2, 0x0, 0x44483828),
    (0xa30000, 2, 0x0, 0x444e9460),
    (0x717000000000, 0, 0x0, 0x480ab8b8),
    (0x25f40000, 2, 0x0, 0x44773e80),
    (0x7fffec004000, 2, 0x0, 0x44480008),
    (0x7fffecdc0000, 2, 0x0, 0x44481b80),
    (0x23a000000000, 0, 0x0, 0x480a91d0),
    (0x2df000000000, 0, 0x0, 0x480a96f8),
    (0x7fffacc44000, 2, 0x0, 0x444ed888),
];
