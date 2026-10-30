//! The ARM64 translation core against a real **64 KiB-granule 512 MiB block**, and real non-zero invalid descriptors
//! (`MEM-043`): the Ubuntu 6.8 64 KiB kernel of `arm64_64k_real_test.rs` booted again under QEMU TCG with 4 GiB of RAM,
//! so that its linear map is big enough for level-2 blocks, compared leaf by leaf with an independent walker.
//!
//! # Evidence
//!
//! `linux-image-unsigned-6.8.0-71-generic-64k` (Ubuntu noble; see `forensic_corpora/arm64_64k_qemu/SOURCE.md`), the same
//! busybox initrd, `qemu-system-aarch64` 10.2.1, `-M virt -cpu max,lpa2=off -m 4096`, and the kernel command line
//! `console=ttyAMA0 earlycon rodata=on kfence.sample_interval=100` (`~/arm-qemu/run64.sh`). The three extra words are
//! what makes the capture useful: Ubuntu's kernel is built with KFENCE, and in this kernel version a KFENCE that is
//! compiled in but not started forces the linear map into pages whatever the RAM size or `rodata=` says (two captures
//! with `rodata=on` and `rodata=off` alone had 70,624 64 KiB pages and no block); starting KFENCE early lets the linear
//! map use blocks. KFENCE also protects its guard pages by **clearing the valid bit of their descriptors and leaving the
//! rest in place**, which is the source of the non-zero invalid descriptors below. RAM was saved with `pmemsave
//! 0x40000000 4294967296` after the init printed `SEANCE_READY`, and the registers read through the gdbstub
//! (`gdbregs.py`): `TCR_EL1` `0x0150_01f5_f550_7510`, `TTBR1_EL1` `0x001a_0000_428a_0001`, `TTBR0_EL1`
//! `0x001a_0001_0058_1801`. **QEMU-emulated, not hardware.**
//!
//! The independent answer is `scripts/oracle/arm64_walk.py --granule 16`, written from ARM DDI 0487 D8 without reference to
//! this crate: it reproduces `arm64_64k_real_test.rs`'s 512 MiB capture exactly (13,203 pages, the same digest) and gives
//! here: kernel 21,211 64 KiB pages and **6 512 MiB blocks**, with **261 invalid descriptors that are not zero** and
//! 20,855 no-execute leaves, and six of the faults pinned below stop at one of those non-zero invalid descriptors (the
//! crate reports the entry as written); a process tree of 26 pages. `PXNTable`/`UXNTable` bits are set on table descriptors here too
//! and, as on the 16 KiB capture, no leaf is made no-execute by them alone.
//!
//! # Running it
//!
//! `SEANCE_ARM64_64K_4G` names a directory holding the capture as `mem.raw` (4 GiB, file offset 0 is physical
//! `0x4000_0000`). Unset, every test here skips.

const CORPUS_VAR: &str = "SEANCE_ARM64_64K_4G";

/// `-M virt` RAM: `0x4000_0000`, 4 GiB, file offset 0.
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 4 << 30;

/// Read through the gdbstub with the guest paused.
const TCR: u64 = 0x0150_01f5_f550_7510;
const TTBR1: u64 = 0x001a_0000_428a_0001;
const TTBR0: u64 = 0x001a_0001_0058_1801;

use std::collections::BTreeMap;
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

fn dump() -> Option<std::path::PathBuf> {
    corpus::file(CORPUS_VAR, "mem.raw")
}

#[test]
fn the_64k_kernel_tables_with_512m_blocks_agree_with_an_independent_walker_on_every_leaf() {
    let Some(dump) = dump() else { return };
    check(
        &dump,
        Ttbr::Ttbr1,
        TTBR1,
        &Expected {
            pages: 21211,
            blocks_512m: 6,
            digest: 0x9be6ddb0924d530b,
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
            digest: 0x310432f5adee69fb,
            spots: PROCESS_SPOTS,
            faults: PROCESS_FAULTS,
        },
    );
}

const KERNEL_SPOTS: &[(u64, u64, u64)] = &[
    (0xffff000011320114, 0x51320114, 0x10000),
    (0xffff8000992de409, 0x40192de409, 0x10000),
    (0xffff00000813885c, 0x4813885c, 0x10000),
    (0xffff0000e0a07520, 0x120a07520, 0x10000),
    (0xffff00000f173457, 0x4f173457, 0x10000),
    (0xffff800080b5a286, 0x10178a286, 0x10000),
    (0xffff0000f9820fa9, 0x139820fa9, 0x10000),
    (0xffff0000fc6c0b6d, 0x13c6c0b6d, 0x10000),
    (0xffff0000f0910d07, 0x130910d07, 0x10000),
    (0xffff00001adf04b6, 0x5adf04b6, 0x10000),
    (0xffff00000c03c32d, 0x4c03c32d, 0x10000),
    (0xffff0000fee46ee6, 0x13ee46ee6, 0x10000),
    (0xffff000003a0d81f, 0x43a0d81f, 0x10000),
    (0xffff0000f1df0ede, 0x131df0ede, 0x10000),
    (0xffff0000f75e7181, 0x1375e7181, 0x10000),
    (0xffff80009e12e032, 0x401e12e032, 0x10000),
];

const KERNEL_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0xffff77568d88348a, 0, 0x0, 0x428a00e8),
    (0xffff7634587fd280, 0, 0x0, 0x428a00e8),
    (0xfffffddbf06d3fef, 1, 0x0, 0x43ac76f8),
    (0xffff02ecbab9f87f, 1, 0x0, 0x13dfdbb28),
    (0xffff80008fa10000, 2, 0x0, 0x100767d08),
    (0xffff80008da10000, 2, 0x0, 0x100766d08),
    // Six of the 261 invalid descriptors that are not zero: KFENCE guard pages, valid bit clear, the rest as written.
    (0xffff0000fdfe0000, 2, 0x6800013dfe0706, 0x13dfbeff0),
    (0xffff0000fe4b0000, 2, 0x6800013e4b0706, 0x13dfbf258),
    (0xffff0000fea10000, 2, 0x6800013ea10706, 0x13dfbf508),
    (0xffff0000fef70000, 2, 0x6800013ef70706, 0x13dfbf7b8),
    (0xffff0000ff4d0000, 2, 0x6800013f4d0706, 0x13dfbfa68),
    (0xffff0000ffa30000, 2, 0x6800013fa30706, 0x13dfbfd18),
];

const PROCESS_SPOTS: &[(u64, u64, u64)] = &[
    (0x440114, 0x13d300114, 0x10000),
    (0x5ae409, 0x13d02e409, 0x10000),
    (0x42885c, 0x13d34885c, 0x10000),
    (0x487520, 0x13d207520, 0x10000),
    (0x433457, 0x13d353457, 0x10000),
    (0x57a286, 0x13d2fa286, 0x10000),
    (0x560fa9, 0x13d2e0fa9, 0x10000),
    (0x5c0b6d, 0x13d040b6d, 0x10000),
    (0x4c0d07, 0x13d240d07, 0x10000),
    (0x4604b6, 0x13d3204b6, 0x10000),
    (0x5dc32d, 0x13d10c32d, 0x10000),
    (0x476ee6, 0x13d336ee6, 0x10000),
    (0x40d81f, 0x13db3d81f, 0x10000),
    (0x580ede, 0x13d000ede, 0x10000),
    (0x597181, 0x13d017181, 0x10000),
    (0x49e032, 0x13d21e032, 0x10000),
];

const PROCESS_FAULTS: &[(u64, u8, u64, u64)] = &[
    (0x77568d88348a, 0, 0x0, 0x1005818e8),
    (0x7634587fd280, 0, 0x0, 0x1005818e8),
    (0xfddbf06d3fef, 1, 0x0, 0x1030376f8),
    (0xeb51c2cd789a, 1, 0x0, 0x1030bd470),
    (0x5f0000, 2, 0x0, 0x1030902f8),
    (0x550000, 2, 0x0, 0x1030902a8),
];
