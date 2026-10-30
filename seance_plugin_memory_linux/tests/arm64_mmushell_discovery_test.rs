//! Why Linux discovery may not offer an arm64 image to Intel paging, shown on
//! two real AArch64 memory dumps.
//!
//! The arm64 tables map each banner at two addresses: the kernel image's and
//! the linear map's. Four-level x86-64 paging reads the Debian (48-bit) root
//! and translates the linear-map alias to the **same** physical page, because
//! a simple arm64 4K/48 hierarchy is also a valid x86-64 one. Only the kernel
//! image address is not x86-64 canonical on 4.19, which is why an Intel proof
//! of `linux_banner` fails there; from 5.4 the image moved to an address that
//! is canonical, and nothing but the architecture hint (or the image's
//! VMCOREINFO) keeps Intel out. Discovery's own tests pin that decision on
//! synthetic tables; this file pins the hazard on real ones.
//!
//! # Evidence
//!
//! The MMUShell dataset's `aarch64/linux.7z` (buildroot, `4.19.91`) and
//! `aarch64/linux_debian.7z` (Debian `4.19.0-11-arm64`), provenance
//! `forensic_corpora/mmushell_dataset/PROVENANCE.md`. Each is a 4 GiB
//! `linux.dump` of a **QEMU-emulated** AArch64 guest placed at physical
//! `0x4000_0000` by its `Linux.yaml`. Not ARM64 hardware.
//!
//! `SEANCE_MMUSHELL_AARCH64` names the directory the archives were extracted
//! into, one subdirectory each (the layout
//! `seance_memory/tests/arm64_mmushell_real_test.rs` uses):
//!
//! ```text
//! $SEANCE_MMUSHELL_AARCH64/linux/linux.dump    (from aarch64/linux.7z)
//! $SEANCE_MMUSHELL_AARCH64/debian/linux.dump   (from aarch64/linux_debian.7z)
//! ```
//!
//! Unset, the tests skip; set and missing a dump, they fail.
//!
//! # The independent answers
//!
//! The roots are the `TTBR1_EL1` BADDRs QEMU recorded (read from `linux.regs`
//! with `pickletools`, never unpickled — see the memory crate's test):
//! `0x4075_5000` (buildroot, `T1SZ = 25`, 39-bit) and `0x412e_e000` (Debian,
//! `T1SZ = 16`, 48-bit). The banners' physical addresses are where the bytes
//! `Linux version ` stand in each file (file offset + `0x4000_0000`), found by
//! streaming the dumps, not by this crate. The expected virtual addresses are
//! the 4.19 arm64 layout's arithmetic (`Documentation/arm64/memory.txt`,
//! `PHYS_OFFSET = 0x4000_0000`): the linear map at `PAGE_OFFSET` plus
//! `pa - PHYS_OFFSET`, and the kernel image at `KIMAGE_VADDR` plus the image
//! offset — not addresses this crate chose.

use std::path::Path;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::translate::{
    Arm64Granule, Arm64Regime, Blindness, EnumerateLimits, MappingRun, MappingSink, PageWalk,
    PagingMode, PagingSpec, PteSemantics, SinkFlow, Ttbr, VirtualLayer,
};
use seance_memory::{LayerMeta, MemoryImageFormat, MemoryLayer};

const CORPUS_VAR: &str = "SEANCE_MMUSHELL_AARCH64";
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 4 << 30;

struct Dump {
    path: &'static str,
    root: u64,
    va_bits: u8,
    banner_physical: u64,
    banner_prefix: &'static str,
}

const BUILDROOT: Dump = Dump {
    path: "linux/linux.dump",
    root: 0x4075_5000,
    va_bits: 39,
    banner_physical: RAM_BASE + 5_439_584,
    banner_prefix: "Linux version 4.19.91 (root@buildroot)",
};

const DEBIAN: Dump = Dump {
    path: "debian/linux.dump",
    root: 0x412e_e000,
    va_bits: 48,
    banner_physical: RAM_BASE + 9_765_048,
    banner_prefix: "Linux version 4.19.0-11-arm64",
};

fn physical(dump: &Path) -> Arc<dyn MemoryLayer> {
    let source = FileDataSource::new(dump.to_path_buf()).expect("the corpus gate proved it exists");
    Arc::new(
        SegmentedLayer::new(
            Arc::new(source),
            vec![Segment::new(0, RAM_BASE, RAM_LEN)],
            LayerMeta::new(MemoryImageFormat::Raw),
        )
        .expect("one 4 GiB segment at 0x4000_0000"),
    )
}

/// Every virtual address whose leaf covers one physical address.
struct Covering {
    target: u64,
    found: Vec<u64>,
}

impl MappingSink for Covering {
    fn run(&mut self, run: &MappingRun) -> SinkFlow {
        if (run.phys_start..run.phys_start + run.len).contains(&self.target) {
            self.found
                .push(run.va_start + (self.target - run.phys_start));
        }
        SinkFlow::Continue
    }

    fn blind(&mut self, _: &Blindness) -> SinkFlow {
        SinkFlow::Continue
    }
}

fn arm64_kernel_spec(va_bits: u8) -> PagingSpec {
    let regime = Arm64Regime::new(Arm64Granule::Kb4, Ttbr::Ttbr1, va_bits).expect("a valid width");
    PagingSpec::new(PagingMode::Arm64(regime), PteSemantics::Linux)
}

/// The kernel virtual addresses the arm64 tables map the banner at.
fn banner_virtuals(physical: &Arc<dyn MemoryLayer>, dump: &Dump) -> Vec<u64> {
    let space = VirtualLayer::new(
        Arc::clone(physical),
        dump.root,
        arm64_kernel_spec(dump.va_bits),
    )
    .expect("the recorded root");
    let suppressed = AtomicU64::new(0);
    let walk = PageWalk::new(
        &**space.physical(),
        space.spec(),
        space.table_cache(),
        space.policy(),
        &suppressed,
    );
    let mut sink = Covering {
        target: dump.banner_physical,
        found: Vec::new(),
    };
    let outcome = walk.enumerate(dump.root, &EnumerateLimits::default(), &mut sink);
    assert!(outcome.is_complete(), "{outcome:?}");
    for va in &sink.found {
        assert_eq!(
            space
                .translate(*va)
                .expect("an enumerated VA translates")
                .phys,
            dump.banner_physical
        );
    }
    sink.found
}

fn banner_bytes(physical: &Arc<dyn MemoryLayer>, at: u64) -> String {
    let mut buf = vec![0u8; 64];
    let read = seance_core::io::read_full(physical.as_data_source(), at, &mut buf);
    String::from_utf8_lossy(&buf[..read]).into_owned()
}

#[test]
fn the_debian_tables_map_the_banner_at_its_image_and_linear_map_addresses() {
    let Some(path) = corpus::file(CORPUS_VAR, DEBIAN.path) else {
        return;
    };
    let physical = physical(&path);
    assert!(banner_bytes(&physical, DEBIAN.banner_physical).starts_with(DEBIAN.banner_prefix));
    // PAGE_OFFSET 0xffff_8000_0000_0000 + 0x9500b8; KIMAGE_VADDR
    // 0xffff_0000_0800_0000 + 0x9500b8.
    assert_eq!(
        banner_virtuals(&physical, &DEBIAN),
        vec![0xffff_0000_0895_00b8, 0xffff_8000_0095_00b8]
    );
}

#[test]
fn the_buildroot_tables_map_the_banner_at_its_image_and_linear_map_addresses() {
    let Some(path) = corpus::file(CORPUS_VAR, BUILDROOT.path) else {
        return;
    };
    let physical = physical(&path);
    assert!(banner_bytes(&physical, BUILDROOT.banner_physical).starts_with(BUILDROOT.banner_prefix));
    // 39-bit: KIMAGE_VADDR 0xffff_ff80_0800_0000 + 0x530060; PAGE_OFFSET
    // 0xffff_ffc0_0000_0000 + 0x530060.
    assert_eq!(
        banner_virtuals(&physical, &BUILDROOT),
        vec![0xffff_ff80_0853_0060, 0xffff_ffc0_0053_0060]
    );
}

#[test]
fn intel_four_level_paging_reads_the_real_debian_arm64_root_and_finds_the_banner() {
    let Some(path) = corpus::file(CORPUS_VAR, DEBIAN.path) else {
        return;
    };
    let physical = physical(&path);
    let intel = |mode| {
        VirtualLayer::new(
            Arc::clone(&physical),
            DEBIAN.root,
            PagingSpec::new(mode, PteSemantics::Linux),
        )
        .expect("the recorded root is inside the image")
    };
    // The hazard: the linear-map alias translates under x86-64 four-level
    // rules, through a 2 MiB leaf, to the banner's own physical page.
    let four = intel(PagingMode::Intel32e);
    let alias = four
        .translate(0xffff_8000_0095_00b8)
        .expect("an arm64 4K/48 hierarchy reads as a valid x86-64 one");
    assert_eq!(alias.phys, DEBIAN.banner_physical);
    assert_eq!(alias.run_len, 0x20_0000);
    // What keeps a 4.19 proof out: the kernel image's address is not x86-64
    // canonical, so `linux_banner` cannot be proved under Intel paging.
    assert!(
        matches!(
            four.translate(0xffff_0000_0895_00b8),
            Err(seance_memory::translate::TranslateError::NonCanonical { .. })
        ),
        "a 4.19 arm64 kernel-image address is not x86-64 canonical"
    );
    // Five-level rules read the same root differently, and find nothing.
    let five = intel(PagingMode::Intel32eLa57);
    assert!(five.translate(0xffff_8000_0095_00b8).is_err());
}

#[test]
fn intel_paging_translates_neither_buildroot_banner_address() {
    let Some(path) = corpus::file(CORPUS_VAR, BUILDROOT.path) else {
        return;
    };
    let physical = physical(&path);
    for mode in [PagingMode::Intel32e, PagingMode::Intel32eLa57] {
        let space = VirtualLayer::new(
            Arc::clone(&physical),
            BUILDROOT.root,
            PagingSpec::new(mode, PteSemantics::Linux),
        )
        .expect("the recorded root is inside the image");
        for va in [0xffff_ff80_0853_0060, 0xffff_ffc0_0053_0060] {
            assert!(space.translate(va).is_err(), "{mode} {va:#x}");
        }
    }
}

/// The kernel's own symbol table, decoded from the first 256 MiB of the dump
/// (the kernel image sits near the bottom of RAM on both guests).
fn kallsyms_of(dump: &Path) -> seance_memory::kallsyms::Kallsyms {
    use std::io::{Read, Seek, SeekFrom};
    const WINDOW: usize = 64 << 20;
    const OVERLAP: usize = 16 << 20;
    let mut file = std::fs::File::open(dump).expect("the corpus gate proved it exists");
    let mut buffer = vec![0u8; WINDOW];
    let mut at = 0usize;
    while at < 256 << 20 {
        file.seek(SeekFrom::Start(at as u64)).expect("seek");
        let mut filled = 0;
        while filled < WINDOW {
            match file.read(&mut buffer[filled..]).expect("read") {
                0 => break,
                n => filled += n,
            }
        }
        if let Some((_, table)) = seance_memory::kallsyms::Kallsyms::find_in(&buffer[..filled]) {
            return table;
        }
        at += WINDOW - OVERLAP;
    }
    panic!(
        "no kallsyms table decoded in the first 256 MiB of {}",
        dump.display()
    );
}

/// What each dump's kallsyms decode must give, read independently: the
/// count from `kallsyms_num_syms` and the base from `kallsyms_relative_base`
/// (each at a 256-byte-aligned label, read by hand with a byte dump), and
/// the kernel-image offset from the arm64 `Image` header at physical
/// `0x4008_0000` (`text_offset` = `0x80000`, magic `ARM\x64` at 0x38 —
/// `Documentation/arm64/booting.txt`).
struct KallsymsAnswer {
    count: usize,
    relative_base: u64,
}

const DEBIAN_KALLSYMS: KallsymsAnswer = KallsymsAnswer {
    count: 38_164,
    relative_base: 0xffff_0000_0808_0000,
};

const BUILDROOT_KALLSYMS: KallsymsAnswer = KallsymsAnswer {
    count: 20_637,
    relative_base: 0xffff_ff80_0808_0000,
};

/// The arm64 `Image` header the boot loader placed at the start of RAM plus
/// `text_offset`.
const IMAGE_HEADER_PHYSICAL: u64 = RAM_BASE + 0x8_0000;

fn kallsyms_decodes_and_its_addresses_walk_to_the_kernel_image(
    dump: &Dump,
    answer: &KallsymsAnswer,
) {
    let Some(path) = corpus::file(CORPUS_VAR, dump.path) else {
        return;
    };
    let symbols = kallsyms_of(&path);
    assert_eq!(symbols.len(), answer.count, "kallsyms_num_syms");
    // `_stext` is one page past `_text`, which is the Image header.
    let stext = symbols
        .address_of("_stext")
        .expect("_stext is a text symbol");
    assert_eq!(stext, answer.relative_base + 0x1000);
    let physical = physical(&path);
    let space = VirtualLayer::new(
        Arc::clone(&physical),
        dump.root,
        arm64_kernel_spec(dump.va_bits),
    )
    .expect("the recorded root");
    let head = space
        .translate(stext - 0x1000)
        .expect("the kernel image is mapped")
        .phys;
    assert_eq!(head, IMAGE_HEADER_PHYSICAL);
    let mut header = [0u8; 64];
    assert_eq!(
        seance_core::io::read_full(physical.as_data_source(), head, &mut header),
        header.len()
    );
    assert_eq!(&header[0x38..0x3c], b"ARM\x64", "the arm64 Image magic");
    assert_eq!(
        u64::from_le_bytes(header[8..16].try_into().unwrap()),
        0x8_0000
    );
    // Why the banner proof cannot run from these tables: neither kernel was
    // built with CONFIG_KALLSYMS_ALL, so no data symbol is listed. That is
    // read off a complete decode (every one of `count` entries), not
    // inferred from a partial one.
    for data_symbol in [
        "linux_banner",
        "swapper_pg_dir",
        "init_task",
        "kimage_voffset",
    ] {
        assert_eq!(symbols.address_of(data_symbol), None, "{data_symbol}");
    }
}

#[test]
fn the_debian_kallsyms_decodes_and_its_addresses_walk_to_the_kernel_image() {
    kallsyms_decodes_and_its_addresses_walk_to_the_kernel_image(&DEBIAN, &DEBIAN_KALLSYMS);
}

#[test]
fn the_buildroot_kallsyms_decodes_and_its_addresses_walk_to_the_kernel_image() {
    kallsyms_decodes_and_its_addresses_walk_to_the_kernel_image(&BUILDROOT, &BUILDROOT_KALLSYMS);
}
