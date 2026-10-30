//! The arm64 kernel page-table root, proved from the kernel's own
//! `VMCOREINFO` in a real AArch64 memory dump.
//!
//! # Evidence
//!
//! The MMUShell dataset's `aarch64/linux_debian.7z` (Oliveri & Balzarotti,
//! ACM TOPS 2022; provenance `forensic_corpora/mmushell_dataset/PROVENANCE.md`):
//! a 4 GiB `linux.dump` of a **QEMU-emulated** AArch64 guest running Debian's
//! `4.19.0-11-arm64`, placed at physical `0x4000_0000` by its `Linux.yaml`.
//! Not ARM64 hardware.
//!
//! `SEANCE_MMUSHELL_AARCH64` names the directory the archives were extracted
//! into, one subdirectory each (the layout
//! `seance_memory/tests/arm64_mmushell_real_test.rs` uses):
//!
//! ```text
//! $SEANCE_MMUSHELL_AARCH64/debian/linux.dump   (from aarch64/linux_debian.7z)
//! $SEANCE_MMUSHELL_AARCH64/linux/linux.dump    (from aarch64/linux.7z)
//! ```
//!
//! Unset, the tests skip; set and missing a dump, they fail.
//!
//! # The independent answer
//!
//! QEMU recorded the guest's `TTBR1_EL1` as `0x42e_0000_412e_e000` (ASID
//! `0x42e`, BADDR `0x412e_e000`), read from `linux.regs` with `pickletools`
//! (see the memory crate's test). That register value is what the hardware
//! walked from; this crate never reads it here. The note's
//! `SYMBOL(swapper_pg_dir) - NUMBER(kimage_voffset)` must equal it, and the
//! walk from it must read the release back out of `init_uts_ns`.
//!
//! # Not exercised
//!
//! The buildroot `aarch64/linux` dump holds **no** `VMCOREINFO` text: the
//! sweep examines every byte and meets no `OSRELEASE=` at all — no note and
//! no refused hit, not even the `.rodata` format string a kernel with the
//! feature carries — so the proof has only one real image. That its kernel
//! was built without `CONFIG_CRASH_CORE` is an inference from that absence,
//! not something read from the image. No 16 or 64 KiB granule, no 39-bit kernel and no arm64
//! symbol table is held, so this is a root proof, not a Linux profile.

use std::path::Path;
use std::sync::Arc;

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::translate::{Arm64Granule, Ttbr};
use seance_memory::{LayerMeta, MemoryImageFormat, MemoryLayer};
use seance_plugin_memory_linux::vmcoreinfo::{
    self, prove_arm64_kernel_root, VmcoreArchitecture, ARM64_KERNEL_REGIMES,
};

const CORPUS_VAR: &str = "SEANCE_MMUSHELL_AARCH64";
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 4 << 30;
/// BADDR of the `TTBR1_EL1` QEMU recorded last for the Debian guest.
const QEMU_TTBR1_BADDR: u64 = 0x412e_e000;

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

#[test]
fn the_debian_arm64_root_from_vmcoreinfo_is_the_ttbr1_qemu_recorded() {
    let Some(dump) = corpus::file(CORPUS_VAR, "debian/linux.dump") else {
        return;
    };
    let physical = physical(&dump);
    let sweep = vmcoreinfo::sweep(&*physical).expect("the dump sweeps");
    assert!(sweep.complete, "every byte of the dump was examined");
    // Two copies: the ELF note and the vmcoreinfo_data buffer. The hits the
    // kernel's own "OSRELEASE=%s" format string makes are refused.
    assert_eq!(sweep.found.len(), 2, "{:?}", sweep.refused);
    assert!(!sweep.refused.is_empty(), "the .rodata format strings");
    let info = sweep
        .agreed()
        .expect("the copies agree")
        .expect("a note was found");
    assert_eq!(info.osrelease(), "4.19.0-11-arm64");
    assert_eq!(info.architecture(), VmcoreArchitecture::Arm64);
    assert_eq!(info.arm64_kernel_root(), Some(QEMU_TTBR1_BADDR));

    let proof = prove_arm64_kernel_root(&physical, info).expect("the root proves");
    assert_eq!(proof.root, QEMU_TTBR1_BADDR);
    assert_eq!(proof.regime.granule(), Arm64Granule::Kb4);
    assert_eq!(proof.regime.ttbr(), Ttbr::Ttbr1);
    assert_eq!(proof.regime.va_bits(), 48);
    assert_eq!(
        proof.tried.len(),
        ARM64_KERNEL_REGIMES.len(),
        "every candidate regime was walked, and only one proved: {:?}",
        proof.tried
    );
}

#[test]
fn the_buildroot_arm64_dump_holds_no_vmcoreinfo_and_the_sweep_says_so() {
    let Some(dump) = corpus::file(CORPUS_VAR, "linux/linux.dump") else {
        return;
    };
    let sweep = vmcoreinfo::sweep(&*physical(&dump)).expect("the dump sweeps");
    assert!(sweep.complete, "every byte of the dump was examined");
    assert!(sweep.found.is_empty(), "{:?}", sweep.found);
    // Not one `OSRELEASE=` hit, refused or accepted: the needle never occurs.
    assert!(sweep.refused.is_empty(), "{:?}", sweep.refused);
    assert_eq!(sweep.agreed().unwrap(), None);
}
