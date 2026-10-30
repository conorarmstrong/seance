//! Linux discovery over a real 64 KiB-granule arm64 capture: Ubuntu noble's
//! own `6.8.0-71-generic-64k` kernel, booted under QEMU TCG and paused.
//!
//! # Evidence
//!
//! `SEANCE_ARM64_64K` names `forensic_corpora/arm64_64k_qemu`, whose
//! `SOURCE.md` holds the packages, hashes and the exact command line. `mem.raw`
//! is the guest's 512 MiB of RAM at physical `0x4000_0000`, saved with QMP
//! `pmemsave`. **QEMU-emulated, not ARM64 hardware.**
//!
//! # Ground truth
//!
//! * `TCR_EL1` / `TTBR1_EL1` read off the paused machine through the gdbstub
//!   (`0x0150_01f5_f550_7510`, `0x001a_0000_428a_0001`): 64 KiB, 48-bit.
//! * The kernel package's name (`-generic-64k`, Ubuntu's `CONFIG_ARM64_64K_PAGES`
//!   flavour) and the guest's boot log, which prints the banner. No `System.map`
//!   or `config` is held for this capture: only the kernel image was fetched.
//! * The guest's serial log, which prints the banner discovery must recover.
//! * The ELF program headers of the busybox the guest ran (`readelf -l`, the
//!   package `busybox-static_1.37.0-6+b9_arm64`, binary sha256 `7d93682b...8bc34`):
//!   text `LOAD` at file offset 0 / vaddr `0x400000`, memsz `0x1cb1ac`, and
//!   data `LOAD` at offset `0x1d8a90` / vaddr `0x5d8a90`. An ELF `LOAD` keeps
//!   `vaddr - offset = 0x400000`, so a file-backed mapping's offset is
//!   `start - 0x400000` whatever the kernel's page size: a reader scaling
//!   `vm_pgoff` by 4 KiB on this 64 KiB kernel is a factor of 16 short.
//!
//! The profile is image-derived (BTF plus kallsyms from the
//! capture), no symbol file is passed to discovery.
//!
//! Until 2026-10-20 discovery refused this kernel by name because the stages
//! counted file offsets in 4 KiB pages. `proc_maps` now takes the page shift
//! from the profile's paging spec and the refusal is gone; this file is the
//! evidence the stages run on a real 64 KiB kernel.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::{LayerMeta, MemoryImageFormat, MemoryLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::profile::LinuxProfile;
use seance_plugin_memory_linux::{proc_maps, tasks};

const CORPUS_VAR: &str = "SEANCE_ARM64_64K";
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 512 << 20;

fn physical(dump: &std::path::Path) -> Arc<dyn MemoryLayer> {
    let source = FileDataSource::new(dump.to_path_buf()).expect("the corpus gate proved it exists");
    Arc::new(
        SegmentedLayer::new(
            Arc::new(source),
            vec![Segment::new(0, RAM_BASE, RAM_LEN)],
            LayerMeta::new(MemoryImageFormat::Raw),
        )
        .expect("one 512 MiB segment at 0x4000_0000"),
    )
}

fn dump() -> Option<PathBuf> {
    corpus::file(CORPUS_VAR, "mem.raw")
}

fn profile() -> Option<LinuxProfile> {
    let dump = dump()?;
    Some(
        discovery::discover(physical(&dump), &[], &DiscoveryOptions::default())
            .unwrap_or_else(|err| panic!("discovery refused the 64 KiB kernel: {err}")),
    )
}

const BANNER_PREFIX: &str = "Linux version 6.8.0-71-generic-64k (buildd@bos03-arm64-036)";

#[test]
fn the_64k_kernel_is_profiled_under_its_own_regime_from_its_own_btf() {
    let Some(dump) = dump() else { return };
    let (profile, report) =
        discovery::discover_reported(physical(&dump), &[], &DiscoveryOptions::default())
            .unwrap_or_else(|err| panic!("discovery refused the 64 KiB kernel: {err}"));
    assert!(
        profile.build.banner.starts_with(BANNER_PREFIX),
        "{}",
        profile.build.banner
    );
    assert_eq!(
        profile.paging.mode().to_string(),
        "arm64_64k_ttbr1 (48-bit VA)"
    );
    assert_eq!(profile.paging.page_offset_bits(), 16);
    // TTBR1_EL1 0x001a_0000_41f5_4001 read off the paused machine: BADDR
    // without ASID and CnP.
    assert_eq!(profile.dtb.value, 0x428a_0000);
    assert_eq!(profile.dtb_symbol, "swapper_pg_dir");
    let notes = report.notes.join("\n");
    assert!(notes.contains("arm64_64k_ttbr1"), "{notes}");
}

#[test]
fn the_process_list_of_the_64k_kernel_closes_and_agrees_with_the_boot_script() {
    let Some(profile) = profile() else { return };
    let layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");
    assert!(list.is_complete(), "{:?}", list.incomplete());

    let by_pid: HashMap<i64, &tasks::TaskRecord> = list
        .tasks
        .iter()
        .map(|t| (*t.pid.known().expect("every pid reads"), t))
        .collect();
    assert_eq!(by_pid.len(), list.tasks.len(), "a pid is listed twice");
    let init = by_pid.get(&1).expect("pid 1");
    assert_eq!(init.comm.known().map(String::as_str), Some("init"));
    assert_eq!(init.ppid.known(), Some(&0));
    assert_eq!(init.kernel_thread.known(), Some(&false));
    let kthreadd = by_pid.get(&2).expect("pid 2");
    assert_eq!(kthreadd.comm.known().map(String::as_str), Some("kthreadd"));

    let listed: HashSet<i64> = by_pid.keys().copied().chain([0]).collect();
    for task in &list.tasks {
        let pid = *task.pid.known().expect("pid");
        let ppid = *task.ppid.known().expect("ppid");
        assert!(
            listed.contains(&ppid),
            "pid {pid}: parent {ppid} not listed"
        );
        if task.kernel_thread.known() == Some(&true) && pid != 2 {
            assert_eq!(ppid, 2, "kernel thread {:?}", task.comm);
        }
    }
    // The boot script (initramfs /init) is the only user-space: busybox sh as
    // pid 1 and three `sleep` children of it, two backgrounded and one in the
    // loop. Nothing else is started.
    let user: Vec<_> = list
        .tasks
        .iter()
        .filter(|t| t.kernel_thread.known() == Some(&false))
        .collect();
    assert_eq!(user.len(), 4);
    let sleeps = user
        .iter()
        .filter(|t| t.comm.known().map(String::as_str) == Some("sleep"))
        .count();
    assert_eq!(sleeps, 3);
    for sleeper in user.iter().filter(|t| t.pid.known() != Some(&1)) {
        assert_eq!(sleeper.ppid.known(), Some(&1));
    }
}

#[test]
fn file_offsets_of_the_64k_kernels_mappings_match_the_elf_program_headers() {
    let Some(profile) = profile() else { return };
    let layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");
    let maps = proc_maps::bind(&profile)
        .and_then(|l| {
            proc_maps::survey_process_maps(
                &profile,
                &l,
                &list,
                &proc_maps::ProcessMapsConfig::default(),
            )
        })
        .expect("the maps survey runs");
    assert!(maps.is_complete());

    let mut file_backed = 0;
    let mut checked_processes = 0;
    for process in maps.processes.iter().filter(|p| !p.regions.is_empty()) {
        checked_processes += 1;
        for region in &process.regions {
            let (&start, &end) = (
                region.vm_start.known().expect("start"),
                region.vm_end.known().expect("end"),
            );
            assert!(
                region.is_valid,
                "{start:#x}-{end:#x} is not a 64 KiB multiple"
            );
            assert_eq!((end - start) % 0x1_0000, 0);
            if let Some(path) = region.path.known() {
                file_backed += 1;
                assert_eq!(path, "/bin/busybox");
                // ELF: vaddr - offset = 0x400000 for every LOAD.
                assert_eq!(
                    region.file_offset.known(),
                    Some(&(start - 0x40_0000)),
                    "pid {:?} {start:#x}",
                    process.pid
                );
            }
        }
        // Text LOAD: vaddr 0x400000, memsz 0x1cb1ac rounded up to 64 KiB.
        let text = &process.regions[0];
        assert_eq!(text.vm_start.known(), Some(&0x40_0000));
        assert_eq!(text.vm_end.known(), Some(&0x5d_0000));
        assert_eq!(text.file_offset.known(), Some(&0));
    }
    assert_eq!(checked_processes, 4);
    assert_eq!(
        file_backed,
        4 * 3,
        "text, relro and data of busybox, per process"
    );
}
