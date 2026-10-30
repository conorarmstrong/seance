//! An end-to-end arm64 `LinuxProfile` on real data: the MMUShell AArch64
//! `linux_debian` dump, profiled from the symbol file of its **exact** kernel,
//! and the process-list stages run over it.
//!
//! # Evidence
//!
//! * The memory: MMUShell `aarch64/linux_debian.7z` -> `linux.dump`, a 4 GiB
//!   capture of a **QEMU-emulated** AArch64 guest placed at physical
//!   `0x4000_0000` by its `Linux.yaml` (provenance
//!   `forensic_corpora/mmushell_dataset/PROVENANCE.md`). Not ARM64 hardware.
//! * The kernel: Debian `linux-image-4.19.0-11-arm64-dbg_4.19.146-1`
//!   (snapshot.debian.org, sha256 `d205f2eb…42b2`) for the DWARF `vmlinux`, and
//!   `linux-image-4.19.0-11-arm64-unsigned_4.19.146-1` (sha256 `34cb26b4…967b`)
//!   for `System.map`. Its banner is byte-identical to the one in the dump.
//! * The symbol file: `dwarf2json linux --elf vmlinux --system-map System.map`
//!   (dwarf2json 0.9.0, commit `9f14607e`), provenance in
//!   `forensic_corpora/debian_4.19.0-11-arm64_dbg/SOURCE.md`.
//!
//! `SEANCE_MMUSHELL_AARCH64` names the directory the MMUShell archives were
//! extracted into (`debian/linux.dump`), and `SEANCE_ARM64_DEBIAN_KERNEL` the
//! directory holding the kernel package's files: the ISF under `isf/`, and the
//! package's own modules under `extracted/lib/modules/4.19.0-11-arm64/`.
//! Unset, the tests skip; set and missing, they fail.
//!
//! # The independent answers
//!
//! Nothing below is graded against this crate's own output. The root is the
//! `TTBR1_EL1` BADDR QEMU recorded in `linux.regs` (`0x412e_e000`), which the
//! memory crate's corpus test reads with `pickletools`. No published process
//! list exists for this capture, so the process list is graded against what
//! the kernel's own structures prove, each check independent of the walk:
//!
//! * `init_task` is the idle task: pid 0, `comm` `swapper/0` (`INIT_TASK_COMM`
//!   plus the per-CPU suffix `sched_init` writes), no `mm`.
//! * pid 1 is the first user process and pid 2 `kthreadd`, both children of
//!   pid 0 (`rest_init`), and every kernel thread's parent is `kthreadd` or the
//!   idle task.
//! * The list is circular and closed: the walk returns to `init_task`, and
//!   every task's `tasks.prev` names the task before it (the list is doubly
//!   linked, and the walk follows only `next`).
//! * Every listed pid is unique, and every parent pid is itself listed.
//! * Each task's `comm` as read through the arm64 walk equals the bytes at the
//!   physical address the linear map puts it at (`PAGE_OFFSET` arithmetic of
//!   the 4.19 arm64 layout, not this crate's translation).
//! * Every loaded module is a `.ko` the kernel package ships, and where that
//!   `.ko` carries a `srcversion` the one read out of memory is the same.
//! * The kernel log opens with the boot CPU line and then the banner that is
//!   in `vmlinux`.
//! * Each user process's command line names a binary its own memory map holds
//!   (two sources: the process's user memory through `TTBR0`, and the kernel's
//!   VMA structures), with the exceptions stated where they are asserted.
//!
//! Offsets used for the independent reads (`task_struct.tasks` 1000, `.pid`
//! 1256, `.comm` 1680) are the DWARF's, read from the ISF with a JSON tool and
//! written here as constants, so that the checks do not go through the symbol
//! table under test.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use seance_core::data_source::FileDataSource;
use seance_core::test_support::corpus;
use seance_memory::meta::Architecture as LayerArch;
use seance_memory::segmented::{Segment, SegmentedLayer};
use seance_memory::{LayerMeta, MemoryImageFormat, MemoryLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::profile::LinuxProfile;
use seance_plugin_memory_linux::{
    bash, cmdline, kernel_log, lsmod, mounts, proc_maps, tasks, taskscan,
};

const CORPUS_VAR: &str = "SEANCE_MMUSHELL_AARCH64";
const KERNEL_VAR: &str = "SEANCE_ARM64_DEBIAN_KERNEL";
const RAM_BASE: u64 = 0x4000_0000;
const RAM_LEN: u64 = 4 << 30;
/// `TTBR1_EL1` BADDR from QEMU's `linux.regs`.
const RECORDED_TTBR1: u64 = 0x412e_e000;
/// `NUMBER(kimage_voffset)` in the dump's own VMCOREINFO.
const KIMAGE_VOFFSET: u64 = 0xfffe_ffff_c800_0000;
/// `PAGE_OFFSET` of a 48-bit 4.19 arm64 kernel (`Documentation/arm64/memory.txt`).
const PAGE_OFFSET: u64 = 0xffff_8000_0000_0000;
/// `System.map-4.19.0-11-arm64`.
const INIT_TASK: u64 = 0xffff_0000_090e_2e80;
/// `task_struct` member offsets from the DWARF.
const TASKS_AT: u64 = 1000;
const PID_AT: u64 = 1256;
const COMM_AT: u64 = 1680;
const BANNER: &str = "Linux version 4.19.0-11-arm64 (debian-kernel@lists.debian.org) \
                      (gcc version 8.3.0 (Debian 8.3.0-6)) #1 SMP Debian 4.19.146-1 (2020-09-17)";

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

/// The dump and the kernel-package directory, or `None` to skip.
fn inputs() -> Option<(PathBuf, PathBuf)> {
    let dump = corpus::file(CORPUS_VAR, "debian/linux.dump")?;
    let kernel = corpus::dir(KERNEL_VAR)?;
    Some((dump, kernel))
}

fn profiled() -> Option<&'static LinuxProfile> {
    static PROFILE: OnceLock<Option<LinuxProfile>> = OnceLock::new();
    PROFILE
        .get_or_init(|| {
            let (dump, kernel) = inputs()?;
            Some(
                discovery::discover(
                    physical(&dump),
                    &[kernel.join("isf")],
                    &DiscoveryOptions::default(),
                )
                .unwrap_or_else(|err| panic!("discovery refused the Debian arm64 dump: {err}")),
            )
        })
        .as_ref()
}

fn task_list(profile: &LinuxProfile) -> (seance_memory::binding::BuildBinding, tasks::TaskList) {
    let layout = tasks::bind(profile).expect("the task layout binds");
    let list = tasks::list_tasks(profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");
    (layout, list)
}

/// Bytes at a physical address, read straight from the dump.
fn raw(profile: &LinuxProfile, at: u64, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    let read = seance_core::io::read_full(profile.physical.as_data_source(), at, &mut buf);
    assert_eq!(read, len, "{at:#x} is inside the 4 GiB of RAM");
    buf
}

fn u64_at(profile: &LinuxProfile, at: u64) -> u64 {
    u64::from_le_bytes(raw(profile, at, 8).try_into().expect("eight bytes"))
}

fn comm_at(profile: &LinuxProfile, at: u64) -> String {
    let bytes = raw(profile, at, 16);
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(16);
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

/// The physical address of a slab-allocated (linear-map) kernel VA.
fn linear(va: u64) -> u64 {
    assert!(va >= PAGE_OFFSET, "{va:#x} is a linear-map address");
    va - PAGE_OFFSET + RAM_BASE
}

#[test]
fn the_debian_arm64_dump_is_profiled_from_its_own_kernels_symbol_file() {
    let Some((dump, kernel)) = inputs() else {
        return;
    };
    let (profile, report) = discovery::discover_reported(
        physical(&dump),
        &[kernel.join("isf")],
        &DiscoveryOptions::default(),
    )
    .unwrap_or_else(|err| panic!("discovery refused the Debian arm64 dump: {err}"));

    assert_eq!(profile.build.banner, BANNER);
    assert_eq!(profile.architecture, LayerArch::Arm64);
    assert_eq!(
        profile.paging.mode().to_string(),
        "arm64_4k_ttbr1 (48-bit VA)"
    );
    assert_eq!(profile.dtb.value, RECORDED_TTBR1, "the root QEMU recorded");
    assert_eq!(profile.dtb_symbol, "swapper_pg_dir");
    // `virtual - physical` of the kernel image is the kernel's own
    // `kimage_voffset`, which its VMCOREINFO publishes.
    assert_eq!(profile.kernel_shift.value.shift, KIMAGE_VOFFSET);
    // The report must say what this profile has and has not been checked on,
    // not that the stages were never run on arm64.
    let notes = report.notes.join("\n");
    assert!(notes.contains("arm64"), "{notes}");
    assert!(
        !notes.contains("have not been checked against a real arm64 capture"),
        "the stages have now been run on one: {notes}"
    );
    assert!(notes.contains("QEMU-emulated"), "{notes}");
}

#[test]
fn the_process_list_walks_from_init_task_and_closes() {
    let Some(profile) = profiled() else { return };
    let (_, list) = task_list(profile);
    assert_eq!(list.init_task, INIT_TASK);
    assert!(list.is_complete(), "{:?}", list.incomplete());
    assert_eq!(list.tasks.len(), 73);

    // The idle task, read through the image mapping's own arithmetic.
    let init_phys = INIT_TASK - KIMAGE_VOFFSET;
    assert_eq!(u64_at(profile, init_phys + PID_AT) as u32, 0);
    assert_eq!(comm_at(profile, init_phys + COMM_AT), "swapper/0");

    // Doubly linked and closed: each task's `tasks.prev` names the one before,
    // and the last `tasks.next` is init_task's own link.
    let mut previous = INIT_TASK + TASKS_AT;
    for task in &list.tasks {
        let phys = linear(task.address);
        assert_eq!(
            u64_at(profile, phys + TASKS_AT + 8),
            previous,
            "{:?}",
            task.comm
        );
        assert_eq!(
            Some(&comm_at(profile, phys + COMM_AT)),
            task.comm.known(),
            "comm read through the walk differs from the linear-map bytes"
        );
        assert_eq!(
            Some(&i64::from(u64_at(profile, phys + PID_AT) as u32 as i32)),
            task.pid.known()
        );
        previous = task.address + TASKS_AT;
    }
    let last = linear(list.tasks.last().expect("a task").address);
    assert_eq!(u64_at(profile, last + TASKS_AT), INIT_TASK + TASKS_AT);

    let by_pid: HashMap<i64, &tasks::TaskRecord> = list
        .tasks
        .iter()
        .map(|t| (*t.pid.known().expect("every pid reads"), t))
        .collect();
    assert_eq!(by_pid.len(), list.tasks.len(), "a pid is listed twice");

    let init = by_pid.get(&1).expect("pid 1 is listed");
    assert_eq!(init.comm.known().map(String::as_str), Some("systemd"));
    assert_eq!(init.ppid.known(), Some(&0));
    assert_eq!(init.kernel_thread.known(), Some(&false));
    let kthreadd = by_pid.get(&2).expect("pid 2 is listed");
    assert_eq!(kthreadd.comm.known().map(String::as_str), Some("kthreadd"));
    assert_eq!(kthreadd.ppid.known(), Some(&0));

    // The idle task (pid 0) is the list head and is not itself listed.
    let listed: HashSet<i64> = by_pid.keys().copied().chain([0]).collect();
    for task in &list.tasks {
        let pid = *task.pid.known().expect("every pid reads");
        let ppid = *task.ppid.known().expect("every ppid reads");
        assert!(
            listed.contains(&ppid),
            "pid {pid}'s parent {ppid} is not listed"
        );
        if task.kernel_thread.known() == Some(&true) && pid != 2 {
            assert!(ppid == 2, "kernel thread {:?} has parent {ppid}", task.comm);
        }
        assert!(task.comm_well_formed, "{:?}", task.comm);
    }
}

/// The physical sweep the analysis module runs beside the list walk finds
/// every listed process. Before this capture was profiled it did not: the
/// last task (`bash`, which links forward to `init_task` in the kernel image)
/// and `systemd --user` with its `(sd-pam)` helper read as out of its reach.
#[test]
fn the_independent_sweep_corroborates_every_listed_process() {
    let Some(profile) = profiled() else { return };
    let (layout, list) = task_list(profile);
    let cross = taskscan::corroborate_list(profile, &layout, &list);
    assert!(cross.scan_ran);
    assert_eq!(cross.from_list(), list.tasks.len());
    let missed: Vec<_> = cross
        .rows
        .iter()
        .filter(|r| r.verdict == taskscan::CrossViewVerdict::ListOnly)
        .map(|r| (r.pid, r.comm.clone()))
        .collect();
    assert!(missed.is_empty(), "the sweep missed {missed:?}");
    assert_eq!(cross.corroborated(), list.tasks.len());
}

/// Every loaded module is one the kernel package ships, and a module whose
/// `.ko` records a `srcversion` has that same `srcversion` in memory.
#[test]
fn every_loaded_module_is_a_module_of_this_kernel_package() {
    let Some(profile) = profiled() else { return };
    let (_, kernel) = inputs().expect("profiled implies inputs");
    let shipped = shipped_modules(&kernel.join("extracted/lib/modules/4.19.0-11-arm64"));
    assert!(shipped.len() > 2000, "{} .ko files", shipped.len());

    let layout = lsmod::bind(profile).expect("the module layout binds");
    let list = lsmod::list_modules(profile, &layout, &lsmod::ModuleListConfig::default())
        .expect("the module list walks");
    assert!(list.is_complete());
    assert_eq!(list.modules.len(), 37);
    let mut compared = 0;
    for module in &list.modules {
        let name = module.name.known().expect("every name reads");
        let srcversion = shipped
            .get(name)
            .unwrap_or_else(|| panic!("{name} is not a module the package ships"));
        if let Some(expected) = srcversion {
            assert_eq!(module.srcversion.known(), Some(expected), "{name}");
            compared += 1;
        }
    }
    assert!(compared > 0, "no srcversion was compared");
}

/// `.ko` name (with `-` as `_`, as the kernel stores it) to its `srcversion`.
fn shipped_modules(dir: &Path) -> HashMap<String, Option<String>> {
    let mut out = HashMap::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)
            .expect("the modules directory reads")
            .flatten()
        {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
                continue;
            }
            let Some(stem) = path
                .file_name()
                .and_then(|n| n.to_str())
                .and_then(|n| n.strip_suffix(".ko"))
            else {
                continue;
            };
            let bytes = std::fs::read(&path).expect("a .ko reads");
            let needle = b"srcversion=";
            let srcversion = bytes
                .windows(needle.len())
                .position(|w| w == needle)
                .map(|at| {
                    let rest = &bytes[at + needle.len()..];
                    let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
                    String::from_utf8_lossy(&rest[..end]).into_owned()
                });
            out.insert(stem.replace('-', "_"), srcversion);
        }
    }
    out
}

#[test]
fn the_kernel_log_opens_with_the_boot_cpu_and_the_banner_in_vmlinux() {
    let Some(profile) = profiled() else { return };
    let layout = kernel_log::bind(profile).expect("the log layout binds");
    let log = kernel_log::survey_kernel_log(profile, &layout, &kernel_log::LogConfig::default())
        .expect("the log reads");
    assert!(log.is_complete());
    let first: Vec<&str> = log
        .lines
        .iter()
        .take(2)
        .map(|l| l.message.known().expect("a message").as_str())
        .collect();
    assert!(
        first[0].starts_with("Booting Linux on physical CPU 0x0000000000"),
        "{first:?}"
    );
    assert_eq!(first[1], BANNER);
}

/// A user process's command line (its own memory, through the `TTBR0` regime)
/// names a binary its memory map (the kernel's VMA structures) holds.
#[test]
fn each_user_command_line_names_a_binary_its_memory_map_holds() {
    let Some(profile) = profiled() else { return };
    let (_, list) = task_list(profile);
    let lines = cmdline::bind(profile)
        .and_then(|l| {
            cmdline::survey_command_lines(
                profile,
                &l,
                &list,
                &cmdline::CommandLinesConfig::default(),
            )
        })
        .expect("the command-line survey runs");
    let maps = proc_maps::bind(profile)
        .and_then(|l| {
            proc_maps::survey_process_maps(
                profile,
                &l,
                &list,
                &proc_maps::ProcessMapsConfig::default(),
            )
        })
        .expect("the maps survey runs");
    assert!(lines.is_complete() && maps.is_complete());

    let user: Vec<_> = list
        .tasks
        .iter()
        .filter(|t| t.kernel_thread.known() == Some(&false))
        .collect();
    assert_eq!(user.len(), 15);
    assert_eq!(
        lines.read_count(),
        user.len(),
        "every user process's command line reads"
    );

    for process in &lines.processes {
        let Some(line) = &process.command_line else {
            continue;
        };
        let pid = *process.pid.known().expect("a pid");
        let argv0 = line.arguments.first().expect("argv[0]").as_str();
        let mapped: HashSet<&str> = maps
            .processes
            .iter()
            .find(|m| m.pid.known() == Some(&pid))
            .expect("the maps survey saw the process")
            .regions
            .iter()
            .filter_map(|r| r.path.known().map(String::as_str))
            .collect();
        // Three argv[0]s are not the binary's path, each for a reason the
        // kernel does not record: Debian's `/sbin/init` is a symlink to
        // systemd; a login shell's argv[0] is `-bash`; systemd's PAM helper
        // rewrites its own argv to `(sd-pam)` and runs from systemd's image.
        let binary = match argv0 {
            "/sbin/init" | "(sd-pam)" => "/lib/systemd/systemd",
            "-bash" => "/bin/bash",
            path => path,
        };
        // Debian 10 installs with a merged `/usr` (`/bin`, `/sbin` and `/lib`
        // are symlinks into `/usr`), and the kernel names a mapping by the
        // path it resolved, so the map holds the `/usr` spelling.
        let binary = if binary.starts_with("/usr/") {
            binary.to_string()
        } else {
            format!("/usr{binary}")
        };
        assert!(
            mapped.contains(binary.as_str()),
            "pid {pid} ({argv0}) does not map {binary}: {mapped:?}"
        );
    }
}

#[test]
fn the_login_shells_history_is_read_through_its_own_page_tables() {
    let Some(profile) = profiled() else { return };
    let (_, list) = task_list(profile);
    let survey = bash::bind(profile)
        .and_then(|l| bash::survey_bash(profile, &l, &list, &bash::BashConfig::default()))
        .expect("the bash survey runs");
    assert_eq!(survey.shells.len(), 1);
    let shell = &survey.shells[0];
    assert_eq!(shell.pid.known(), Some(&378));
    assert_eq!(shell.commands.len(), 30);
    // Every timestamp is on the day the dump was written (2020-10-03 UTC).
    for command in &shell.commands {
        assert!(
            (1_601_683_200..1_601_769_600).contains(&command.timestamp_unix),
            "{command:?}"
        );
    }
    let commands: HashSet<&str> = shell.commands.iter().map(|c| c.command.as_str()).collect();
    assert!(commands.contains("cat /etc/shadow"), "{commands:?}");
    // The heap was not captured in full, and the survey says so rather than
    // presenting 30 as every command.
    assert!(!survey.is_complete());
}

#[test]
fn the_root_mount_is_the_disk_the_ext4_journal_thread_names() {
    let Some(profile) = profiled() else { return };
    let (_, list) = task_list(profile);
    let survey = mounts::bind(profile)
        .and_then(|l| mounts::survey_mounts(profile, &l, &list, &mounts::MountsConfig::default()))
        .expect("the mount survey runs");
    assert!(survey.is_complete());
    // `jbd2/vda2-8` is the journal thread of an ext4 file system on vda2.
    assert!(list
        .tasks
        .iter()
        .any(|t| t.comm.known().is_some_and(|c| c == "jbd2/vda2-8")));
    // The first mount at `/` is the boot-time `rootfs`; the root file system
    // is mounted over it.
    let at_root: Vec<&str> = survey
        .namespaces
        .iter()
        .flat_map(|ns| &ns.mounts)
        .filter(|m| m.mount_point.known().is_some_and(|p| p == "/"))
        .filter_map(|m| m.devname.known().map(String::as_str))
        .collect();
    assert!(at_root.contains(&"/dev/vda2"), "{at_root:?}");
}
