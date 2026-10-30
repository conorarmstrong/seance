//! Mount-crossing paths, pseudo-paths and command lines against a real Linux
//! capture, graded against facts established without the walks under test.
//!
//! `SEANCE_LINUX_SWAP_MEM` must name the directory holding the Ubuntu 22.04 /
//! Linux 5.15 lab capture (`mem.raw`) described in `documentation/VALIDATION.md`.
//! Absent, these skip.
//!
//! What each assertion is graded against:
//!
//! * **The mount list.** The mount stage walks `mnt_namespace.list`, a
//!   different structure from the `file.f_path.mnt` chain the path walk
//!   follows. A file's mount-crossing path must begin with the mount point the
//!   mount list gives for the mount that file was opened through.
//! * **PID 1's standard descriptors.** systemd as PID 1 holds `/dev/null` on
//!   fds 0, 1 and 2 — a property of systemd, not of this tool — and `/dev` is a
//!   separate mount (devtmpfs), so the reduced walk showed `/null` and only a
//!   walk that crosses the mount can show `/dev/null`.
//! * **The raw image.** The workload's argument vector — `<python3>\0/tmp/swaptest.py\0`
//!   — is a byte string a plain scan of the physical image finds without page
//!   tables or structures; the command-line stage, which reads it through the
//!   process's own page tables from `mm_struct.arg_start`, must produce
//!   arguments whose NUL-joined bytes occur in that scan.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::paths::{PathKind, PathScope, WalkEnd};
use seance_plugin_memory_linux::profile::LinuxProfile;
use seance_plugin_memory_linux::{cmdline, lsof, mounts, proc_maps, tasks};
use std::path::PathBuf;
use std::sync::Arc;

fn dir() -> Option<PathBuf> {
    let d = PathBuf::from(std::env::var("SEANCE_LINUX_SWAP_MEM").ok()?);
    d.is_dir().then_some(d)
}

fn profiled() -> Option<&'static LinuxProfile> {
    static ONCE: std::sync::OnceLock<Option<LinuxProfile>> = std::sync::OnceLock::new();
    let _ = dir()?;
    let profile = ONCE
        .get_or_init(|| {
            let src: Arc<dyn DataSource> = Arc::new(
                FileDataSource::new(dir().unwrap().join("mem.raw")).expect("open mem.raw"),
            );
            let physical: Arc<dyn MemoryLayer> =
                Arc::new(PhysicalLayer::raw(src).expect("raw is a physical layer"));
            discovery::discover(physical, &[], &DiscoveryOptions::default()).ok()
        })
        .as_ref();
    assert!(
        profile.is_some(),
        "the capture is present and did not profile; nothing below can be graded"
    );
    profile
}

fn task_list(profile: &LinuxProfile) -> tasks::TaskList {
    let layout = tasks::bind(profile).expect("the task layout binds");
    tasks::list_tasks(profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks")
}

#[test]
fn pid_1_holds_dev_null_on_its_standard_descriptors_with_the_mount_crossed() {
    let Some(profile) = profiled() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the capture dir");
        return;
    };
    let list = task_list(profile);
    let layout = lsof::bind(profile).expect("the open-files layout binds");
    let survey =
        lsof::survey_open_files(profile, &layout, &list, &lsof::OpenFilesConfig::default())
            .expect("the survey runs");
    assert_eq!(survey.path_scope, "mount_crossing");

    let init = survey
        .processes
        .iter()
        .find(|p| p.pid.known() == Some(&1))
        .expect("PID 1 is on the list");
    for fd in 0..3u64 {
        let file = init
            .files
            .iter()
            .find(|f| f.fd == fd)
            .unwrap_or_else(|| panic!("PID 1 has fd {fd} open"));
        assert_eq!(
            file.path.known().map(String::as_str),
            Some("/dev/null"),
            "fd {fd} of PID 1: {:?}",
            file.path
        );
        assert_eq!(file.path_kind, PathKind::File);
        match &file.path_scope {
            PathScope::MountCrossing {
                mounts_crossed,
                ended,
                ..
            } => {
                assert_eq!(*mounts_crossed, 1, "/dev is one mount below /");
                assert_eq!(*ended, WalkEnd::ProcessRoot);
            }
            other => panic!("fd {fd} did not cross its mount: {other:?}"),
        }
    }
}

#[test]
fn every_crossing_path_begins_with_a_mount_point_the_mount_list_knows() {
    let Some(profile) = profiled() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the capture dir");
        return;
    };
    let list = task_list(profile);

    // The mount points, from the namespace's mount list.
    let mounts_layout = mounts::bind(profile).expect("the mounts layout binds");
    let mounts = mounts::survey_mounts(
        profile,
        &mounts_layout,
        &list,
        &mounts::MountsConfig::default(),
    )
    .expect("the mount survey runs");
    let mut mount_points: Vec<String> = mounts
        .namespaces
        .iter()
        .flat_map(|ns| ns.mounts.iter())
        .filter_map(|m| m.mount_point.known().cloned())
        .collect();
    mount_points.sort();
    mount_points.dedup();
    assert!(
        mount_points.iter().any(|m| m == "/dev/pts"),
        "a nested mount point must show its parent's prefix; got {mount_points:?}"
    );

    // Every crossing file path must start with one of them.
    let layout = lsof::bind(profile).expect("binds");
    let survey =
        lsof::survey_open_files(profile, &layout, &list, &lsof::OpenFilesConfig::default())
            .expect("runs");
    let mut checked = 0usize;
    let mut crossed_at_least_once = 0usize;
    for process in &survey.processes {
        for file in &process.files {
            let (Some(path), PathKind::File) = (file.path.known(), &file.path_kind) else {
                continue;
            };
            let PathScope::MountCrossing {
                mounts_crossed,
                ended: WalkEnd::ProcessRoot,
                ..
            } = &file.path_scope
            else {
                continue;
            };
            checked += 1;
            if *mounts_crossed > 0 {
                crossed_at_least_once += 1;
                let prefixed = mount_points
                    .iter()
                    .any(|mp| mp != "/" && (path == mp || path.starts_with(&format!("{mp}/"))));
                assert!(
                    prefixed,
                    "{path} crossed {mounts_crossed} mount(s) but begins with no mount point the \
                     mount list knows: {mount_points:?}"
                );
            }
        }
    }
    assert!(
        checked > 50,
        "only {checked} file paths were walked to the process root"
    );
    assert!(
        crossed_at_least_once > 10,
        "only {crossed_at_least_once} paths crossed a mount on a machine with /dev, /proc, /run \
         and /sys mounted"
    );
}

#[test]
fn sockets_and_pipes_are_rendered_as_the_kernel_renders_them() {
    let Some(profile) = profiled() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the capture dir");
        return;
    };
    let list = task_list(profile);
    let layout = lsof::bind(profile).expect("binds");
    let survey =
        lsof::survey_open_files(profile, &layout, &list, &lsof::OpenFilesConfig::default())
            .expect("runs");

    let mut sockets = 0usize;
    let mut pipes = 0usize;
    let mut anon = 0usize;
    let mut unresolved = 0usize;
    for file in survey.processes.iter().flat_map(|p| p.files.iter()) {
        let Some(path) = file.path.known() else {
            continue;
        };
        if matches!(
            file.path_kind,
            PathKind::Socket | PathKind::Pipe | PathKind::AnonInode
        ) {
            // No walk is made for a pseudo-file, so the record must not
            // describe one: its scope is `pseudo`, never a mount walk.
            assert!(
                matches!(file.path_scope, PathScope::Pseudo { .. }),
                "{path}: scope {:?}",
                file.path_scope
            );
        }
        match &file.path_kind {
            PathKind::Socket => {
                sockets += 1;
                let inode = path
                    .strip_prefix("socket:[")
                    .and_then(|rest| rest.strip_suffix(']'))
                    .and_then(|n| n.parse::<u64>().ok());
                assert!(
                    inode.is_some_and(|n| n > 0),
                    "not a socket pseudo-path: {path}"
                );
            }
            PathKind::Pipe => {
                pipes += 1;
                assert!(path.starts_with("pipe:[") && path.ends_with(']'), "{path}");
            }
            PathKind::AnonInode => {
                anon += 1;
                assert!(path.starts_with("anon_inode:"), "{path}");
            }
            PathKind::PseudoUnresolved { .. } => unresolved += 1,
            PathKind::File => {
                assert!(
                    path.starts_with('/'),
                    "a file path that is not absolute: {path}"
                );
            }
        }
    }
    eprintln!("sockets {sockets}, pipes {pipes}, anon inodes {anon}, unresolved {unresolved}");
    assert!(
        sockets > 10,
        "a systemd machine has dozens of sockets open; found {sockets}"
    );
    assert!(pipes > 0, "found no pipe");
    assert!(
        anon > 0,
        "found no anonymous inode (systemd holds eventpoll and timerfd)"
    );
}

#[test]
fn memory_map_paths_cross_mounts_too() {
    let Some(profile) = profiled() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the capture dir");
        return;
    };
    let list = task_list(profile);
    let layout = proc_maps::bind(profile).expect("binds");
    let survey = proc_maps::survey_process_maps(
        profile,
        &layout,
        &list,
        &proc_maps::ProcessMapsConfig::default(),
    )
    .expect("runs");
    assert_eq!(survey.path_scope, "mount_crossing");
    // journald maps /run/systemd/journal/kernel-seqnum, on the /run tmpfs.
    let journald = survey
        .processes
        .iter()
        .find(|p| p.comm.known().is_some_and(|c| c == "systemd-journal"))
        .expect("systemd-journald is running");
    let seqnum = journald
        .regions
        .iter()
        .find(|r| {
            r.path
                .known()
                .is_some_and(|p| p.ends_with("/journal/kernel-seqnum"))
        })
        .expect("journald maps its kernel-seqnum file");
    assert_eq!(
        seqnum.path.known().map(String::as_str),
        Some("/run/systemd/journal/kernel-seqnum")
    );
    assert!(matches!(
        seqnum.path_scope,
        PathScope::MountCrossing {
            mounts_crossed: 1,
            ended: WalkEnd::ProcessRoot,
            ..
        }
    ));
}

#[test]
fn the_workload_command_line_matches_the_bytes_in_the_raw_image() {
    let Some(profile) = profiled() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the capture dir");
        return;
    };
    let list = task_list(profile);
    let layout = cmdline::bind(profile).expect("the command-line layout binds");
    let survey = cmdline::survey_command_lines(
        profile,
        &layout,
        &list,
        &cmdline::CommandLinesConfig::default(),
    )
    .expect("the survey runs");

    let python = survey
        .processes
        .iter()
        .find(|p| p.comm.known().is_some_and(|c| c.starts_with("python")))
        .expect("the workload's python process is on the list");
    let command_line = python
        .command_line
        .as_ref()
        .unwrap_or_else(|| panic!("no command line read: {:?}", python.outcome));
    // The workload was started as `<python3> /tmp/swaptest.py`; whether argv[0]
    // is the bare name or the resolved binary depends on how the shell invoked
    // it, and is not assumed — the raw-image check below settles which.
    assert_eq!(
        command_line.arguments.len(),
        2,
        "{:?}",
        command_line.arguments
    );
    assert!(
        command_line.arguments[0].ends_with("python3"),
        "{:?}",
        command_line.arguments
    );
    assert_eq!(command_line.arguments[1], "/tmp/swaptest.py");
    assert!(command_line.well_formed);
    assert_eq!(command_line.argv_rewritten, Some(false));
    assert!(!command_line.argv_short_read);
    assert_eq!(command_line.bytes_missing, 0);
    assert_eq!(python.outcome, cmdline::CmdlineOutcome::Read);

    // Independent of every structure above: the NUL-separated vector is a byte
    // string in the physical image.
    let needle: Vec<u8> = {
        let mut v = Vec::new();
        for argument in &command_line.arguments {
            v.extend_from_slice(argument.as_bytes());
            v.push(0);
        }
        v
    };
    let raw = std::fs::File::open(dir().unwrap().join("mem.raw")).expect("mem.raw opens");
    assert!(
        raw_image_contains(raw, &needle),
        "the argument vector read through the page tables does not occur anywhere in the raw \
         image, so it was not read from the process's memory"
    );

    // Kernel threads have no command line, and are not gaps.
    let kthreadd = survey
        .processes
        .iter()
        .find(|p| p.pid.known() == Some(&2))
        .expect("kthreadd is PID 2");
    assert!(kthreadd.command_line.is_none());
    assert!(!kthreadd.outcome.is_a_gap());

    // Every task the task list says has a user address space yields a command
    // line, and no task without one does: the two stages read `mm` from the
    // same structure and must agree on it.
    let with_user_memory: Vec<&tasks::TaskRecord> = list
        .tasks
        .iter()
        .filter(|t| t.has_user_memory() == Some(true))
        .collect();
    let read = survey.read_count();
    eprintln!(
        "command lines read for {read} of {} tasks; {} have user memory",
        survey.processes.len(),
        with_user_memory.len()
    );
    for task in &with_user_memory {
        let row = survey
            .processes
            .iter()
            .find(|p| p.task_address == task.address)
            .expect("every task has a row");
        assert!(
            row.command_line.is_some(),
            "{:?} (pid {:?}) has a user address space and no command line: {}",
            task.comm,
            task.pid,
            row.outcome.detail()
        );
    }
    assert_eq!(read, with_user_memory.len());
    assert!(survey.is_complete(), "{:?}", survey.incomplete());
}

fn raw_image_contains(mut file: std::fs::File, needle: &[u8]) -> bool {
    use std::io::Read;
    const WINDOW: usize = 32 * 1024 * 1024;
    let mut buffer = vec![0u8; WINDOW + needle.len()];
    let mut carry = 0usize;
    loop {
        let read = match file.read(&mut buffer[carry..]) {
            Ok(0) => return false,
            Ok(n) => n,
            Err(_) => return false,
        };
        let filled = carry + read;
        if buffer[..filled]
            .windows(needle.len())
            .any(|window| window == needle)
        {
            return true;
        }
        carry = needle.len().min(filled);
        let tail_start = filled - carry;
        buffer.copy_within(tail_start..filled, 0);
    }
}
