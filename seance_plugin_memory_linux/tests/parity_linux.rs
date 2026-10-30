//! Parity against Volatility 3 on a real Linux memory capture.
//!
//! Unit tests prove the code does what its author intended on fixtures its
//! author built. This file proves something different and harder: that on a real
//! Linux capture, Séance reaches the same answers as the tool the field already
//! trusts. Every expected value here was produced by running Volatility 3 against
//! the same file — none of it is hand-derived, and none of it comes from Séance.
//!
//! The image is large and not committed, so these tests skip when it is absent.
//! Point `SEANCE_MEM_IMAGES` at a directory holding `linux-sample-1.bin` — a
//! 512 MiB raw physical capture of Debian 7 running
//! `3.2.0-4-amd64 #1 SMP Debian 3.2.57-3+deb7u2` — and `SEANCE_SYMBOL_DIRS` at a
//! directory holding `Debian_3.2.57-3+deb7u2_3.2.0-4-amd64_x64.json.xz`.
//!
//! The oracle lives in `~/forensic_images/memory/oracle_linux/`. Its row counts
//! are `wc -l` **minus two**: the CSV header and a trailing blank line.
//!
//! | Plugin | Rows |
//! |---|---|
//! | `linux.pslist` | 133 |
//! | `linux.lsmod` | 79 |
//! | `linux.bash` | 27 |
//! | `linux.envars` | 1402 |
//!
//! A disagreement with Volatility is a defect in Séance until proven otherwise.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::data_source::DataSource;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::{bash, envars, lsmod, tasks, LinuxProfile};

/// The reference image, or `None` when the corpus was never provisioned.
///
/// Named-but-missing panics rather than skipping: these four tests reported
/// `ok` having compared nothing every time the corpus was absent, and CI has
/// never had it.
fn image() -> Option<Arc<dyn MemoryLayer>> {
    let path = seance_core::test_support::corpus::file("SEANCE_MEM_IMAGES", "linux-sample-1.bin")?;
    let file = seance_core::data_source::FileDataSource::new(path.clone())
        .unwrap_or_else(|e| panic!("{} could not be opened: {e}", path.display()));
    let source: Arc<dyn DataSource> = Arc::new(file);
    let layer = PhysicalLayer::raw(source).expect("a raw image is a physical layer");
    Some(Arc::new(layer) as Arc<dyn MemoryLayer>)
}

/// Directories holding ISF symbol files.
fn symbol_dirs() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
        // The same splitter the analysis uses, so a lab whose symbol store is
        // at `C:\symbols` runs this parity suite over the store it named rather
        // than over two fragments of its path.
        let dirs: Vec<PathBuf> = seance_memory::analysis::split_env_list(&list)
            .into_iter()
            .map(PathBuf::from)
            .collect();
        if !dirs.is_empty() {
            return dirs;
        }
    }
    // Resolved from the crate manifest, NOT the process CWD. `cargo test` runs an
    // integration test with the CWD set to the crate directory, so the bare
    // relative path this used to hold pointed at
    // `<crate>/reference/volatility3/...`, which does not exist. `read_dir`
    // failed, the directory was skipped, and discovery saw zero candidate ISFs —
    // so every parity test here failed to find symbols and then returned early
    // as a skip, reporting `ok` while comparing nothing. It never once ran.
    vec![PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("the crate sits directly under the workspace root")
        .join("reference/volatility3/volatility3/symbols")]
}

/// Discover a profile, or skip when the image or its symbols are absent.
fn profile() -> Option<LinuxProfile> {
    let physical = image()?;
    let dirs = symbol_dirs();
    match discovery::discover(physical, &dirs, &DiscoveryOptions::default()) {
        Ok(profile) => Some(profile),
        Err(err) if err.means_not_a_linux_image() => {
            panic!("the reference image is a Linux capture and discovery said it is not: {err}")
        }
        Err(err) => panic!("discovery failed, which is the finding: {err}"),
    }
}

/// Discovery must land on the facts read directly out of the symbol file and the
/// image, not on anything hardcoded.
///
/// `init_level4_pgt` is at `0xFFFFFFFF81605000` in the ISF and the banner is at
/// physical `0x1400070`, so the shift is `0xFFFFFFFF80000000` and the directory
/// table base is `0x1605000`. This build declares **no** `swapper_pg_dir` and no
/// `init_top_pgt`, which is why the candidate list has three names in it.
#[test]
fn discovery_derives_the_page_table_root_from_the_banner() {
    let Some(profile) = profile() else { return };

    assert_eq!(profile.dtb.value, 0x160_5000, "directory table base");
    assert_eq!(
        profile.dtb_symbol, "init_level4_pgt",
        "this build declares no swapper_pg_dir and no init_top_pgt"
    );
    assert_eq!(profile.kernel_shift.value.shift, 0xFFFF_FFFF_8000_0000);
    assert_eq!(profile.kernel_shift.value.banner_physical, 0x140_0070);
    assert_eq!(
        profile.kernel_shift.value.banner_virtual,
        0xFFFF_FFFF_8140_0070
    );
    assert!(
        profile.build.banner.contains("3.2.57-3+deb7u2"),
        "{}",
        profile.build.banner
    );
    assert_eq!(profile.build.release.as_deref(), Some("3.2.0-4-amd64"));
    assert_eq!(profile.pointer_size(), 8);

    // The grade is not decoration. The root was derived from a symbol and then
    // proved by translating the banner back to the address it was found at,
    // which is `Validated` and not `Confirmed` — nothing in the image published
    // the root itself.
    assert_eq!(
        profile.weakest_evidence(),
        seance_plugin_memory_linux::Evidence::Validated
    );
}

/// The build binding must resolve to exactly the names this kernel declares, and
/// must answer `not_declared` — not fail — for the ones it does not.
///
/// Debian 3.2 has `state` and not `__state`, `cred.uid` as a bare `unsigned int`
/// and not a `kuid_t`, and `start_time` as a `timespec` and not a nanosecond
/// count. Every one of those is a build difference that a single hardcoded name
/// would turn into a dead stage.
#[test]
fn the_binding_resolves_the_names_this_kernel_actually_declares() {
    let Some(profile) = profile() else { return };
    let layout = tasks::bind(&profile).expect("the task layout binds to this build");

    assert_eq!(layout.member("state").unwrap().member(), Some("state"));
    assert_eq!(layout.member("comm").unwrap().member(), Some("comm"));
    assert_eq!(layout.member("uid").unwrap().member(), Some("uid"));
    assert_eq!(
        layout.member("start_time").unwrap().member(),
        Some("start_time.tv_sec")
    );
    assert_eq!(
        layout.member("real_parent").unwrap().member(),
        Some("real_parent")
    );
    assert_eq!(layout.member("tasks").unwrap().offset(), Some(368));
    assert_eq!(layout.member("comm").unwrap().offset(), Some(920));

    // And the layout report names what was used, so a defence expert can check
    // it against the same symbol pack.
    let json = layout.to_json();
    assert_eq!(json["stage"], "linux_processes");
    let state = json["members"]
        .as_array()
        .expect("members")
        .iter()
        .find(|m| m["key"] == "state")
        .expect("state is declared");
    assert_eq!(state["kind"], "declared");
    assert_eq!(state["member"], "state");
}

/// `linux.capabilities` — init (pid 1) runs with the full root capability set.
#[test]
fn init_carries_a_broad_capability_set() {
    use seance_plugin_memory_linux::capabilities;
    let Some(profile) = profile() else { return };
    let layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let init = list
        .tasks
        .iter()
        .find(|t| t.pid.known() == Some(&1))
        .expect("pid 1 present");
    let eff = *init
        .capabilities
        .effective
        .known()
        .expect("init's effective capability set was read");
    // init is fully privileged: it must hold the marquee capabilities.
    assert!(
        capabilities::holds(eff, 21), // CAP_SYS_ADMIN
        "init should hold CAP_SYS_ADMIN; mask {eff:#x} -> {:?}",
        capabilities::decode(eff)
    );
    assert!(capabilities::holds(eff, 0), "init should hold CAP_CHOWN");
    // The permitted set is at least as broad as the effective set.
    let perm = *init.capabilities.permitted.known().expect("permitted read");
    assert_eq!(eff & perm, eff, "effective must be a subset of permitted");
}

/// `linux.capabilities` — one row per process the task walk reached, at parity
/// with `linux.pslist`'s 133, and init fully privileged.
///
/// Volatility's `linux.capabilities` reuses `pslist.list_tasks`, so its row
/// count is the process count. The capability masks were already validated
/// against Volatility in [`init_carries_a_broad_capability_set`]; this proves
/// the dedicated stage projects them for every process, completely, and keeps
/// the not-declared ambient set (this kernel predates Linux 4.3) apart from an
/// empty one.
#[test]
fn the_capabilities_stage_matches_the_task_list() {
    use seance_plugin_memory_linux::capabilities;
    let Some(profile) = profile() else { return };
    let layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let survey = capabilities::survey_capabilities(&list);
    assert_eq!(
        survey.count(),
        133,
        "linux.capabilities reuses the pslist task walk, which reports 133"
    );
    assert!(
        survey.is_complete(),
        "every process's cred read on this capture: {:?}",
        survey.incomplete()
    );

    let json = survey.to_json();
    assert_eq!(json["count"], 133);
    assert_eq!(json["complete"], true);

    // init (pid 1) holds CAP_SYS_ADMIN in its effective set, and its ambient set
    // is not-declared rather than empty on this pre-4.3 kernel.
    let rows = json["processes"].as_array().expect("rows");
    let init = rows
        .iter()
        .find(|row| row["pid"]["value"] == 1)
        .expect("pid 1 present");
    let effective = init["capabilities"]["effective"]["capabilities"]
        .as_array()
        .expect("init's effective set was read");
    assert!(
        effective.iter().any(|c| c == "CAP_SYS_ADMIN"),
        "init should hold CAP_SYS_ADMIN: {effective:?}"
    );
    assert_eq!(
        init["capabilities"]["ambient"]["not_declared"], "cap_ambient",
        "Debian 3.2 predates the ambient set; it must be not-declared, not empty"
    );
}

/// `linux.proc_maps` — structural parity on the real capture.
///
/// Volatility's oracle for this plugin was not captured (the committed oracle
/// covers only pslist/lsmod/bash/envars), so rather than a row count this asserts
/// the invariants a correct VMA walk must hold on a real Debian 7 image: every
/// process with a memory descriptor yields regions, init's regions include a
/// file-backed mapping whose reconstructed path is absolute, permissions decode,
/// and kernel threads yield none. It runs when the image is provisioned.
#[test]
fn the_process_maps_walk_holds_on_a_real_capture() {
    use seance_plugin_memory_linux::proc_maps;
    let Some(profile) = profile() else { return };
    let task_layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let layout = proc_maps::bind(&profile).expect("the maps layout binds");
    let survey = proc_maps::survey_process_maps(
        &profile,
        &layout,
        &list,
        &proc_maps::ProcessMapsConfig::default(),
    )
    .expect("the maps survey runs");

    assert_eq!(
        survey.process_count(),
        list.tasks.len(),
        "one row per process"
    );
    assert!(
        survey.region_count() > 100,
        "a running Debian 7 machine has hundreds of VMAs across its processes, found {}",
        survey.region_count()
    );

    let json = survey.to_json();
    let processes = json["processes"].as_array().expect("processes");

    // init (pid 1) is a userland process: it has a memory map with file-backed
    // regions, and every path reconstructed for it is absolute.
    let init = processes
        .iter()
        .find(|p| p["pid"]["value"] == 1)
        .expect("pid 1 present");
    assert_eq!(init["outcome"]["class"], "walked");
    let regions = init["regions"].as_array().expect("init has regions");
    assert!(!regions.is_empty(), "init has a memory map");
    let file_backed: Vec<&serde_json::Value> = regions
        .iter()
        .filter(|r| r["anonymous"] == false && r["path"]["kind"] == "known")
        .collect();
    assert!(
        !file_backed.is_empty(),
        "init maps at least one file (its executable and libraries)"
    );
    for region in &file_backed {
        let path = region["path"]["value"].as_str().expect("a known path");
        assert!(
            path.starts_with('/'),
            "a reconstructed path is absolute: {path}"
        );
    }
    // Permissions decode to the classic protection string on a real region.
    assert!(regions
        .iter()
        .filter_map(|r| r["protection"].as_str())
        .all(|p| p.len() == 4));

    // Kernel threads have no user address space and so no regions — reported as
    // such, never as a process with an empty map.
    let kernel_threads = processes
        .iter()
        .filter(|p| p["outcome"]["class"] == "kernel_thread")
        .count();
    assert!(
        kernel_threads > 20,
        "a Debian 7 machine runs dozens of kernel threads, found {kernel_threads}"
    );
}

/// `linux.lsof` — structural parity on the real capture.
///
/// As with the maps stage, no Volatility oracle was captured for this plugin,
/// so this asserts the invariants a correct fd walk must hold on a real Debian 7
/// image: descriptors are enumerated, init has open files with absolute
/// reconstructed paths, fd numbering skips closed slots, and kernel threads yield
/// no file table. It runs when the image is provisioned.
#[test]
fn the_open_files_walk_holds_on_a_real_capture() {
    use seance_plugin_memory_linux::lsof;
    let Some(profile) = profile() else { return };
    let task_layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let layout = lsof::bind(&profile).expect("the open-files layout binds");
    let survey =
        lsof::survey_open_files(&profile, &layout, &list, &lsof::OpenFilesConfig::default())
            .expect("the open-files survey runs");

    assert_eq!(
        survey.process_count(),
        list.tasks.len(),
        "one row per process"
    );
    assert!(
        survey.open_file_count() > 100,
        "a running machine has hundreds of open descriptors, found {}",
        survey.open_file_count()
    );

    let json = survey.to_json();
    let processes = json["processes"].as_array().expect("processes");

    // init has open files; every reconstructed path is absolute; fd numbers are
    // the kernel's own (a closed slot leaves a gap, never a renumber).
    let init = processes
        .iter()
        .find(|p| p["pid"]["value"] == 1)
        .expect("pid 1 present");
    assert_eq!(init["outcome"]["class"], "walked");
    let files = init["files"].as_array().expect("init has open files");
    assert!(!files.is_empty(), "init has open descriptors");
    for file in files {
        if file["path"]["kind"] == "known" {
            let path = file["path"]["value"].as_str().expect("a known path");
            assert!(
                path.starts_with('/'),
                "a reconstructed path is absolute: {path}"
            );
        }
    }

    // Kernel threads carry no file table — reported as such, not as a process
    // with zero open files.
    let no_table = processes
        .iter()
        .filter(|p| p["outcome"]["class"] == "no_file_table")
        .count();
    assert!(
        no_table > 20,
        "a Debian 7 machine runs dozens of kernel threads with no fd table, found {no_table}"
    );
}

/// `linux.sockstat` — structural parity on the real capture.
///
/// No Volatility oracle was captured, so this asserts the invariants a correct
/// socket walk must hold on a real Debian 7 image: sockets are found, every
/// decoded family is a real `AF_*` name, INET rows carry dotted-quad addresses
/// and host-order ports, and a listening service is present. It runs when the
/// image is provisioned.
#[test]
fn the_socket_walk_holds_on_a_real_capture() {
    use seance_plugin_memory_linux::sockstat;
    let Some(profile) = profile() else { return };
    let task_layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let layout = sockstat::bind(&profile).expect("the sockets layout binds");
    let survey = sockstat::survey_network_sockets(
        &profile,
        &layout,
        &list,
        &sockstat::SocketsConfig::default(),
    )
    .expect("the socket survey runs");

    assert_eq!(survey.process_count(), list.tasks.len());
    assert!(
        survey.socket_count() > 5,
        "a running machine holds sockets (sshd, rpc, syslog…), found {}",
        survey.socket_count()
    );

    let json = survey.to_json();
    let sockets: Vec<&serde_json::Value> = json["processes"]
        .as_array()
        .expect("processes")
        .iter()
        .flat_map(|p| p["sockets"].as_array().expect("sockets").iter())
        .collect();

    // Every decoded family that read is a plausible name; INET rows carry a
    // dotted-quad source address and a host-order port.
    let mut inet_seen = 0;
    for socket in &sockets {
        if socket["family"]["kind"] == "known" {
            let family = socket["family"]["value"].as_str().unwrap();
            assert!(
                family.starts_with("AF_") || family.starts_with("unknown("),
                "family decodes to a name: {family}"
            );
            if family == "AF_INET" {
                inet_seen += 1;
                if socket["src_addr"]["kind"] == "known" {
                    let addr = socket["src_addr"]["value"].as_str().unwrap();
                    assert_eq!(addr.split('.').count(), 4, "dotted-quad: {addr}");
                }
                if socket["src_port"]["kind"] == "known" {
                    assert!(socket["src_port"]["value"].as_u64().unwrap() < 65536);
                }
            }
        }
    }
    assert!(
        inet_seen > 0,
        "a running machine has at least one IPv4 socket"
    );
}

/// `linux.mountinfo` — structural parity on the real capture.
///
/// One mount namespace (a non-containerised Debian 7 box), a plausible number of
/// mounts, the root filesystem present with an absolute mount point, and every
/// filesystem root reconstructed. It runs when the image is provisioned.
#[test]
fn the_mount_walk_holds_on_a_real_capture() {
    use seance_plugin_memory_linux::mounts;
    let Some(profile) = profile() else { return };
    let task_layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let layout = mounts::bind(&profile).expect("the mounts layout binds");
    let survey = mounts::survey_mounts(&profile, &layout, &list, &mounts::MountsConfig::default())
        .expect("the mount survey runs");

    assert_eq!(
        survey.namespace_count(),
        1,
        "a non-containerised machine has one mount namespace shared by every task"
    );
    assert!(
        survey.mount_count() > 5 && survey.mount_count() < 200,
        "a plausible number of mounts, found {}",
        survey.mount_count()
    );

    let json = survey.to_json();
    let mounts_json = json["namespaces"][0]["mounts"].as_array().expect("mounts");
    // The root filesystem is mounted at "/".
    assert!(
        mounts_json.iter().any(|m| m["mount_point"]["value"] == "/"),
        "the root filesystem is present"
    );
    // Every mount point that reconstructed is absolute.
    for mount in mounts_json {
        if mount["mount_point"]["kind"] == "known" {
            let mp = mount["mount_point"]["value"].as_str().unwrap();
            assert!(mp.starts_with('/'), "an absolute mount point: {mp}");
        }
    }
}

/// `linux.dmesg` — structural parity on the real capture.
///
/// The Debian 3.2 corpus is a pre-3.5 flat ring, so this is the fully-validated
/// path: it discriminates as flat, recovers the boot banner line, and every
/// recovered line carries a syslog level in range. It runs when the image is
/// provisioned.
#[test]
fn the_kernel_log_walk_holds_on_a_real_capture() {
    use seance_plugin_memory_linux::kernel_log;
    let Some(profile) = profile() else { return };
    let layout = kernel_log::bind(&profile).expect("the log layout binds");
    let survey =
        kernel_log::survey_kernel_log(&profile, &layout, &kernel_log::LogConfig::default())
            .expect("the log survey runs");

    let json = survey.to_json();
    assert_eq!(
        json["ring_shape"], "flat_ring",
        "Debian 3.2 uses the pre-3.5 flat ring"
    );
    assert_eq!(json["validated_on_corpus"], true);
    assert!(
        survey.line_count() > 20,
        "a booted machine has many kernel log lines, found {}",
        survey.line_count()
    );

    let lines = json["lines"].as_array().expect("lines");
    // The classic boot line is present.
    assert!(
        lines.iter().any(|l| l["message"]["value"]
            .as_str()
            .is_some_and(|m| m.contains("Linux version"))),
        "the boot banner is in the ring"
    );
    // Every level that read is a valid syslog priority.
    for line in lines {
        if line["level"]["kind"] == "known" {
            let level = line["level"]["value"].as_i64().unwrap();
            assert!((0..8).contains(&level), "a syslog level in range: {level}");
        }
    }
}

/// `linux.pslist` — 133 rows.
#[test]
fn the_task_list_matches_volatility() {
    let Some(profile) = profile() else { return };
    let layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    assert_eq!(list.tasks.len(), 133, "linux.pslist reports 133 rows");
    assert!(
        list.is_complete(),
        "the walk did not complete: {:?}",
        list.incomplete()
    );

    // The first three rows of `linux.pslist.csv`, by PID, PPID and name.
    let row = |index: usize| {
        let task = &list.tasks[index];
        (
            *task.pid.known().expect("a pid"),
            *task.ppid.known().expect("a ppid"),
            task.comm.known().expect("a name").clone(),
        )
    };
    assert_eq!(row(0), (1, 0, "init".to_string()));
    assert_eq!(row(1), (2, 0, "kthreadd".to_string()));
    assert_eq!(row(2), (3, 2, "ksoftirqd/0".to_string()));

    // Every row's credentials read: `linux.pslist` prints 0 for all four on this
    // image, and a blank there would be a different claim.
    for task in &list.tasks {
        assert!(task.uid.is_known(), "uid at {:#x}", task.address);
        assert!(task.euid.is_known(), "euid at {:#x}", task.address);
    }

    // Kernel threads are distinguishable from processes, which is what the two
    // user-memory stages skip on.
    let kernel_threads = list
        .tasks
        .iter()
        .filter(|t| t.kernel_thread.known() == Some(&true))
        .count();
    assert!(
        kernel_threads > 20,
        "a Debian 7 machine runs dozens of kernel threads, found {kernel_threads}"
    );
}

/// `linux.lsmod` — 79 rows, and the code sizes Volatility prints.
#[test]
fn the_module_list_matches_volatility() {
    let Some(profile) = profile() else { return };
    let layout = lsmod::bind(&profile).expect("the module layout binds");
    let list = lsmod::list_modules(&profile, &layout, &lsmod::ModuleListConfig::default())
        .expect("the module list walks");

    assert_eq!(list.modules.len(), 79, "linux.lsmod reports 79 rows");
    assert!(
        list.is_complete(),
        "the walk did not complete: {:?}",
        list.incomplete()
    );

    // The first two rows of `linux.lsmod.csv`: name and Code Size, which is
    // init_size + core_size.
    let first = &list.modules[0];
    assert_eq!(first.name.known().map(String::as_str), Some("rfcomm"));
    assert_eq!(first.code_size.known(), Some(&0x83A4));
    let second = &list.modules[1];
    assert_eq!(second.name.known().map(String::as_str), Some("bnep"));
    assert_eq!(second.code_size.known(), Some(&0x449F));

    // This build spells the extent the old way, so the newer candidate must not
    // have been what resolved.
    assert_eq!(
        layout.member("core_size").unwrap().member(),
        Some("core_size")
    );
    assert!(
        !layout.member("module_memory").unwrap().is_declared(),
        "Linux 3.2 has no module.mem[], and claiming it did would suppress the size columns"
    );
}

/// `linux.bash` — 27 rows.
#[test]
fn the_shell_history_matches_volatility() {
    let Some(profile) = profile() else { return };
    let task_layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let layout = bash::bind(&profile).expect("the bash layout binds");
    let survey = bash::survey_bash(&profile, &layout, &list, &bash::BashConfig::default())
        .expect("the bash survey runs");

    assert_eq!(survey.command_count(), 27, "linux.bash reports 27 rows");

    let commands: Vec<&bash::BashCommand> = survey
        .shells
        .iter()
        .flat_map(|s| s.commands.iter())
        .collect();

    // Commands the oracle lists, by name and time. Asserted by membership rather
    // than by index because two of the oracle's rows share a timestamp to the
    // second and their relative order is not evidence.
    let has = |text: &str, when: i64| {
        commands
            .iter()
            .any(|c| c.command == text && c.timestamp_unix == when)
    };
    assert!(has("su", 1_403_606_200), "{commands:?}");
    assert!(has("sudo bash", 1_403_606_200), "{commands:?}");
    assert!(has("ls", 1_403_613_909), "{commands:?}");
    assert!(commands
        .iter()
        .any(|c| c.command.contains("lime-forensics")));

    // Within one shell the rows are oldest first, which is how a history reads.
    for shell in &survey.shells {
        let times: Vec<i64> = shell.commands.iter().map(|c| c.timestamp_unix).collect();
        let mut sorted = times.clone();
        sorted.sort_unstable();
        assert_eq!(times, sorted, "one shell's history is out of order");
    }

    // Every timestamp must be a time a clock could show; a marker that is not a
    // time must never be rendered as 1970.
    for command in &commands {
        assert!(
            command.timestamp_rfc3339.is_some(),
            "{} has no renderable time",
            command.command
        );
        assert!(!command.command.is_empty());
    }

    // Completeness is a claim about the search, not about the count. Whatever it
    // says, it must say the same thing the reasons do.
    assert_eq!(survey.is_complete(), survey.incomplete().is_empty());
}

/// `linux.envars` — 1402 rows.
#[test]
fn the_environment_matches_volatility() {
    let Some(profile) = profile() else { return };
    let task_layout = tasks::bind(&profile).expect("the task layout binds");
    let list = tasks::list_tasks(&profile, &task_layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let layout = envars::bind(&profile).expect("the environment layout binds");
    let survey = envars::survey_environment(
        &profile,
        &layout,
        &list,
        &envars::EnvironmentConfig::default(),
    )
    .expect("the environment survey runs");

    assert_eq!(
        survey.variable_count(),
        1402,
        "linux.envars reports 1402 rows"
    );

    // Every process on the list gets a row, including the kernel threads with
    // nothing to read: a process with no row would be indistinguishable from one
    // nobody looked at.
    assert_eq!(survey.processes.len(), list.tasks.len());

    // The breakdown below is derived from the oracle, not from Séance. Every
    // task on the list falls into exactly one bucket and they sum to the 133
    // rows `linux.pslist` reports:
    //
    // | Rows | Outcome | How the oracle establishes it |
    // |---|---|---|
    // | 83 | read end to end | distinct PIDs in `linux.envars.csv` |
    // | 8 | parse stopped | have a `linux.elfs.csv` entry and no envars row |
    // | 1 | over-sized | `dovecot`, 0x20e3 bytes, above the 8192 cap |
    // | 2 | not captured | `init` and `atd`, absent from both |
    // | 39 | no user address space | 133 less the 94 with a memory descriptor |
    //
    // **1402 rows across 83 processes, not 91.** The eight are `avahi-daemon`
    // (2388) and its chroot helper (2390), `dovecot/anvil` (3482),
    // `dovecot/log` (3483), `dovecot/config` (3485), `udisks-daemon` (3831) and
    // the two `sshd` privilege-separation processes (8497, 8502) — every one of
    // which `linux.psaux` shows with a rewritten argument vector
    // (`sshd: mark [priv]`, `avahi-daemon: running [deb…]`). Each rewrote its
    // own `argv` over the contiguous environment area, so the first entry there
    // has no `=` in it. Volatility's `linux.envars` `break`s on exactly that —
    // naming avahi-daemon in the comment where it does — and yields no row for
    // any of them, which is why those eight PIDs appear in `linux.elfs.csv` and
    // in no envars row.
    // A local item rather than a closure: a closure cannot be generic over the
    // predicate, and coercing each one to `&dyn Fn` leaves its argument type to
    // inference.
    fn pids_where(
        survey: &envars::EnvironmentSurvey,
        want: impl Fn(&envars::EnvOutcome) -> bool,
    ) -> Vec<i64> {
        let mut out: Vec<i64> = survey
            .processes
            .iter()
            .filter(|p| want(&p.outcome))
            // A row whose pid could not be read still counts, and would be lost
            // here, so the counts below are asserted against `count_where` and
            // only the named sets against this.
            .filter_map(|p| p.pid.known().copied())
            .collect();
        out.sort_unstable();
        out
    }

    fn count_where(
        survey: &envars::EnvironmentSurvey,
        want: impl Fn(&envars::EnvOutcome) -> bool,
    ) -> usize {
        survey.processes.iter().filter(|p| want(&p.outcome)).count()
    }

    assert_eq!(
        count_where(&survey, |o| matches!(o, envars::EnvOutcome::Read)),
        83,
        "83 processes had an environment area that read end to end, which is the number of \
         distinct PIDs linux.envars.csv has rows for"
    );

    // Séance stops where Volatility breaks, and says so on the row. Naming the
    // processes rather than counting them is what makes this check able to
    // catch the stage stopping on the wrong ones.
    assert_eq!(
        pids_where(&survey, |o| matches!(
            o,
            envars::EnvOutcome::ParseStopped(_)
        )),
        vec![2388, 2390, 3482, 3483, 3485, 3831, 8497, 8502],
        "these are the processes linux.psaux shows with a rewritten argument vector, and the \
         ones Volatility emits no environment row for"
    );

    // The kernel threads: recorded as having no user address space rather than
    // as processes that had no environment. Volatility skips them for the same
    // reason and its 1402 rows do not include them.
    assert_eq!(
        count_where(&survey, |o| matches!(
            o,
            envars::EnvOutcome::NotRead(
                seance_plugin_memory_linux::space::SpaceRefusal::NoUserAddressSpace
            )
        )),
        39,
        "39 tasks on this machine are kernel threads"
    );
    // `dovecot` declares an 8419-byte environment area, above the cap. Not read,
    // and said so — Volatility skips it identically.
    assert_eq!(
        pids_where(&survey, |o| matches!(
            o,
            envars::EnvOutcome::OverSized { .. }
        )),
        vec![3444],
        "dovecot declares 0x20e3 bytes, above the 8192 cap Volatility applies too"
    );
    // `init` and `atd` have environment areas the acquisition did not capture.
    assert_eq!(
        pids_where(&survey, |o| matches!(
            o,
            envars::EnvOutcome::NotRead(
                seance_plugin_memory_linux::space::SpaceRefusal::Unreadable(_)
            )
        )),
        vec![1, 2344],
        "init and atd"
    );

    // Eleven processes' environments could not be established, so the stage must
    // NOT claim completeness — the 1402 rows are a floor. This is the assertion
    // that separates "1402 variables is what this machine had" from "1402 is
    // what could be read", and Volatility's own 1402 is the second of those with
    // nothing on the output to say so.
    assert!(!survey.is_complete());
    let reasons = survey.incomplete();
    assert_eq!(
        reasons.len(),
        11,
        "eight argv-rewriting daemons, one over-sized area and two that were not captured: \
         {reasons:?}"
    );
}

/// The whole tier, through the seam the orchestrator actually calls.
///
/// This is the check the project learned to insist on: an analysis tier can be
/// entirely correct and still ship a dispatch that returns an empty vector, with
/// every unit test passing. Nothing below touches an internal function.
#[test]
fn the_module_produces_the_records_a_case_reads() {
    use seance_core::artifact::{Artifact, ArtifactType};
    use seance_core::module::ForensicsModule;

    let Some(physical) = image() else { return };
    let dirs = symbol_dirs();

    // The record the container stage emits, with the decoded space attached.
    let source: Arc<dyn DataSource> = Arc::new(
        seance_core::data_source::FileDataSource::new(
            PathBuf::from(std::env::var("SEANCE_MEM_IMAGES").expect("checked by image()"))
                .join("linux-sample-1.bin"),
        )
        .expect("the image opens"),
    );
    let image_record = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::ParsedRecord,
        Some(source),
        serde_json::json!({"type": "MemoryImage", "image_format": "raw"}),
    );
    let _ = physical;

    let module = seance_memory::analysis::MemoryAnalysisModule::new(
        seance_plugin_memory_linux::LinuxMemoryAnalysis::new().with_symbol_dirs(dirs),
    );
    let out = module.process(&image_record).expect("the module runs");

    let of_type = |name: &str| {
        out.iter()
            .filter(|a| a.metadata["type"] == name)
            .collect::<Vec<_>>()
    };

    let manifest = of_type("MemoryStageManifest");
    assert_eq!(
        manifest.len(),
        1,
        "the stage manifest must always be emitted"
    );
    assert_eq!(
        manifest[0].metadata["stage_count"],
        seance_plugin_memory_linux::STAGES.len()
    );

    let profile = of_type("MemoryProfile");
    assert_eq!(profile.len(), 1);
    assert_eq!(profile[0].metadata["profile_established"], true);
    assert_eq!(profile[0].metadata["analysed_os"], "linux");

    // Every declared stage produced a record under its own name, and none of
    // them failed.
    let failures = of_type("MemoryStageFailure");
    assert!(
        failures.is_empty(),
        "stages failed: {:?}",
        failures
            .iter()
            .map(|a| a.metadata["failure"].clone())
            .collect::<Vec<_>>()
    );
    for stage in seance_plugin_memory_linux::STAGES {
        let records = of_type(stage.record_type);
        assert_eq!(
            records.len(),
            1,
            "the {} stage emitted {} record(s)",
            stage.key,
            records.len()
        );
        assert_eq!(records[0].metadata["stage"], stage.key);
        assert_eq!(records[0].metadata["stage_ran"], true);
        // Completeness is per stage and is a claim, not decoration.
        match stage.key {
            // The environment stage is a floor on this machine: three processes
            // have environment areas that were not captured or are too large to
            // be one, so it must say so.
            "linux_environment" => {
                assert_eq!(records[0].metadata["content_complete"], false);
                assert!(
                    records[0].metadata["content_incomplete_reason"]
                        .as_str()
                        .is_some_and(|r| r.contains("could not be established")),
                    "a stage that is short must say why: {}",
                    records[0].metadata["content_incomplete_reason"]
                );
            }
            // The memory-map and open-files stages' completeness depends on
            // which dentry, VMA and file pages the acquisition caught, which is a
            // property of the capture rather than of the code; assert only that
            // each makes a coherent claim, and that whenever it is a floor it
            // says why.
            "linux_process_maps"
            | "linux_open_files"
            | "linux_network_sockets"
            | "linux_mounts"
            | "linux_kernel_log" => {
                let complete = records[0].metadata["content_complete"]
                    .as_bool()
                    .expect("a boolean completeness claim");
                if !complete {
                    assert!(
                        records[0].metadata["content_incomplete_reason"]
                            .as_str()
                            .is_some_and(|r| !r.is_empty()),
                        "a map stage that is short must say why"
                    );
                }
            }
            // The rest establish everything they look for on this capture.
            _ => assert_eq!(
                records[0].metadata["content_complete"], true,
                "the {} stage's completeness claim: {}",
                stage.key, records[0].metadata["content_incomplete_reason"]
            ),
        }
    }

    // The counts an examiner reads, through the artifacts rather than the
    // internals.
    let tasks = of_type("LinuxMemoryTaskList");
    assert_eq!(tasks[0].metadata["count"], 133);
    let capabilities = of_type("LinuxMemoryCapabilities");
    assert_eq!(capabilities[0].metadata["count"], 133);
    let modules = of_type("LinuxMemoryKernelModules");
    assert_eq!(modules[0].metadata["count"], 79);
    let bash = of_type("LinuxMemoryBashHistory");
    assert_eq!(bash[0].metadata["command_count"], 27);
    let env = of_type("LinuxMemoryEnvironment");
    assert_eq!(env[0].metadata["variable_count"], 1402);
}

/// An image that is not a Linux capture must produce nothing, and must do so for
/// the right reason.
///
/// A raw buffer of zeros holds no kernel banner and the sweep covers all of it,
/// which is the one case this tier is entitled to be silent about. If the sweep
/// could not finish, silence would be a claim about the part nobody looked at,
/// and the analysis emits a failure record instead.
#[test]
fn an_image_with_no_kernel_banner_is_not_claimed_by_this_tier() {
    use seance_core::data_source::ByteSliceDataSource;

    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(vec![0u8; 0x40000]));
    let layer: Arc<dyn MemoryLayer> =
        Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"));
    let err = discovery::discover(layer, &symbol_dirs(), &DiscoveryOptions::default())
        .expect_err("there is no kernel here");
    assert!(
        err.means_not_a_linux_image(),
        "a complete sweep that found no banner is the one silent case: {err}"
    );
    assert_eq!(err.class(), "no_kernel_banner");
}
