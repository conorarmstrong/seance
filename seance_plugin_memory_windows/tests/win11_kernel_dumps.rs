//! The kernel-structure dumps and the odds and ends (`ROADMAP` §5.3) on the
//! Windows 11 build 26200 capture: `kpcrs`, `bigpools`, `virtmap`,
//! `getcellroutine`, `verinfo`, `mbrscan`, `scheduled_tasks` and the
//! TrueCrypt decision, each graded against something the image itself
//! establishes independently.
//!
//! Provisioning is the same as `win11_corpus_analysis.rs`: the capture in
//! `test_data/win11_bitlocker/` (or `SEANCE_WIN11_MEMORY`) and its ISF. The
//! tests are release-only for the same reason: a 10 GiB capture read through
//! the page tables is minutes per stage unoptimised.
//!
//! # The ground truth these rest on
//!
//! - The VM that produced the capture ran with `-smp 8` (`~/win11-lab/vm/run-vm.sh`),
//!   which the timer walk already established from `KiProcessorBlock`.
//! - Its disk is a 64 GiB GPT disk (`~/win11-lab/README.md`), so the boot
//!   sector Windows read is a protective MBR with a single `0xEE` entry
//!   starting at LBA 1. Its sector count is `0xFFFFFFFF` on the image, not
//!   the disk's 134,217,727 remaining sectors: Windows writes the UEFI
//!   specification's "or 0xFFFFFFFF" alternative, and the first version of
//!   this test assumed the other form until the bytes said otherwise.
//! - The kernel is build 26200, established by discovery from
//!   `_KUSER_SHARED_DATA`; the kernel image's own version resource must say so.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use seance_core::data_source::DataSource;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_windows::automagic::{self, DiscoveryOptions};
use seance_plugin_memory_windows::WindowsProfile;

fn capture_path() -> Option<PathBuf> {
    let p = if let Ok(p) = std::env::var("SEANCE_WIN11_MEMORY") {
        PathBuf::from(p)
    } else {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()?
            .join("test_data/win11_bitlocker/memory-unlocked.raw")
    };
    p.exists().then_some(p)
}

fn symbol_dirs() -> Vec<PathBuf> {
    if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
        let dirs: Vec<PathBuf> = list
            .split(':')
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .collect();
        if !dirs.is_empty() {
            return dirs;
        }
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate sits under the workspace root")
        .to_path_buf();
    vec![
        root.join("test_data/win11_bitlocker/symbols"),
        root.join("reference/volatility3/volatility3/symbols"),
    ]
}

static PROFILE: OnceLock<Option<WindowsProfile>> = OnceLock::new();

fn profile() -> Option<&'static WindowsProfile> {
    PROFILE
        .get_or_init(|| {
            let path = capture_path()?;
            let source: Arc<dyn DataSource> =
                Arc::new(seance_core::data_source::FileDataSource::new(path).ok()?);
            let physical: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).ok()?);
            match automagic::discover(physical, &symbol_dirs(), &DiscoveryOptions::default()) {
                Ok(profile) => Some(profile),
                Err(err) => panic!("discovery failed on the corpus capture: {err}"),
            }
        })
        .as_ref()
}

macro_rules! require_profile {
    () => {
        match profile() {
            Some(p) => p,
            None => {
                eprintln!(
                    "skipping: put memory-unlocked.raw and its ISF in test_data/win11_bitlocker/"
                );
                return;
            }
        }
    };
}

/// The processor count the VM was started with.
const PROCESSORS: u64 = 8;

/// **`kpcrs`: eight processors, every one coherent with itself**, and the
/// count the kernel states agrees with the array.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_processor_blocks_are_read_and_self_checked_on_the_win11_capture() {
    use seance_plugin_memory_windows::processor_blocks::*;
    let profile = require_profile!();
    let symbols = ProcessorSymbols::from_profile(profile).expect("26200 declares the KPCR");
    let out = survey_processors(profile, &symbols);
    eprintln!("processor_blocks: {}", out.describe());
    for cpu in &out.processors {
        eprintln!(
            "  cpu {} kpcr {:#x} prcb {:#x} self={:?} prcb={:?} number={:?} idle={:?} running {:?}",
            cpu.index,
            cpu.kpcr,
            cpu.prcb,
            cpu.self_agrees,
            cpu.current_prcb_agrees,
            cpu.number_agrees,
            cpu.idle,
            cpu.current_process
                .as_ref()
                .map(|p| (p.pid, p.name.clone()))
        );
    }
    assert_eq!(out.processors.len() as u64, PROCESSORS);
    assert_eq!(out.claimed, Some(PROCESSORS));
    assert!(out.count_note.is_none(), "{:?}", out.count_note);
    for cpu in &out.processors {
        assert_eq!(cpu.self_agrees, Some(true), "cpu {}", cpu.index);
        assert_eq!(cpu.current_prcb_agrees, Some(true), "cpu {}", cpu.index);
        assert_eq!(cpu.number_agrees, Some(true), "cpu {}", cpu.index);
        assert_eq!(cpu.checks_made(), 3);
        assert!(cpu.current_thread.is_some());
        assert!(cpu.idle_thread.is_some());
    }
    // Every processor's current thread resolved to a process. Measured
    // 2026-09-19: the capture was taken through QMP with the guest quiescent,
    // and all eight processors were on their idle thread, which belongs to the
    // Idle process (pid 0, image name "Idle") -- not to System (pid 4).
    for cpu in &out.processors {
        let process = cpu
            .current_process
            .as_ref()
            .unwrap_or_else(|| panic!("cpu {} has no process: {:?}", cpu.index, cpu.notes));
        assert!(process.name.is_some(), "cpu {}", cpu.index);
        if cpu.idle == Some(true) {
            assert_eq!(
                process.pid,
                Some(0),
                "the idle thread belongs to the Idle process"
            );
            assert_eq!(process.name.as_deref(), Some("Idle"));
        }
    }
    assert_eq!(
        out.processors
            .iter()
            .filter(|c| c.idle == Some(true))
            .count(),
        8,
        "measured: every processor idle at capture"
    );
    assert!(out.is_complete());
}

/// **`bigpools`: the table walked whole, with the kernel's own counter beside
/// the walk** and the table itself inside the non-paged pool region the
/// virtual map names.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_big_pool_table_is_walked_on_the_win11_capture() {
    use seance_plugin_memory_windows::big_pool::*;
    let profile = require_profile!();
    let symbols = BigPoolSymbols::from_profile(profile).expect("26200 declares the table");
    assert!(
        symbols.pool_type.is_none(),
        "26200 declares no PoolType on the tracker entry"
    );
    assert!(
        symbols.pool_flags.is_some(),
        "26200 declares PoolFlags instead"
    );
    let out = survey_big_pool(profile, &symbols, &BigPoolConfig::default());
    eprintln!("big_pool: {}", out.describe());
    let mut tags: Vec<(&String, &TagTotals)> = out.tags.iter().collect();
    tags.sort_by_key(|(_, t)| std::cmp::Reverse(t.bytes_in_use));
    for (tag, totals) in tags.iter().take(10) {
        eprintln!(
            "  {tag}: {} live ({} bytes), {} freed",
            totals.in_use, totals.bytes_in_use, totals.free
        );
    }
    // Measured 2026-09-19: 32,768 slots, 6,965 live, 25,803 freed, none
    // never used, 300 distinct tags, and the kernel's counter reads 6,965.
    assert_eq!(out.entries_declared, 32_768);
    assert_eq!(out.entries_read, out.entries_declared);
    assert_eq!(out.entries_unreadable, 0);
    assert_eq!(out.entries_in_use, 6_965);
    assert_eq!(out.entries_free, 25_803);
    assert_eq!(out.entries_empty, 0);
    assert_eq!(out.tags.len(), 300);
    assert!(
        out.in_use_claimed.is_some(),
        "26200 declares ExpPoolBigEntriesInUse"
    );
    assert_eq!(
        out.counter_agrees(),
        Some(true),
        "the kernel says {:?} live slots and the walk counted {}",
        out.in_use_claimed,
        out.entries_in_use
    );
    // Every live allocation's address is canonical kernel space.
    for entry in out.entries.iter().filter(|e| !e.free) {
        assert!(entry.va >= 0xFFFF_8000_0000_0000, "{entry:?}");
        assert_eq!(
            entry.va & 0xFFF,
            0,
            "a big-page allocation is page-aligned: {entry:?}"
        );
    }
    assert!(
        out.tags.contains_key("MmSt") || out.tags.contains_key("Vad "),
        "{:?}",
        out.tags.keys().take(20).collect::<Vec<_>>()
    );
    assert!(out.is_complete());
}

/// **`virtmap`: eighteen regions, the kernel in slot 17 typed
/// `MiVaDriverImages` by the kernel's own map** (not the boot-loaded region,
/// and not what the slot's index would name), and the big-pool table inside
/// the non-paged pool region — two facts read from two different structures
/// agreeing about the same address.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_virtual_map_places_the_kernel_and_the_pool_table_on_the_win11_capture() {
    use seance_plugin_memory_windows::big_pool::{survey_big_pool, BigPoolConfig, BigPoolSymbols};
    use seance_plugin_memory_windows::virtual_map::*;
    let profile = require_profile!();
    let symbols = VirtualMapSymbols::from_profile(profile).expect("26200 declares MiState");
    let out = survey_virtual_map(profile, &symbols);
    eprintln!("virtual_map: {}", out.describe());
    for region in out.regions.iter().filter(|r| !r.is_empty()) {
        eprintln!(
            "  [{}] {:<28} {:#018x} + {:#x}",
            region.index,
            region.type_name.clone().unwrap_or_default(),
            region.base,
            region.bytes
        );
    }
    for check in &out.checks {
        eprintln!(
            "  check {} -> {:?}: {}",
            check.name, check.passed, check.detail
        );
    }
    assert_eq!(out.regions_declared, 18, "the 26200 ISF declares 18 slots");
    assert_eq!(out.regions.len(), 18);
    assert!(out.regions_unreadable.is_empty());
    assert_eq!(out.regions_non_canonical, 0);
    assert_eq!(
        out.slice_bytes,
        Some(0x80_0000_0000),
        "512 GiB per top-level slot"
    );
    // Measured 2026-09-19: the kernel image lies in slot 17 -- which the
    // enumeration would call MiVaSystemDataViews if a slot's index were its
    // type. The kernel's own per-slice map types that slot MiVaDriverImages:
    // on this build the kernel is loaded into the driver-image region, not a
    // boot-loaded one, and the record says which.
    let placed = out
        .kernel_base_region
        .as_ref()
        .expect("the kernel is in a region");
    assert_eq!(placed.index, 17);
    assert_eq!(placed.type_name.as_deref(), Some("MiVaDriverImages"));
    // And the PFN database pointer lands in slot 0, typed for it -- the slot
    // the enumeration would call MiVaUnused by index.
    let pfn = out
        .checks
        .iter()
        .find(|c| c.name == "pfn_database_in_its_region")
        .expect("the check is made");
    assert!(pfn.detail.contains("slot 0"), "{}", pfn.detail);
    assert!(out.overlaps.is_empty(), "{:?}", out.overlaps);
    assert_eq!(out.regions_in_use(), 17);
    for check in &out.checks {
        assert_eq!(check.passed, Some(true), "{check:?}");
    }

    // The big-pool table, located through a different global, lies in the
    // region the map types as non-paged pool: slot 1, not slot 4.
    let pool = BigPoolSymbols::from_profile(profile).expect("symbols");
    let table = survey_big_pool(profile, &pool, &BigPoolConfig::default()).table;
    let holder = out
        .region_of(table)
        .expect("the pool table lies in a region");
    assert_eq!(holder.index, 1);
    assert_eq!(holder.type_name.as_deref(), Some("MiVaNonPagedPool"));
    assert_eq!(holder.type_uniform, Some(true));
    assert!(out.is_complete());
}

/// **`virtmap`: `SystemVaTypeCount` is published in the kernel's own
/// dynamic-VA granules.** The 26200 ISF declares
/// `_MI_VISIBLE_STATE.SystemVaTypeCount` as `u64[20]`, one per
/// `_MI_SYSTEM_VA_TYPE` value. Measured 2026-09-27 on this capture, the
/// hypothesis that it counts 512 GiB slices of `SystemVaType` is **false**
/// (the slice histogram is `[85, 1, 0, 26, 32, 32, 2, 32, 32, 1, 0, 1, 0, 2,
/// 1, 1, 2, 1, 5, 0]` against the counts pinned below). What holds: each
/// `SystemVa.DynamicBitMap<Type>` spans its region at `region bytes /
/// MaximumSize` = 2 MiB per bit, and for five types (paged pool, system
/// cache, driver images, kernel stacks, system data views) the count equals
/// the bitmap's set bits exactly; for system PTEs (2,399 against 2,066) and
/// non-cached mappings (5 against 1) it exceeds them -- and there, measured
/// by a one-off walk of the page tables, equals the present page-directory
/// entries in the type's slices. The count is never below its bitmap. The
/// non-paged pool (2,146) has no bitmap and is not cross-checked. One build.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_virtual_map_type_counts_agree_with_the_dynamic_bitmaps_on_the_win11_capture() {
    use seance_plugin_memory_windows::virtual_map::*;
    let profile = require_profile!();
    let symbols = VirtualMapSymbols::from_profile(profile).expect("26200 declares MiState");
    let out = survey_virtual_map(profile, &symbols);
    for check in &out.type_count_checks {
        eprintln!("  {check:?}");
    }
    let counts = out
        .type_counts
        .as_ref()
        .unwrap_or_else(|| panic!("published: {:?}", out.type_counts_withheld));
    assert_eq!(
        counts,
        &vec![0, 0, 0, 0, 2146, 80, 5, 269, 2399, 0, 0, 71, 0, 33, 0, 0, 0, 2044, 0, 0],
        "one per _MI_SYSTEM_VA_TYPE value, as measured"
    );
    assert_eq!(out.type_count_granule, Some(0x20_0000), "2 MiB per unit");
    let by_name = |name: &str| {
        out.type_count_checks
            .iter()
            .find(|c| c.type_name.as_deref() == Some(name))
            .unwrap_or_else(|| panic!("{name} is checked"))
    };
    for (name, set) in [
        ("MiVaPagedPool", 80),
        ("MiVaSystemCache", 269),
        ("MiVaDriverImages", 71),
        ("MiVaKernelStacks", 33),
        ("MiVaSystemDataViews", 2044),
        ("MiVaSystemPtes", 2066),
        ("MiVaNonCachedMappings", 1),
        ("MiVaKernelShadowStacks", 0),
        ("MiVaSecureNonPagedPool", 0),
    ] {
        let check = by_name(name);
        assert_eq!(check.bits_set, Some(set), "{check:?}");
        assert_eq!(check.holds, Some(true), "{check:?}");
    }
    assert_eq!(out.type_count_checks.len(), 9);
    assert!(out.type_counts_withheld.is_none());
    assert!(out.is_complete());
}

/// **`getcellroutine`: every hive's routines are named kernel functions**, at
/// their exact start, and none lies outside the kernel image.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn every_hive_cell_routine_is_a_named_kernel_function_on_the_win11_capture() {
    use seance_plugin_memory_windows::hive_cell_routines::*;
    use seance_plugin_memory_windows::kernel_hooks::ModuleMap;
    let profile = require_profile!();
    let symbols =
        HiveCellRoutineSymbols::from_profile(profile).expect("26200 declares the routine");
    assert!(symbols.release_cell_routine.is_some());
    let map = ModuleMap::from_profile(profile);
    assert!(map.is_authoritative(), "{:?}", map.note());
    let out = survey_hive_cell_routines(profile, &symbols, &map);
    eprintln!("hive_cell_routines: {}", out.describe());
    for hive in &out.hives {
        eprintln!(
            "  {:<60} get={:?} release={:?}",
            hive.name.clone().unwrap_or_default(),
            hive.get_cell
                .as_ref()
                .map(|r| (r.symbol.clone(), r.symbol_offset)),
            hive.release_cell
                .as_ref()
                .map(|r| (r.symbol.clone(), r.symbol_offset)),
        );
    }
    // Measured 2026-09-19: 38 hives, every routine HvpGetCellPaged /
    // HvpReleaseCellPaged at offset zero.
    assert_eq!(out.hives.len(), 38);
    assert!(out.hive_list_complete);
    assert_eq!(out.hives_unreadable(), 0);
    assert_eq!(out.hives_with_a_routine_outside_the_kernel(), 0);
    assert_eq!(out.hives_with_a_routine_off_a_symbol(), 0);
    for hive in &out.hives {
        let get = hive.get_cell.as_ref().expect("read");
        assert!(get.at_a_symbol(), "{hive:?}");
        let name = get.symbol.as_deref().unwrap_or_default();
        assert!(name.starts_with("HvpGetCell"), "{name}");
        let release = hive.release_cell.as_ref().expect("read");
        assert!(release.at_a_symbol(), "{hive:?}");
        assert!(release
            .symbol
            .as_deref()
            .unwrap_or_default()
            .starts_with("HvpReleaseCell"));
    }
    assert!(out.is_complete());
}

/// **`verinfo`: the kernel's own resource section is marked discardable and
/// not read, and a user-mode `ntdll.dll` names the build discovery
/// established** from
/// a different structure. Every image's outcome is stated.
///
/// Measured 2026-09-19 on the kernel side: 155 modules, of which 150 have a
/// `.rsrc` marked `IMAGE_SCN_MEM_DISCARDABLE` -- `ntoskrnl.exe` among them,
/// and the bytes at its resource directory's address after boot are code --
/// so their version is not in RAM by the loader's design; 3 carry a readable
/// version and 2 have no resource directory. The version of the running
/// kernel is therefore established from the user-mode images of the same
/// build, whose resource sections are resident.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn version_resources_are_read_where_they_are_resident_on_the_win11_capture() {
    use seance_plugin_memory_windows::modules::{
        list_kernel_modules, ModuleSymbols, ModuleWalkConfig,
    };
    use seance_plugin_memory_windows::process::{
        list_processes, ProcessListConfig, ProcessSymbols,
    };
    use seance_plugin_memory_windows::version_info::*;
    let profile = require_profile!();
    let module_symbols = ModuleSymbols::from_profile(profile).expect("symbols");
    let kernel = list_kernel_modules(profile, &module_symbols, &ModuleWalkConfig::default())
        .expect("the kernel module list");

    // A handful of ordinary processes are enough to grade the user-mode side;
    // the whole list is what the stage runs over in the pipeline. The earliest
    // processes (System, Registry, smss.exe) map few or no DLLs, so the ones
    // the corpus notes say were running are taken instead.
    let process_symbols = ProcessSymbols::from_profile(profile).expect("symbols");
    let mut list = list_processes(profile, &process_symbols, &ProcessListConfig::default())
        .expect("the process list");
    let wanted = [
        "lsass.exe",
        "explorer.exe",
        "msedge.exe",
        "sshd.exe",
        "svchost.exe",
    ];
    let mut chosen = Vec::new();
    for name in wanted {
        if let Some(process) = list.processes.iter().find(|p| {
            p.image_file_name
                .known()
                .is_some_and(|n| n.eq_ignore_ascii_case(name))
        }) {
            chosen.push(process.clone());
        }
    }
    assert!(
        chosen.len() >= 4,
        "{} of the named processes found",
        chosen.len()
    );
    list.processes = chosen;

    let out = survey_version_info(
        profile,
        Ok(&kernel),
        Some(&list),
        &VersionInfoConfig::default(),
    );
    eprintln!("version_info: {}", out.describe());
    let nt = out
        .kernel
        .iter()
        .find(|i| {
            i.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case("ntoskrnl.exe"))
        })
        .expect("ntoskrnl.exe is on the list");
    eprintln!("  ntoskrnl.exe: {:?}", nt.version.outcome);
    assert!(
        nt.version.outcome.is_discarded(),
        "the kernel's .rsrc is discardable on 26200: {:?}",
        nt.version.outcome
    );
    assert!(nt.version.fixed.is_none());
    let kernel_read = out
        .kernel
        .iter()
        .filter(|i| i.version.fixed.is_some())
        .count();
    let kernel_discarded = out
        .kernel
        .iter()
        .filter(|i| i.version.outcome.is_discarded())
        .count();
    let kernel_absent = out
        .kernel
        .iter()
        .filter(|i| i.version.outcome.is_absence())
        .count();
    eprintln!(
        "  {} kernel modules: {kernel_read} read, {kernel_discarded} discarded, {kernel_absent} absent",
        out.kernel.len()
    );
    assert_eq!(out.kernel.len(), 155);
    assert_eq!(kernel_read, 3);
    assert_eq!(kernel_discarded, 150);
    assert_eq!(kernel_absent, 2);
    assert_eq!(out.images_malformed(), 0);

    // The whole survey -- the 155 kernel modules above plus the DLLs of these
    // five processes -- measured 2026-09-19: 767 images in all, 561 with a
    // version, 6 with none, 150 discarded, 50 whose resource page is not
    // present, 0 malformed. `images_examined` and the counters on
    // `VersionSurvey` run over both sides, so every discarded image here is a
    // kernel module and the user-mode side is the remainder: 612 images, 558
    // with a version, 4 with none, none discarded, 50 unreadable (`ntdll.dll`'s
    // among them in every process: a shared page nothing had touched).
    assert_eq!(out.images_examined, 767);
    assert_eq!(out.images_with_a_version(), 561);
    assert_eq!(out.images_without_a_version(), 6);
    assert_eq!(out.images_discarded(), 150);
    assert_eq!(out.images_unreadable(), 50);
    let user: Vec<&ImageRecord> = out.processes.iter().flat_map(|p| p.images.iter()).collect();
    let user_count = |f: &dyn Fn(&ImageRecord) -> bool| user.iter().filter(|i| f(i)).count();
    assert_eq!(user.len(), 612);
    assert_eq!(user_count(&|i| i.version.fixed.is_some()), 558);
    assert_eq!(user_count(&|i| i.version.outcome.is_absence()), 4);
    assert_eq!(user_count(&|i| i.version.outcome.is_discarded()), 0);
    assert_eq!(user_count(&|i| i.version.outcome.is_unreadable()), 50);

    // **The binaries say 26100 and the kernel says 26200.** Every Windows
    // image with a readable version in these processes carries product
    // version 10.0.26100.x (89 of them in lsass.exe alone), while discovery
    // read build 26200 from `_KUSER_SHARED_DATA`. That is what an enablement
    // package looks like from memory: Windows 11 25H2 (26200) ships the 24H2
    // (26100) binaries with the build number raised, so the two numbers are
    // both right and a reader must not treat their disagreement as a
    // tampered image. The test pins both facts so the record can be quoted.
    assert_eq!(profile.build.build, Some(26200));
    let mut microsoft = 0usize;
    for process in &out.processes {
        assert!(process.unavailable.is_none());
        let mut builds: std::collections::BTreeMap<u16, usize> = Default::default();
        for image in &process.images {
            assert!(
                !matches!(image.version.outcome, VersionOutcome::Malformed(_)),
                "{:?}: {:?}",
                image.name,
                image.version.outcome
            );
            let Some(fixed) = &image.version.fixed else {
                continue;
            };
            // Operating-system binaries only: Microsoft also ships runtimes
            // versioned on their own lines (a 7.x here), which say nothing
            // about the Windows build.
            if image.version.string("CompanyName") != Some("Microsoft Corporation")
                || !image
                    .version
                    .string("ProductVersion")
                    .is_some_and(|v| v.starts_with("10.0."))
            {
                continue;
            }
            microsoft += 1;
            *builds.entry(fixed.product_version[2]).or_default() += 1;
            // The product version, not the file version: `UIAutomationCore.DLL`
            // carries file version 7.x under product version 10.0.26100.5074.
            assert_eq!(
                &fixed.product_version[..3],
                &[10, 0, 26100],
                "{:?} {:?}",
                image.name,
                image.version.string("ProductVersion")
            );
        }
        eprintln!(
            "  pid {:?} {:?}: {} images; Windows product-version builds {builds:?}",
            process.pid,
            process.name,
            process.images.len()
        );
        assert!(!builds.is_empty(), "pid {:?}", process.pid);
    }
    assert!(microsoft > 300, "{microsoft}");
    let lsass = out
        .processes
        .iter()
        .find(|p| p.name.as_deref() == Some("lsass.exe"))
        .expect("lsass.exe was chosen");
    let lsass_image = lsass
        .images
        .iter()
        .find(|i| {
            i.name
                .as_deref()
                .is_some_and(|n| n.eq_ignore_ascii_case("lsass.exe"))
        })
        .expect("the main image is on its own DLL list");
    assert_eq!(
        lsass_image
            .version
            .fixed
            .as_ref()
            .map(|f| f.file_version_text()),
        Some("10.0.26100.6584".to_string())
    );
    assert_eq!(
        lsass_image.version.string("OriginalFilename"),
        Some("lsass.exe")
    );
    assert!(out.images_with_a_version() > kernel_read as u64);
}

/// **`mbrscan`: the GPT disk's protective MBR is in RAM**, its one `0xEE`
/// entry declaring `0xFFFFFFFF` sectors (the UEFI alternative Windows writes,
/// not the 64 GiB disk's own count), and every other sector ending in
/// `55 AA` is reported with the checks it failed.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn the_gpt_disks_protective_mbr_is_found_in_physical_memory_on_the_win11_capture() {
    use seance_plugin_memory_windows::mbr_scan::*;
    let profile = require_profile!();
    let out = scan_for_mbrs(profile.physical.as_ref(), &MbrScanConfig::default());
    eprintln!("mbr_scan: {}", out.describe());
    for candidate in out.candidates.iter().filter(|c| c.well_formed) {
        eprintln!(
            "  {:#x} {:?} signature {:08x} boot code {} partitions {:?}",
            candidate.offset,
            candidate.kind,
            candidate.disk_signature,
            &candidate.boot_code_sha256[..16],
            candidate
                .partitions
                .iter()
                .filter(|p| !p.is_empty())
                .map(|p| (p.partition_type, p.first_lba, p.sectors))
                .collect::<Vec<_>>()
        );
    }
    assert!(out.scan.is_complete(), "{:?}", out.scan.unread);
    assert!(!out.candidates_truncated);
    assert_eq!(out.scan.bytes_scanned, 10 * 1024 * 1024 * 1024);
    // Measured 2026-09-19: 14 sector-aligned sectors end in 55 AA; exactly
    // one is a well-formed partition table, and it is the GPT disk's
    // protective MBR at physical 0x1b5e49000, disk signature zero. Its single
    // 0xEE entry starts at LBA 1 and declares 0xFFFFFFFF sectors -- Windows
    // writes the UEFI specification's "0xFFFFFFFF" alternative rather than
    // the disk's actual 134,217,727, which is what this test first assumed.
    assert_eq!(out.sectors_with_signature, 14);
    assert_eq!(out.candidates.len(), 14);
    assert_eq!(out.well_formed(), 1);
    let protective: Vec<&MbrCandidate> = out
        .candidates
        .iter()
        .filter(|c| c.kind == MbrKind::GptProtective)
        .collect();
    assert_eq!(
        protective.len(),
        1,
        "the disk's protective MBR: a partition table the machine held in memory"
    );
    let mbr = protective[0];
    assert_eq!(mbr.offset, 0x1_b5e4_9000);
    assert_eq!(mbr.disk_signature, 0);
    assert!(!mbr.boot_code_empty);
    let entry = mbr
        .partitions
        .iter()
        .find(|p| !p.is_empty())
        .expect("one entry");
    assert_eq!(entry.partition_type, 0xEE);
    assert_eq!(entry.type_name, Some("GPT protective"));
    assert_eq!(entry.first_lba, 1);
    assert_eq!(entry.sectors, 0xFFFF_FFFF);
    assert_eq!(mbr.partitions_in_use(), 1);
    // The other thirteen are reported with the checks they failed, not dropped.
    for other in out.candidates.iter().filter(|c| !c.well_formed) {
        assert_eq!(other.kind, MbrKind::NotAPartitionTable);
        assert!(other.checks.iter().any(|c| !c.passed), "{other:?}");
    }
}

/// **`scheduled_tasks`: a stock task is read from the SOFTWARE hive in RAM**
/// with its command decoded, every `Actions` blob read decoding whole and
/// every `DynamicInfo` at its declared 36 bytes. `Triggers` is decoded by
/// `scheduled_tasks_triggers` (graded in `scheduled_task_triggers_win11.rs`),
/// and two tasks have a value whose data cell was
/// paged out, so the survey reports itself incomplete.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn scheduled_tasks_are_read_from_the_in_memory_software_hive_on_the_win11_capture() {
    use seance_plugin_memory_windows::scheduled_tasks::*;
    let profile = require_profile!();
    let out = survey_scheduled_tasks(profile);
    eprintln!("scheduled_tasks: {}", out.describe());
    assert!(out.unavailable.is_none(), "{:?}", out.unavailable);
    // Measured 2026-09-19: 246 tasks declared and read, all 246 with an
    // Actions blob that decodes whole and a DynamicInfo of 36 bytes.
    assert_eq!(out.tasks.len(), 246);
    assert_eq!(out.tasks_declared, Some(246));
    let mut decoded = 0usize;
    let mut with_dynamic = 0usize;
    for task in &out.tasks {
        if let Some(actions) = &task.actions {
            if actions.unknown_kind.is_none()
                && actions.malformed.is_none()
                && actions.trailing_bytes == 0
            {
                decoded += 1;
            } else {
                eprintln!("  not whole: {:?} {:?}", task.id, actions);
            }
        }
        if task.dynamic_info.is_some() {
            with_dynamic += 1;
        }
    }
    eprintln!(
        "  {} tasks; {decoded} action blobs decoded whole; {with_dynamic} with dynamic info",
        out.tasks.len()
    );
    let defrag = out
        .tasks
        .iter()
        .find(|t| {
            matches!(&t.path, TaskValue::Text(p) if p.eq_ignore_ascii_case("\\Microsoft\\Windows\\Defrag\\ScheduledDefrag"))
        })
        .expect("the stock defrag task is registered on every Windows 11 install");
    eprintln!("  defrag: {:?}", defrag.actions);
    eprintln!("  defrag dynamic: {:?}", defrag.dynamic_info);
    let command = defrag.first_command().expect("an exec action");
    assert_eq!(command, "%windir%\\system32\\defrag.exe");
    match &defrag.actions.as_ref().unwrap().actions[0] {
        TaskAction::Exec { arguments, .. } => assert_eq!(arguments, "-c -h -o -$"),
        other => panic!("{other:?}"),
    }
    let info = defrag.dynamic_info.as_ref().expect("dynamic info");
    assert_eq!(info.magic, 3);
    assert_eq!(info.length, 36);
    // The image was installed on 2026-07-31 (the task's creation time is the
    // install's) and captured on 2026-08-06; the task had not run.
    let creation = info.creation.as_ref().expect("a creation time");
    assert!(
        creation.rfc3339.starts_with("2026-07-31T19:03:11"),
        "{}",
        creation.rfc3339
    );
    assert!(info.last_run.is_none());
    assert_eq!(info.last_result, Some(0));
    // Across every task: every DynamicInfo is 36 bytes with magic 3, every
    // creation time falls in the machine's lifetime, and every last-result
    // code is zero or an HRESULT -- which pins the field's offset against a
    // real hive rather than a description.
    for task in &out.tasks {
        let info = task.dynamic_info.as_ref().expect("dynamic info");
        assert_eq!(info.magic, 3, "{}", task.id);
        assert_eq!(info.length, 36, "{}", task.id);
        let creation = info.creation.as_ref().expect("creation");
        assert!(
            creation.rfc3339.starts_with("2026-0"),
            "{} {}",
            task.id,
            creation.rfc3339
        );
        let result = info.last_result.expect("result");
        assert!(
            result == 0
                || (0x0004_1300..=0x0004_13FF).contains(&result)
                || result & 0x8000_0000 != 0,
            "{} last result {result:#010x}",
            task.id
        );
    }
    // Every task's action blob decodes whole: the layout holds across the
    // whole TaskCache, not just the one task looked at.
    assert_eq!(
        decoded,
        out.tasks.iter().filter(|t| t.actions.is_some()).count()
    );
    assert!(decoded > 100);
    assert!(out.tasks_index_complete);
    // Two tasks have a value whose data cell was paged out; they stay on the
    // list with the value marked unavailable, and the survey is incomplete.
    let partial: Vec<&ScheduledTask> = out.tasks.iter().filter(|t| !t.complete).collect();
    for task in &partial {
        eprintln!(
            "  incomplete: {} path={:?} notes={:?} triggers={:?}",
            task.id,
            task.path.to_json(),
            task.notes,
            task.triggers_length
        );
    }
    assert_eq!(partial.len(), 2);
    assert!(!out.is_complete());

    // **The planted persistence.** The corpus VM ran
    // `schtasks /create /tn 'SeanceTestBeacon' /tr 'powershell.exe -w hidden -c exit' /sc hourly`
    // (`~/win11-lab/answers/guest/plant-artifacts.ps1`, recorded in the lab's
    // README under "Persistence"), so the in-memory TaskCache must hold that
    // task with that command -- the known answer this whole stage exists for.
    let beacon = out
        .tasks
        .iter()
        .find(|t| matches!(&t.path, TaskValue::Text(p) if p == "\\SeanceTestBeacon"))
        .expect("the planted task is in the TaskCache");
    eprintln!("  beacon: {:?}", beacon.actions);
    eprintln!(
        "  beacon author: {:?} dynamic: {:?}",
        beacon.author, beacon.dynamic_info
    );
    let actions = beacon.actions.as_ref().expect("its actions decode");
    assert_eq!(actions.actions.len(), 1);
    match &actions.actions[0] {
        TaskAction::Exec {
            command, arguments, ..
        } => {
            assert_eq!(command, "powershell.exe");
            assert_eq!(arguments, "-w hidden -c exit");
        }
        other => panic!("{other:?}"),
    }
    assert!(
        matches!(&beacon.author, TaskValue::Text(a) if a == "FORENSIC-W11\\analyst"),
        "{:?}",
        beacon.author
    );
    let info = beacon.dynamic_info.as_ref().expect("dynamic info");
    let created = info.creation.as_ref().expect("creation");
    assert!(
        created.rfc3339.starts_with("2026-08-06T19:04:27"),
        "planted on the capture day: {}",
        created.rfc3339
    );
    assert!(info.last_run.is_none(), "planted hourly, never yet run");
    // The beacon is one of the two incomplete tasks: one of its key's values
    // has a paged-out data cell. Its Actions, DynamicInfo and Author decode
    // whole, and the record says the task is incomplete rather than letting
    // those three stand for the whole key.
    assert!(!beacon.complete, "{:?}", beacon.notes);
    assert!(partial.iter().any(|t| t.id == beacon.id));

    // **Triggers** (measured 2026-09-27): every one of the 246 blobs is
    // resident and decodes to its last byte, 279 triggers in all. The counts
    // per kind pin the layout across the whole TaskCache.
    assert_eq!(out.tasks_with_triggers_whole(), 246);
    assert_eq!(out.tasks_with_triggers_undecoded(), 0);
    let mut kinds = std::collections::BTreeMap::<&str, usize>::new();
    for task in &out.tasks {
        for trigger in &task.triggers.as_ref().expect("decoded").triggers {
            *kinds.entry(trigger.kind.name()).or_default() += 1;
        }
    }
    eprintln!("  trigger kinds: {kinds:?}");
    let expected: std::collections::BTreeMap<&str, usize> = [
        ("wnf_state_change", 148),
        ("time", 47),
        ("logon", 32),
        ("boot", 21),
        ("event", 12),
        ("session_state_change", 11),
        ("idle", 4),
        ("registration", 4),
    ]
    .into_iter()
    .collect();
    assert_eq!(kinds, expected);
    // The planted task's trigger: /sc hourly is one time trigger repeating
    // every hour, enabled, starting at a wall-clock time on the capture day.
    let triggers = beacon
        .triggers
        .as_ref()
        .expect("the beacon's Triggers decode");
    assert_eq!(triggers.triggers.len(), 1);
    let hourly = &triggers.triggers[0];
    assert_eq!(hourly.kind.name(), "time");
    assert_eq!(hourly.repetition_interval_seconds, 3600);
    assert!(hourly.enabled);
    let start = hourly.start.as_ref().expect("a start");
    assert!(start.localized);
    assert_eq!(start.text, "2026-08-06T20:08:00");
}

/// **TrueCrypt: no driver on this machine**, stated with the walk that
/// established it, and no sweep run.
#[test]
#[cfg_attr(
    debug_assertions,
    ignore = "slow in an unoptimised build; run with --release"
)]
fn no_truecrypt_driver_is_loaded_on_the_win11_capture() {
    use seance_plugin_memory_windows::modules::{
        list_kernel_modules, ModuleSymbols, ModuleWalkConfig,
    };
    use seance_plugin_memory_windows::truecrypt::*;
    let profile = require_profile!();
    let module_symbols = ModuleSymbols::from_profile(profile).expect("symbols");
    let kernel = list_kernel_modules(profile, &module_symbols, &ModuleWalkConfig::default())
        .expect("the kernel module list");
    let candidates: Vec<DriverCandidate> = kernel
        .modules
        .iter()
        .map(|m| DriverCandidate {
            name: m.base_name.name().map(str::to_string),
            base: m.base,
            size: m.size_of_image,
        })
        .collect();
    let out = survey_truecrypt(
        &candidates,
        kernel.is_complete(),
        None,
        &TrueCryptConfig::default(),
    );
    eprintln!("truecrypt: {}", out.describe());
    match out.driver {
        DriverPresence::Absent {
            modules_walked,
            list_complete,
        } => {
            // Measured 2026-09-19: 155 modules, list walked whole.
            assert_eq!(modules_walked, 155);
            assert!(list_complete);
        }
        other => panic!("{other:?}"),
    }
    assert!(out.sweep.is_none());
    assert!(out.is_complete());
}
