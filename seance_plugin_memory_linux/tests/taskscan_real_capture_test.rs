//! The scan and the cross-view, against a real Linux capture.
//!
//! The unit tests decide what the scan must accept and refuse. This decides
//! whether it works: a cross-view that finds nothing on a real machine, or
//! finds a thousand processes that are not there, is worthless whatever its
//! unit tests say.
//!
//! # Corpus
//!
//! `SEANCE_LINUX_MEM` must name a directory holding
//! `oberon_mem.lime.compressed`. Absent, these skip; named and missing, they
//! fail.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_core::test_support::corpus;
use seance_memory::layer::MemoryLayer;
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::profile::LinuxProfile;
use seance_plugin_memory_linux::{tasks, taskscan};
use std::sync::Arc;

const CORPUS_VAR: &str = "SEANCE_LINUX_MEM";
const CAPTURE: &str = "oberon_mem.lime.compressed";

fn profiled() -> Option<&'static LinuxProfile> {
    static ONCE: std::sync::OnceLock<Option<LinuxProfile>> = std::sync::OnceLock::new();
    corpus::file(CORPUS_VAR, CAPTURE)?;
    let profile = ONCE
        .get_or_init(|| {
            let path = corpus::file(CORPUS_VAR, CAPTURE)?;
            let source: Arc<dyn DataSource> =
                Arc::new(FileDataSource::new(path).expect("gate checked"));
            let physical: Arc<dyn MemoryLayer> =
                Arc::new(seance_memory::formats::avml::open(source).expect("the capture opens"));
            discovery::discover(physical, &[], &DiscoveryOptions::default()).ok()
        })
        .as_ref();
    assert!(
        profile.is_some(),
        "the capture is present and did not profile; the scan cannot be exercised"
    );
    profile
}

/// **The scan finds real processes on a real machine.**
///
/// The threshold is deliberately loose. What is being tested is that the
/// signature works at all against a kernel nobody wrote it for — not that a
/// particular count comes back, which is a property of one capture.
#[test]
fn the_scan_finds_task_structures_in_a_real_capture() {
    let Some(profile) = profiled() else { return };

    let layout = tasks::bind(profile).expect("the task layout binds");
    let size = profile
        .symbols
        .size_of("task_struct")
        .expect("task_struct has a size");
    let offsets =
        taskscan::ScanOffsets::resolve(&layout, size).expect("every scanned member is declared");

    // The sweep needs the direct-map offset: its link check follows a kernel
    // pointer into physical space, and without the conversion no neighbour
    // resolves and only poisoned structures survive.
    let list = tasks::list_tasks(profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");
    let direct_map =
        taskscan::calibrate_direct_map(profile, &list).expect("the offset is measurable");

    let outcome = taskscan::scan_physical(
        profile.physical.as_ref(),
        offsets,
        direct_map.0,
        &taskscan::ScanConfig::default(),
    );

    assert!(
        !outcome.tasks.is_empty(),
        "the scan found no task_struct at all in a capture that certainly holds hundreds"
    );
    // Names a real Linux machine has. Finding none of these would mean the
    // signature matched something else entirely.
    let names: std::collections::HashSet<&str> =
        outcome.tasks.iter().map(|t| t.comm.as_str()).collect();
    assert!(
        names
            .iter()
            .any(|n| n.starts_with("systemd") || *n == "init"),
        "no init-like process among {} candidates; the signature is matching the wrong \
         thing. A sample: {:?}",
        outcome.tasks.len(),
        names.iter().take(20).collect::<Vec<_>>()
    );
}

/// **The cross-view corroborates the task list against a real capture.**
///
/// This is the assertion whose absence let a broken cross-view ship once
/// already. `rows.len() >= list.len()` is trivially true when NOTHING
/// correlates — the rows are then just the two sets printed side by side — so
/// what is checked here is the correlation itself, against real evidence.
#[test]
fn the_cross_view_corroborates_the_list_against_a_real_capture() {
    let Some(profile) = profiled() else { return };

    let layout = tasks::bind(profile).expect("the task layout binds");
    let list = tasks::list_tasks(profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");
    assert!(!list.tasks.is_empty(), "the list walk must find processes");

    let size = profile.symbols.size_of("task_struct").expect("a size");
    let offsets = taskscan::ScanOffsets::resolve(&layout, size).expect("members declared");
    let direct_map = taskscan::calibrate_direct_map(profile, &list)
        .expect("the direct-map offset must be measurable from a real capture");
    let outcome = taskscan::scan_physical(
        profile.physical.as_ref(),
        offsets,
        direct_map.0,
        &taskscan::ScanConfig::default(),
    );

    let view = taskscan::CrossView::build(&list, &outcome.tasks, true);
    let corroborated = view.corroborated();

    // Measured at 576 of 587. The floor is set well below that so an ordinary
    // difference between captures does not fail the build, while a collapse in
    // correlation — the defect this exists to catch — still does.
    assert!(
        corroborated * 10 >= list.tasks.len() * 9,
        "only {corroborated} of {} processes were confirmed by both methods. A cross-view \
         that correlates poorly is not a corroboration; it is two lists printed together.",
        list.tasks.len()
    );

    // The sweep must reach the whole image. Truncating early is how the first
    // version reached 236 of 587 while reporting itself as a corroboration.
    assert!(
        !outcome.truncated,
        "the sweep stopped early, so processes in the memory it never reached would read \
         as uncorroborated through no fault of the list"
    );

    // And the record must not turn the scan's noise into accusations.
    let json = view.to_json();
    assert!(
        json["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .all(|r| r["verdict"] != "scan_only"),
        "scan-only structures must never be reported as findings — on this capture there \
         are thousands, and they are page-cache text, not hidden processes"
    );
    assert!(json["hidden_process_detection"]
        .as_str()
        .unwrap()
        .contains("NOT PERFORMED"));
}

/// **The module cross-view corroborates the module list against a real capture.**
///
/// Hiding its own module is usually the first thing a Linux rootkit does, so
/// this is the enumeration most likely to be lied to. What is asserted is the
/// correlation itself: "the scan ran" is equally true of a scan that correlated
/// nothing, which is how a broken cross-view shipped once already.
#[test]
fn the_module_cross_view_corroborates_the_list_against_a_real_capture() {
    use seance_plugin_memory_linux::{lsmod, modscan};

    let Some(profile) = profiled() else { return };

    let layout = lsmod::bind(profile).expect("the module layout binds");
    let list = lsmod::list_modules(profile, &layout, &lsmod::ModuleListConfig::default())
        .expect("the module list walks");
    assert!(
        !list.modules.is_empty(),
        "a real machine has modules loaded"
    );

    let size = profile
        .symbols
        .size_of("module")
        .expect("struct module has a size");
    let offsets =
        modscan::ModScanOffsets::resolve(&layout, size).expect("every scanned member is declared");

    // Correlated in PHYSICAL space: a struct module lives in the module region,
    // which is vmalloc space mapped page by page, so no single offset converts
    // it the way the direct map converts a task_struct. Applying the task
    // scan's constant here correlated 0 of 83.
    let listed: Vec<(u64, Option<u64>)> = list
        .modules
        .iter()
        .map(|m| (m.address, modscan::physical_address_of(profile, m.address)))
        .collect();
    let translated = listed.iter().filter(|(_, p)| p.is_some()).count();
    assert!(
        translated * 10 >= list.modules.len() * 9,
        "only {translated} of {} listed modules could be translated to a physical \
         address, so most of the list could not be compared with anything",
        list.modules.len()
    );

    let translate = |va: u64| modscan::physical_address_of(profile, va);
    let (found, _truncated) = modscan::scan_physical(
        profile.physical.as_ref(),
        offsets,
        &translate,
        16 * 1024 * 1024 * 1024,
        65_536,
    );
    assert!(
        !found.is_empty(),
        "the scan found no struct module at all in a capture from a machine that \
         certainly has modules loaded"
    );
    for module in &found {
        assert!(
            modscan::plausible_state(module.state),
            "{} carries state {}, which the kernel does not define",
            module.name,
            module.state
        );
    }

    let view = modscan::ModuleCrossView::build_physical(&list, &listed, &found, true);
    let corroborated = view.corroborated();
    assert!(
        corroborated * 10 >= list.modules.len() * 9,
        "only {corroborated} of {} modules were confirmed by both methods. A cross-view \
         that correlates poorly is not a corroboration; it is two lists printed together.",
        list.modules.len()
    );

    // And the scan's noise must not become accusations.
    let json = view.to_json();
    assert!(
        json["rows"]
            .as_array()
            .expect("rows")
            .iter()
            .all(|r| r["verdict"] != "scan_only"),
        "scan-only structures must never be reported as findings"
    );
    assert!(json["hidden_module_detection"]
        .as_str()
        .unwrap()
        .contains("NOT PERFORMED"));
}

/// **The calibration is what makes the cross-view mean anything.**
///
/// The scan works in physical space and the list walk in virtual space. Linux
/// maps all physical memory linearly, so one addition converts between them —
/// but the base moves with KASLR, so it must be measured from the evidence
/// rather than assumed. This asserts the measurement is possible, consistent,
/// and actually maps a known structure back to where the list says it is.
#[test]
fn the_direct_map_offset_is_measured_and_maps_a_known_task_back() {
    let Some(profile) = profiled() else { return };
    let layout = tasks::bind(profile).expect("binds");
    let list = tasks::list_tasks(profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");

    let offset = taskscan::calibrate_direct_map(profile, &list)
        .expect("a real capture must yield a measurable direct-map offset");

    // Round-trip a process the list already found: translate its virtual
    // address to physical, then convert back with the measured offset. Landing
    // anywhere else means the offset is wrong in a way that would silently
    // decorrelate the whole cross-view.
    let task = list.tasks.first().expect("at least one process");
    let runs = profile
        .kernel_space
        .mapping(task.address, 1)
        .expect("a listed task is mapped");
    let run = runs.first().expect("a run");
    let physical = run.mapped_offset + (task.address - run.offset);

    assert_eq!(
        offset.to_virtual(physical),
        task.address,
        "the measured offset does not carry a known task_struct from its physical \
         location back to the address the list walk reported"
    );
}

/// **Reaching `init_task` through the image mapping widens what the sweep can
/// follow, not what it accepts.**
///
/// The last task on the list links forward to `init_task`, a static in the
/// kernel image mapping rather than the direct map the sweep converts with.
/// The module's sweep ([`taskscan::corroborate_list`]) now also tries the
/// profile's proved kernel-image shift, which corroborated `bash` on the
/// MMUShell AArch64 Debian dump (`arm64_debian_profile_real_test.rs`).
///
/// On this capture the second mapping reaches `init_task`, but the list's tail
/// was changing while it was acquired: `init_task.tasks.prev` names a different
/// task from the one the walk ended on (a short-lived `kworker`). The link
/// check must therefore still refuse to corroborate that task, and it does;
/// and no process corroborated by the direct map alone may be lost.
#[test]
fn the_image_mapping_reaches_init_task_but_a_smeared_tail_is_still_refused() {
    let Some(profile) = profiled() else { return };
    let layout = tasks::bind(profile).expect("the task layout binds");
    let list = tasks::list_tasks(profile, &layout, &tasks::TaskListConfig::default())
        .expect("the task list walks");
    let size = profile.symbols.size_of("task_struct").expect("a size");
    let offsets = taskscan::ScanOffsets::resolve(&layout, size).expect("members declared");
    let links = offsets.tasks as u64;
    let last = list.tasks.last().expect("a task").address;

    // `init_task.tasks.prev`, read in physical memory through the image shift.
    let init_links_phys = list.init_task + links - profile.kernel_shift.value.shift;
    let mut prev = [0u8; 8];
    assert_eq!(
        seance_core::io::read_full(
            profile.physical.as_data_source(),
            init_links_phys + 8,
            &mut prev
        ),
        8,
        "init_task is reachable through the image mapping"
    );
    let prev = u64::from_le_bytes(prev);
    assert!(
        prev >= 0xffff_8000_0000_0000,
        "{prev:#x} is a kernel pointer"
    );
    assert_ne!(prev, last + links, "this capture's tail is smeared");

    let direct_map = taskscan::calibrate_direct_map(profile, &list).expect("measurable");
    let direct_only = taskscan::CrossView::build(
        &list,
        &taskscan::scan_physical(
            profile.physical.as_ref(),
            offsets,
            direct_map.0,
            &taskscan::ScanConfig::default(),
        )
        .tasks,
        true,
    );
    let view = taskscan::corroborate_list(profile, &layout, &list);
    let verdict = |view: &taskscan::CrossView| {
        view.rows
            .iter()
            .find(|r| r.address == last)
            .map(|r| r.verdict)
            .expect("the last task has a row")
    };
    assert_eq!(verdict(&view), taskscan::CrossViewVerdict::ListOnly);
    assert!(view.corroborated() >= direct_only.corroborated());
}
