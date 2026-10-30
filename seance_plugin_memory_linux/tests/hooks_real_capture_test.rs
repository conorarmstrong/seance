//! The hook checks against real Linux captures whose state is known.
//!
//! Both lab guests (`SEANCE_LINUX_SWAP_MEM`: Ubuntu 22.04 / 5.15;
//! `SEANCE_LINUX_NOBLE_MEM`: Ubuntu 24.04 / 6.8) were built from stock cloud
//! images under KVM for this project's own validation and had no rootkit, no
//! tracing tool and no live patch installed. What is graded here:
//!
//! * **The system-call table has no candidate, and is exactly the kernel's.**
//!   Every entry resolves to a kernel symbol at its start; the number that do
//!   is the kernel's own `__NR_syscalls` (449 on 5.15, 462 on 6.8, from
//!   `arch/x86/include/generated/uapi/asm/unistd_64.h` of each release), and
//!   the entry count the next-symbol bound gives is that table plus a short
//!   run of padding whose length is pinned (3 and 2) — not hundreds of "hooks"
//!   made of alignment zeros.
//! * **The registry cross-check holds.** Each eBPF program's own `aux->id`
//!   equals the index the `prog_idr` xarray holds it at — two structures, one
//!   number. systemd loads cgroup programs on every Ubuntu boot, so the
//!   registry holds the number of programs each guest was first observed
//!   with (12 on 5.15, 13 on 6.8, pinned as known answers), the types decode
//!   to cgroup types, and on 6.8 the names systemd gives its programs
//!   (`sd_devices`, `sd_fw_egress`, `sd_fw_ingress`) and the kernel's own
//!   `hid_tail_call` are read from `bpf_prog_aux.name`; 5.15's programs
//!   carry no name.
//! * **ftrace and kprobes read to their ends** with every callback in the
//!   kernel's text, and the direct-call table reads.
//! * **6.8's `module.mem[]` extents are decoded** and are where a module's
//!   code can be: the `struct module` itself lies in the module's data
//!   extent, never in its text extent, which pins the MOD_TEXT index. The
//!   index is the image's own `mod_mem_type.MOD_TEXT` (`MEM-042`), so no
//!   assumed index is stated on the map, and `bpf_prog.type` is named from the
//!   image's own `bpf_prog_type`.

use seance_core::data_source::{DataSource, FileDataSource};
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_plugin_memory_linux::discovery::{self, DiscoveryOptions};
use seance_plugin_memory_linux::hooks::{self, ftrace::OpsVerdict};
use seance_plugin_memory_linux::lsmod;
use seance_plugin_memory_linux::profile::LinuxProfile;
use std::path::PathBuf;
use std::sync::Arc;

fn dir(var: &str) -> Option<PathBuf> {
    let d = PathBuf::from(std::env::var(var).ok()?);
    d.is_dir().then_some(d)
}

fn profile_in(d: &std::path::Path) -> LinuxProfile {
    let src: Arc<dyn DataSource> =
        Arc::new(FileDataSource::new(d.join("mem.raw")).expect("open mem.raw"));
    let physical: Arc<dyn MemoryLayer> =
        Arc::new(PhysicalLayer::raw(src).expect("raw is a physical layer"));
    discovery::discover(physical, &[], &DiscoveryOptions::default())
        .expect("the capture is present and profiles")
}

fn profiled_515() -> Option<&'static LinuxProfile> {
    static ONCE: std::sync::OnceLock<LinuxProfile> = std::sync::OnceLock::new();
    let d = dir("SEANCE_LINUX_SWAP_MEM")?;
    Some(ONCE.get_or_init(|| profile_in(&d)))
}

fn profiled_68() -> Option<&'static LinuxProfile> {
    static ONCE: std::sync::OnceLock<LinuxProfile> = std::sync::OnceLock::new();
    let d = dir("SEANCE_LINUX_NOBLE_MEM")?;
    Some(ONCE.get_or_init(|| profile_in(&d)))
}

fn hooks_for(profile: &LinuxProfile) -> (hooks::HooksSurvey, lsmod::ModuleList) {
    let mod_layout = lsmod::bind(profile).expect("the module layout binds");
    let modules = lsmod::list_modules(profile, &mod_layout, &lsmod::ModuleListConfig::default())
        .expect("the module list walks");
    let layout = hooks::bind(profile).expect("the hooks layout binds");
    let survey = hooks::survey_hooks(profile, &layout, Some(&modules)).expect("the checks run");
    (survey, modules)
}

/// What each capture is known to hold. The syscall count is independent of
/// this code: it is the kernel's `__NR_syscalls` for the release, from
/// `arch/x86/include/generated/uapi/asm/unistd_64.h` (449 on 5.15, whose last
/// call is 448 `process_mrelease`; 462 on 6.8, whose last is 461
/// `lsm_list_modules`). The padding, the program count and the program names
/// were read from the captures by this stage on its first run and are pinned
/// here as known answers so a later change that drops an entry, a program or
/// a name fails — they are regression pins, not facts established outside
/// this code; no `bpftool` listing was taken on the guests before acquisition.
struct Known {
    kernel: &'static str,
    /// The kernel's `__NR_syscalls`.
    syscalls: u64,
    /// Alignment padding after the table, before the next symbol.
    trailing_nulls: u64,
    /// Programs loaded at acquisition.
    programs: usize,
    /// Names that must be among them; empty where the loader gave none.
    program_names: &'static [&'static str],
}

const KNOWN_5_15: Known = Known {
    kernel: "5.15",
    syscalls: 449,
    trailing_nulls: 3,
    programs: 12,
    program_names: &[],
};

const KNOWN_6_8: Known = Known {
    kernel: "6.8",
    syscalls: 462,
    trailing_nulls: 2,
    programs: 13,
    program_names: &[
        "sd_devices",
        "sd_fw_egress",
        "sd_fw_ingress",
        "hid_tail_call",
    ],
};

fn assert_clean_and_complete(survey: &hooks::HooksSurvey, known: &Known) {
    let kernel = known.kernel;
    let json = survey.to_json();
    eprintln!(
        "{kernel}: not_checked = {}",
        serde_json::to_string_pretty(&json["not_checked"]).unwrap()
    );

    // System-call table.
    let table = survey
        .syscalls
        .tables
        .iter()
        .find(|t| t.symbol == "sys_call_table")
        .expect("sys_call_table was checked");
    eprintln!(
        "{kernel}: sys_call_table {} entries ({}), {} at kernel symbols, {} trailing nulls, \
         notable {:?}",
        table.entry_count,
        table.entry_count_source,
        table.kernel_symbol_count,
        table.trailing_null_count,
        table
            .notable
            .iter()
            .map(|e| (e.index, e.verdict_str()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        table.kernel_symbol_count, known.syscalls,
        "{kernel}'s __NR_syscalls is {}; {} entries resolved to kernel symbols",
        known.syscalls, table.kernel_symbol_count
    );
    assert_eq!(
        table.trailing_null_count, known.trailing_nulls,
        "{kernel}'s table is followed by {} alignment nulls before the next symbol",
        known.trailing_nulls
    );
    assert_eq!(
        table.entry_count,
        known.syscalls + known.trailing_nulls,
        "the next-symbol bound sizes the table as the syscalls plus the padding"
    );
    assert_eq!(
        survey.syscalls.candidate_count(),
        0,
        "a stock guest has no hooked system call: {:?}",
        table.notable
    );
    assert_eq!(table.unreadable_count, 0);
    assert!(
        survey.syscalls.switch_dispatch,
        "both lab kernels carry the BHI-era x64_sys_call switch, and the survey must say so"
    );

    // ftrace.
    assert!(survey.ftrace.list_complete, "{}", survey.ftrace.list_stop);
    eprintln!(
        "{kernel}: {} ftrace_ops, direct calls read {} (count {:?})",
        survey.ftrace.ops.len(),
        survey.ftrace.direct_calls_read,
        survey.ftrace.direct_calls_count
    );
    for ops in &survey.ftrace.ops {
        assert_eq!(
            ops.verdict,
            OpsVerdict::KernelCallback,
            "ftrace_ops at {:#x}: {:?}",
            ops.address,
            ops.func_attribution
        );
    }
    assert!(survey.ftrace.direct_calls_read);
    assert_eq!(survey.ftrace.candidate_count(), 0);

    // kprobes.
    assert!(survey.kprobes.table_read);
    assert_eq!(survey.kprobes.unreadable_buckets, 0);
    assert_eq!(survey.kprobes.candidate_count(), 0);

    // eBPF: systemd's cgroup programs are there, and the registry agrees with
    // each program's own record of its id.
    assert!(survey.ebpf.registry_read);
    assert!(survey.ebpf.registry_complete);
    let programs = &survey.ebpf.programs;
    eprintln!(
        "{kernel}: {} eBPF programs: {:?}",
        programs.len(),
        programs
            .iter()
            .map(|p| (p.registry_id, p.prog_type_name.clone(), p.name.clone()))
            .collect::<Vec<_>>()
    );
    assert_eq!(
        programs.len(),
        known.programs,
        "{kernel} was acquired with {} programs loaded",
        known.programs
    );
    for name in known.program_names {
        assert!(
            programs.iter().any(|p| p.name.as_deref() == Some(name)),
            "{kernel}: no program named {name} among {:?}",
            programs.iter().map(|p| p.name.clone()).collect::<Vec<_>>()
        );
    }
    for program in programs {
        assert_eq!(
            program.id,
            Some(program.registry_id),
            "program at {:#x}: aux->id disagrees with its registry index",
            program.address
        );
        assert!(
            program.prog_type_name.is_some(),
            "program {} has an undecoded type {:?}",
            program.registry_id,
            program.prog_type
        );
    }
    assert!(
        programs.iter().any(|p| {
            p.prog_type_name
                .as_deref()
                .is_some_and(|t| t.starts_with("BPF_PROG_TYPE_CGROUP_"))
        }),
        "no cgroup-type program among systemd's"
    );
    assert_eq!(survey.ebpf.unexplained_direct_calls(), 0);

    assert!(
        survey.is_complete(),
        "the checks did not all run to the end: {:?}",
        survey.not_checked()
    );
}

#[test]
fn a_stock_5_15_guest_has_no_candidate_hook_and_every_check_runs() {
    let Some(profile) = profiled_515() else {
        eprintln!("skipping: set SEANCE_LINUX_SWAP_MEM to the 5.15 capture dir");
        return;
    };
    let (survey, modules) = hooks_for(profile);
    assert!(
        !modules.modules.is_empty(),
        "a booted guest has modules loaded"
    );
    // The code map attributed every listed module: on 5.15 the extent is
    // core_layout, which the module stage reads.
    assert_eq!(
        survey.code_map["modules_without_extent"]
            .as_array()
            .map(Vec::len),
        Some(0),
        "{}",
        survey.code_map
    );
    assert_clean_and_complete(&survey, &KNOWN_5_15);
}

#[test]
fn a_stock_6_8_guest_has_no_candidate_hook_and_module_text_extents_are_decoded_from_mem() {
    let Some(profile) = profiled_68() else {
        eprintln!("skipping: set SEANCE_LINUX_NOBLE_MEM to the 6.8 capture dir");
        return;
    };
    let (survey, modules) = hooks_for(profile);
    assert!(!modules.modules.is_empty());
    // 6.8 keeps a module's extent in mem[]; the module stage decodes it and
    // the code map reuses its MOD_TEXT region.
    let without = survey.code_map["modules_without_extent"]
        .as_array()
        .map(Vec::len)
        .unwrap_or(usize::MAX);
    assert_eq!(
        without, 0,
        "module extents were not decoded from mem[]: {}",
        survey.code_map
    );
    assert_eq!(
        survey.code_map["module_count_with_extent"].as_u64(),
        Some(modules.modules.len() as u64)
    );

    // The MOD_TEXT index is pinned by geometry: a `struct module` lives in its
    // module's data, so no module's own address may fall inside the extent the
    // map calls its text. A wrong index (data read as text) would put every
    // one of them inside.
    let layout = hooks::bind(profile).expect("binds");
    let reader = seance_plugin_memory_linux::tasks::reader_for(profile);
    let map = hooks::regions::CodeMap::build(&reader, &layout, Some(&modules));
    for module in &modules.modules {
        let inside = map
            .modules
            .iter()
            .any(|r| module.address >= r.base && module.address < r.base + r.size);
        assert!(
            !inside,
            "the struct module of {:?} lies inside what the map calls its text extent, so \
             mem[MOD_TEXT] was read at the wrong index",
            module.name
        );
    }
    // Since MEM-042 the image-derived table carries `mod_mem_type`, the module
    // stage decodes mem[] through it, and the map uses that MOD_TEXT region:
    // no index is assumed, so no assumption is stated.
    assert!(
        map.modules
            .iter()
            .all(|r| r.source == hooks::regions::MEM_TEXT_SOURCE),
        "{:?}",
        map.modules.first()
    );
    assert!(
        map.notes.is_empty(),
        "the MOD_TEXT index came from the image's own mod_mem_type, so no assumed index \
         may be stated: {:?}",
        map.notes
    );
    // bpf_prog.type is named from the image's own bpf_prog_type now, not from
    // the labelled UAPI fallback.
    assert!(
        survey
            .ebpf
            .programs
            .iter()
            .all(|p| p.prog_type_source == "symbol_table"),
        "{:?}",
        survey
            .ebpf
            .programs
            .iter()
            .map(|p| p.prog_type_source)
            .collect::<Vec<_>>()
    );

    assert_clean_and_complete(&survey, &KNOWN_6_8);
}
