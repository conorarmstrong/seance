//! Kernel hook detection: the system-call table, `ftrace`, kprobes and eBPF,
//! each a cross-view between what the kernel's own registration structures
//! say and where the code they point at actually lives.
//!
//! The task-list and module-list stages already corroborate their walks against
//! an independent physical sweep, which catches a structure unlinked from its
//! list. That is the *hiding* half of a rootkit. This stage is the *hooking*
//! half: the places a kernel is made to run someone else's code without any
//! list being unlinked.
//!
//! ## Four checks, four pairs of sources
//!
//! Every check names its two sources and reports a verdict per row, and every
//! check reports what it could **not** examine — a symbol the table lacks, a
//! member this build does not declare, a structure whose bytes were not
//! acquired — under `not_checked`, never as "no hooks found".
//!
//! | Check | Source A (what the kernel will run) | Source B (where code is allowed to be) |
//! |---|---|---|
//! | [`syscalls`] | each entry of `sys_call_table` (and the ia32/x32 tables) | the kernel's text bounds and symbols; the module list's code extents |
//! | [`ftrace`] | each `ftrace_ops` on `ftrace_ops_list`: its callback, its filter hash, its trampoline; the `direct_functions` hash | as above |
//! | [`kprobes`] | each `kprobe` in `kprobe_table`: the probed address and its handlers | as above |
//! | [`ebpf`] | each `bpf_prog` in `prog_idr`: type, name, attach target | the tracing/kprobe attach points the other two checks saw |
//!
//! The attribution both halves rest on is [`regions::CodeMap`], and its
//! limitations (a module with no readable extent, kernel text bounds missing)
//! are published on the survey, because every "unknown" verdict below is read
//! against them.
//!
//! ## What a verdict is, and is not
//!
//! A callback attributed to a module is a **finding with an owner**: named,
//! and left to the examiner, because `kprobe` handlers and `ftrace` callbacks
//! installed by legitimate modules (`systemd`'s BPF, tracing tools, live
//! patches) look exactly like a rootkit's. A callback attributed to nothing —
//! outside the kernel's text and every listed module's extent — is the shape
//! of a hook installed by hand or by a module that has hidden itself, and is
//! reported as a candidate, qualified by the map's limitations. Nothing here
//! is reported as "malicious".

pub mod ebpf;
pub mod ftrace;
pub mod kprobes;
pub mod regions;
pub mod syscalls;
pub mod xarray;

#[cfg(test)]
mod tests;

use seance_memory::binding::{BuildBinding, MemberSet, MemberSpec, TypeSpec};
use seance_memory::object::StructReader;

use crate::error::StageError;
use crate::lsmod::ModuleList;
use crate::module::STAGE_LINUX_KERNEL_HOOKS;
use crate::profile::LinuxProfile;

/// Everything the hook stage reads out of the symbol table. Nothing is
/// required: each check runs when its own members are declared and reports
/// itself not checked, by name, when they are not.
pub const HOOKS_LAYOUT: MemberSet = MemberSet::new(
    STAGE_LINUX_KERNEL_HOOKS,
    &[
        TypeSpec::new("ftrace_ops", &["ftrace_ops"]),
        TypeSpec::new("ftrace_ops_hash", &["ftrace_ops_hash"]),
        TypeSpec::new("ftrace_hash", &["ftrace_hash"]),
        TypeSpec::new("ftrace_func_entry", &["ftrace_func_entry"]),
        TypeSpec::new("hlist_head", &["hlist_head"]),
        TypeSpec::new("hlist_node", &["hlist_node"]),
        TypeSpec::new("kprobe", &["kprobe"]),
        TypeSpec::new("bpf_prog", &["bpf_prog"]),
        TypeSpec::new("bpf_prog_aux", &["bpf_prog_aux"]),
        TypeSpec::new("idr", &["idr"]),
        TypeSpec::new("xa_node", &["xa_node"]),
        TypeSpec::new("module", &["module"]),
    ],
    &[
        // ftrace
        MemberSpec::new("ops_func", &["ftrace_ops"], &["func"]),
        MemberSpec::new("ops_next", &["ftrace_ops"], &["next"]),
        MemberSpec::new("ops_flags", &["ftrace_ops"], &["flags"]),
        MemberSpec::new("ops_func_hash", &["ftrace_ops"], &["func_hash"]),
        MemberSpec::new("ops_trampoline", &["ftrace_ops"], &["trampoline"]),
        // From 3.16 the hashes hang off `func_hash`; before, off the ops itself.
        MemberSpec::new(
            "hash_filter",
            &["ftrace_ops_hash", "ftrace_ops"],
            &["filter_hash"],
        ),
        MemberSpec::new(
            "hash_notrace",
            &["ftrace_ops_hash", "ftrace_ops"],
            &["notrace_hash"],
        ),
        MemberSpec::new("fhash_size_bits", &["ftrace_hash"], &["size_bits"]),
        MemberSpec::new("fhash_buckets", &["ftrace_hash"], &["buckets"]),
        MemberSpec::new("fhash_count", &["ftrace_hash"], &["count"]),
        MemberSpec::new("fentry_hlist", &["ftrace_func_entry"], &["hlist"]),
        MemberSpec::new("fentry_ip", &["ftrace_func_entry"], &["ip"]),
        MemberSpec::new("fentry_direct", &["ftrace_func_entry"], &["direct"]),
        MemberSpec::new("hlist_first", &["hlist_head"], &["first"]),
        MemberSpec::new("hlist_next", &["hlist_node"], &["next"]),
        // kprobes
        MemberSpec::new("kp_hlist", &["kprobe"], &["hlist"]),
        MemberSpec::new("kp_addr", &["kprobe"], &["addr"]),
        MemberSpec::new("kp_pre_handler", &["kprobe"], &["pre_handler"]),
        MemberSpec::new("kp_post_handler", &["kprobe"], &["post_handler"]),
        MemberSpec::new("kp_symbol_name", &["kprobe"], &["symbol_name"]),
        MemberSpec::new("kp_offset", &["kprobe"], &["offset"]),
        MemberSpec::new("kp_flags", &["kprobe"], &["flags"]),
        // eBPF
        MemberSpec::new("idr_rt", &["idr"], &["idr_rt"]),
        MemberSpec::new("idr_base", &["idr"], &["idr_base"]),
        MemberSpec::new("xa_head", &["xarray", "radix_tree_root"], &["xa_head"]),
        MemberSpec::new("xa_shift", &["xa_node"], &["shift"]),
        MemberSpec::new("xa_slots", &["xa_node"], &["slots"]),
        MemberSpec::new("prog_type", &["bpf_prog"], &["type"]),
        MemberSpec::new("prog_aux", &["bpf_prog"], &["aux"]),
        MemberSpec::new("prog_bpf_func", &["bpf_prog"], &["bpf_func"]),
        MemberSpec::new("prog_jited_len", &["bpf_prog"], &["jited_len"]),
        MemberSpec::new("prog_len", &["bpf_prog"], &["len"]),
        MemberSpec::new("prog_tag", &["bpf_prog"], &["tag"]),
        MemberSpec::new("aux_id", &["bpf_prog_aux"], &["id"]),
        MemberSpec::new("aux_name", &["bpf_prog_aux"], &["name"]),
        MemberSpec::new(
            "aux_attach_func_name",
            &["bpf_prog_aux"],
            &["attach_func_name"],
        ),
        MemberSpec::new("aux_load_time", &["bpf_prog_aux"], &["load_time"]),
        // 6.4+ module extents, for attribution.
        MemberSpec::new("module_mem", &["module"], &["mem"]),
    ],
);

/// The stage's whole result: four checks and the map they were made against.
#[derive(Debug, Clone)]
pub struct HooksSurvey {
    /// The system-call tables.
    pub syscalls: syscalls::SyscallCheck,
    /// The ftrace registrations and direct calls.
    pub ftrace: ftrace::FtraceCheck,
    /// The registered kprobes.
    pub kprobes: kprobes::KprobeCheck,
    /// The loaded eBPF programs.
    pub ebpf: ebpf::EbpfCheck,
    /// The attribution map's own account of itself.
    pub code_map: serde_json::Value,
    /// What this kernel build provided for the stage.
    pub layout: serde_json::Value,
}

impl HooksSurvey {
    /// Whether every check ran to its end with nothing unreadable. A check
    /// that could not run at all is a gap, not a clean result.
    pub fn is_complete(&self) -> bool {
        self.syscalls.is_complete()
            && self.ftrace.is_complete()
            && self.kprobes.is_complete()
            && self.ebpf.is_complete()
    }

    /// Rows across every check whose verdict is a candidate hook.
    pub fn candidate_count(&self) -> usize {
        self.syscalls.candidate_count()
            + self.ftrace.candidate_count()
            + self.kprobes.candidate_count()
    }

    /// Everything that could not be examined, gathered from every check.
    pub fn not_checked(&self) -> Vec<String> {
        let mut out = Vec::new();
        out.extend(self.syscalls.not_checked.iter().cloned());
        out.extend(self.ftrace.not_checked.iter().cloned());
        out.extend(self.kprobes.not_checked.iter().cloned());
        out.extend(self.ebpf.not_checked.iter().cloned());
        out
    }

    /// Serializable form for the hooks artifact.
    pub fn to_json(&self) -> serde_json::Value {
        let not_checked = self.not_checked();
        serde_json::json!({
            "complete": self.is_complete(),
            "candidate_hook_count": self.candidate_count(),
            "not_checked": not_checked,
            "verdict_note": VERDICT_NOTE,
            "syscall_tables": self.syscalls.to_json(),
            "ftrace": self.ftrace.to_json(),
            "kprobes": self.kprobes.to_json(),
            "ebpf": self.ebpf.to_json(),
            "code_map": self.code_map,
            "layout": self.layout,
            "incomplete": self.incomplete(),
        })
    }

    fn incomplete(&self) -> Vec<serde_json::Value> {
        self.not_checked()
            .into_iter()
            .map(|detail| {
                seance_memory::meta::Incomplete::new(
                    seance_core::io::IncompleteReason::ShortRead,
                    detail,
                )
                .to_json()
            })
            .collect()
    }
}

/// The sentence every verdict is read under.
pub const VERDICT_NOTE: &str =
    "A row attributed to a loaded module names that module and is left to the examiner: the \
     hooks a tracing tool, a live patch or systemd's BPF install look exactly like a rootkit's. \
     A row attributed to nothing — outside the kernel's text and every listed module's code \
     extent — is a candidate hook, and only as strong as the code map's limitations allow. \
     Nothing here is a statement that the machine was clean: a check that could not run is \
     listed under not_checked, and an unlisted module's code reads as unknown, not as absent.";

/// Bind the hook stage's declared layout to this kernel build.
pub fn bind(profile: &LinuxProfile) -> Result<BuildBinding, StageError> {
    let reader = crate::tasks::reader_for(profile);
    Ok(HOOKS_LAYOUT.bind(&reader)?)
}

/// Run every check.
///
/// `modules` is the module list the module stage walked, or `None` when it did
/// not; without it no address can be attributed to a module, which the survey
/// states.
pub fn survey_hooks(
    profile: &LinuxProfile,
    layout: &BuildBinding,
    modules: Option<&ModuleList>,
) -> Result<HooksSurvey, StageError> {
    let reader = crate::tasks::reader_for(profile);
    survey_with_reader(&reader, layout, modules)
}

/// The checks over a reader the caller supplies, so a synthetic image can drive
/// them in a test.
pub fn survey_with_reader(
    reader: &StructReader,
    layout: &BuildBinding,
    modules: Option<&ModuleList>,
) -> Result<HooksSurvey, StageError> {
    let map = regions::CodeMap::build(reader, layout, modules);
    let syscalls = syscalls::check(reader, &map);
    let ftrace = ftrace::check(reader, layout, &map)?;
    let kprobes = kprobes::check(reader, layout, &map)?;
    let ebpf = ebpf::check(reader, layout, &ftrace, &kprobes)?;
    Ok(HooksSurvey {
        syscalls,
        ftrace,
        kprobes,
        ebpf,
        code_map: map.to_json(),
        layout: layout.to_json(),
    })
}
