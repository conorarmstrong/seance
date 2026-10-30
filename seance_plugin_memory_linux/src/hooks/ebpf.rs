//! Loaded eBPF programs, and what the tracing hooks the other checks saw are
//! accounted for by them.
//!
//! Source A is `prog_idr`, the kernel's registry of every loaded `bpf_prog`,
//! walked as the `xarray` it has been since Linux 4.20 ([`super::xarray`]);
//! the 4.11–4.19 radix tree and the layered IDR before it are refused by name.
//! Each program yields its id, name, type, tag, instruction and JIT lengths,
//! the address of its JIT image, and — for the tracing types — the kernel
//! function it attaches to (`aux->attach_func_name`).
//!
//! Source B is the ftrace check's direct-call table. A `fentry`/`fexit`/
//! `fmod_ret` program reaches its function through a BPF trampoline that the
//! kernel installs as a *direct call*, so every direct call whose target is a
//! trampoline should be explained by a listed program naming that function.
//! A direct call no listed program explains is a candidate: either a program
//! hidden from the registry, or a direct caller that is not BPF at all — the
//! row says which module, if any, owns the target.
//!
//! ## What is not claimed
//!
//! A `KPROBE`-type program attaches through a `perf_event`, and this check does
//! not walk perf events; it reports how many such programs are loaded beside
//! how many kprobes the kprobe check found with the perf dispatcher as their
//! handler, and says the two need not match one to one. The JIT image of a
//! program lives in executable memory the code map cannot attribute — that is
//! what a JIT image is — so a program's `bpf_func` outside known code is the
//! expected case, labelled `jit_image`, not a candidate.

use std::collections::BTreeMap;

use seance_memory::binding::BuildBinding;
use seance_memory::object::{Obj, StructReader};

use super::ftrace::FtraceCheck;
use super::kprobes::KprobeCheck;
use super::regions::Attribution;
use super::xarray;
use crate::error::StageError;
use crate::read::{decode_nul_terminated, read_c_string, MAX_C_STRING};

/// The registry symbol.
pub const PROG_IDR_SYMBOL: &str = "prog_idr";
/// The kernel's own kprobe-to-perf dispatcher.
pub const KPROBE_PERF_DISPATCHER: &str = "kprobe_dispatcher";
/// Most programs one walk reports.
pub const MAX_PROGRAMS: usize = 65_536;

/// `enum bpf_prog_type`, from `include/uapi/linux/bpf.h`. A UAPI enumeration:
/// values are never renumbered, only appended. Used only when the symbol table
/// carries no `bpf_prog_type` of its own (an image-derived table carries the
/// kernel's, from its BTF, so this is the fallback for an ISF without it).
pub const PROG_TYPES_UAPI: [&str; 33] = [
    "BPF_PROG_TYPE_UNSPEC",
    "BPF_PROG_TYPE_SOCKET_FILTER",
    "BPF_PROG_TYPE_KPROBE",
    "BPF_PROG_TYPE_SCHED_CLS",
    "BPF_PROG_TYPE_SCHED_ACT",
    "BPF_PROG_TYPE_TRACEPOINT",
    "BPF_PROG_TYPE_XDP",
    "BPF_PROG_TYPE_PERF_EVENT",
    "BPF_PROG_TYPE_CGROUP_SKB",
    "BPF_PROG_TYPE_CGROUP_SOCK",
    "BPF_PROG_TYPE_LWT_IN",
    "BPF_PROG_TYPE_LWT_OUT",
    "BPF_PROG_TYPE_LWT_XMIT",
    "BPF_PROG_TYPE_SOCK_OPS",
    "BPF_PROG_TYPE_SK_SKB",
    "BPF_PROG_TYPE_CGROUP_DEVICE",
    "BPF_PROG_TYPE_SK_MSG",
    "BPF_PROG_TYPE_RAW_TRACEPOINT",
    "BPF_PROG_TYPE_CGROUP_SOCK_ADDR",
    "BPF_PROG_TYPE_LWT_SEG6LOCAL",
    "BPF_PROG_TYPE_LIRC_MODE2",
    "BPF_PROG_TYPE_SK_REUSEPORT",
    "BPF_PROG_TYPE_FLOW_DISSECTOR",
    "BPF_PROG_TYPE_CGROUP_SYSCTL",
    "BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE",
    "BPF_PROG_TYPE_CGROUP_SOCKOPT",
    "BPF_PROG_TYPE_TRACING",
    "BPF_PROG_TYPE_STRUCT_OPS",
    "BPF_PROG_TYPE_EXT",
    "BPF_PROG_TYPE_LSM",
    "BPF_PROG_TYPE_SK_LOOKUP",
    "BPF_PROG_TYPE_SYSCALL",
    "BPF_PROG_TYPE_NETFILTER",
];
const PROG_TYPE_KPROBE: u64 = 2;

/// The name a program type resolves to, and where the name came from.
pub fn prog_type_name(
    symbols: &seance_symbols::SymbolTable,
    raw: u64,
) -> (Option<String>, &'static str) {
    if let Ok(Some(name)) = symbols.enum_constant_name("bpf_prog_type", i128::from(raw)) {
        return (Some(name.to_string()), "symbol_table");
    }
    match usize::try_from(raw)
        .ok()
        .and_then(|i| PROG_TYPES_UAPI.get(i))
    {
        Some(name) => (Some((*name).to_string()), "uapi_header"),
        None => (None, "unknown"),
    }
}

/// One loaded program.
#[derive(Debug, Clone)]
pub struct BpfProgram {
    pub address: u64,
    /// The index the registry holds it at, plus `idr_base`.
    pub registry_id: u64,
    /// `aux->id`, which should equal the registry id.
    pub id: Option<u64>,
    pub name: Option<String>,
    pub prog_type: Option<u64>,
    pub prog_type_name: Option<String>,
    pub prog_type_source: &'static str,
    pub tag: Option<String>,
    pub len: Option<u64>,
    pub jited_len: Option<u64>,
    pub bpf_func: Option<u64>,
    pub bpf_func_class: &'static str,
    pub attach_func_name: Option<String>,
    pub load_time: Option<u64>,
    pub notes: Vec<String>,
}

impl BpfProgram {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address_hex": format!("{:#x}", self.address),
            "registry_id": self.registry_id,
            "id": self.id,
            "name": self.name,
            "type": self.prog_type,
            "type_name": self.prog_type_name,
            "type_name_source": self.prog_type_source,
            "tag": self.tag,
            "len": self.len,
            "jited_len": self.jited_len,
            "bpf_func_hex": self.bpf_func.map(|f| format!("{f:#x}")),
            "bpf_func_class": self.bpf_func_class,
            "attach_func_name": self.attach_func_name,
            "load_time_ns_since_boot": self.load_time,
            "notes": self.notes,
        })
    }
}

/// One direct call read against the program list.
#[derive(Debug, Clone)]
pub struct DirectCallExplanation {
    pub ip: u64,
    pub function: Option<String>,
    pub target: u64,
    pub target_attribution: Attribution,
    /// Registry ids of the programs that name this function as their attach
    /// target.
    pub explained_by: Vec<u64>,
    pub verdict: &'static str,
}

impl DirectCallExplanation {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ip_hex": format!("{:#x}", self.ip),
            "function": self.function,
            "target_hex": format!("{:#x}", self.target),
            "target": self.target_attribution.to_json(),
            "explained_by_program_ids": self.explained_by,
            "verdict": self.verdict,
        })
    }
}

/// The check's whole result.
#[derive(Debug, Clone)]
pub struct EbpfCheck {
    pub programs: Vec<BpfProgram>,
    pub registry_read: bool,
    pub registry_complete: bool,
    pub direct_calls: Vec<DirectCallExplanation>,
    pub kprobe_programs: usize,
    pub perf_dispatched_kprobes: usize,
    pub not_checked: Vec<String>,
}

impl EbpfCheck {
    pub fn is_complete(&self) -> bool {
        self.registry_read && self.registry_complete && self.not_checked.is_empty()
    }

    /// Direct calls no listed program accounts for.
    pub fn unexplained_direct_calls(&self) -> usize {
        self.direct_calls
            .iter()
            .filter(|d| d.verdict == "unexplained")
            .count()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sources": [
                "prog_idr: every loaded bpf_prog — id, name, type, tag, sizes, JIT image, attach target",
                "the ftrace check's direct_functions table: every function whose entry jumps to a direct target",
                "the kprobe check: probes whose handler is the kernel's perf dispatcher",
            ],
            "registry_read": self.registry_read,
            "registry_complete": self.registry_complete,
            "program_count": self.programs.len(),
            "programs": self.programs.iter().map(BpfProgram::to_json).collect::<Vec<_>>(),
            "direct_calls": self.direct_calls.iter().map(DirectCallExplanation::to_json).collect::<Vec<_>>(),
            "unexplained_direct_call_count": self.unexplained_direct_calls(),
            "kprobe_program_count": self.kprobe_programs,
            "perf_dispatched_kprobe_count": self.perf_dispatched_kprobes,
            "kprobe_note": "a KPROBE-type program attaches through a perf_event this check does not \
                            walk; one program may sit behind several probes and a perf probe may \
                            carry no program, so these two counts need not match",
            "not_checked": self.not_checked,
        })
    }
}

/// Walk the registry and read the other checks against it.
pub fn check(
    reader: &StructReader,
    layout: &BuildBinding,
    ftrace: &FtraceCheck,
    kprobes: &KprobeCheck,
) -> Result<EbpfCheck, StageError> {
    let symbols = reader.symbols();
    let mut not_checked = Vec::new();
    let mut programs = Vec::new();
    let mut registry_read = false;
    let mut registry_complete = false;

    let perf_dispatched_kprobes = kprobes
        .probes
        .iter()
        .filter(|p| {
            matches!(&p.pre_handler_attribution, Some(Attribution::KernelText { symbol, offset: 0 })
                if symbol == KPROBE_PERF_DISPATCHER)
        })
        .count();

    match symbols.symbol_address(PROG_IDR_SYMBOL) {
        Err(_) => not_checked.push(format!(
            "eBPF programs were not checked: the symbol table has no {PROG_IDR_SYMBOL} (the \
             registry arrived in Linux 4.13; a sparse symbol file may also omit it)"
        )),
        Ok(idr_address) => match (
            layout.member("idr_rt")?.offset(),
            layout.member("xa_head")?.offset(),
        ) {
            (None, _) => not_checked.push(
                "eBPF programs were not checked: this build's idr has no idr_rt, the pre-4.11 \
                 layered IDR this stage does not walk"
                    .to_string(),
            ),
            (_, None) => not_checked.push(
                "eBPF programs were not checked: this build's idr_rt has no xa_head, the \
                 pre-4.20 radix tree this stage does not walk"
                    .to_string(),
            ),
            (Some(rt_offset), Some(head_offset)) => {
                let idr_base = match layout.member("idr_base")?.member() {
                    Some(member) => reader
                        .object(
                            idr_address,
                            layout.member("idr_base")?.type_name().unwrap_or("idr"),
                        )
                        .and_then(|idr| idr.unsigned(member))
                        .unwrap_or(0),
                    None => 0,
                };
                let head_address = idr_address
                    .wrapping_add(rt_offset)
                    .wrapping_add(head_offset);
                match xarray::walk(reader, layout, head_address) {
                    Err(reason) => {
                        not_checked.push(format!("eBPF programs were not checked: {reason}"))
                    }
                    Ok(walk) => {
                        registry_read = true;
                        registry_complete = walk.is_complete();
                        if !walk.unreadable_nodes.is_empty() {
                            not_checked.push(format!(
                                "{} node(s) of the eBPF registry could not be read, so the \
                                 program list is a floor",
                                walk.unreadable_nodes.len()
                            ));
                        }
                        if walk.capped {
                            not_checked.push(
                                "the eBPF registry walk hit its bound, so the program list is a \
                                 floor"
                                    .to_string(),
                            );
                        }
                        for (index, address) in walk.entries.into_iter().take(MAX_PROGRAMS) {
                            programs.push(read_program(
                                reader,
                                layout,
                                address,
                                index.wrapping_add(idr_base),
                            )?);
                        }
                    }
                }
            }
        },
    }

    // Direct calls against the attach targets the listed programs name.
    let mut by_target: BTreeMap<&str, Vec<u64>> = BTreeMap::new();
    for program in &programs {
        if let Some(target) = &program.attach_func_name {
            by_target
                .entry(target.as_str())
                .or_default()
                .push(program.registry_id);
        }
    }
    let direct_calls = ftrace
        .direct_calls
        .iter()
        .map(|call| {
            let function = match &call.ip_attribution {
                Attribution::KernelText { symbol, .. }
                | Attribution::NearestSymbolOnly { symbol, .. } => Some(symbol.clone()),
                _ => None,
            };
            let explained_by = function
                .as_deref()
                .and_then(|f| by_target.get(f))
                .cloned()
                .unwrap_or_default();
            let verdict = if !explained_by.is_empty() {
                "explained_by_bpf_program"
            } else if matches!(call.target_attribution, Attribution::Module { .. }) {
                "module_direct_call"
            } else if !registry_read {
                "unexplained_registry_not_read"
            } else {
                "unexplained"
            };
            DirectCallExplanation {
                ip: call.ip,
                function,
                target: call.target,
                target_attribution: call.target_attribution.clone(),
                explained_by,
                verdict,
            }
        })
        .collect();

    let kprobe_programs = programs
        .iter()
        .filter(|p| p.prog_type == Some(PROG_TYPE_KPROBE))
        .count();

    Ok(EbpfCheck {
        programs,
        registry_read,
        registry_complete,
        direct_calls,
        kprobe_programs,
        perf_dispatched_kprobes,
        not_checked,
    })
}

fn read_program(
    reader: &StructReader,
    layout: &BuildBinding,
    address: u64,
    registry_id: u64,
) -> Result<BpfProgram, StageError> {
    let symbols = reader.symbols();
    let mut notes = Vec::new();
    let Some(prog_struct) = layout.type_of("bpf_prog")?.type_name() else {
        return Ok(BpfProgram {
            address,
            registry_id,
            id: None,
            name: None,
            prog_type: None,
            prog_type_name: None,
            prog_type_source: "unknown",
            tag: None,
            len: None,
            jited_len: None,
            bpf_func: None,
            bpf_func_class: "not_read",
            attach_func_name: None,
            load_time: None,
            notes: vec!["this build declares no bpf_prog type, so the program was not read".into()],
        });
    };
    let prog = match reader.object(address, prog_struct) {
        Ok(prog) => prog,
        Err(err) => {
            return Ok(BpfProgram {
                address,
                registry_id,
                id: None,
                name: None,
                prog_type: None,
                prog_type_name: None,
                prog_type_source: "unknown",
                tag: None,
                len: None,
                jited_len: None,
                bpf_func: None,
                bpf_func_class: "not_read",
                attach_func_name: None,
                load_time: None,
                notes: vec![format!(
                    "the bpf_prog at {address:#x} could not be read: {err}"
                )],
            })
        }
    };

    // `type` is an enumeration; an image-derived table stores it as a plain
    // `int`, a symbol file as the enum, so either signedness is accepted.
    let raw_type = crate::read::read_integer(layout, &prog, "prog_type")?
        .known()
        .copied()
        .and_then(|value| u64::try_from(value).ok());
    let (type_name, type_source) = match raw_type {
        Some(raw) => prog_type_name(symbols, raw),
        None => (None, "unknown"),
    };
    let len = layout.read_unsigned(&prog, "prog_len")?.known().copied();
    let jited_len = layout
        .read_unsigned(&prog, "prog_jited_len")?
        .known()
        .copied();
    let bpf_func = layout
        .read_pointer(&prog, "prog_bpf_func")?
        .known()
        .copied();
    let bpf_func_class = match (bpf_func, jited_len) {
        (None, _) => "not_read",
        (Some(0), _) => "null",
        (Some(_), Some(0)) => "interpreter_or_unjited",
        (Some(_), _) => "jit_image",
    };
    let tag = match layout.member("prog_tag")?.member() {
        Some(member) => prog
            .bytes(member)
            .ok()
            .map(|bytes| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()),
        None => None,
    };

    let (id, name, attach_func_name, load_time) = match layout.member("prog_aux")?.member() {
        Some(member) => match prog.follow(member) {
            Ok(Some(aux)) => read_aux(reader, layout, &aux)?,
            Ok(None) => {
                notes.push("the program has no aux structure".into());
                (None, None, None, None)
            }
            Err(err) => {
                notes.push(format!(
                    "the program's aux structure could not be read: {err}"
                ));
                (None, None, None, None)
            }
        },
        None => (None, None, None, None),
    };
    if let Some(id) = id {
        if id != registry_id {
            notes.push(format!(
                "the program records id {id} but the registry holds it at {registry_id}"
            ));
        }
    }

    Ok(BpfProgram {
        address,
        registry_id,
        id,
        name,
        prog_type: raw_type,
        prog_type_name: type_name,
        prog_type_source: type_source,
        tag,
        len,
        jited_len,
        bpf_func,
        bpf_func_class,
        attach_func_name,
        load_time,
        notes,
    })
}

type AuxFields = (Option<u64>, Option<String>, Option<String>, Option<u64>);

fn read_aux(
    reader: &StructReader,
    layout: &BuildBinding,
    aux: &Obj,
) -> Result<AuxFields, StageError> {
    let id = layout.read_unsigned(aux, "aux_id")?.known().copied();
    let name = match layout.member("aux_name")?.member() {
        Some(member) => aux
            .bytes(member)
            .ok()
            .map(|bytes| decode_nul_terminated(&bytes).0)
            .filter(|s| !s.is_empty()),
        None => None,
    };
    let attach_func_name = match layout.member("aux_attach_func_name")?.member() {
        Some(member) => match aux.pointer(member) {
            Ok(0) | Err(_) => None,
            Ok(pointer) => read_c_string(&**reader.native_layer(), pointer, MAX_C_STRING)
                .ok()
                .map(|(text, _)| text),
        },
        None => None,
    };
    let load_time = layout.read_unsigned(aux, "aux_load_time")?.known().copied();
    Ok((id, name, attach_func_name, load_time))
}
