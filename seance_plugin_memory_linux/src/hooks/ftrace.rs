//! `ftrace` registrations: every `ftrace_ops` on the kernel's list, what it
//! runs, what it filters to, and the direct-call table.
//!
//! Source A is `ftrace_ops_list`, the singly linked list of every registered
//! `ftrace_ops`, terminated by `&ftrace_list_end`; each carries the callback
//! (`func`) the traced functions will call, the `filter_hash` of the functions
//! it applies to, its flags, and on x86 the trampoline it was given. Source B is
//! the code map. The `direct_functions` hash (Linux 5.5 onward) is read too:
//! each entry is a kernel function whose `fentry` site has been rewritten to
//! jump straight to an arbitrary address — the mechanism BPF trampolines use,
//! and the one a hook that wants no callback of its own would use.
//!
//! ## What a row means
//!
//! An `ftrace_ops` is a *registration*. Its callback attributed to the kernel
//! is the ordinary case (the function tracer, kprobes' `kprobe_ftrace_ops`,
//! live patching, the BPF direct-call ops). Attributed to a module, it is a
//! module that has asked to run at the entry of kernel functions — named and
//! left to the examiner. Attributed to nothing, it is a candidate hook.
//!
//! The `IPMODIFY` flag is the one that matters most and is called out on the
//! row: an ops with it may change the instruction pointer, which is how a
//! traced function is *replaced* rather than observed.
//!
//! ## What an empty filter means
//!
//! An enabled ops whose filter hash has no entries applies to **every**
//! traceable function. That is reported in words, not as "0 functions hooked".

use std::collections::HashSet;

use seance_memory::binding::BuildBinding;
use seance_memory::object::{Obj, StructReader};

use super::regions::{Attribution, CodeMap};
use crate::error::StageError;

/// The list head and its terminator.
pub const OPS_LIST_SYMBOL: &str = "ftrace_ops_list";
pub const OPS_LIST_END_SYMBOL: &str = "ftrace_list_end";
/// The direct-call hash.
pub const DIRECT_FUNCTIONS_SYMBOL: &str = "direct_functions";

/// More registrations than this is a corrupt list.
pub const MAX_OPS: usize = 4096;
/// The widest hash this walks (`FTRACE_HASH_MAX_BITS` is 12 in the kernel).
pub const MAX_HASH_BITS: u64 = 16;
/// Most entries one hash walk yields.
pub const MAX_HASH_ENTRIES: usize = 262_144;
/// Most filtered functions listed on one row; the count is always published.
pub const MAX_LISTED_FILTERS: usize = 256;

/// `FTRACE_OPS_FL_*`, from `include/linux/ftrace.h` (the 5.x/6.x numbering;
/// the raw word is published beside the decode).
pub const FLAGS: [(u64, &str); 19] = [
    (1 << 0, "ENABLED"),
    (1 << 1, "DYNAMIC"),
    (1 << 2, "SAVE_REGS"),
    (1 << 3, "SAVE_REGS_IF_SUPPORTED"),
    (1 << 4, "RECURSION"),
    (1 << 5, "STUB"),
    (1 << 6, "INITIALIZED"),
    (1 << 7, "DELETED"),
    (1 << 8, "ADDING"),
    (1 << 9, "REMOVING"),
    (1 << 10, "MODIFYING"),
    (1 << 11, "ALLOC_TRAMP"),
    (1 << 12, "IPMODIFY"),
    (1 << 13, "PID"),
    (1 << 14, "RCU"),
    (1 << 15, "TRACE_ARRAY"),
    (1 << 16, "PERMANENT"),
    (1 << 17, "DIRECT"),
    (1 << 18, "SUBOP"),
];
const FL_ENABLED: u64 = 1 << 0;
const FL_IPMODIFY: u64 = 1 << 12;
const FL_DIRECT: u64 = 1 << 17;

/// Decode a flags word to names.
pub fn decode_flags(flags: u64) -> Vec<&'static str> {
    FLAGS
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// One function an ops filters to.
#[derive(Debug, Clone)]
pub struct FilteredFunction {
    pub ip: u64,
    pub attribution: Attribution,
}

impl FilteredFunction {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ip_hex": format!("{:#x}", self.ip),
            "attribution": self.attribution.to_json(),
        })
    }
}

/// A hash of functions, as read.
#[derive(Debug, Clone)]
pub struct FunctionHash {
    /// `ftrace_hash.count`, the kernel's own count.
    pub count: u64,
    /// The entries walked, up to [`MAX_LISTED_FILTERS`] listed.
    pub listed: Vec<FilteredFunction>,
    /// Entries walked but not listed.
    pub unlisted: usize,
    /// Buckets whose chain would not read.
    pub unreadable_buckets: usize,
    /// Whether the walk found as many entries as the count claims.
    pub walked: usize,
}

impl FunctionHash {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "count": self.count,
            "walked": self.walked,
            "listed": self.listed.iter().map(FilteredFunction::to_json).collect::<Vec<_>>(),
            "unlisted": self.unlisted,
            "unreadable_buckets": self.unreadable_buckets,
        })
    }
}

/// What a hash read resolved to.
#[derive(Debug, Clone)]
pub enum HashRead {
    /// The hash was walked.
    Read(FunctionHash),
    /// A null hash pointer: on a live ops, no filter at all.
    Null,
    /// The build declares no such member.
    NotDeclared(&'static str),
    /// The hash or its buckets would not read.
    Unreadable(String),
}

impl HashRead {
    fn to_json(&self) -> serde_json::Value {
        match self {
            HashRead::Read(hash) => hash.to_json(),
            HashRead::Null => serde_json::json!({ "null": true }),
            HashRead::NotDeclared(member) => serde_json::json!({ "not_declared": member }),
            HashRead::Unreadable(detail) => serde_json::json!({ "unavailable": detail }),
        }
    }

    fn is_unreadable(&self) -> bool {
        matches!(self, HashRead::Unreadable(_))
            || matches!(self, HashRead::Read(h) if h.unreadable_buckets > 0)
    }
}

/// The verdict on one registration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpsVerdict {
    /// Callback in the kernel's text.
    KernelCallback,
    /// Callback in a listed module.
    ModuleCallback,
    /// Callback outside known code: a candidate hook.
    CallbackUnknown,
    /// Callback attributed by nearest symbol only.
    CallbackUnbounded,
    /// The callback pointer would not read.
    Unreadable,
}

impl OpsVerdict {
    fn as_str(&self) -> &'static str {
        match self {
            OpsVerdict::KernelCallback => "kernel_callback",
            OpsVerdict::ModuleCallback => "module_callback",
            OpsVerdict::CallbackUnknown => "callback_unknown",
            OpsVerdict::CallbackUnbounded => "callback_unbounded",
            OpsVerdict::Unreadable => "unreadable",
        }
    }
    fn is_candidate(&self) -> bool {
        matches!(
            self,
            OpsVerdict::ModuleCallback | OpsVerdict::CallbackUnknown
        )
    }
}

/// One `ftrace_ops`.
#[derive(Debug, Clone)]
pub struct FtraceOps {
    pub address: u64,
    pub ops_symbol: Option<String>,
    pub func: Option<u64>,
    pub func_attribution: Option<Attribution>,
    pub flags: Option<u64>,
    pub flags_decoded: Vec<&'static str>,
    pub filter: HashRead,
    pub notrace: HashRead,
    pub trampoline: Option<u64>,
    pub trampoline_attribution: Option<Attribution>,
    pub verdict: OpsVerdict,
    pub notes: Vec<String>,
}

impl FtraceOps {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address_hex": format!("{:#x}", self.address),
            "ops_symbol": self.ops_symbol,
            "func_hex": self.func.map(|f| format!("{f:#x}")),
            "func_attribution": self.func_attribution.as_ref().map(Attribution::to_json),
            "flags": self.flags,
            "flags_decoded": self.flags_decoded,
            "filter": self.filter.to_json(),
            "notrace": self.notrace.to_json(),
            "trampoline_hex": self.trampoline.map(|t| format!("{t:#x}")),
            "trampoline_attribution": self.trampoline_attribution.as_ref().map(Attribution::to_json),
            "verdict": self.verdict.as_str(),
            "notes": self.notes,
        })
    }
}

/// One direct call: a function whose entry jumps straight to `target`.
#[derive(Debug, Clone)]
pub struct DirectCall {
    pub ip: u64,
    pub ip_attribution: Attribution,
    pub target: u64,
    pub target_attribution: Attribution,
}

impl DirectCall {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "ip_hex": format!("{:#x}", self.ip),
            "function": self.ip_attribution.to_json(),
            "target_hex": format!("{:#x}", self.target),
            "target": self.target_attribution.to_json(),
        })
    }
}

/// The check's whole result.
#[derive(Debug, Clone)]
pub struct FtraceCheck {
    pub ops: Vec<FtraceOps>,
    /// How the ops walk ended.
    pub list_stop: String,
    pub list_complete: bool,
    /// The direct-call table, when the build has one and it read.
    pub direct_calls: Vec<DirectCall>,
    pub direct_calls_read: bool,
    pub direct_calls_count: Option<u64>,
    pub not_checked: Vec<String>,
}

impl FtraceCheck {
    pub fn is_complete(&self) -> bool {
        self.list_complete
            && self.not_checked.is_empty()
            && self
                .ops
                .iter()
                .all(|o| o.verdict != OpsVerdict::Unreadable && !o.filter.is_unreadable())
    }

    pub fn candidate_count(&self) -> usize {
        self.ops.iter().filter(|o| o.verdict.is_candidate()).count()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sources": [
                "ftrace_ops_list: every registered ftrace_ops, its callback, flags, filter hash and trampoline",
                "direct_functions: every function whose entry has been redirected to a direct target",
                "the kernel's text bounds and symbol table, and the module list's code extents",
            ],
            "ops_count": self.ops.len(),
            "list_stop": self.list_stop,
            "list_complete": self.list_complete,
            "candidate_count": self.candidate_count(),
            "ops": self.ops.iter().map(FtraceOps::to_json).collect::<Vec<_>>(),
            "direct_calls_read": self.direct_calls_read,
            "direct_calls_count": self.direct_calls_count,
            "direct_calls": self.direct_calls.iter().map(DirectCall::to_json).collect::<Vec<_>>(),
            "not_checked": self.not_checked,
        })
    }
}

/// Walk the registrations and the direct-call table.
pub fn check(
    reader: &StructReader,
    layout: &BuildBinding,
    map: &CodeMap,
) -> Result<FtraceCheck, StageError> {
    let symbols = reader.symbols();
    let mut not_checked = Vec::new();
    let mut ops_rows = Vec::new();
    let mut list_stop = "not walked".to_string();
    let mut list_complete = false;

    let ops_type = layout.type_of("ftrace_ops")?.type_name();
    let func_member = layout.member("ops_func")?.member();
    let next_member = layout.member("ops_next")?.member();

    match (
        symbols.symbol_address(OPS_LIST_SYMBOL),
        ops_type,
        func_member,
        next_member,
    ) {
        (Err(_), _, _, _) => not_checked.push(format!(
            "ftrace registrations were not checked: the symbol table has no {OPS_LIST_SYMBOL}"
        )),
        (_, None, _, _) => not_checked.push(
            "ftrace registrations were not checked: this build declares no ftrace_ops type"
                .to_string(),
        ),
        (_, _, None, _) | (_, _, _, None) => not_checked.push(
            "ftrace registrations were not checked: this build declares no ftrace_ops.func or \
             ftrace_ops.next"
                .to_string(),
        ),
        (Ok(list_symbol), Some(ops_type), Some(func_member), Some(next_member)) => {
            let end = symbols.symbol_address(OPS_LIST_END_SYMBOL).ok();
            match reader.read_pointer_at(list_symbol) {
                Err(err) => not_checked.push(format!(
                    "ftrace registrations were not checked: {OPS_LIST_SYMBOL} at \
                     {list_symbol:#x} could not be read: {err}"
                )),
                Ok(head) => {
                    let mut seen: HashSet<u64> = HashSet::new();
                    let mut current = head;
                    list_complete = true;
                    loop {
                        if current == 0 {
                            list_stop = "null".to_string();
                            break;
                        }
                        if Some(current) == end {
                            list_stop = format!("reached {OPS_LIST_END_SYMBOL}");
                            break;
                        }
                        if !seen.insert(current) {
                            list_stop = format!("cycle at {current:#x}");
                            list_complete = false;
                            break;
                        }
                        if ops_rows.len() >= MAX_OPS {
                            list_stop = format!("cap of {MAX_OPS} registrations reached");
                            list_complete = false;
                            break;
                        }
                        let ops = match reader.object(current, ops_type) {
                            Ok(obj) => obj,
                            Err(err) => {
                                list_stop = format!(
                                    "the ftrace_ops at {current:#x} could not be read: {err}"
                                );
                                list_complete = false;
                                break;
                            }
                        };
                        ops_rows.push(read_ops(reader, layout, map, &ops, func_member)?);
                        match ops.pointer(next_member) {
                            Ok(next) => current = next,
                            Err(err) => {
                                list_stop = format!(
                                    "the next pointer of the ftrace_ops at {current:#x} could \
                                     not be read: {err}"
                                );
                                list_complete = false;
                                break;
                            }
                        }
                    }
                }
            }
        }
    }

    // Direct calls.
    let mut direct_calls = Vec::new();
    let mut direct_calls_read = false;
    let mut direct_calls_count = None;
    match symbols.symbol_address(DIRECT_FUNCTIONS_SYMBOL) {
        Err(_) => not_checked.push(format!(
            "direct calls were not checked: the symbol table has no {DIRECT_FUNCTIONS_SYMBOL} \
             (the mechanism arrived in Linux 5.5; a sparse symbol file may also omit it)"
        )),
        Ok(address) => match reader.read_pointer_at(address) {
            Err(err) => not_checked.push(format!(
                "direct calls were not checked: {DIRECT_FUNCTIONS_SYMBOL} at {address:#x} could \
                 not be read: {err}"
            )),
            Ok(0) => {
                direct_calls_read = true;
                direct_calls_count = Some(0);
            }
            Ok(hash_address) => match read_hash(reader, layout, map, hash_address) {
                HashRead::Read(hash) => {
                    direct_calls_read = true;
                    direct_calls_count = Some(hash.count);
                    if hash.unreadable_buckets > 0 {
                        not_checked.push(format!(
                            "{} bucket(s) of {DIRECT_FUNCTIONS_SYMBOL} could not be read, so \
                             the direct-call list is a floor",
                            hash.unreadable_buckets
                        ));
                    }
                    direct_calls = read_direct_entries(reader, layout, map, hash_address);
                }
                HashRead::Null => {
                    direct_calls_read = true;
                    direct_calls_count = Some(0);
                }
                HashRead::NotDeclared(member) => not_checked.push(format!(
                    "direct calls were not checked: this build declares no {member}"
                )),
                HashRead::Unreadable(detail) => {
                    not_checked.push(format!("direct calls were not checked: {detail}"))
                }
            },
        },
    }

    Ok(FtraceCheck {
        ops: ops_rows,
        list_stop,
        list_complete,
        direct_calls,
        direct_calls_read,
        direct_calls_count,
        not_checked,
    })
}

/// Read one registration.
fn read_ops(
    reader: &StructReader,
    layout: &BuildBinding,
    map: &CodeMap,
    ops: &Obj,
    func_member: &'static str,
) -> Result<FtraceOps, StageError> {
    let symbols = reader.symbols();
    let ops_symbol = symbols
        .nearest_symbol(ops.address())
        .filter(|(_, d)| *d == 0)
        .map(|(s, _)| s.name.to_string());
    let (func, func_attribution, verdict) = match ops.pointer(func_member) {
        Ok(func) => {
            let attribution = map.attribute(func);
            let verdict = match &attribution {
                Attribution::KernelText { .. } => OpsVerdict::KernelCallback,
                Attribution::Module { .. } => OpsVerdict::ModuleCallback,
                Attribution::Unknown { .. } | Attribution::Null => OpsVerdict::CallbackUnknown,
                Attribution::NearestSymbolOnly { .. } => OpsVerdict::CallbackUnbounded,
            };
            (Some(func), Some(attribution), verdict)
        }
        Err(_) => (None, None, OpsVerdict::Unreadable),
    };
    let flags = layout.read_unsigned(ops, "ops_flags")?.known().copied();
    let flags_decoded = flags.map(decode_flags).unwrap_or_default();

    let (filter, notrace) = read_ops_hashes(reader, layout, map, ops)?;

    let trampoline = layout.read_pointer(ops, "ops_trampoline")?.known().copied();
    let trampoline_attribution = trampoline.filter(|t| *t != 0).map(|t| map.attribute(t));

    let mut notes = Vec::new();
    if let Some(flags) = flags {
        if flags & FL_IPMODIFY != 0 {
            notes.push(
                "IPMODIFY: this registration may change the instruction pointer of the functions \
                 it filters to, which is how a kernel function is replaced rather than observed"
                    .to_string(),
            );
        }
        if flags & FL_DIRECT != 0 {
            notes.push(
                "DIRECT: this registration carries direct calls; the functions it filters to \
                 jump to the targets listed under direct_calls"
                    .to_string(),
            );
        }
        if flags & FL_ENABLED != 0 {
            if let HashRead::Read(hash) = &filter {
                if hash.count == 0 {
                    notes.push(
                        "the filter hash is empty on an enabled registration, which means it \
                         applies to every traceable function, not to none"
                            .to_string(),
                    );
                }
            }
        }
    }

    Ok(FtraceOps {
        address: ops.address(),
        ops_symbol,
        func,
        func_attribution,
        flags,
        flags_decoded,
        filter,
        notrace,
        trampoline,
        trampoline_attribution,
        verdict,
        notes,
    })
}

/// The filter and notrace hashes of one ops, through `func_hash` when the
/// build has it and off the ops itself before 3.16.
fn read_ops_hashes(
    reader: &StructReader,
    layout: &BuildBinding,
    map: &CodeMap,
    ops: &Obj,
) -> Result<(HashRead, HashRead), StageError> {
    let holder: Obj = match layout.member("ops_func_hash")?.member() {
        Some(member) => match ops.follow(member) {
            Ok(Some(hash_holder)) => hash_holder,
            Ok(None) => {
                return Ok((
                    HashRead::Unreadable("func_hash is null".into()),
                    HashRead::Unreadable("func_hash is null".into()),
                ))
            }
            Err(err) => {
                let detail = format!("func_hash could not be followed: {err}");
                return Ok((
                    HashRead::Unreadable(detail.clone()),
                    HashRead::Unreadable(detail),
                ));
            }
        },
        None => ops.clone(),
    };
    let read = |key: &'static str| -> Result<HashRead, StageError> {
        let bound = layout.member(key)?;
        let Some(member) = bound.member() else {
            return Ok(HashRead::NotDeclared(bound.candidates()[0]));
        };
        if bound.type_name() != Some(holder.type_name()) {
            return Ok(HashRead::Unreadable(format!(
                "{key} is declared on {} but the hashes hang off a {}",
                bound.type_name().unwrap_or("?"),
                holder.type_name()
            )));
        }
        Ok(match holder.pointer(member) {
            Ok(0) => HashRead::Null,
            Ok(address) => read_hash(reader, layout, map, address),
            Err(err) => HashRead::Unreadable(format!("{key} could not be read: {err}")),
        })
    };
    Ok((read("hash_filter")?, read("hash_notrace")?))
}

/// Walk one `ftrace_hash`.
fn read_hash(
    reader: &StructReader,
    layout: &BuildBinding,
    map: &CodeMap,
    address: u64,
) -> HashRead {
    let mut listed = Vec::new();
    let mut unlisted = 0usize;
    let mut walked = 0usize;
    let outcome = walk_hash(reader, layout, address, |ip, _direct| {
        walked += 1;
        if listed.len() < MAX_LISTED_FILTERS {
            listed.push(FilteredFunction {
                ip,
                attribution: map.attribute(ip),
            });
        } else {
            unlisted += 1;
        }
    });
    match outcome {
        Ok((count, unreadable_buckets)) => HashRead::Read(FunctionHash {
            count,
            listed,
            unlisted,
            unreadable_buckets,
            walked,
        }),
        Err(detail) => HashRead::Unreadable(detail),
    }
}

/// The direct-call entries of a hash, ip and target together.
fn read_direct_entries(
    reader: &StructReader,
    layout: &BuildBinding,
    map: &CodeMap,
    address: u64,
) -> Vec<DirectCall> {
    let mut out = Vec::new();
    let _ = walk_hash(reader, layout, address, |ip, direct| {
        if let Some(target) = direct {
            out.push(DirectCall {
                ip,
                ip_attribution: map.attribute(ip),
                target,
                target_attribution: map.attribute(target),
            });
        }
    });
    out
}

/// Walk every bucket of an `ftrace_hash`, handing each entry's `ip` (and its
/// `direct` target when the build declares one) to `visit`. Returns the
/// kernel's own count and the number of buckets that would not read.
fn walk_hash(
    reader: &StructReader,
    layout: &BuildBinding,
    address: u64,
    mut visit: impl FnMut(u64, Option<u64>),
) -> Result<(u64, usize), String> {
    let hash_type = layout
        .type_of("ftrace_hash")
        .ok()
        .and_then(|t| t.type_name())
        .ok_or("this build declares no ftrace_hash type")?;
    let entry_type = layout
        .type_of("ftrace_func_entry")
        .ok()
        .and_then(|t| t.type_name())
        .ok_or("this build declares no ftrace_func_entry type")?;
    let size_bits_member = layout
        .member("fhash_size_bits")
        .ok()
        .and_then(|m| m.member())
        .ok_or("this build declares no ftrace_hash.size_bits")?;
    let buckets_member = layout
        .member("fhash_buckets")
        .ok()
        .and_then(|m| m.member())
        .ok_or("this build declares no ftrace_hash.buckets")?;
    let count_member = layout
        .member("fhash_count")
        .ok()
        .and_then(|m| m.member())
        .ok_or("this build declares no ftrace_hash.count")?;
    let ip_member = layout
        .member("fentry_ip")
        .ok()
        .and_then(|m| m.member())
        .ok_or("this build declares no ftrace_func_entry.ip")?;
    let hlist_offset = layout
        .member("fentry_hlist")
        .ok()
        .and_then(|m| m.offset())
        .ok_or("this build declares no ftrace_func_entry.hlist")?;
    let next_offset = layout
        .member("hlist_next")
        .ok()
        .and_then(|m| m.offset())
        .ok_or("this build declares no hlist_node.next")?;
    let direct_member = layout.member("fentry_direct").ok().and_then(|m| m.member());

    let hash = reader
        .object(address, hash_type)
        .map_err(|e| format!("the ftrace_hash at {address:#x} could not be read: {e}"))?;
    let size_bits = hash
        .unsigned(size_bits_member)
        .map_err(|e| format!("ftrace_hash.size_bits: {e}"))?;
    let count = hash
        .unsigned(count_member)
        .map_err(|e| format!("ftrace_hash.count: {e}"))?;
    let buckets = hash
        .pointer(buckets_member)
        .map_err(|e| format!("ftrace_hash.buckets: {e}"))?;
    if count == 0 {
        return Ok((0, 0));
    }
    if size_bits > MAX_HASH_BITS {
        return Err(format!(
            "the ftrace_hash at {address:#x} claims {size_bits} size bits, past the \
             {MAX_HASH_BITS} this check accepts"
        ));
    }
    if buckets == 0 {
        return Err(format!(
            "the ftrace_hash at {address:#x} counts {count} entries but has no bucket array"
        ));
    }
    let pointer = u64::from(reader.pointer_size().map_err(|e| e.to_string())?);
    let bucket_count = 1u64 << size_bits;
    let mut bad_buckets = 0usize;
    let mut seen: HashSet<u64> = HashSet::new();
    let mut total = 0usize;
    'buckets: for bucket in 0..bucket_count {
        let head = buckets.wrapping_add(bucket * pointer);
        let mut node = match reader.read_pointer_at(head) {
            Ok(node) => node,
            Err(_) => {
                bad_buckets += 1;
                continue;
            }
        };
        while node != 0 {
            if !seen.insert(node) || total >= MAX_HASH_ENTRIES {
                bad_buckets += 1;
                continue 'buckets;
            }
            total += 1;
            let entry_address = node.wrapping_sub(hlist_offset);
            let entry = match reader.object(entry_address, entry_type) {
                Ok(entry) => entry,
                Err(_) => {
                    bad_buckets += 1;
                    continue 'buckets;
                }
            };
            let ip = match entry.unsigned(ip_member) {
                Ok(ip) => ip,
                Err(_) => {
                    bad_buckets += 1;
                    continue 'buckets;
                }
            };
            let direct = direct_member.and_then(|m| entry.unsigned(m).ok());
            visit(ip, direct);
            node = match reader.read_pointer_at(node.wrapping_add(next_offset)) {
                Ok(next) => next,
                Err(_) => {
                    bad_buckets += 1;
                    continue 'buckets;
                }
            };
        }
    }
    Ok((count, bad_buckets))
}
