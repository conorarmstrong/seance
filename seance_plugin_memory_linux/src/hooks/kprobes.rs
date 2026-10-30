//! Registered kprobes: every `kprobe` in `kprobe_table`, the address it
//! probes and the handlers it runs.
//!
//! Source A is `kprobe_table`, the kernel's array of `KPROBE_TABLE_SIZE`
//! (64) hash-list heads, each chaining `kprobe` structures by `hlist`. Source B
//! is the code map: the probed address is attributed so the row names the
//! function under the probe, and each handler is attributed so the row names
//! who runs when it fires.
//!
//! A kprobe is the ordinary way a tracing tool, `perf` or a BPF program of type
//! `KPROBE` observes a kernel function; the kernel's own dispatchers
//! (`kprobe_dispatcher`, `aggr_pre_handler`, `pre_handler_kretprobe`) are what
//! the handler usually resolves to, and the BPF check reads those rows against
//! the programs it lists. A handler attributed to a module is named; one
//! attributed to nothing is a candidate hook; a probe whose two handler
//! pointers are both null has no handler to judge and says so, rather than
//! being counted among the kernel-handled.

use std::collections::HashSet;

use seance_memory::binding::BuildBinding;
use seance_memory::object::{Obj, StructReader};

use super::regions::{Attribution, CodeMap};
use crate::error::StageError;
use crate::read::{read_c_string, MAX_C_STRING};

/// The table symbol.
pub const TABLE_SYMBOL: &str = "kprobe_table";
/// `KPROBE_TABLE_SIZE`: `1 << KPROBE_HASH_BITS`, and `KPROBE_HASH_BITS` has
/// been 6 since the table was introduced. Published on the check so the
/// assumption is on the record.
pub const TABLE_SIZE: u64 = 64;
/// More probes than this is a corrupt table.
pub const MAX_PROBES: usize = 65_536;

/// Verdict on one probe's handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeVerdict {
    /// Every handler that was read and is non-null is in the kernel's text.
    /// A handler pointer that could not be read (its member undeclared in
    /// the binding, or the read failing) is not counted, so one handler in
    /// the kernel and the other unread still earns this verdict.
    KernelHandlers,
    /// A handler is in a listed module.
    ModuleHandler,
    /// A handler is outside known code: a candidate hook.
    HandlerUnknown,
    /// A handler attributed by nearest symbol only.
    HandlerUnbounded,
    /// No handler to attribute: at least one handler pointer was read, and
    /// every one that was read is null. On the stock captures that is both
    /// pointers reading as null, so nothing runs when the probe fires; it
    /// also covers a null `pre_handler` whose `post_handler` could not be
    /// read (undeclared in the binding, or the read failing), where the
    /// unread pointer is not counted. Kept apart from
    /// [`ProbeVerdict::KernelHandlers`], which would otherwise be claimed of
    /// no handler at all.
    NoHandlers,
    /// Neither handler pointer could be read.
    Unreadable,
}

impl ProbeVerdict {
    fn as_str(&self) -> &'static str {
        match self {
            ProbeVerdict::KernelHandlers => "kernel_handlers",
            ProbeVerdict::ModuleHandler => "module_handler",
            ProbeVerdict::HandlerUnknown => "handler_unknown",
            ProbeVerdict::HandlerUnbounded => "handler_unbounded",
            ProbeVerdict::NoHandlers => "no_handlers",
            ProbeVerdict::Unreadable => "unreadable",
        }
    }
    fn is_candidate(&self) -> bool {
        matches!(
            self,
            ProbeVerdict::ModuleHandler | ProbeVerdict::HandlerUnknown
        )
    }
}

/// One registered probe.
#[derive(Debug, Clone)]
pub struct Kprobe {
    pub address: u64,
    /// The probed address and what it is.
    pub probed: Option<u64>,
    pub probed_attribution: Option<Attribution>,
    /// `kprobe.symbol_name`, when the registrant gave one.
    pub symbol_name: Option<String>,
    pub offset: Option<u64>,
    pub flags: Option<u64>,
    pub pre_handler: Option<u64>,
    pub pre_handler_attribution: Option<Attribution>,
    pub post_handler: Option<u64>,
    pub post_handler_attribution: Option<Attribution>,
    pub verdict: ProbeVerdict,
}

impl Kprobe {
    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address_hex": format!("{:#x}", self.address),
            "probed_hex": self.probed.map(|p| format!("{p:#x}")),
            "probed": self.probed_attribution.as_ref().map(Attribution::to_json),
            "symbol_name": self.symbol_name,
            "offset": self.offset,
            "flags": self.flags,
            "pre_handler_hex": self.pre_handler.map(|p| format!("{p:#x}")),
            "pre_handler": self.pre_handler_attribution.as_ref().map(Attribution::to_json),
            "post_handler_hex": self.post_handler.map(|p| format!("{p:#x}")),
            "post_handler": self.post_handler_attribution.as_ref().map(Attribution::to_json),
            "verdict": self.verdict.as_str(),
        })
    }
}

/// The check's whole result.
#[derive(Debug, Clone)]
pub struct KprobeCheck {
    pub probes: Vec<Kprobe>,
    pub table_read: bool,
    pub unreadable_buckets: usize,
    pub not_checked: Vec<String>,
}

impl KprobeCheck {
    pub fn is_complete(&self) -> bool {
        self.table_read
            && self.not_checked.is_empty()
            && self.unreadable_buckets == 0
            && self
                .probes
                .iter()
                .all(|p| p.verdict != ProbeVerdict::Unreadable)
    }

    pub fn candidate_count(&self) -> usize {
        self.probes
            .iter()
            .filter(|p| p.verdict.is_candidate())
            .count()
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "sources": [
                "kprobe_table: every registered kprobe, the address it probes and its handlers",
                "the kernel's text bounds and symbol table, and the module list's code extents",
            ],
            "table_read": self.table_read,
            "table_size_assumed": TABLE_SIZE,
            "probe_count": self.probes.len(),
            "unreadable_buckets": self.unreadable_buckets,
            "candidate_count": self.candidate_count(),
            "probes": self.probes.iter().map(Kprobe::to_json).collect::<Vec<_>>(),
            "not_checked": self.not_checked,
        })
    }
}

/// Walk the table.
pub fn check(
    reader: &StructReader,
    layout: &BuildBinding,
    map: &CodeMap,
) -> Result<KprobeCheck, StageError> {
    let symbols = reader.symbols();
    let mut not_checked = Vec::new();
    let empty = |not_checked: Vec<String>| KprobeCheck {
        probes: Vec::new(),
        table_read: false,
        unreadable_buckets: 0,
        not_checked,
    };

    let Ok(table) = symbols.symbol_address(TABLE_SYMBOL) else {
        not_checked.push(format!(
            "kprobes were not checked: the symbol table has no {TABLE_SYMBOL}"
        ));
        return Ok(empty(not_checked));
    };
    let Some(kprobe_type) = layout.type_of("kprobe")?.type_name() else {
        not_checked.push("kprobes were not checked: this build declares no kprobe type".into());
        return Ok(empty(not_checked));
    };
    let (Some(hlist_offset), Some(next_offset)) = (
        layout.member("kp_hlist")?.offset(),
        layout.member("hlist_next")?.offset(),
    ) else {
        not_checked.push(
            "kprobes were not checked: this build declares no kprobe.hlist or hlist_node.next"
                .into(),
        );
        return Ok(empty(not_checked));
    };
    let pointer = u64::from(reader.pointer_size()?);

    let mut probes = Vec::new();
    let mut unreadable_buckets = 0usize;
    let mut seen: HashSet<u64> = HashSet::new();
    'buckets: for bucket in 0..TABLE_SIZE {
        let head = table.wrapping_add(bucket * pointer);
        let mut node = match reader.read_pointer_at(head) {
            Ok(node) => node,
            Err(_) => {
                unreadable_buckets += 1;
                continue;
            }
        };
        while node != 0 {
            if !seen.insert(node) || probes.len() >= MAX_PROBES {
                unreadable_buckets += 1;
                continue 'buckets;
            }
            let address = node.wrapping_sub(hlist_offset);
            match reader.object(address, kprobe_type) {
                Ok(obj) => probes.push(read_probe(reader, layout, map, &obj)?),
                Err(_) => {
                    unreadable_buckets += 1;
                    continue 'buckets;
                }
            }
            node = match reader.read_pointer_at(node.wrapping_add(next_offset)) {
                Ok(next) => next,
                Err(_) => {
                    unreadable_buckets += 1;
                    continue 'buckets;
                }
            };
        }
    }

    Ok(KprobeCheck {
        probes,
        table_read: true,
        unreadable_buckets,
        not_checked,
    })
}

fn read_probe(
    reader: &StructReader,
    layout: &BuildBinding,
    map: &CodeMap,
    obj: &Obj,
) -> Result<Kprobe, StageError> {
    let probed = layout.read_pointer(obj, "kp_addr")?.known().copied();
    let probed_attribution = probed.map(|a| map.attribute(a));
    let symbol_name = match layout.member("kp_symbol_name")?.member() {
        Some(member) => match obj.pointer(member) {
            Ok(0) | Err(_) => None,
            Ok(address) => read_c_string(&**reader.native_layer(), address, MAX_C_STRING)
                .ok()
                .map(|(text, _)| text),
        },
        None => None,
    };
    let offset = layout.read_unsigned(obj, "kp_offset")?.known().copied();
    let flags = layout.read_unsigned(obj, "kp_flags")?.known().copied();
    let pre_handler = layout.read_pointer(obj, "kp_pre_handler")?.known().copied();
    let post_handler = layout
        .read_pointer(obj, "kp_post_handler")?
        .known()
        .copied();
    let pre_handler_attribution = pre_handler.filter(|p| *p != 0).map(|p| map.attribute(p));
    let post_handler_attribution = post_handler.filter(|p| *p != 0).map(|p| map.attribute(p));

    let handlers: Vec<&Attribution> = pre_handler_attribution
        .iter()
        .chain(post_handler_attribution.iter())
        .collect();
    let verdict = if pre_handler.is_none() && post_handler.is_none() {
        ProbeVerdict::Unreadable
    } else if handlers.is_empty() {
        ProbeVerdict::NoHandlers
    } else if handlers
        .iter()
        .any(|a| matches!(a, Attribution::Unknown { .. }))
    {
        ProbeVerdict::HandlerUnknown
    } else if handlers
        .iter()
        .any(|a| matches!(a, Attribution::Module { .. }))
    {
        ProbeVerdict::ModuleHandler
    } else if handlers
        .iter()
        .any(|a| matches!(a, Attribution::NearestSymbolOnly { .. }))
    {
        ProbeVerdict::HandlerUnbounded
    } else {
        ProbeVerdict::KernelHandlers
    };

    Ok(Kprobe {
        address: obj.address(),
        probed,
        probed_attribution,
        symbol_name,
        offset,
        flags,
        pre_handler,
        pre_handler_attribution,
        post_handler,
        post_handler_attribution,
        verdict,
    })
}
