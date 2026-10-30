//! The hook checks over a synthetic kernel image.
//!
//! The fixture layouts are written from the kernel's own structure
//! definitions (`include/linux/ftrace.h`, `kprobes.h`, `bpf.h`, `xarray.h`),
//! not copied from a capture; the real-capture tests under `tests/` grade the
//! checks against evidence. What is decided here is the verdict logic: which
//! address goes to which verdict, that a candidate is a candidate, and that a
//! check that cannot run says so by name instead of reporting nothing found.

use std::sync::Arc;

use seance_core::data_source::{ByteSliceDataSource, DataSource};
use seance_memory::binding::Field;
use seance_memory::object::ListStop;
use seance_memory::{MemoryLayer, PhysicalLayer};
use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

use super::ebpf::PROG_TYPES_UAPI;
use super::regions::Attribution;
use super::*;
use crate::lsmod::{ModuleList, ModuleRecord};

// Kernel text: [0x1000, 0x8000). Symbols inside it.
const STEXT: u64 = 0x1000;
const ETEXT: u64 = 0x8000;
const SYS_READ: u64 = 0x1100;
const SYS_WRITE: u64 = 0x1200;
const SYS_OPEN: u64 = 0x1300;
const FTRACE_STUB: u64 = 0x1400;
const KPROBE_DISPATCHER: u64 = 0x1500;
const SECURITY_FILE_OPEN: u64 = 0x1600;
const VFS_READ: u64 = 0x1700;
// A loaded module "evil" at [0x9000, 0xa000).
const MODULE_EVIL: u64 = 0x9000;
const MODULE_EVIL_SIZE: u64 = 0x1000;
const EVIL_HOOK: u64 = 0x9100;
// Code nobody accounts for.
const NOWHERE: u64 = 0xc000;
// Tables and globals.
const SYS_CALL_TABLE: u64 = 0x2000; // 4 entries, then padding, then the next symbol at 0x2040
const FTRACE_OPS_LIST: u64 = 0x2100; // holds a pointer
const FTRACE_LIST_END: u64 = 0x2200; // an ftrace_ops
const OPS_A: u64 = 0x2300; // kernel callback (ftrace_stub), filter: sys_open
const OPS_B: u64 = 0x2400; // module callback with IPMODIFY, filter: vfs_read
const HASH_HOLDER_A: u64 = 0x2500; // ftrace_ops_hash
const HASH_HOLDER_B: u64 = 0x2540;
const HASH_A: u64 = 0x2600; // ftrace_hash, one entry
const HASH_B: u64 = 0x2640;
const BUCKETS_A: u64 = 0x2700; // 2 buckets
const BUCKETS_B: u64 = 0x2720;
const ENTRY_A: u64 = 0x2800; // ftrace_func_entry
const ENTRY_B: u64 = 0x2840;
const DIRECT_FUNCTIONS: u64 = 0x2900; // holds a pointer to HASH_D
const HASH_D: u64 = 0x2940;
const BUCKETS_D: u64 = 0x2980;
const ENTRY_D1: u64 = 0x2a00; // security_file_open -> trampoline (nowhere)
const ENTRY_D2: u64 = 0x2a40; // vfs_read -> EVIL_HOOK
const TRAMPOLINE: u64 = 0xd000;
const KPROBE_TABLE: u64 = 0x3000; // 64 pointers
const KPROBE_1: u64 = 0x3400; // probes sys_read, handler kprobe_dispatcher
const KPROBE_2: u64 = 0x3500; // probes sys_write, handler in module
const KPROBE_2_NAME: u64 = 0x3600;
const PROG_IDR: u64 = 0x3700; // idr {xarray {xa_head @8}, idr_base @16}
const XA_NODE: u64 = 0x3800; // 576 bytes
const PROG_1: u64 = 0x4000; // TRACING, attach security_file_open, id 7
const PROG_2: u64 = 0x4100; // KPROBE, id 9
const AUX_1: u64 = 0x4400;
const AUX_2: u64 = 0x4800;
const ATTACH_NAME_1: u64 = 0x4c00;

const FIXTURE_ISF: &str = r#"{
  "metadata": {"format":"6.2.0","producer":{"name":"seance-hooks-fixture","version":"1.0.0"},"linux":{"symbols":[],"types":[]}},
  "base_types": {
    "pointer": {"size":8,"signed":false,"kind":"int","endian":"little"},
    "unsigned long": {"size":8,"signed":false,"kind":"int","endian":"little"},
    "long": {"size":8,"signed":true,"kind":"int","endian":"little"},
    "unsigned int": {"size":4,"signed":false,"kind":"int","endian":"little"},
    "unsigned char": {"size":1,"signed":false,"kind":"int","endian":"little"},
    "char": {"size":1,"signed":true,"kind":"char","endian":"little"},
    "void": {"size":0,"signed":false,"kind":"void","endian":"little"}
  },
  "user_types": {
    "hlist_head": {"size":8,"kind":"struct","fields":{
      "first":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"hlist_node"}}}
    }},
    "hlist_node": {"size":16,"kind":"struct","fields":{
      "next":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"hlist_node"}}},
      "pprev":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"pointer","subtype":{"kind":"struct","name":"hlist_node"}}}}
    }},
    "ftrace_hash": {"size":48,"kind":"struct","fields":{
      "size_bits":{"offset":0,"type":{"kind":"base","name":"unsigned long"}},
      "buckets":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"hlist_head"}}},
      "count":{"offset":16,"type":{"kind":"base","name":"unsigned long"}}
    }},
    "ftrace_ops_hash": {"size":48,"kind":"struct","fields":{
      "notrace_hash":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"ftrace_hash"}}},
      "filter_hash":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"ftrace_hash"}}}
    }},
    "ftrace_func_entry": {"size":32,"kind":"struct","fields":{
      "hlist":{"offset":0,"type":{"kind":"struct","name":"hlist_node"}},
      "ip":{"offset":16,"type":{"kind":"base","name":"unsigned long"}},
      "direct":{"offset":24,"type":{"kind":"base","name":"unsigned long"}}
    }},
    "ftrace_ops": {"size":176,"kind":"struct","fields":{
      "func":{"offset":0,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
      "next":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"ftrace_ops"}}},
      "flags":{"offset":16,"type":{"kind":"base","name":"unsigned long"}},
      "func_hash":{"offset":88,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"ftrace_ops_hash"}}},
      "trampoline":{"offset":144,"type":{"kind":"base","name":"unsigned long"}}
    }},
    "kprobe": {"size":128,"kind":"struct","fields":{
      "hlist":{"offset":0,"type":{"kind":"struct","name":"hlist_node"}},
      "addr":{"offset":40,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
      "symbol_name":{"offset":48,"type":{"kind":"pointer","subtype":{"kind":"base","name":"char"}}},
      "offset":{"offset":56,"type":{"kind":"base","name":"unsigned int"}},
      "pre_handler":{"offset":64,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
      "post_handler":{"offset":72,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
      "flags":{"offset":120,"type":{"kind":"base","name":"unsigned int"}}
    }},
    "xa_node": {"size":576,"kind":"struct","fields":{
      "shift":{"offset":0,"type":{"kind":"base","name":"unsigned char"}},
      "slots":{"offset":40,"type":{"kind":"array","count":64,"subtype":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}}}
    }},
    "xarray": {"size":16,"kind":"struct","fields":{
      "xa_head":{"offset":8,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}}
    }},
    "idr": {"size":24,"kind":"struct","fields":{
      "idr_rt":{"offset":0,"type":{"kind":"struct","name":"xarray"}},
      "idr_base":{"offset":16,"type":{"kind":"base","name":"unsigned int"}}
    }},
    "bpf_prog_aux": {"size":656,"kind":"struct","fields":{
      "id":{"offset":32,"type":{"kind":"base","name":"unsigned int"}},
      "attach_func_name":{"offset":168,"type":{"kind":"pointer","subtype":{"kind":"base","name":"char"}}},
      "load_time":{"offset":504,"type":{"kind":"base","name":"unsigned long"}},
      "name":{"offset":528,"type":{"kind":"array","count":16,"subtype":{"kind":"base","name":"char"}}}
    }},
    "bpf_prog": {"size":72,"kind":"struct","fields":{
      "type":{"offset":4,"type":{"kind":"base","name":"unsigned int"}},
      "len":{"offset":12,"type":{"kind":"base","name":"unsigned int"}},
      "jited_len":{"offset":16,"type":{"kind":"base","name":"unsigned int"}},
      "tag":{"offset":20,"type":{"kind":"array","count":8,"subtype":{"kind":"base","name":"unsigned char"}}},
      "bpf_func":{"offset":48,"type":{"kind":"pointer","subtype":{"kind":"base","name":"void"}}},
      "aux":{"offset":56,"type":{"kind":"pointer","subtype":{"kind":"struct","name":"bpf_prog_aux"}}}
    }},
    "module": {"size":768,"kind":"struct","fields":{
      "name":{"offset":24,"type":{"kind":"array","count":56,"subtype":{"kind":"base","name":"char"}}}
    }}
  },
  "enums": {},
  "symbols": {
    "_stext": {"address": 4096},
    "__x64_sys_read": {"address": 4352},
    "__x64_sys_write": {"address": 4608},
    "__x64_sys_open": {"address": 4864},
    "ftrace_stub": {"address": 5120},
    "kprobe_dispatcher": {"address": 5376},
    "security_file_open": {"address": 5632},
    "vfs_read": {"address": 5888},
    "_etext": {"address": 32768},
    "sys_call_table": {"address": 8192},
    "vdso_mapping": {"address": 8256},
    "ftrace_ops_list": {"address": 8448},
    "ftrace_list_end": {"address": 8704},
    "direct_functions": {"address": 10496},
    "kprobe_table": {"address": 12288},
    "prog_idr": {"address": 14080}
  }
}"#;

struct Image {
    bytes: Vec<u8>,
}
impl Image {
    fn new() -> Self {
        Self {
            bytes: vec![0u8; 0x10000],
        }
    }
    fn put(&mut self, a: u64, d: &[u8]) {
        let at = a as usize;
        self.bytes[at..at + d.len()].copy_from_slice(d);
    }
    fn u64(&mut self, a: u64, v: u64) {
        self.put(a, &v.to_le_bytes());
    }
    fn u32(&mut self, a: u64, v: u32) {
        self.put(a, &v.to_le_bytes());
    }
    fn hash(&mut self, hash: u64, buckets: u64, count: u64, entries: &[(u64, u64, u64)]) {
        // size_bits 1 -> 2 buckets; entries are (entry_address, ip, direct)
        // chained one per bucket, in order.
        self.u64(hash, 1);
        self.u64(hash + 8, buckets);
        self.u64(hash + 16, count);
        for (i, (entry, ip, direct)) in entries.iter().enumerate() {
            self.u64(buckets + 8 * i as u64, *entry);
            self.u64(*entry, 0); // hlist.next
            self.u64(*entry + 16, *ip);
            self.u64(*entry + 24, *direct);
        }
    }
}

fn image() -> Image {
    let mut m = Image::new();
    // sys_call_table: read, write, EVIL_HOOK, NOWHERE, then nulls to the next symbol.
    m.u64(SYS_CALL_TABLE, SYS_READ);
    m.u64(SYS_CALL_TABLE + 8, SYS_WRITE);
    m.u64(SYS_CALL_TABLE + 16, EVIL_HOOK);
    m.u64(SYS_CALL_TABLE + 24, NOWHERE);
    // ftrace: list -> OPS_A -> OPS_B -> ftrace_list_end.
    m.u64(FTRACE_OPS_LIST, OPS_A);
    m.u64(OPS_A, FTRACE_STUB);
    m.u64(OPS_A + 8, OPS_B);
    m.u64(OPS_A + 16, 0x1); // ENABLED
    m.u64(OPS_A + 88, HASH_HOLDER_A);
    m.u64(HASH_HOLDER_A + 8, HASH_A);
    m.hash(HASH_A, BUCKETS_A, 1, &[(ENTRY_A, SYS_OPEN, 0)]);
    m.u64(OPS_B, EVIL_HOOK);
    m.u64(OPS_B + 8, FTRACE_LIST_END);
    m.u64(OPS_B + 16, 0x1 | (1 << 12)); // ENABLED | IPMODIFY
    m.u64(OPS_B + 88, HASH_HOLDER_B);
    m.u64(HASH_HOLDER_B + 8, HASH_B);
    m.hash(HASH_B, BUCKETS_B, 1, &[(ENTRY_B, VFS_READ, 0)]);
    // direct calls: security_file_open -> TRAMPOLINE, vfs_read -> EVIL_HOOK.
    m.u64(DIRECT_FUNCTIONS, HASH_D);
    m.hash(
        HASH_D,
        BUCKETS_D,
        2,
        &[
            (ENTRY_D1, SECURITY_FILE_OPEN, TRAMPOLINE),
            (ENTRY_D2, VFS_READ, EVIL_HOOK),
        ],
    );
    // kprobes: bucket 3 -> KPROBE_1 -> KPROBE_2.
    m.u64(KPROBE_TABLE + 8 * 3, KPROBE_1);
    m.u64(KPROBE_1, KPROBE_2);
    m.u64(KPROBE_1 + 40, SYS_READ);
    m.u64(KPROBE_1 + 64, KPROBE_DISPATCHER);
    m.u64(KPROBE_2 + 40, SYS_WRITE);
    m.u64(KPROBE_2 + 48, KPROBE_2_NAME);
    m.put(KPROBE_2_NAME, b"__x64_sys_write\0");
    m.u64(KPROBE_2 + 64, EVIL_HOOK);
    // prog_idr: xa_head -> node (internal tag 2), idr_base 0; node shift 0,
    // slot 7 -> PROG_1, slot 9 -> PROG_2.
    m.u64(PROG_IDR + 8, XA_NODE | 2);
    m.u64(XA_NODE + 40 + 8 * 7, PROG_1);
    m.u64(XA_NODE + 40 + 8 * 9, PROG_2);
    m.u32(PROG_1 + 4, 26); // TRACING
    m.u32(PROG_1 + 12, 10);
    m.u32(PROG_1 + 16, 80);
    m.put(PROG_1 + 20, &[0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4]);
    m.u64(PROG_1 + 48, TRAMPOLINE + 0x100);
    m.u64(PROG_1 + 56, AUX_1);
    m.u32(AUX_1 + 32, 7);
    m.u64(AUX_1 + 168, ATTACH_NAME_1);
    m.put(ATTACH_NAME_1, b"security_file_open\0");
    m.put(AUX_1 + 528, b"file_open_lsm\0");
    m.u32(PROG_2 + 4, 2); // KPROBE
    m.u64(PROG_2 + 56, AUX_2);
    m.u32(AUX_2 + 32, 9);
    m.put(AUX_2 + 528, b"kp_read\0");
    m
}

fn reader_over(m: Image) -> StructReader {
    let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(m.bytes));
    let layer: Arc<dyn MemoryLayer> = Arc::new(PhysicalLayer::raw(source).expect("image"));
    let symbols = Arc::new(
        SymbolTable::compile_source(
            seance_symbols::load_slice(FIXTURE_ISF.as_bytes(), &DecompressLimits::default())
                .expect("loads"),
            &CompileOptions::default(),
        )
        .expect("compiles"),
    );
    StructReader::new(layer, symbols)
}

fn module_list() -> ModuleList {
    let mut evil = ModuleRecord::address_only_for_test(0xf000);
    evil.name = Field::Known("evil".into());
    evil.core_base = Field::Known(MODULE_EVIL);
    evil.core_size = Field::Known(MODULE_EVIL_SIZE as i64);
    let mut blind = ModuleRecord::address_only_for_test(0xf400);
    blind.name = Field::Known("blind".into());
    ModuleList {
        head: 0,
        links_offset: 0,
        modules: vec![evil, blind],
        stop: ListStop::Wrapped,
        layout: serde_json::json!({}),
    }
}

fn survey() -> HooksSurvey {
    let reader = reader_over(image());
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let modules = module_list();
    survey_with_reader(&reader, &layout, Some(&modules)).expect("runs")
}

#[test]
fn the_code_map_attributes_kernel_module_and_unknown_addresses_apart() {
    let reader = reader_over(image());
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let modules = module_list();
    let map = regions::CodeMap::build(&reader, &layout, Some(&modules));
    assert_eq!(map.kernel_text, Some((STEXT, ETEXT)));
    assert_eq!(
        map.attribute(SYS_READ),
        Attribution::KernelText {
            symbol: "__x64_sys_read".into(),
            offset: 0
        }
    );
    assert_eq!(
        map.attribute(SYS_READ + 4),
        Attribution::KernelText {
            symbol: "__x64_sys_read".into(),
            offset: 4
        }
    );
    assert_eq!(
        map.attribute(EVIL_HOOK),
        Attribution::Module {
            name: "evil".into(),
            offset: 0x100
        }
    );
    assert!(matches!(
        map.attribute(NOWHERE),
        Attribution::Unknown { .. }
    ));
    assert_eq!(map.attribute(0), Attribution::Null);
    // The module with no extent weakens every unknown, and the map says so.
    assert_eq!(map.modules_without_extent.len(), 1);
    assert_eq!(map.modules_without_extent[0].0, "blind");
    assert!(map
        .limitations()
        .iter()
        .any(|l| l.contains("blind") && l.contains("unknown")));
}

#[test]
fn syscall_entries_in_a_module_or_nowhere_are_candidates_and_padding_is_not() {
    let survey = survey();
    let table = &survey.syscalls.tables[0];
    assert_eq!(table.symbol, "sys_call_table");
    assert_eq!(table.entry_count, 8, "bounded by the next symbol");
    assert_eq!(table.kernel_symbol_count, 2);
    assert_eq!(
        table.trailing_null_count, 4,
        "the padding to the next symbol"
    );
    let verdicts: Vec<(u64, &str)> = table
        .notable
        .iter()
        .map(|e| (e.index, e.verdict_str()))
        .collect();
    assert_eq!(verdicts, vec![(2, "module"), (3, "unknown")]);
    assert_eq!(survey.syscalls.candidate_count(), 2);
    assert!(!survey.syscalls.switch_dispatch);
    let json = survey.syscalls.to_json();
    assert_eq!(
        json["tables"][0]["notable"][0]["attribution"]["module"],
        "evil"
    );
}

#[test]
fn a_missing_syscall_table_symbol_is_not_checked_by_name() {
    let reader = reader_over(image());
    // A symbol table with no sys_call_table at all.
    let isf = FIXTURE_ISF.replace(r#""sys_call_table": {"address": 8192},"#, "");
    let symbols = Arc::new(
        SymbolTable::compile_source(
            seance_symbols::load_slice(isf.as_bytes(), &DecompressLimits::default()).unwrap(),
            &CompileOptions::default(),
        )
        .unwrap(),
    );
    let reader = StructReader::new(Arc::clone(reader.layer()), symbols);
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let survey = survey_with_reader(&reader, &layout, None).expect("runs");
    assert!(survey.syscalls.tables.is_empty());
    assert!(survey.syscalls.not_checked[0].contains("sys_call_table"));
    assert!(!survey.syscalls.is_complete());
    assert!(!survey.is_complete());
    assert!(survey.to_json()["not_checked"]
        .as_array()
        .unwrap()
        .iter()
        .any(|n| n
            .as_str()
            .unwrap()
            .contains("system-call table was not checked")));
}

#[test]
fn ftrace_registrations_name_their_callback_filter_and_ipmodify() {
    let survey = survey();
    let ftrace = &survey.ftrace;
    assert_eq!(ftrace.ops.len(), 2);
    assert!(ftrace.list_complete);
    assert!(ftrace.list_stop.contains("ftrace_list_end"));

    let a = &ftrace.ops[0];
    assert_eq!(a.verdict, ftrace::OpsVerdict::KernelCallback);
    assert_eq!(a.flags_decoded, vec!["ENABLED"]);
    let ftrace::HashRead::Read(filter) = &a.filter else {
        panic!("{:?}", a.filter)
    };
    assert_eq!(filter.count, 1);
    assert_eq!(filter.walked, 1);
    assert_eq!(
        filter.listed[0].attribution,
        Attribution::KernelText {
            symbol: "__x64_sys_open".into(),
            offset: 0
        }
    );

    let b = &ftrace.ops[1];
    assert_eq!(b.verdict, ftrace::OpsVerdict::ModuleCallback);
    assert!(b.flags_decoded.contains(&"IPMODIFY"));
    assert!(b.notes.iter().any(|n| n.contains("IPMODIFY")));
    assert_eq!(ftrace.candidate_count(), 1);

    // Direct calls: both entries read with their targets.
    assert!(ftrace.direct_calls_read);
    assert_eq!(ftrace.direct_calls_count, Some(2));
    assert_eq!(ftrace.direct_calls.len(), 2);
}

#[test]
fn an_enabled_registration_with_an_empty_filter_applies_to_every_function() {
    let mut m = image();
    m.u64(HASH_A + 16, 0); // count 0
    let reader = reader_over(m);
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let survey = survey_with_reader(&reader, &layout, None).expect("runs");
    let a = &survey.ftrace.ops[0];
    assert!(a
        .notes
        .iter()
        .any(|n| n.contains("every traceable function")));
}

#[test]
fn kprobes_name_the_probed_function_and_judge_the_handler() {
    let survey = survey();
    let probes = &survey.kprobes.probes;
    assert_eq!(probes.len(), 2);
    assert!(survey.kprobes.table_read);
    let p1 = &probes[0];
    assert_eq!(
        p1.probed_attribution,
        Some(Attribution::KernelText {
            symbol: "__x64_sys_read".into(),
            offset: 0
        })
    );
    assert_eq!(p1.verdict, kprobes::ProbeVerdict::KernelHandlers);
    let p2 = &probes[1];
    assert_eq!(p2.symbol_name.as_deref(), Some("__x64_sys_write"));
    assert_eq!(p2.verdict, kprobes::ProbeVerdict::ModuleHandler);
    assert_eq!(survey.kprobes.candidate_count(), 1);
}

#[test]
fn a_probe_with_no_handler_at_all_is_said_to_have_none_not_kernel_handlers() {
    // Both handler pointers null: nothing runs when it fires, so there is
    // nothing to attribute, and "every handler is in the kernel's text" would
    // be true of no handler at all.
    let mut m = image();
    m.u64(KPROBE_1 + 64, 0); // pre_handler = NULL (post_handler is already 0)
    let reader = reader_over(m);
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let survey = survey_with_reader(&reader, &layout, Some(&module_list())).expect("runs");
    let p1 = &survey.kprobes.probes[0];
    assert_eq!(p1.pre_handler, Some(0));
    assert_eq!(p1.post_handler, Some(0));
    assert_eq!(p1.verdict, kprobes::ProbeVerdict::NoHandlers);
    assert!(p1.pre_handler_attribution.is_none());
    assert!(
        survey.kprobes.is_complete(),
        "a handler-less probe was read, not missed"
    );
    assert_eq!(
        survey.kprobes.candidate_count(),
        1,
        "the module probe still is"
    );
    let json = survey.kprobes.to_json();
    assert_eq!(json["probes"][0]["verdict"], "no_handlers");
}

#[test]
fn ebpf_programs_are_listed_from_the_registry_and_explain_direct_calls() {
    let survey = survey();
    let ebpf = &survey.ebpf;
    assert!(ebpf.registry_read);
    assert!(ebpf.registry_complete);
    assert_eq!(ebpf.programs.len(), 2);
    let p1 = &ebpf.programs[0];
    assert_eq!(p1.registry_id, 7);
    assert_eq!(p1.id, Some(7));
    assert_eq!(p1.name.as_deref(), Some("file_open_lsm"));
    assert_eq!(p1.prog_type_name.as_deref(), Some("BPF_PROG_TYPE_TRACING"));
    assert_eq!(p1.prog_type_source, "uapi_header");
    assert_eq!(p1.tag.as_deref(), Some("deadbeef01020304"));
    assert_eq!(p1.attach_func_name.as_deref(), Some("security_file_open"));
    assert_eq!(p1.bpf_func_class, "jit_image");
    let p2 = &ebpf.programs[1];
    assert_eq!(p2.registry_id, 9);
    assert_eq!(p2.prog_type_name.as_deref(), Some("BPF_PROG_TYPE_KPROBE"));
    assert_eq!(ebpf.kprobe_programs, 1);
    assert_eq!(ebpf.perf_dispatched_kprobes, 1);

    // The direct call on security_file_open is explained by program 7; the
    // one on vfs_read goes to the evil module and no program explains it.
    let by_function: std::collections::HashMap<&str, &ebpf::DirectCallExplanation> = ebpf
        .direct_calls
        .iter()
        .map(|d| (d.function.as_deref().unwrap_or(""), d))
        .collect();
    let open = by_function["security_file_open"];
    assert_eq!(open.verdict, "explained_by_bpf_program");
    assert_eq!(open.explained_by, vec![7]);
    let read = by_function["vfs_read"];
    assert_eq!(read.verdict, "module_direct_call");
    assert!(read.explained_by.is_empty());
    assert_eq!(ebpf.unexplained_direct_calls(), 0);
}

#[test]
fn a_direct_call_no_program_explains_is_unexplained() {
    let mut m = image();
    m.u64(ENTRY_D2 + 24, NOWHERE); // vfs_read -> nowhere
    let reader = reader_over(m);
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let modules = module_list();
    let survey = survey_with_reader(&reader, &layout, Some(&modules)).expect("runs");
    assert_eq!(survey.ebpf.unexplained_direct_calls(), 1);
    let json = survey.to_json();
    assert_eq!(json["ebpf"]["unexplained_direct_call_count"], 1);
}

#[test]
fn a_registry_that_cannot_be_walked_is_not_checked_not_empty() {
    let mut m = image();
    m.u64(PROG_IDR + 8, 0x9_0000 | 2); // node off the end of the image
    let reader = reader_over(m);
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let survey = survey_with_reader(&reader, &layout, None).expect("runs");
    assert!(survey.ebpf.programs.is_empty());
    assert!(!survey.ebpf.registry_complete);
    assert!(survey
        .ebpf
        .not_checked
        .iter()
        .any(|n| n.contains("could not be read")));
    assert!(!survey.is_complete());
}

#[test]
fn without_a_module_list_nothing_is_attributed_to_a_module_and_the_map_says_so() {
    let reader = reader_over(image());
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let survey = survey_with_reader(&reader, &layout, None).expect("runs");
    let table = &survey.syscalls.tables[0];
    assert!(table.notable.iter().all(|e| e.verdict_str() == "unknown"));
    assert!(survey.code_map["limitations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|l| l.as_str().unwrap().contains("module list was not walked")));
}

#[test]
fn the_uapi_program_type_table_is_the_header_order() {
    assert_eq!(PROG_TYPES_UAPI[0], "BPF_PROG_TYPE_UNSPEC");
    assert_eq!(PROG_TYPES_UAPI[2], "BPF_PROG_TYPE_KPROBE");
    assert_eq!(PROG_TYPES_UAPI[26], "BPF_PROG_TYPE_TRACING");
    assert_eq!(PROG_TYPES_UAPI[29], "BPF_PROG_TYPE_LSM");
}

#[test]
fn the_xarray_walk_handles_a_single_entry_head_and_a_marker_slot() {
    let mut m = image();
    // A head that is itself the entry at index 0.
    m.u64(PROG_IDR + 8, PROG_1);
    let reader = reader_over(m);
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let walk = xarray::walk(&reader, &layout, PROG_IDR + 8).expect("walks");
    assert_eq!(walk.entries, vec![(0, PROG_1)]);

    let mut m = image();
    m.u64(XA_NODE + 40 + 8 * 3, 0x102); // XA_ZERO_ENTRY-style marker: skipped
    m.u64(XA_NODE + 40 + 8 * 4, 0x11); // a value entry: skipped and counted
    let reader = reader_over(m);
    let layout = HOOKS_LAYOUT.bind(&reader).expect("binds");
    let walk = xarray::walk(&reader, &layout, PROG_IDR + 8).expect("walks");
    assert_eq!(walk.entries, vec![(7, PROG_1), (9, PROG_2)]);
    assert_eq!(walk.value_entries_skipped, 1);
    assert!(walk.is_complete());
}
