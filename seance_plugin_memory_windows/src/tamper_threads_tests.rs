//! The three thread groups: a listing, a reading, and one graded claim.
//!
//! # The fixture declares a build whose members vary
//!
//! `_KTHREAD.SystemThread` is a **bitfield** whose position is 10, 11, 12 or 13
//! depending on the build, and it is absent on 650 of the 1,724 ISFs measured;
//! `_ETHREAD.StartAddressInvalid` is absent on 231; 93 builds declare
//! `_KTRAP_FRAME` with none of the `Dr` members. So the fixture is
//! parameterised on which members exist, and the tests that matter are the ones
//! where a member does not.

use std::sync::Arc;

use super::tamper_threads::*;
use crate::image_fixture::{Image, BASE_TYPES_X64};
use crate::kernel_hooks::{ModuleMap, ModuleRange};
use crate::poolscan::test_support::{profile, table};
use crate::process::{list_processes, ProcessListConfig, ProcessSymbols};
use crate::psxview::threads::ThreadSymbols;
use crate::tamper_unloaded::{RecordLayout, UnloadedDriver, UnloadedTable};
use seance_memory::Architecture;

// Where the fixture puts things. Plain image offsets.
const PS_ACTIVE_HEAD: u64 = 0x200;
const PS_INITIAL_SYSTEM: u64 = 0x300;
const SYSTEM_EPROCESS: u64 = 0x1000;
const THREAD_A: u64 = 0x3000;
const THREAD_B: u64 = 0x4000;
const TRAP_FRAME_A: u64 = 0x5000;
const TRAP_FRAME_B: u64 = 0x6000;

// `_EPROCESS`: ActiveProcessLinks at 48, ThreadListHead at 64.
const EP_LINKS: u64 = 48;
const EP_THREAD_LIST: u64 = 64;

// `_ETHREAD` members the fixture declares.
const ET_CID_THREAD: u64 = 0;
const ET_CID_PROCESS: u64 = 8;
const ET_LIST_ENTRY: u64 = 16;
const ET_CREATE_TIME: u64 = 32;
const ET_EXIT_TIME: u64 = 40;
const ET_START: u64 = 48;
const ET_WIN32_START: u64 = 56;
const ET_START_INVALID: u64 = 64;
// `Tcb` at 128, so every `_KTHREAD` member is reached through it.
const ET_TCB: u64 = 128;
const KT_PROCESS: u64 = 0; // Tcb.Process   -> 128
const KT_STATE: u64 = 8; // Tcb.State     -> 136
const KT_SUSPEND: u64 = 12; // Tcb.SuspendCount -> 140
const KT_MISC: u64 = 16; // Tcb.MiscFlags (SystemThread bit 12) -> 144
const KT_TRAP_FRAME: u64 = 24; // Tcb.TrapFrame -> 152
const KT_HEADER: u64 = 32; // Tcb.Header    -> 160
const DH_DEBUG_ACTIVE: u64 = 0; // Header.DebugActive -> 160
/// `_KTHREAD.DebugActive`, where the NT 5.x builds keep it -> 188.
const KT_DEBUG_ACTIVE: u64 = 60;

/// The bit `SystemThread` occupies in this fixture's `MiscFlags`, chosen to be
/// none of 10/11/13 so a reader masking a remembered constant fails.
const SYSTEM_THREAD_BIT: u32 = 12;

// `_KTRAP_FRAME` members.
const TF_DR0: u64 = 216;
const TF_DR1: u64 = 224;
const TF_DR2: u64 = 232;
const TF_DR3: u64 = 240;
const TF_DR6: u64 = 248;
const TF_DR7: u64 = 256;

/// The x86 layout: six `unsigned long` members at a four-byte stride, as
/// XP SP2's `ntkrnlpa.pdb` declares them (`Dr0` at 0x18 ... `Dr7` at 0x2c).
const TF32_DR: [u64; 6] = [24, 28, 32, 36, 40, 44];

/// A loaded module, and two addresses: one inside it and one in nothing.
const MODULE_BASE: u64 = 0x10_0000;
const MODULE_END: u64 = 0x11_0000;
const IN_MODULE: u64 = 0x10_0400;
const OUTSIDE_ANY_MODULE: u64 = 0x20_0000;
/// Inside the range of the unloaded driver the tests build.
const GONE_START: u64 = 0x30_0000;
const GONE_END: u64 = 0x30_8000;
const IN_GONE: u64 = 0x30_0080;

/// 2021-06-01T00:00:00Z.
const CREATE_TIME: u64 = 132_669_792_000_000_000;

/// Which optional members this build declares.
#[derive(Clone, Copy)]
struct Declares {
    system_thread: bool,
    start_address_invalid: bool,
    debug_registers: bool,
    /// Whether `_DISPATCHER_HEADER` declares `DebugActive`/`ActiveDR7` at all.
    debug_flags: bool,
    /// Whether the `Dr` members are declared `unsigned long` (four bytes, at a
    /// four-byte stride) as every x86 ISF declares them, rather than eight.
    narrow_debug_registers: bool,
    /// Whether `_KTHREAD` itself declares a `DebugActive` byte, as the NT 5.x
    /// builds do (XP SP2's `ntkrnlpa.pdb` has it at `_KTHREAD` + 0x2c) instead
    /// of carrying it in `_DISPATCHER_HEADER`.
    kthread_debug_active: bool,
    /// Where `ActiveDR7` sits inside the `DebugActive` byte. 0 on every real
    /// ISF measured; moved in a test so a reader masking a remembered bit
    /// position fails.
    active_dr7_bit: u32,
}

impl Default for Declares {
    fn default() -> Self {
        Self {
            system_thread: true,
            start_address_invalid: true,
            debug_registers: true,
            debug_flags: true,
            narrow_debug_registers: false,
            kthread_debug_active: false,
            active_dr7_bit: 0,
        }
    }
}

fn isf(d: Declares) -> String {
    let system_thread = if d.system_thread {
        format!(
            r#","SystemThread": {{"offset": {KT_MISC}, "type": {{"kind": "bitfield",
                       "bit_position": {SYSTEM_THREAD_BIT}, "bit_length": 1,
                       "type": {{"kind": "base", "name": "unsigned long"}}}}}}"#
        )
    } else {
        String::new()
    };
    let start_invalid = if d.start_address_invalid {
        format!(
            r#","StartAddressInvalid": {{"offset": {ET_START_INVALID}, "type": {{"kind": "base",
                             "name": "unsigned char"}}}}"#
        )
    } else {
        String::new()
    };
    let active_dr7_bit = d.active_dr7_bit;
    let debug_flags = if d.debug_flags {
        format!(
            r#","DebugActive": {{"offset": {DH_DEBUG_ACTIVE}, "type": {{"kind": "base",
                      "name": "unsigned char"}}}},
      "ActiveDR7": {{"offset": {DH_DEBUG_ACTIVE}, "type": {{"kind": "bitfield",
                    "bit_position": {active_dr7_bit}, "bit_length": 1,
                    "type": {{"kind": "base", "name": "unsigned char"}}}}}}"#
        )
    } else {
        String::new()
    };
    let dr = if d.debug_registers && d.narrow_debug_registers {
        let [d0, d1, d2, d3, d6, d7] = TF32_DR;
        format!(
            r#"
      "Dr0": {{"offset": {d0}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "Dr1": {{"offset": {d1}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "Dr2": {{"offset": {d2}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "Dr3": {{"offset": {d3}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "Dr6": {{"offset": {d6}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "Dr7": {{"offset": {d7}, "type": {{"kind": "base", "name": "unsigned long"}}}}"#
        )
    } else if d.debug_registers {
        format!(
            r#"
      "Dr0": {{"offset": {TF_DR0}, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Dr1": {{"offset": {TF_DR1}, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Dr2": {{"offset": {TF_DR2}, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Dr3": {{"offset": {TF_DR3}, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Dr6": {{"offset": {TF_DR6}, "type": {{"kind": "base", "name": "unsigned long long"}}}},
      "Dr7": {{"offset": {TF_DR7}, "type": {{"kind": "base", "name": "unsigned long long"}}}}"#
        )
    } else {
        // The 93 ISFs that declare the type with none of the registers.
        r#""Rip": {"offset": 336, "type": {"kind": "base", "name": "unsigned long long"}}"#
            .to_string()
    };

    let kthread_debug_active = if d.kthread_debug_active {
        format!(
            r#","DebugActive": {{"offset": {KT_DEBUG_ACTIVE}, "type": {{"kind": "base",
                      "name": "unsigned char"}}}}"#
        )
    } else {
        String::new()
    };

    format!(
        r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "1A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {base},
  "user_types": {{
    "_LIST_ENTRY": {{"size": 16, "kind": "struct", "fields": {{
      "Flink": {{"offset": 0, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}},
      "Blink": {{"offset": 8, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}
    }}}},
    "_LARGE_INTEGER": {{"size": 8, "kind": "union", "fields": {{
      "QuadPart": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    "_CLIENT_ID": {{"size": 16, "kind": "struct", "fields": {{
      "UniqueThread": {{"offset": 0, "type": {{"kind": "pointer",
                       "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "UniqueProcess": {{"offset": 8, "type": {{"kind": "pointer",
                        "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}},
    "_DISPATCHER_HEADER": {{"size": 24, "kind": "struct", "fields": {{
      "Type": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned char"}}}}{debug_flags}
    }}}},
    "_KTRAP_FRAME": {{"size": 400, "kind": "struct", "fields": {{{dr}
    }}}},
    "_KTHREAD": {{"size": 64, "kind": "struct", "fields": {{
      "Process": {{"offset": {kt_process}, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "State": {{"offset": {kt_state}, "type": {{"kind": "base", "name": "unsigned char"}}}},
      "SuspendCount": {{"offset": {kt_suspend}, "type": {{"kind": "base", "name": "long"}}}},
      "MiscFlags": {{"offset": {kt_misc}, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "TrapFrame": {{"offset": {kt_trap}, "type": {{"kind": "pointer",
                    "subtype": {{"kind": "struct", "name": "_KTRAP_FRAME"}}}}}},
      "Header": {{"offset": {kt_header}, "type": {{"kind": "struct",
                 "name": "_DISPATCHER_HEADER"}}}}{system_thread}{kthread_debug_active}
    }}}},
    "_ETHREAD": {{"size": 256, "kind": "struct", "fields": {{
      "Cid": {{"offset": 0, "type": {{"kind": "struct", "name": "_CLIENT_ID"}}}},
      "ThreadListEntry": {{"offset": {et_list}, "type": {{"kind": "struct",
                          "name": "_LIST_ENTRY"}}}},
      "CreateTime": {{"offset": {et_create}, "type": {{"kind": "union",
                     "name": "_LARGE_INTEGER"}}}},
      "ExitTime": {{"offset": {et_exit}, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "StartAddress": {{"offset": {et_start}, "type": {{"kind": "pointer",
                       "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "Win32StartAddress": {{"offset": {et_win32}, "type": {{"kind": "pointer",
                            "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "Tcb": {{"offset": {et_tcb}, "type": {{"kind": "struct", "name": "_KTHREAD"}}}}{start_invalid}
    }}}},
    "_EPROCESS": {{"size": 640, "kind": "struct", "fields": {{
      "UniqueProcessId": {{"offset": 0, "type": {{"kind": "pointer",
                          "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ImageFileName": {{"offset": 8, "type": {{"kind": "array", "count": 15,
                        "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "CreateTime": {{"offset": 32, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "ActiveProcessLinks": {{"offset": {ep_links}, "type": {{"kind": "struct",
                             "name": "_LIST_ENTRY"}}}},
      "ThreadListHead": {{"offset": {ep_threads}, "type": {{"kind": "struct",
                         "name": "_LIST_ENTRY"}}}},
      "DirectoryTableBase": {{"offset": 96, "type": {{"kind": "base",
                             "name": "unsigned long long"}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "PsActiveProcessHead": {{"address": {head}}},
    "PsInitialSystemProcess": {{"address": {system}}}
  }}
}}"#,
        base = BASE_TYPES_X64,
        debug_flags = debug_flags,
        dr = dr,
        kt_process = KT_PROCESS,
        kt_state = KT_STATE,
        kt_suspend = KT_SUSPEND,
        kt_misc = KT_MISC,
        kt_trap = KT_TRAP_FRAME,
        kt_header = KT_HEADER,
        system_thread = system_thread,
        kthread_debug_active = kthread_debug_active,
        et_list = ET_LIST_ENTRY,
        et_create = ET_CREATE_TIME,
        et_exit = ET_EXIT_TIME,
        et_start = ET_START,
        et_win32 = ET_WIN32_START,
        et_tcb = ET_TCB,
        start_invalid = start_invalid,
        ep_links = EP_LINKS,
        ep_threads = EP_THREAD_LIST,
        head = PS_ACTIVE_HEAD,
        system = PS_INITIAL_SYSTEM,
    )
}

/// How one thread is set up.
#[derive(Clone, Copy)]
struct Thread {
    at: u64,
    tid: u64,
    start: u64,
    kernel_thread: bool,
    terminated: bool,
    start_invalid: bool,
    suspend_count: u32,
    trap_frame: Option<u64>,
    dr: [u64; 4],
    dr6: u64,
    dr7: u64,
    debug_active: u8,
    /// Write the registers as four-byte values at [`TF32_DR`].
    narrow_debug_registers: bool,
}

impl Thread {
    fn new(at: u64, tid: u64, start: u64) -> Self {
        Self {
            at,
            tid,
            start,
            kernel_thread: true,
            terminated: false,
            start_invalid: false,
            suspend_count: 0,
            trap_frame: None,
            dr: [0; 4],
            dr6: 0,
            dr7: 0,
            debug_active: 0,
            narrow_debug_registers: false,
        }
    }
}

/// One system process with the given threads on its list.
fn image(threads: &[Thread]) -> Image {
    let mut img = Image::sized(0x40_0000);
    // The active process list: head -> the one process -> head.
    let links = SYSTEM_EPROCESS + EP_LINKS;
    img.put_u64(PS_ACTIVE_HEAD, links);
    img.put_u64(PS_ACTIVE_HEAD + 8, links);
    img.put_u64(links, PS_ACTIVE_HEAD);
    img.put_u64(links + 8, PS_ACTIVE_HEAD);
    img.put_u64(PS_INITIAL_SYSTEM, SYSTEM_EPROCESS);
    img.put_u64(SYSTEM_EPROCESS, 4);
    img.write(SYSTEM_EPROCESS + 8, b"System\0");
    img.put_u64(SYSTEM_EPROCESS + 32, CREATE_TIME);
    img.put_u64(SYSTEM_EPROCESS + 96, 0x1000);

    // The thread list, threaded through ThreadListEntry.
    let head = SYSTEM_EPROCESS + EP_THREAD_LIST;
    let mut previous = head;
    for t in threads {
        let link = t.at + ET_LIST_ENTRY;
        img.put_u64(previous, link);
        img.put_u64(link + 8, previous);
        previous = link;

        img.put_u64(t.at + ET_CID_THREAD, t.tid);
        img.put_u64(t.at + ET_CID_PROCESS, 4);
        img.put_u64(t.at + ET_CREATE_TIME, CREATE_TIME);
        img.put_u64(
            t.at + ET_EXIT_TIME,
            if t.terminated { CREATE_TIME } else { 0 },
        );
        img.put_u64(t.at + ET_START, t.start);
        img.put_u64(t.at + ET_WIN32_START, 0);
        img.put_u8(t.at + ET_START_INVALID, u8::from(t.start_invalid));
        img.put_u64(t.at + ET_TCB + KT_PROCESS, SYSTEM_EPROCESS);
        img.put_u8(t.at + ET_TCB + KT_STATE, 2);
        img.put_u32(t.at + ET_TCB + KT_SUSPEND, t.suspend_count);
        img.put_u32(
            t.at + ET_TCB + KT_MISC,
            if t.kernel_thread {
                1 << SYSTEM_THREAD_BIT
            } else {
                0
            },
        );
        img.put_u64(t.at + ET_TCB + KT_TRAP_FRAME, t.trap_frame.unwrap_or(0));
        img.put_u8(t.at + ET_TCB + KT_HEADER + DH_DEBUG_ACTIVE, t.debug_active);
        img.put_u8(t.at + ET_TCB + KT_DEBUG_ACTIVE, t.debug_active);
        if let Some(frame) = t.trap_frame {
            if t.narrow_debug_registers {
                let values = [t.dr[0], t.dr[1], t.dr[2], t.dr[3], t.dr6, t.dr7];
                for (off, value) in TF32_DR.iter().zip(values) {
                    img.put_u32(frame + off, value as u32);
                }
            } else {
                for (i, off) in [TF_DR0, TF_DR1, TF_DR2, TF_DR3].iter().enumerate() {
                    img.put_u64(frame + off, t.dr[i]);
                }
                img.put_u64(frame + TF_DR6, t.dr6);
                img.put_u64(frame + TF_DR7, t.dr7);
            }
        }
    }
    // Close the ring.
    img.put_u64(previous, head);
    img.put_u64(head + 8, previous);
    img
}

fn modules() -> ModuleMap {
    ModuleMap::from_ranges(vec![ModuleRange {
        base: MODULE_BASE,
        end: MODULE_END,
        name: Some("loaded.sys".to_string()),
        entry: 0,
    }])
}

/// An unloaded-driver table holding one freed range.
fn unloaded_table() -> UnloadedTable {
    UnloadedTable {
        drivers: vec![UnloadedDriver {
            slot: 0,
            newest: true,
            name: Some("gone.sys".to_string()),
            name_unavailable: None,
            start: GONE_START,
            end: GONE_END,
            unloaded_filetime: 0,
            layout: RecordLayout::DocumentedX64,
        }],
        write_count: 1,
        wrapped: false,
        layout: RecordLayout::DocumentedX64,
        hits: Vec::new(),
        notes: Vec::new(),
        capped: None,
    }
}

fn run(threads: &[Thread], d: Declares, unloaded: Option<&UnloadedTable>) -> ThreadTamperOutcome {
    let isf_text = isf(d);
    let profile = profile(
        image(threads).layer(),
        table(&isf_text),
        Architecture::X64,
        10,
        0,
        Some(22000),
    );
    let process_symbols = ProcessSymbols::from_profile(&profile).expect("process symbols");
    let list = list_processes(&profile, &process_symbols, &ProcessListConfig::default())
        .expect("the process list walks");
    assert_eq!(list.processes.len(), 1, "one process on the fixture's list");
    let thread_symbols = ThreadSymbols::from_profile(&profile).expect("thread symbols");
    examine_threads(&profile, &thread_symbols, &list, &modules(), unloaded, 4096)
        .expect("the pass runs")
}

// --- DR7's enable bits -----------------------------------------------------

/// **`Dr7`'s enable bits decide what a breakpoint is**, per slot, and the two
/// enables are distinguished.
#[test]
fn dr7_names_the_armed_slots_and_which_enable_armed_each() {
    assert_eq!(armed_slots(0), [None, None, None, None]);
    // L0 only, then G0 only, then both.
    assert_eq!(armed_slots(0b0000_0001)[0], Some("local"));
    assert_eq!(armed_slots(0b0000_0010)[0], Some("global"));
    assert_eq!(armed_slots(0b0000_0011)[0], Some("local+global"));
    // Slot 3's enables are bits 6 and 7, not bits 3 and 4.
    assert_eq!(armed_slots(0b0100_0000)[3], Some("local"));
    assert_eq!(armed_slots(0b1000_0000)[3], Some("global"));
    assert_eq!(armed_slots(0b0000_1000)[3], None);
    assert_eq!(armed_slots(0b0000_1000)[1], Some("global"));
    // The bits above 7 are not enables and arm nothing.
    assert_eq!(armed_slots(0xFFFF_FF00), [None, None, None, None]);
}

/// **A non-zero `Dr0` with no enable bit is stale, not a breakpoint.** This is
/// the rule that would otherwise fire on a clean machine.
#[test]
fn an_address_in_a_slot_dr7_does_not_arm_is_stale_and_not_a_breakpoint() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.debug_active = 1; // the thread claims debug state, so the registers are live
    t.dr = [OUTSIDE_ANY_MODULE, 0, 0, 0];
    t.dr7 = 0; // nothing armed
    let out = run(&[t], Declares::default(), None);
    assert_eq!(out.debug.len(), 1, "the row is published");
    let row = &out.debug[0];
    assert!(!row.has_breakpoint());
    assert_eq!(row.stale_slots, vec![0]);
    let j = row.to_json();
    assert_eq!(j["armed_slots"], serde_json::json!(0));
    assert_eq!(j["has_breakpoint"], serde_json::json!(false));
    assert!(
        j["basis"].as_str().unwrap_or_default().contains("STALE"),
        "the record says why: {:?}",
        j["basis"]
    );
    assert_eq!(out.with_breakpoints(), 0);
}

/// An armed slot is a breakpoint, with the address attributed.
#[test]
fn an_armed_slot_is_a_breakpoint_with_its_address_attributed() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.dr = [IN_MODULE, 0, 0, OUTSIDE_ANY_MODULE];
    // L0 and G3: slots 0 and 3.
    t.dr7 = 0b1000_0001;
    t.dr6 = 0b0000_0001;
    t.debug_active = 1;
    let out = run(&[t], Declares::default(), None);
    let row = &out.debug[0];
    assert!(row.has_breakpoint());
    assert_eq!(row.armed_by_dr7.len(), 2);
    assert_eq!(row.armed_by_dr7[0].slot, 0);
    assert_eq!(row.armed_by_dr7[0].enable, "local");
    assert_eq!(row.armed_by_dr7[1].slot, 3);
    assert_eq!(row.armed_by_dr7[1].enable, "global");
    assert!(row.armed_by_dr7[1].ownership.is_outside_any_module());
    assert_eq!(row.debug_active, Some(1));
    assert_eq!(
        row.active_dr7,
        Some(1),
        "the bitfield reads through the table"
    );
    assert_eq!(row.dr6, Some(1));
    assert!(row.stale_slots.is_empty());
    assert_eq!(out.with_breakpoints(), 1);
}

/// **A breakpoint whose every armed address is in the null page is published
/// and not graded** (`MEM-050`, decided 2026-09-24).
///
/// The register values are the ones measured on all four Windows XP captures
/// held here: one `winlogon.exe` thread with `DebugActive` = 0x8f, `Dr7` =
/// 0x555 (L0-L3) and `Dr0`-`Dr3` = 1, 2, 1, 0xa. Graded, that is an armed
/// breakpoint on every clean XP capture of the build — the `HUNT-051` shape.
/// No address below `MM_LOWEST_USER_ADDRESS` (0x10000) is ever handed out by
/// the ordinary allocator, so the row is kept, with the addresses and the
/// reason, and is not a lead.
#[test]
fn a_breakpoint_armed_only_in_the_null_page_is_published_and_not_graded() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.narrow_debug_registers = true;
    t.debug_active = 0x8f;
    t.dr = [1, 2, 1, 0xa];
    t.dr7 = 0x555;
    let out = run(
        &[t],
        Declares {
            debug_flags: false,
            narrow_debug_registers: true,
            kthread_debug_active: true,
            ..Declares::default()
        },
        None,
    );
    assert_eq!(out.debug.len(), 1, "the observation is still published");
    let row = &out.debug[0];
    assert_eq!(row.claim, DebugClaim::ConfirmedByThread);
    assert_eq!(row.armed_by_dr7.len(), 4, "Dr7 still arms all four slots");
    assert!(
        !row.has_breakpoint(),
        "every armed address is in the null page, so this is not graded: {row:?}"
    );
    assert_eq!(out.with_breakpoints(), 0);
    let j = row.to_json();
    assert_eq!(j["has_breakpoint"], serde_json::json!(false));
    assert_eq!(j["armed_only_in_the_null_page"], serde_json::json!(true));
    assert_eq!(j["armed_slots"], serde_json::json!(4));
    let reason = j["not_graded_reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("0x10000") && reason.contains("MM_LOWEST_USER_ADDRESS"),
        "the record states the bound and where it comes from: {reason:?}"
    );
    assert_eq!(
        j["breakpoints"][3]["address"],
        serde_json::json!("0x000000000000000a"),
        "the addresses stay on the record"
    );
}

/// **One armed address outside the null page is enough to grade the row**,
/// even when the other armed slots sit in it.
#[test]
fn an_armed_address_outside_the_null_page_is_still_graded() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.narrow_debug_registers = true;
    t.debug_active = 0x8f;
    t.dr = [1, 2, 1, 0x10000]; // the first address the bound admits
    t.dr7 = 0x555;
    let out = run(
        &[t],
        Declares {
            debug_flags: false,
            narrow_debug_registers: true,
            kthread_debug_active: true,
            ..Declares::default()
        },
        None,
    );
    let row = &out.debug[0];
    assert!(
        row.has_breakpoint(),
        "Dr3 = 0x10000 is outside the null page"
    );
    assert_eq!(out.with_breakpoints(), 1);
    let j = row.to_json();
    assert_eq!(j["armed_only_in_the_null_page"], serde_json::json!(false));
    assert!(j["not_graded_reason"].is_null());
}

/// A thread with no debug state at all produces **no row**. Publishing one per
/// thread would bury the threads that matter under every thread on the
/// machine.
#[test]
fn a_thread_with_no_debug_state_produces_no_row() {
    let t = Thread::new(THREAD_A, 100, IN_MODULE);
    let out = run(&[t], Declares::default(), None);
    assert!(out.debug.is_empty());
    assert_eq!(out.threads_examined, 1, "it was still examined");
}

/// **A build whose `_KTRAP_FRAME` declares no `Dr` members reads none**, and
/// says so rather than reporting a machine with no breakpoints.
#[test]
fn a_build_without_the_debug_registers_says_so_and_claims_nothing() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.debug_active = 1;
    t.dr = [OUTSIDE_ANY_MODULE, 0, 0, 0];
    t.dr7 = 1;
    let out = run(
        &[t],
        Declares {
            debug_registers: false,
            ..Declares::default()
        },
        None,
    );
    assert!(out.debug.is_empty(), "nothing was read, so nothing is said");
    let note = out
        .symbols
        .unavailable
        .iter()
        .find(|n| n.contains("_KTRAP_FRAME"))
        .expect("the absence is stated");
    assert!(note.contains("would look exactly like"), "got {note}");
    assert_eq!(
        out.symbols.to_json()["debug_registers_readable"],
        serde_json::json!(false)
    );
}

/// **The registers are read only when the thread's own flags say they are
/// live, and this is the single most important rule in the group.**
///
/// Measured on the Windows 11 26200 capture, and then confirmed in that build's
/// own symbols: `_KTRAP_FRAME.Dr0` shares offset 216 with `ShadowStackFrame`
/// and `Dr1` shares 224 with `Spare[5]` — the ISF flattens a union, and the
/// only thing that says which interpretation applies is
/// `_DISPATCHER_HEADER.DebugActive` / `ActiveDR7`. Reading them regardless
/// produced **nine rows on a clean machine, five of them claiming armed
/// breakpoints**, every one of which was a shadow-stack pointer read as a
/// debug register. That is the `HUNT-051` shape exactly, and it was caught by
/// running the check against a real capture before shipping it.
#[test]
fn a_thread_claiming_no_debug_state_has_no_readable_registers() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.debug_active = 0;
    // Bytes that would read as three armed breakpoints if they were registers.
    t.dr = [OUTSIDE_ANY_MODULE, IN_MODULE, OUTSIDE_ANY_MODULE, 0];
    t.dr7 = 0xFFFF_9A0B_A9CD_8A40; // a kernel pointer, as measured
    let out = run(&[t], Declares::default(), None);
    assert!(
        out.debug.is_empty(),
        "a thread whose own flags are clear has no debug registers to read: {:?}",
        out.debug
    );
    assert_eq!(out.with_breakpoints(), 0);
    let j = out.to_json();
    assert_eq!(j["threads_claiming_debug_state"], serde_json::json!(0));
    assert!(
        j["debug_register_basis"]
            .as_str()
            .unwrap_or_default()
            .contains("ShadowStackFrame"),
        "the record names the union that makes this necessary: {:?}",
        j["debug_register_basis"]
    );
}

/// `ActiveDR7` alone is enough: it is the bit that says `Dr7` is live.
#[test]
fn the_active_dr7_flag_alone_makes_the_registers_readable() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    // Bit 0 of the same byte is `ActiveDR7` in this build, as in the real one.
    t.debug_active = 1;
    t.dr = [IN_MODULE, 0, 0, 0];
    t.dr7 = 1;
    let out = run(&[t], Declares::default(), None);
    assert_eq!(out.debug.len(), 1);
    assert!(out.debug[0].has_breakpoint());
    assert_eq!(out.debug[0].claim, DebugClaim::ConfirmedByThread);
}

/// **`MEM-051`: on a build that declares `ActiveDR7`, only that bit confirms
/// the registers.** `DebugActive` is the whole byte, and on Windows 10 the
/// same byte carries `Instrumented` (bit 1), `Minimal`, `AltSyscall` and the
/// UMS flags. LoneWolf's graded row was a thread with `DebugActive` = 2 —
/// `Instrumented` set, `ActiveDR7` clear — whose trap-frame bytes read as an
/// armed `Dr7`. A byte that is non-zero for another reason is not the
/// thread saying its debug registers are live.
#[test]
fn a_debug_active_byte_set_by_another_flag_is_not_confirmation() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.debug_active = 2; // `Instrumented`, not `ActiveDR7`
    t.dr = [OUTSIDE_ANY_MODULE, 0, 0, 0];
    t.dr7 = 1;
    let out = run(&[t], Declares::default(), None);
    assert_eq!(
        out.with_breakpoints(),
        0,
        "ActiveDR7 is clear, so nothing says these bytes are debug registers: {:?}",
        out.debug
    );
    assert!(
        out.debug.is_empty(),
        "the thread's declared flag says its registers are not live: {:?}",
        out.debug
    );
}

/// The bit position comes from this build's own bitfield declaration, never
/// from a remembered constant: with `ActiveDR7` declared at bit 3, a byte with
/// only bit 0 set confirms nothing and a byte with bit 3 set does.
#[test]
fn the_active_dr7_bit_is_read_where_this_build_declares_it() {
    let declares = Declares {
        active_dr7_bit: 3,
        ..Declares::default()
    };
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.dr = [OUTSIDE_ANY_MODULE, 0, 0, 0];
    t.dr7 = 1;
    t.debug_active = 1;
    let out = run(&[t], declares, None);
    assert!(
        out.debug.is_empty(),
        "bit 0 is not ActiveDR7 on this build: {:?}",
        out.debug
    );
    t.debug_active = 1 << 3;
    let out = run(&[t], declares, None);
    assert_eq!(out.debug.len(), 1);
    assert_eq!(out.debug[0].claim, DebugClaim::ConfirmedByThread);
    assert!(out.debug[0].has_breakpoint());
}

/// **`MEM-051`: a thread that cannot be a real thread is published and not
/// graded.** Thread ID 0 belongs to no thread a process owns (the idle
/// threads are the only holders), and the LoneWolf and 13Cubed rows that
/// graded were Tid 0 with register values that read as pool bytes.
#[test]
fn a_breakpoint_on_a_thread_with_tid_zero_is_published_and_not_graded() {
    let mut t = Thread::new(THREAD_A, 0, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.debug_active = 1;
    t.dr = [OUTSIDE_ANY_MODULE, 0, 0, 0];
    t.dr7 = 1;
    let out = run(&[t], Declares::default(), None);
    assert_eq!(out.debug.len(), 1, "the row is still published");
    let row = &out.debug[0];
    assert!(
        !row.has_breakpoint(),
        "a Tid-0 thread is not graded: {row:?}"
    );
    assert_eq!(out.with_breakpoints(), 0);
    let reason = row.to_json()["not_graded_reason"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(reason.contains("Tid 0"), "the reason is stated: {reason:?}");
}

/// An armed address that is not a canonical address for this build's pointer
/// width cannot be where a breakpoint fires: the processor faults on it. The
/// LoneWolf row's `Dr1` was 0x65536d4d02060005.
#[test]
fn a_breakpoint_on_a_non_canonical_address_is_published_and_not_graded() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.debug_active = 1;
    t.dr = [0x6553_6d4d_0206_0005, 0, 0, 0];
    t.dr7 = 1;
    let out = run(&[t], Declares::default(), None);
    let row = &out.debug[0];
    assert!(!row.has_breakpoint(), "{row:?}");
    let reason = row.to_json()["not_graded_reason"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(
        reason.contains("canonical"),
        "the reason is stated: {reason:?}"
    );
}

/// **A build declaring neither flag cannot confirm the registers**, so the
/// values are published and no breakpoint is claimed. 152 of the 1,724 ISFs
/// measured declare no `DebugActive`.
#[test]
fn without_either_flag_the_values_are_published_and_no_breakpoint_is_claimed() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.dr = [IN_MODULE, 0, 0, 0];
    t.dr7 = 1;
    let out = run(
        &[t],
        Declares {
            debug_flags: false,
            ..Declares::default()
        },
        None,
    );
    assert_eq!(out.debug.len(), 1, "the values are still published");
    let row = &out.debug[0];
    assert_eq!(row.claim, DebugClaim::Unconfirmed);
    assert!(
        !row.has_breakpoint(),
        "nothing confirms these bytes are debug registers, so no breakpoint is claimed"
    );
    assert_eq!(
        row.armed_by_dr7.len(),
        1,
        "what DR7's bits say is still shown"
    );
    let j = row.to_json();
    assert_eq!(j["has_breakpoint"], serde_json::json!(false));
    assert!(
        j["claim"]
            .as_str()
            .unwrap_or_default()
            .contains("unconfirmed"),
        "got {:?}",
        j["claim"]
    );
}

/// **An x86 build's debug registers are four bytes wide, and are read at the
/// width the build declares** (found 2026-09-24 on `tigger.vmem`, XP SP2 PAE).
///
/// `_KTRAP_FRAME.Dr0`-`Dr7` are `unsigned long` at a four-byte stride on every
/// x86 ISF. Reading eight bytes at each offset glues two registers together:
/// the real capture published `Dr0 = 0x0000000200000001` for a winlogon thread
/// whose `Dr0` and `Dr1` were 1 and 2, and attributed that to no module.
#[test]
fn an_x86_builds_debug_registers_are_read_at_their_declared_width() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.narrow_debug_registers = true;
    t.debug_active = 1;
    t.dr = [IN_MODULE, 2, 0, OUTSIDE_ANY_MODULE];
    t.dr6 = 0xFFFF_0FF0;
    t.dr7 = 0b0000_0001; // L0 only
    let out = run(
        &[t],
        Declares {
            narrow_debug_registers: true,
            ..Declares::default()
        },
        None,
    );
    assert_eq!(out.debug.len(), 1, "the confirmed thread is published");
    let row = &out.debug[0];
    assert_eq!(
        row.dr,
        [Some(IN_MODULE), Some(2), Some(0), Some(OUTSIDE_ANY_MODULE)],
        "each register is its own four bytes, not two registers read as one"
    );
    assert_eq!(row.dr6, Some(0xFFFF_0FF0));
    assert_eq!(row.dr7, Some(1));
    assert_eq!(row.armed_by_dr7.len(), 1);
    assert_eq!(row.armed_by_dr7[0].address, IN_MODULE);
    assert!(
        !row.armed_by_dr7[0].ownership.is_outside_any_module(),
        "Dr0 is inside the loaded module"
    );
}

/// **The NT 5.x builds keep `DebugActive` in `_KTHREAD` itself**, and a
/// thread whose flag there is clear has no live registers (found 2026-09-24
/// on `tigger.vmem`).
///
/// XP SP2's ISF declares no `_DISPATCHER_HEADER.DebugActive`; the flag is
/// `_KTHREAD.DebugActive`, a byte at 0x2c. Looking only in the dispatcher
/// header left the XP capture with an `unconfirmed` row whose trap-frame bytes
/// read as four armed slots, when the thread's own flag said nothing was live.
#[test]
fn an_nt5_builds_kthread_debug_active_is_the_threads_own_claim() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.trap_frame = Some(TRAP_FRAME_A);
    t.narrow_debug_registers = true;
    t.debug_active = 0;
    // What the XP capture held: small integers and an enable-looking Dr7.
    t.dr = [1, 2, 1, 0xa];
    t.dr7 = 0x555;
    let declares = Declares {
        debug_flags: false,
        narrow_debug_registers: true,
        kthread_debug_active: true,
        ..Declares::default()
    };
    let out = run(&[t], declares, None);
    assert_eq!(
        out.symbols.debug_active.as_deref(),
        Some("Tcb.DebugActive"),
        "the flag is found where this build declares it"
    );
    assert!(
        out.debug.is_empty(),
        "the thread says its registers are not live, so there is nothing to read: {:?}",
        out.debug
    );

    // And a thread whose flag IS set is confirmed through the same member.
    let mut armed = Thread::new(THREAD_A, 100, IN_MODULE);
    armed.trap_frame = Some(TRAP_FRAME_A);
    armed.narrow_debug_registers = true;
    armed.debug_active = 1;
    armed.dr = [OUTSIDE_ANY_MODULE, 0, 0, 0];
    armed.dr7 = 1;
    let out = run(&[armed], declares, None);
    assert_eq!(out.debug.len(), 1);
    assert_eq!(out.debug[0].claim, DebugClaim::ConfirmedByThread);
    assert!(out.debug[0].has_breakpoint());
}

/// **A user thread is not this group's question, and does not become a row.**
///
/// Measured: on the Windows 11 capture 1,284 of 1,514 threads are user threads
/// whose `StartAddress` is `RtlUserThreadStart` in ntdll — a *user*-space
/// module, which a kernel module map cannot attribute by construction. A row
/// each would have buried the question under 1,284 observations. The count is
/// kept instead.
#[test]
fn a_user_thread_is_counted_rather_than_published_as_an_observation() {
    let mut user = Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE);
    user.kernel_thread = false;
    let kernel = Thread::new(THREAD_B, 101, OUTSIDE_ANY_MODULE);
    let table = unloaded_table();
    let out = run(&[user, kernel], Declares::default(), Some(&table));
    assert_eq!(out.orphans.len(), 1, "only the kernel thread has a row");
    assert_eq!(out.orphans[0].who.tid, Some(101));
    assert_eq!(out.user_threads_set_aside, 1);
    let j = out.to_json();
    assert_eq!(j["user_threads_set_aside"], serde_json::json!(1));
    assert!(
        j["user_threads_note"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot attribute"),
        "the record says why they are not rows: {:?}",
        j["user_threads_note"]
    );
}

// --- suspended threads -----------------------------------------------------

/// **Suspension is a listing, not a finding**, and every row says so.
#[test]
fn a_suspended_thread_is_listed_and_is_not_a_finding() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.suspend_count = 2;
    let mut other = Thread::new(THREAD_B, 101, IN_MODULE);
    other.suspend_count = 0;
    let out = run(&[t, other], Declares::default(), None);
    assert_eq!(out.suspended.len(), 1, "only the suspended one");
    let row = &out.suspended[0];
    assert_eq!(row.suspend_count, 2);
    assert_eq!(row.who.tid, Some(100));
    assert_eq!(row.who.process_name.as_deref(), Some("System"));
    let j = row.to_json();
    assert_eq!(j["is_a_finding"], serde_json::json!(false));
    assert!(
        j["basis"]
            .as_str()
            .unwrap_or_default()
            .contains("CREATE_SUSPENDED"),
        "the basis names what else suspends a thread: {:?}",
        j["basis"]
    );
}

// --- orphan kernel threads -------------------------------------------------

/// **A kernel thread starting outside every loaded module, with all four
/// exclusions assessed and satisfied, is a graded finding.**
#[test]
fn an_orphan_with_every_exclusion_satisfied_is_graded() {
    let t = Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE);
    let table = unloaded_table();
    let out = run(&[t], Declares::default(), Some(&table));
    assert_eq!(out.orphans.len(), 1);
    let o = &out.orphans[0];
    assert!(o.is_graded(), "{:?}", o.exclusions);
    assert!(o.exclusions.fully_assessed());
    assert_eq!(out.graded_orphans(), 1);
    assert_eq!(out.ungraded_orphans(), 0);
    let j = o.to_json();
    assert_eq!(j["is_graded_finding"], serde_json::json!(true));
    assert!(o.kernel_thread_basis.contains("SystemThread"));
}

/// A start address inside a loaded module is not a candidate at all.
#[test]
fn a_thread_starting_inside_a_loaded_module_is_not_a_candidate() {
    let t = Thread::new(THREAD_A, 100, IN_MODULE);
    let table = unloaded_table();
    let out = run(&[t], Declares::default(), Some(&table));
    assert!(out.orphans.is_empty());
}

/// **Without the unloaded-driver table the claim is not graded**, because the
/// one explanation that accounts for the address without anything being wrong
/// could not be ruled out.
#[test]
fn an_orphan_without_the_unloaded_table_is_an_observation_and_not_a_finding() {
    let t = Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE);
    let out = run(&[t], Declares::default(), None);
    assert_eq!(out.orphans.len(), 1);
    let o = &out.orphans[0];
    assert!(!o.is_graded());
    assert!(!o.exclusions.fully_assessed());
    assert!(matches!(
        o.exclusions.not_in_an_unloaded_range,
        Assessment::NotAssessed(_)
    ));
    assert_eq!(out.graded_orphans(), 0);
    assert_eq!(out.ungraded_orphans(), 1);
    let j = o.to_json();
    assert_eq!(j["is_graded_finding"], serde_json::json!(false));
    assert_eq!(
        j["exclusions"]["not_in_an_unloaded_range"]["state"],
        serde_json::json!("not_assessed")
    );
    assert!(j["exclusions"]["not_in_an_unloaded_range"]["detail"]
        .as_str()
        .unwrap_or_default()
        .contains("WITHOUT anything being wrong"));
}

/// A start address inside an unloaded driver's range is **excluded**: that
/// explains it without anything being wrong.
#[test]
fn an_orphan_inside_an_unloaded_drivers_range_is_excluded_by_name() {
    let t = Thread::new(THREAD_A, 100, IN_GONE);
    let table = unloaded_table();
    let out = run(&[t], Declares::default(), Some(&table));
    let o = &out.orphans[0];
    assert!(!o.is_graded());
    assert!(
        o.exclusions.fully_assessed(),
        "it WAS assessed -- and failed"
    );
    match &o.exclusions.not_in_an_unloaded_range {
        Assessment::Excluded(detail) => assert!(detail.contains("gone.sys"), "got {detail}"),
        other => panic!("expected an exclusion, got {other:?}"),
    }
}

/// A terminated thread is excluded: its start address is a stale value.
#[test]
fn a_terminated_thread_is_excluded() {
    let mut t = Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE);
    t.terminated = true;
    let table = unloaded_table();
    let out = run(&[t], Declares::default(), Some(&table));
    let o = &out.orphans[0];
    assert!(!o.is_graded());
    assert!(matches!(
        o.exclusions.not_terminated,
        Assessment::Excluded(_)
    ));
}

/// `StartAddressInvalid` set is the kernel itself saying the address means
/// nothing.
#[test]
fn a_thread_the_kernel_marked_start_address_invalid_is_excluded() {
    let mut t = Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE);
    t.start_invalid = true;
    let table = unloaded_table();
    let out = run(&[t], Declares::default(), Some(&table));
    assert!(matches!(
        out.orphans[0].exclusions.start_address_valid,
        Assessment::Excluded(_)
    ));
    assert!(!out.orphans[0].is_graded());
}

/// **A build without `StartAddressInvalid` grades nothing**, and names the
/// exclusion it could not apply. 231 of the 1,724 ISFs measured are in this
/// state.
#[test]
fn a_build_without_start_address_invalid_grades_no_orphan() {
    let t = Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE);
    let table = unloaded_table();
    let out = run(
        &[t],
        Declares {
            start_address_invalid: false,
            ..Declares::default()
        },
        Some(&table),
    );
    let o = &out.orphans[0];
    assert!(!o.is_graded());
    assert!(matches!(
        o.exclusions.start_address_valid,
        Assessment::NotAssessed(_)
    ));
    assert!(out
        .symbols
        .unavailable
        .iter()
        .any(|n| n.contains("StartAddressInvalid")));
}

/// **Where `SystemThread` is not declared, identity falls back to the owning
/// process** — and the row says which test answered. 650 of the 1,724 ISFs
/// measured are in this state.
#[test]
fn without_the_system_thread_bit_identity_comes_from_the_owning_process() {
    let t = Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE);
    let table = unloaded_table();
    let out = run(
        &[t],
        Declares {
            system_thread: false,
            ..Declares::default()
        },
        Some(&table),
    );
    let o = &out.orphans[0];
    assert!(matches!(
        o.exclusions.is_kernel_thread,
        Assessment::Satisfied
    ));
    assert!(
        o.kernel_thread_basis.contains("PsInitialSystemProcess"),
        "the record says which test answered: {}",
        o.kernel_thread_basis
    );
    assert!(o.is_graded(), "all four still assessed: {:?}", o.exclusions);
}

/// Every group's own absence is on the record, so a reader can tell which
/// question this build could be asked.
#[test]
fn the_resolved_paths_and_their_basis_are_published() {
    let out = run(
        &[Thread::new(THREAD_A, 100, IN_MODULE)],
        Declares::default(),
        None,
    );
    let j = out.symbols.to_json();
    assert_eq!(
        j["suspend_count_path"],
        serde_json::json!("Tcb.SuspendCount")
    );
    assert_eq!(
        j["system_thread_path"],
        serde_json::json!("Tcb.SystemThread")
    );
    assert_eq!(j["trap_frame_path"], serde_json::json!("Tcb.TrapFrame"));
    assert_eq!(j["debug_registers_readable"], serde_json::json!(true));
    assert!(
        j["basis"].as_str().unwrap_or_default().contains("BITFIELD"),
        "the basis says the bit position varies: {:?}",
        j["basis"]
    );
}

/// The thread cap is stated rather than read as the end of the machine.
#[test]
fn the_thread_cap_is_stated() {
    let isf_text = isf(Declares::default());
    let threads = [
        Thread::new(THREAD_A, 100, IN_MODULE),
        Thread::new(THREAD_B, 101, IN_MODULE),
    ];
    let profile = profile(
        image(&threads).layer(),
        table(&isf_text),
        Architecture::X64,
        10,
        0,
        Some(22000),
    );
    let ps = ProcessSymbols::from_profile(&profile).expect("symbols");
    let list = list_processes(&profile, &ps, &ProcessListConfig::default()).expect("list");
    let ts = ThreadSymbols::from_profile(&profile).expect("thread symbols");
    let out = examine_threads(&profile, &ts, &list, &modules(), None, 1).expect("runs");
    assert_eq!(out.threads_examined, 1);
    assert!(out.capped.expect("a cap fired").contains("cap of 1"));
}

/// The module map is shared rather than rebuilt, like every other group's.
#[test]
fn the_module_map_is_shared() {
    let shared = Arc::new(modules());
    let isf_text = isf(Declares::default());
    let profile = profile(
        image(&[Thread::new(THREAD_A, 100, OUTSIDE_ANY_MODULE)]).layer(),
        table(&isf_text),
        Architecture::X64,
        10,
        0,
        Some(22000),
    );
    let ps = ProcessSymbols::from_profile(&profile).expect("symbols");
    let list = list_processes(&profile, &ps, &ProcessListConfig::default()).expect("list");
    let ts = ThreadSymbols::from_profile(&profile).expect("thread symbols");
    let out = examine_threads(&profile, &ts, &list, &shared, None, 4096).expect("runs");
    assert_eq!(out.orphans.len(), 1);
}

/// A suspend count that is negative is not a count, and is not republished as
/// a very large unsigned one.
#[test]
fn a_negative_suspend_count_is_a_note_and_not_a_suspended_thread() {
    let mut t = Thread::new(THREAD_A, 100, IN_MODULE);
    t.suspend_count = u32::MAX; // -1 as the declared `long`
    let out = run(&[t], Declares::default(), None);
    assert!(out.suspended.is_empty());
    assert!(
        out.notes.iter().any(|n| n.contains("which is not a count")),
        "got {:?}",
        out.notes
    );
    // And nothing anywhere carries 4294967295 as a count.
    assert!(!out.to_json().to_string().contains("4294967295"));
}

/// One profile carrying all three groups' shapes at once, for the stage-level
/// test in `tamper_tests`: a suspended thread, a thread with an armed
/// breakpoint, and a kernel thread starting outside every loaded module.
pub(crate) fn three_group_profile() -> crate::profile::WindowsProfile {
    let mut suspended = Thread::new(THREAD_A, 100, IN_MODULE);
    suspended.suspend_count = 1;
    let mut orphan = Thread::new(THREAD_B, 101, OUTSIDE_ANY_MODULE);
    orphan.trap_frame = Some(TRAP_FRAME_B);
    orphan.dr = [IN_MODULE, 0, 0, 0];
    orphan.dr7 = 0b0000_0001;
    orphan.debug_active = 1;
    let isf_text = isf(Declares::default());
    profile(
        image(&[suspended, orphan]).layer(),
        table(&isf_text),
        Architecture::X64,
        10,
        0,
        Some(22000),
    )
}

/// The module map that profile's addresses are meant to be read against.
pub(crate) fn three_group_modules() -> ModuleMap {
    modules()
}

/// The address the orphan thread in [`three_group_profile`] starts at.
pub(crate) const ORPHAN_START: u64 = OUTSIDE_ANY_MODULE;
