//! Three thread-side checks over one pass, and what each is allowed to claim
//! (`ROADMAP` §5.3).
//!
//! # The three, and why they are not the same kind of thing
//!
//! | Group | What it is |
//! |---|---|
//! | `suspended_threads` | A **listing**. Every thread the scheduler is holding suspended, with its process. |
//! | `debugregisters` | A **reading**. The thread's `DebugActive`/`ActiveDR7` flags *and* the `Dr0`–`Dr3`, `Dr6`, `Dr7` values together — with a *breakpoint* claimed only for the slots `Dr7`'s own enable bits name. |
//! | `orphan_kernel_threads` | A **graded claim**, and the only one of the three. A kernel thread whose start address lands in no loaded module. |
//!
//! Suspension is ordinary: a packaged app's threads are suspended by the
//! platform, a debugger suspends, and `CREATE_SUSPENDED` is how nearly every
//! injector starts. So the group counts and lists, and says so on the record
//! rather than leaving a reader to infer it from a row's existence.
//!
//! # Why `Dr7`'s enable bits decide what a breakpoint is
//!
//! `Dr0`–`Dr3` hold addresses whether or not the slot is armed, and a stale
//! non-zero value with no enable bit set is not a breakpoint. `Dr7` bits 0–7
//! are the L0/G0 … L3/G3 local and global enables, so slot *i* is armed when
//! bit `2i` or bit `2i+1` is set. Reporting the four addresses as breakpoints
//! without that test is precisely the `HUNT-051` mistake — a rule that fires on
//! a clean machine — and it is the reason this module reads the values *and*
//! the flags rather than either alone.
//!
//! # Why a breakpoint armed only in the null page is not graded
//!
//! A row is graded as an armed breakpoint only when at least one armed address
//! is at or above [`NULL_PAGE_END`] (0x10000, `MM_LOWEST_USER_ADDRESS`). On
//! every Windows XP capture held here one `winlogon.exe` thread has its own
//! `DebugActive` set, `Dr7` = 0x555 and `Dr0`–`Dr3` = 1, 2, 1, 0xa — a lead
//! that fires on every clean capture of the build (`MEM-050`, decided
//! 2026-09-24). Such a row is still published, with its addresses and
//! [`NULL_PAGE_BASIS`]; the bound that basis states (page 0 was mappable on
//! 32-bit Windows before 8) is part of the rule.
//!
//! # Which flag confirms the registers, and which threads are not graded
//!
//! Where the build declares `_DISPATCHER_HEADER.ActiveDR7` it is one bit of
//! the `DebugActive` byte, whose other bits are other flags (`Instrumented`,
//! `Minimal`, `AltSyscall`, the UMS flags on Windows 10). So on such a build
//! only `ActiveDR7`, read through the build's own bitfield definition,
//! confirms; `DebugActive` answers only where `ActiveDR7` is not declared
//! (`MEM-051`). A confirmed row whose thread has Tid 0, or whose armed
//! addresses are not canonical, is published and not graded, with the reason.
//!
//! # The orphan claim is gated on every exclusion being assessable
//!
//! A kernel thread starting outside every loaded module is the classic
//! reflectively-loaded driver. It is also what a legitimately unloaded driver's
//! thread looks like, what a terminated thread's stale start address looks
//! like, and what `StartAddressInvalid` is set for. So four exclusions are
//! applied, and **a graded finding is emitted only when all four were
//! assessable**:
//!
//! 1. the thread is a kernel thread at all;
//! 2. it had not terminated;
//! 3. `StartAddressInvalid` is clear;
//! 4. the address is not inside the range of a driver the kernel has unloaded.
//!
//! Where one could not be assessed the row is published as an **observation**
//! with that exclusion marked `not_assessed`, and it is not counted as a
//! finding. A build declaring neither `MmUnloadedDrivers` nor
//! `_UNLOADED_DRIVERS` cannot assess (4) at all — `MmUnloadedDrivers` is absent
//! on 3 of 60 ISFs sampled — and on such a build this group grades nothing and
//! says which control was missing.
//!
//! # What this build's symbols do and do not declare, measured
//!
//! Across the **1,724** `ntkrnlmp.pdb` ISFs on this machine (1,650 declare
//! `_KTHREAD`):
//!
//! | Member | Declared in |
//! |---|---:|
//! | `_KTHREAD.SuspendCount` | 1,650 |
//! | `_KTHREAD.TrapFrame` | 1,650 |
//! | `_ETHREAD.Tcb`, `.StartAddress`, `.Cid` | 1,650 |
//! | `_KTRAP_FRAME` with all six `Dr` members | 1,557 (**93 declare the type with none of them**) |
//! | `_DISPATCHER_HEADER.DebugActive` | 1,572 |
//! | `_DISPATCHER_HEADER.ActiveDR7` | 1,228 |
//! | `_ETHREAD.StartAddressInvalid` | 1,493 |
//! | `_KTHREAD.SystemThread` | **1,000** — and it is a bitfield whose bit position is 10, 11, 12 or 13 depending on the build, at offset 60, 76 or 116 |
//! | `PsInitialSystemProcess` | 1,724 |
//!
//! Two consequences are load-bearing. `SystemThread`'s bit position varies, so
//! it is read through the symbol table's own bit extraction and never by
//! masking a constant. And it is absent on 650 builds, where kernel-thread
//! identity falls back to the owning process being the system process — the
//! record says which test answered.

use std::sync::Arc;

use seance_memory::binding::first_member;
use seance_memory::object::StructReader;
use serde_json::{json, Value};

use crate::kernel_hooks::{ModuleMap, Ownership};
use crate::process::ProcessList;
use crate::profile::WindowsProfile;
use crate::psxview::threads::{
    list_process_threads, ThreadListConfig, ThreadRecord, ThreadSymbols,
};
use crate::tamper::TamperError;
use crate::tamper_unloaded::UnloadedTable;

/// The debug-register slots x86-64 has.
pub const DR_SLOTS: usize = 4;

/// Where the debug registers sit in `_KTRAP_FRAME` on this build.
#[derive(Debug, Clone)]
pub struct DrLayout {
    pub dr: [u64; DR_SLOTS],
    pub dr6: u64,
    pub dr7: u64,
}

/// What the three groups need from this build, and what is absent.
#[derive(Debug, Clone, Default)]
pub struct ThreadTamperSymbols {
    /// `_ETHREAD` path to the scheduler's suspend count.
    pub suspend_count: Option<String>,
    /// `_ETHREAD` path to the kernel-thread bit. A **bitfield** whose position
    /// varies by build, so it is read through the symbol table.
    pub system_thread: Option<String>,
    /// `_ETHREAD` path to the dispatcher header's debug flags.
    pub debug_active: Option<String>,
    pub active_dr7: Option<String>,
    /// `_ETHREAD` path to the trap-frame pointer.
    pub trap_frame: Option<String>,
    /// Debug-register offsets inside `_KTRAP_FRAME`.
    pub dr: Option<DrLayout>,
    /// `_ETHREAD` path to the flag saying the start address is not meaningful.
    pub start_address_invalid: Option<String>,
    /// Virtual address of the `PsInitialSystemProcess` pointer, for the
    /// kernel-thread fallback test.
    pub system_process_pointer: Option<u64>,
    /// One sentence per absent member, saying what is lost.
    pub unavailable: Vec<String>,
}

impl ThreadTamperSymbols {
    /// Resolve what this build declares. Never fails for absence: an absent
    /// member is an answer about the machine, and the group that needed it says
    /// so per row.
    pub fn from_profile(profile: &WindowsProfile) -> Self {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let mut out = Self::default();
        let mut pick = |candidates: &[&str], what: &str, cost: &str| -> Option<String> {
            match first_member(&reader, "_ETHREAD", candidates) {
                Ok(Some(path)) => Some(path.to_string()),
                Ok(None) => {
                    out.unavailable
                        .push(format!("this build declares no {what}. {cost}"));
                    None
                }
                Err(err) => {
                    out.unavailable.push(format!(
                        "the symbol table could not answer for {what}: {err}. That is not the \
                         same as the member being absent, and nothing is claimed about it."
                    ));
                    None
                }
            }
        };

        out.suspend_count = pick(
            &["Tcb.SuspendCount", "SuspendCount"],
            "`_KTHREAD.SuspendCount`",
            "Without it no thread can be reported as suspended, and the absence of suspended \
             threads in this record is the absence of the field rather than of the state.",
        );
        out.system_thread = pick(
            &["Tcb.SystemThread", "SystemThread"],
            "`_KTHREAD.SystemThread`",
            "Kernel-thread identity falls back to the owning process being the system process, \
             and every row says which test answered it. 650 of the 1,724 ISFs measured are in \
             this state, so it is ordinary rather than a defect.",
        );
        // NT 5.x keeps the flag in `_KTHREAD` itself (XP SP2's `ntkrnlpa.pdb`:
        // a byte at 0x2c) and declares no `_DISPATCHER_HEADER.DebugActive`;
        // the dispatcher-header spelling is tried first because that is where
        // every later build carries it. Found on `tigger.vmem` 2026-09-24,
        // where looking only in the header left an XP thread unconfirmed.
        out.debug_active = pick(
            &[
                "Tcb.Header.DebugActive",
                "Header.DebugActive",
                "Tcb.DebugActive",
            ],
            "`_DISPATCHER_HEADER.DebugActive` (or `_KTHREAD.DebugActive`, where NT 5.x keeps it)",
            "Without it the thread's own claim about whether its debug registers are in use \
             cannot be read; the register values are still read and reported.",
        );
        out.active_dr7 = pick(
            &["Tcb.Header.ActiveDR7", "Header.ActiveDR7"],
            "`_DISPATCHER_HEADER.ActiveDR7`",
            "Without it that one flag is unavailable; `Dr7`'s own enable bits are what decide \
             whether a slot is armed, and they are read from the trap frame.",
        );
        out.trap_frame = pick(
            &["Tcb.TrapFrame", "TrapFrame"],
            "`_KTHREAD.TrapFrame`",
            "Without it no debug register can be read at all, so this group reports nothing and \
             that is the absence of the structure rather than of a breakpoint.",
        );
        out.start_address_invalid = pick(
            &["StartAddressInvalid"],
            "`_ETHREAD.StartAddressInvalid`",
            "One of the orphan claim's four exclusions cannot be assessed, so no orphan finding \
             is graded on this build -- every candidate is published as an observation instead.",
        );

        // The debug registers, in the trap frame. 93 of the 1,650 ISFs that
        // declare `_KTRAP_FRAME` declare it with none of these members.
        let dr_member = |name: &str| -> Option<u64> {
            reader
                .member_offset("_KTRAP_FRAME", name)
                .ok()
                .map(|o| o.bytes())
        };
        match (
            dr_member("Dr0"),
            dr_member("Dr1"),
            dr_member("Dr2"),
            dr_member("Dr3"),
            dr_member("Dr6"),
            dr_member("Dr7"),
        ) {
            (Some(d0), Some(d1), Some(d2), Some(d3), Some(d6), Some(d7)) => {
                out.dr = Some(DrLayout {
                    dr: [d0, d1, d2, d3],
                    dr6: d6,
                    dr7: d7,
                });
            }
            _ => out.unavailable.push(
                "this build's `_KTRAP_FRAME` does not declare all six of Dr0-Dr3, Dr6 and Dr7 \
                 (93 of the 1,650 ISFs measured declare the type with none of them), so no \
                 debug-register value is read. A thread carrying a hardware breakpoint would \
                 look exactly like one that does not."
                    .to_string(),
            ),
        }

        out.system_process_pointer = profile
            .symbols
            .symbol_address("PsInitialSystemProcess")
            .ok()
            .and_then(|rva| profile.kernel_base.value.checked_add(rva));
        out
    }

    pub fn to_json(&self) -> Value {
        json!({
            "suspend_count_path": self.suspend_count,
            "system_thread_path": self.system_thread,
            "debug_active_path": self.debug_active,
            "active_dr7_path": self.active_dr7,
            "trap_frame_path": self.trap_frame,
            "start_address_invalid_path": self.start_address_invalid,
            "debug_registers_readable": self.dr.is_some(),
            "unavailable": self.unavailable,
            "basis":
                "Every path here was resolved from this build's own symbol table through \
                 `first_member`, so a build spelling a member differently is answered rather \
                 than failed. `SystemThread` is a BITFIELD whose bit position is 10, 11, 12 or \
                 13 depending on the build and whose offset is 60, 76 or 116: it is read through \
                 the table's own bit extraction and never by masking a constant.",
        })
    }
}

/// One thread's identity, shared by all three groups' rows.
#[derive(Debug, Clone)]
pub struct ThreadIdentity {
    pub thread: u64,
    pub tid: Option<u64>,
    pub pid: Option<u64>,
    pub process: u64,
    pub process_name: Option<String>,
}

impl ThreadIdentity {
    fn to_json(&self) -> Value {
        json!({
            "thread_address": format!("{:#018x}", self.thread),
            "tid": self.tid,
            "pid": self.pid,
            "process_address": format!("{:#018x}", self.process),
            "process_name": self.process_name,
        })
    }
}

/// A thread the scheduler is holding suspended.
#[derive(Debug, Clone)]
pub struct SuspendedThread {
    pub who: ThreadIdentity,
    pub suspend_count: u64,
}

/// What every suspended-thread row carries, because the state is ordinary.
pub const SUSPENSION_BASIS: &str =
    "A non-zero suspend count is NOT a finding. The platform suspends a packaged app's \
     threads, a debugger suspends, and `CREATE_SUSPENDED` is how nearly every injector starts \
     a thread it is about to write over -- so this group is a listing an examiner reads \
     alongside the rest, not a detection. What would make one of these rows interesting is \
     something else about the same thread.";

impl SuspendedThread {
    pub fn to_json(&self) -> Value {
        let mut m = match self.who.to_json() {
            Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        m.insert("type".into(), json!("MemorySuspendedThread"));
        m.insert(
            "name".into(),
            json!(format!(
                "thread {} of {} suspended {} time(s)",
                self.who
                    .tid
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "?".into()),
                self.who.process_name.clone().unwrap_or_else(|| "?".into()),
                self.suspend_count
            )),
        );
        m.insert("suspend_count".into(), json!(self.suspend_count));
        m.insert("is_a_finding".into(), json!(false));
        m.insert("basis".into(), json!(SUSPENSION_BASIS));
        Value::Object(m)
    }
}

/// One armed debug-register slot.
#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub slot: usize,
    pub address: u64,
    /// Whether the enable was local (`L`) or global (`G`), or both.
    pub enable: &'static str,
    pub ownership: Ownership,
}

impl Breakpoint {
    pub fn to_json(&self) -> Value {
        json!({
            "slot": self.slot,
            "address": format!("{:#018x}", self.address),
            "enable": self.enable,
            "ownership": self.ownership.to_json(),
        })
    }
}

/// A thread's debug-register state, read whole.
#[derive(Debug, Clone)]
pub struct DebugRegisterThread {
    pub who: ThreadIdentity,
    /// The dispatcher header's own flags, when this build declares them.
    pub debug_active: Option<u64>,
    pub active_dr7: Option<u64>,
    /// The trap frame the registers were read from. `None` when the thread has
    /// none, which is ordinary for a thread that has never entered the kernel
    /// from user mode.
    pub trap_frame: Option<u64>,
    /// `Dr0`–`Dr3` as read, armed or not.
    pub dr: [Option<u64>; DR_SLOTS],
    pub dr6: Option<u64>,
    pub dr7: Option<u64>,
    /// The slots `Dr7`'s own enable bits name. A **breakpoint** only when
    /// [`Self::claim`] is [`DebugClaim::ConfirmedByThread`].
    pub armed_by_dr7: Vec<Breakpoint>,
    /// What confirms the bytes are debug registers at all.
    pub claim: DebugClaim,
    /// Slots holding a non-zero address that `Dr7` does **not** arm.
    pub stale_slots: Vec<usize>,
    /// Why this thread cannot be a real thread carrying a breakpoint, when it
    /// cannot (`MEM-051`): a thread ID of 0, or an armed address that is not
    /// canonical for this build's pointer width. Such a row is published with
    /// this reason and not graded.
    pub implausible: Option<String>,
}

impl DebugRegisterThread {
    /// Whether this row is the signal: at least one armed slot **and** the
    /// thread's own flags confirming that these bytes are debug registers.
    ///
    /// Without that second half the check reported five armed breakpoints on a
    /// clean Windows 11 capture; see [`DR7_BASIS`].
    ///
    /// And a third condition, decided 2026-09-24 (`MEM-050`): at least one armed
    /// address is at or above [`NULL_PAGE_END`]. A row whose every armed slot
    /// points into the null page is published, with its addresses and
    /// [`NULL_PAGE_BASIS`], and is not graded.
    pub fn has_breakpoint(&self) -> bool {
        !self.armed_by_dr7.is_empty()
            && self.claim == DebugClaim::ConfirmedByThread
            && !self.armed_only_in_the_null_page()
            && self.implausible.is_none()
    }

    /// Whether `Dr7` arms at least one slot and every armed address is below
    /// [`NULL_PAGE_END`]. False when nothing is armed: there is then nothing
    /// for the rule to set aside.
    pub fn armed_only_in_the_null_page(&self) -> bool {
        !self.armed_by_dr7.is_empty()
            && self
                .armed_by_dr7
                .iter()
                .all(|bp| bp.address < NULL_PAGE_END)
    }

    pub fn to_json(&self) -> Value {
        let mut m = match self.who.to_json() {
            Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        m.insert("type".into(), json!("MemoryThreadDebugRegisters"));
        m.insert(
            "name".into(),
            json!(format!(
                "thread {} of {}: {} armed slot(s)",
                self.who
                    .tid
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "?".into()),
                self.who.process_name.clone().unwrap_or_else(|| "?".into()),
                self.armed_by_dr7.len()
            )),
        );
        m.insert("debug_active".into(), json!(self.debug_active));
        m.insert("active_dr7".into(), json!(self.active_dr7));
        m.insert(
            "trap_frame".into(),
            json!(self.trap_frame.map(|t| format!("{t:#018x}"))),
        );
        m.insert(
            "dr".into(),
            json!(self
                .dr
                .iter()
                .map(|v| v.map(|x| format!("{x:#018x}")))
                .collect::<Vec<_>>()),
        );
        m.insert("dr6".into(), json!(self.dr6.map(|v| format!("{v:#018x}"))));
        m.insert("dr7".into(), json!(self.dr7.map(|v| format!("{v:#018x}"))));
        m.insert(
            "breakpoints".into(),
            json!(self
                .armed_by_dr7
                .iter()
                .map(Breakpoint::to_json)
                .collect::<Vec<_>>()),
        );
        m.insert("armed_slots".into(), json!(self.armed_by_dr7.len()));
        m.insert("claim".into(), json!(self.claim.as_str()));
        m.insert("stale_slots".into(), json!(self.stale_slots));
        m.insert("has_breakpoint".into(), json!(self.has_breakpoint()));
        m.insert(
            "armed_only_in_the_null_page".into(),
            json!(self.armed_only_in_the_null_page()),
        );
        // Stated only when it is the reason: a row that is otherwise a
        // breakpoint and is set aside because every armed address is in the
        // null page.
        let null_page_reason = (self.claim == DebugClaim::ConfirmedByThread
            && self.armed_only_in_the_null_page())
        .then_some(NULL_PAGE_BASIS);
        // And, independently, a thread that cannot be a real one (`MEM-051`).
        let implausible = (self.claim == DebugClaim::ConfirmedByThread
            && !self.armed_by_dr7.is_empty())
        .then_some(self.implausible.as_deref())
        .flatten();
        let reason = match (null_page_reason, implausible) {
            (Some(a), Some(b)) => Some(format!("{a} ALSO: {b}")),
            (Some(a), None) => Some(a.to_string()),
            (None, Some(b)) => Some(b.to_string()),
            (None, None) => None,
        };
        m.insert("not_graded_reason".into(), json!(reason));
        m.insert("implausible_thread".into(), json!(self.implausible));
        m.insert("basis".into(), json!(DR7_BASIS));
        Value::Object(m)
    }
}

/// What confirms that the bytes read really are debug registers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugClaim {
    /// The thread's own `DebugActive`/`ActiveDR7` says its registers are live,
    /// so the bytes at the `Dr` offsets are debug registers.
    ConfirmedByThread,
    /// This build declares neither flag, so the values were read and nothing
    /// confirms what they are. No breakpoint is claimed from them.
    Unconfirmed,
}

impl DebugClaim {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::ConfirmedByThread => "confirmed_by_the_thread's_own_flags",
            Self::Unconfirmed => {
                "unconfirmed: this build declares neither DebugActive nor \
                                  ActiveDR7"
            }
        }
    }
}

/// Why an address in `Dr0`–`Dr3` is not by itself a breakpoint.
pub const DR7_BASIS: &str =
    "THREE rules, each established by measurement rather than assumed. FIRST: the registers are \
     read only from a thread whose own `DebugActive`/`ActiveDR7` says they are live. On the \
     Windows 11 26200 build `_KTRAP_FRAME.Dr0` shares offset 216 with `ShadowStackFrame` and \
     `Dr1` shares 224 with `Spare[5]` -- the symbol file flattens a union, and only the \
     thread's own flag says which interpretation applies. Reading them regardless produced nine \
     rows on a CLEAN capture, five claiming armed breakpoints, every one of them a shadow-stack \
     pointer read as a debug register. SECOND: `Dr0`-`Dr3` hold addresses whether or not the \
     slot is armed, so a non-zero value with no enable bit is a STALE value and not a \
     breakpoint; `Dr7` bits 0-7 are the L0/G0 ... L3/G3 local and global enables, so slot i is \
     armed when bit 2i or bit 2i+1 is set, and only those slots are reported as breakpoints. \
     THIRD (2026-09-24): a thread is graded as carrying a breakpoint only when at least one \
     armed address is at or above 0x10000 (MM_LOWEST_USER_ADDRESS); one whose every armed \
     address is in the null page is published with a `not_graded_reason` and not graded -- \
     measured on every Windows XP capture examined, where a clean winlogon.exe thread arms \
     Dr0-Dr3 = 1, 2, 1, 0xa. FOURTH (2026-09-24, MEM-051): on a build that declares \
     `ActiveDR7`, only that bit -- at the position this build's own bitfield declaration gives \
     -- confirms the registers; the rest of the `DebugActive` byte is other flags \
     (`Instrumented` is bit 1 on Windows 10), and a byte non-zero for one of them is not the \
     thread saying its debug registers are live. And a thread that cannot be a real one -- Tid \
     0, or an armed address that is not canonical -- is published with a `not_graded_reason` \
     and not graded.";

/// The end of the null page region, exclusive: `MM_LOWEST_USER_ADDRESS`,
/// defined as `(PVOID)(LONG_PTR)0x10000` in the WDK's `wdm.h` and reported at
/// run time as `SYSTEM_BASIC_INFORMATION.MinimumUserModeAddress`. The same
/// 64 KiB on x86 and x64.
pub const NULL_PAGE_END: u64 = 0x10000;

/// Why a breakpoint armed only in the null page is published and not graded
/// (`MEM-050`).
pub const NULL_PAGE_BASIS: &str =
    "NOT GRADED: every address Dr7 arms on this thread is below 0x10000 \
     (MM_LOWEST_USER_ADDRESS in the WDK's wdm.h), the lowest address the Windows allocator \
     hands to user code, so none of them can be an instruction or datum of a loaded image. \
     Measured: one winlogon.exe thread with DebugActive set, Dr7 = 0x555 and Dr0-Dr3 = 1, 2, 1, \
     0xa is on every Windows XP capture examined, malware or not, and grading it would fire on \
     every clean capture of the build. The row is kept, with its addresses, as an observation. \
     BOUND: before Windows 8 a 32-bit process could map page 0 (NtAllocateVirtualMemory with a \
     base of 1, and NTVDM maps the low megabyte), so on those builds a breakpoint on memory \
     deliberately mapped there would be published here and not graded.";

/// One of the orphan claim's four exclusions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Assessment {
    /// The exclusion holds: this row survives it.
    Satisfied,
    /// The exclusion rules this row out, for the stated reason.
    Excluded(String),
    /// It could not be assessed. **Not the same as satisfied**, and it stops
    /// the row being graded.
    NotAssessed(String),
}

impl Assessment {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Satisfied => "satisfied",
            Self::Excluded(_) => "excluded",
            Self::NotAssessed(_) => "not_assessed",
        }
    }

    fn detail(&self) -> Option<&str> {
        match self {
            Self::Satisfied => None,
            Self::Excluded(d) | Self::NotAssessed(d) => Some(d),
        }
    }

    fn to_json(&self) -> Value {
        json!({"state": self.as_str(), "detail": self.detail()})
    }
}

/// The four exclusions, per candidate.
#[derive(Debug, Clone)]
pub struct Exclusions {
    pub is_kernel_thread: Assessment,
    pub not_terminated: Assessment,
    pub start_address_valid: Assessment,
    pub not_in_an_unloaded_range: Assessment,
}

impl Exclusions {
    fn all(&self) -> [&Assessment; 4] {
        [
            &self.is_kernel_thread,
            &self.not_terminated,
            &self.start_address_valid,
            &self.not_in_an_unloaded_range,
        ]
    }

    /// Whether every exclusion could be assessed at all.
    pub fn fully_assessed(&self) -> bool {
        self.all()
            .iter()
            .all(|a| !matches!(a, Assessment::NotAssessed(_)))
    }

    /// Whether every exclusion is satisfied.
    pub fn all_satisfied(&self) -> bool {
        self.all()
            .iter()
            .all(|a| matches!(a, Assessment::Satisfied))
    }

    fn to_json(&self) -> Value {
        json!({
            "is_kernel_thread": self.is_kernel_thread.to_json(),
            "not_terminated": self.not_terminated.to_json(),
            "start_address_valid": self.start_address_valid.to_json(),
            "not_in_an_unloaded_range": self.not_in_an_unloaded_range.to_json(),
            "fully_assessed": self.fully_assessed(),
        })
    }
}

/// A kernel thread whose start address lands in no loaded module.
#[derive(Debug, Clone)]
pub struct OrphanCandidate {
    pub who: ThreadIdentity,
    pub start_address: u64,
    pub ownership: Ownership,
    /// Which test established that this is a kernel thread.
    pub kernel_thread_basis: &'static str,
    pub exclusions: Exclusions,
}

impl OrphanCandidate {
    /// Whether this row is a **graded finding**, as opposed to an observation.
    ///
    /// Only when every exclusion was assessable and every one is satisfied. A
    /// row that could not assess one of them is an observation, and counting it
    /// as a finding would grade a claim with one of its controls silently
    /// unapplied.
    pub fn is_graded(&self) -> bool {
        self.exclusions.fully_assessed() && self.exclusions.all_satisfied()
    }

    pub fn to_json(&self) -> Value {
        let mut m = match self.who.to_json() {
            Value::Object(m) => m,
            _ => serde_json::Map::new(),
        };
        m.insert("type".into(), json!("MemoryOrphanKernelThread"));
        m.insert(
            "name".into(),
            json!(format!(
                "kernel thread {} starting at {:#018x}",
                self.who
                    .tid
                    .map(|t| t.to_string())
                    .unwrap_or_else(|| "?".into()),
                self.start_address
            )),
        );
        m.insert(
            "start_address".into(),
            json!(format!("{:#018x}", self.start_address)),
        );
        m.insert("start_address_ownership".into(), self.ownership.to_json());
        m.insert(
            "kernel_thread_basis".into(),
            json!(self.kernel_thread_basis),
        );
        m.insert("exclusions".into(), self.exclusions.to_json());
        m.insert("is_graded_finding".into(), json!(self.is_graded()));
        m.insert(
            "grading_basis".into(),
            json!(
                "A graded finding requires all four exclusions to have been ASSESSABLE and all \
                 four to be satisfied. Where one could not be assessed this row is an \
                 observation and is not counted as a finding: grading it would publish a claim \
                 with one of its own controls silently unapplied."
            ),
        );
        Value::Object(m)
    }
}

/// What one pass over the threads produced, for all three groups.
#[derive(Debug, Clone)]
pub struct ThreadTamperOutcome {
    pub symbols: ThreadTamperSymbols,
    /// Threads examined, and the processes they came from.
    pub threads_examined: u64,
    pub processes_walked: u64,
    /// Processes whose thread list could not be walked end to end.
    pub incomplete_lists: u64,
    pub suspended: Vec<SuspendedThread>,
    pub debug: Vec<DebugRegisterThread>,
    pub orphans: Vec<OrphanCandidate>,
    /// User threads set aside before becoming rows. See `assess_orphan`: the
    /// module map is a kernel-module map, so a user thread's start address is
    /// not a question it can answer.
    pub user_threads_set_aside: u64,
    /// Threads whose own flags said their debug registers were live.
    pub threads_claiming_debug_state: u64,
    /// Threads whose suspend count was actually read.
    ///
    /// The distinction a zero needs: "no thread was suspended" and "no suspend
    /// count could be read" are different facts, and without this a reader
    /// cannot tell which produced an empty list.
    pub suspend_counts_read: u64,
    pub notes: Vec<String>,
    pub capped: Option<String>,
}

impl ThreadTamperOutcome {
    /// Orphan rows that are graded findings.
    pub fn graded_orphans(&self) -> usize {
        self.orphans.iter().filter(|o| o.is_graded()).count()
    }

    /// Orphan rows published as observations because an exclusion could not be
    /// assessed.
    pub fn ungraded_orphans(&self) -> usize {
        self.orphans.iter().filter(|o| !o.is_graded()).count()
    }

    /// Threads carrying at least one armed debug-register slot.
    pub fn with_breakpoints(&self) -> usize {
        self.debug.iter().filter(|d| d.has_breakpoint()).count()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "symbols": self.symbols.to_json(),
            "threads_examined": self.threads_examined,
            "processes_walked": self.processes_walked,
            "incomplete_thread_lists": self.incomplete_lists,
            "suspended_threads": self.suspended.iter().map(SuspendedThread::to_json).collect::<Vec<_>>(),
            "suspended_total": self.suspended.len(),
            "suspend_counts_read": self.suspend_counts_read,
            "suspended_absence_note": (self.suspended.is_empty()).then_some(
                "No thread on this image carries a non-zero suspend count. That is a statement \
                 about the machine only insofar as `suspend_counts_read` accounts for the \
                 threads examined: where the two differ, the rest had no count this build could \
                 read."
            ),
            "suspension_basis": SUSPENSION_BASIS,
            "debug_register_threads": self.debug.iter().map(DebugRegisterThread::to_json).collect::<Vec<_>>(),
            "debug_register_rows": self.debug.len(),
            "threads_with_a_breakpoint": self.with_breakpoints(),
            "debug_register_basis": DR7_BASIS,
            "orphan_kernel_threads": self.orphans.iter().map(OrphanCandidate::to_json).collect::<Vec<_>>(),
            "orphan_graded": self.graded_orphans(),
            "orphan_observations": self.ungraded_orphans(),
            "user_threads_set_aside": self.user_threads_set_aside,
            "user_threads_note":
                "A user thread's `StartAddress` is `RtlUserThreadStart` in ntdll, a USER-space \
                 module, and the map every address here is attributed against is a map of \
                 KERNEL modules -- so it cannot attribute a user thread's start address by \
                 construction, and every user thread would look like an orphan to it. On the \
                 Windows 11 capture that is 1,284 of 1,514 threads. They are counted here \
                 rather than published as observations, because 1,284 rows would bury this \
                 group's question. The process-side form of the same question is the \
                 `tampering` stage's.",
            "threads_claiming_debug_state": self.threads_claiming_debug_state,
            "notes": self.notes,
            "content_incomplete": self.capped.is_some() || self.incomplete_lists > 0,
            "cap_detail": self.capped,
        })
    }
}

/// Which slots `Dr7` arms, with the enable that armed each.
///
/// Bits 0-7 are L0/G0 … L3/G3. A slot with a non-zero address and no enable bit
/// is stale, and saying otherwise is a rule that fires on a clean machine.
pub fn armed_slots(dr7: u64) -> [Option<&'static str>; DR_SLOTS] {
    let mut out = [None; DR_SLOTS];
    for (slot, entry) in out.iter_mut().enumerate() {
        let local = dr7 & (1 << (slot * 2)) != 0;
        let global = dr7 & (1 << (slot * 2 + 1)) != 0;
        *entry = match (local, global) {
            (true, true) => Some("local+global"),
            (true, false) => Some("local"),
            (false, true) => Some("global"),
            (false, false) => None,
        };
    }
    out
}

/// Read one thread's debug-register state.
fn read_debug_registers(
    reader: &StructReader,
    symbols: &ThreadTamperSymbols,
    thread: &seance_memory::object::Obj,
    who: &ThreadIdentity,
    modules: &ModuleMap,
    claiming: &mut u64,
) -> Option<DebugRegisterThread> {
    // Only a build declaring all six `Dr` members reads any of them.
    symbols.dr.as_ref()?;
    let debug_active = symbols
        .debug_active
        .as_deref()
        .and_then(|path| thread.unsigned(path).ok());
    let active_dr7 = symbols
        .active_dr7
        .as_deref()
        .and_then(|path| thread.unsigned(path).ok());

    // **The rule the clean capture taught.** The `Dr` members share their
    // offsets with other members of a union (`ShadowStackFrame`, `Spare`), so
    // the only thing that says the bytes there are debug registers is the
    // thread's own flag. A build declaring neither flag can have the values
    // read but nothing to confirm them, and claims no breakpoint.
    //
    // **Which flag answers is decided by the build, not by the bytes**
    // (`MEM-051`). Where this build declares `ActiveDR7` it is a bitfield
    // inside the `DebugActive` byte, and the other bits of that byte are other
    // flags — `Instrumented` (bit 1 on Windows 10), `Minimal`, `AltSyscall`,
    // the UMS flags. So on such a build only `ActiveDR7`, read through the
    // table's own bitfield definition, confirms the registers; a non-zero
    // `DebugActive` byte does not. `DebugActive` answers only on a build that
    // declares no `ActiveDR7` (NT 5.x keeps it as a plain byte in `_KTHREAD`).
    let (declared, flag) = if symbols.active_dr7.is_some() {
        (true, active_dr7)
    } else if symbols.debug_active.is_some() {
        (true, debug_active)
    } else {
        (false, None)
    };
    let claim = match (declared, flag) {
        (true, Some(0)) => {
            // The thread says its registers are not live. There is nothing
            // here to read, and reading it anyway is how five shadow-stack
            // pointers became five armed breakpoints.
            return None;
        }
        (true, Some(_)) => {
            *claiming += 1;
            DebugClaim::ConfirmedByThread
        }
        // Declared and unreadable, or not declared: nothing confirms.
        _ => DebugClaim::Unconfirmed,
    };

    let trap_frame = symbols
        .trap_frame
        .as_deref()
        .and_then(|path| thread.pointer(path).ok())
        .filter(|f| *f != 0);
    // Each register is read at the width THIS build declares for it: eight
    // bytes on x64, four (`unsigned long`) on every x86 ISF. A fixed
    // eight-byte read glued `Dr1:Dr0` into one value on the XP SP2
    // `tigger.vmem` capture (2026-09-24).
    let frame = trap_frame.and_then(|f| reader.object(f, "_KTRAP_FRAME").ok());
    let read = |member: &str| -> Option<u64> { frame.as_ref()?.unsigned(member).ok() };
    let dr = [read("Dr0"), read("Dr1"), read("Dr2"), read("Dr3")];
    let dr6 = read("Dr6");
    let dr7 = read("Dr7");

    // A row is worth publishing when something is set. A thread whose flag is
    // on but whose registers are all zero is worth one row saying exactly
    // that, so `anything` also admits the confirmed case.
    let anything = claim == DebugClaim::ConfirmedByThread
        || dr.iter().any(|v| v.unwrap_or(0) != 0)
        || dr7.unwrap_or(0) != 0;
    if !anything {
        return None;
    }

    let armed = dr7.map(armed_slots).unwrap_or_default();
    let mut armed_by_dr7 = Vec::new();
    let mut stale_slots = Vec::new();
    for slot in 0..DR_SLOTS {
        let address = dr[slot].unwrap_or(0);
        match (armed[slot], address) {
            (Some(enable), address) => armed_by_dr7.push(Breakpoint {
                slot,
                address,
                enable,
                ownership: modules.attribute(address),
            }),
            (None, a) if a != 0 => stale_slots.push(slot),
            _ => {}
        }
    }

    let implausible = implausible_thread(who, &armed_by_dr7, reader.pointer_size().unwrap_or(8));

    Some(DebugRegisterThread {
        who: who.clone(),
        debug_active,
        active_dr7,
        trap_frame,
        dr,
        dr6,
        dr7,
        armed_by_dr7,
        claim,
        stale_slots,
        implausible,
    })
}

/// Why a thread with an armed `Dr7` cannot be a real thread carrying a
/// breakpoint, if it cannot (`MEM-051`).
///
/// Two tests, each a property of the evidence rather than a threshold:
///
/// - **Thread ID 0.** No thread a process creates is given Cid 0; the only
///   holders are the per-processor idle threads, which never run user code
///   and never carry a user trap frame. Measured: the graded LoneWolf row and
///   most of the 13Cubed image's confirmed rows are Tid 0, with register
///   values that read as pool bytes.
/// - **A non-canonical armed address.** The processor raises #GP on a
///   non-canonical linear address, so a breakpoint cannot fire there; a
///   value like LoneWolf's `Dr1` = 0x65536d4d02060005 is not an address.
fn implausible_thread(who: &ThreadIdentity, armed: &[Breakpoint], pointer: u8) -> Option<String> {
    let mut reasons = Vec::new();
    if who.tid == Some(0) {
        reasons.push(
            "the thread's Cid.UniqueThread is Tid 0, which no thread a process creates is given (only the per-processor idle threads hold it, and they never carry a user trap frame), so this structure is not a live thread whose registers can be graded"
                .to_string(),
        );
    }
    let non_canonical: Vec<String> = armed
        .iter()
        .filter(|bp| !seance_memory::object::is_canonical(bp.address, pointer))
        .map(|bp| format!("Dr{} = {:#018x}", bp.slot, bp.address))
        .collect();
    if !non_canonical.is_empty() {
        reasons.push(format!(
            "armed slot(s) {} are not canonical addresses for this build's {}-bit pointers, and the processor faults on a non-canonical address before a breakpoint on it could fire, so these bytes are not debug registers in use",
            non_canonical.join(", "),
            u32::from(pointer) * 8
        ));
    }
    (!reasons.is_empty()).then(|| format!("NOT GRADED: {}.", reasons.join("; and ")))
}

/// What the orphan assessment needs from the pass, gathered once.
struct OrphanContext<'a> {
    symbols: &'a ThreadTamperSymbols,
    modules: &'a ModuleMap,
    unloaded: Option<&'a UnloadedTable>,
    /// The `_EPROCESS` `PsInitialSystemProcess` points at, for the
    /// kernel-thread fallback test.
    system_process: Option<u64>,
}

/// Assess one thread as an orphan-kernel-thread candidate.
fn assess_orphan(
    ctx: &OrphanContext<'_>,
    thread: &seance_memory::object::Obj,
    record: &ThreadRecord,
    who: &ThreadIdentity,
    user_threads: &mut u64,
) -> Option<OrphanCandidate> {
    let OrphanContext {
        symbols,
        modules,
        unloaded,
        system_process,
    } = *ctx;
    let start = *record.start_address.known()?;
    if start == 0 {
        return None;
    }

    // (1) Is it a kernel thread at all? **Settled first, and a user thread
    // produces no row.**
    //
    // The module map is a map of KERNEL modules. A user thread's
    // `StartAddress` is `RtlUserThreadStart` in ntdll -- a user-space module
    // the map cannot attribute by construction -- so every user thread looks
    // like an orphan to it. Measured on the Windows 11 capture: 1,284 of 1,514
    // threads. A row each would have buried this group's actual question under
    // 1,284 observations, so they are counted instead.
    let declared = symbols
        .system_thread
        .as_deref()
        .and_then(|path| thread.unsigned(path).ok());
    let (is_kernel_thread, kernel_thread_basis) = match declared {
        Some(1) => (
            Assessment::Satisfied,
            "`_KTHREAD.SystemThread` is set on this build and on this thread.",
        ),
        Some(_) => (
            Assessment::Excluded(
                "`_KTHREAD.SystemThread` is clear: this is a user thread, and a user thread \
                 starting outside every loaded module is the process-side question, not this one."
                    .to_string(),
            ),
            "`_KTHREAD.SystemThread` is declared on this build.",
        ),
        None => match (system_process, record.owning_process.known()) {
            (Some(system), Some(owner)) if *owner == system => (
                Assessment::Satisfied,
                "This build declares no `_KTHREAD.SystemThread`, so identity was established by \
                 the owning process being `PsInitialSystemProcess`.",
            ),
            (Some(_), Some(_)) => (
                Assessment::Excluded(
                    "this build declares no `_KTHREAD.SystemThread`, and the thread's owning \
                     process is not the system process"
                        .to_string(),
                ),
                "the owning process, because `_KTHREAD.SystemThread` is not declared.",
            ),
            _ => (
                Assessment::NotAssessed(
                    "this build declares no `_KTHREAD.SystemThread` and the owning process or \
                     `PsInitialSystemProcess` could not be read, so whether this is a kernel \
                     thread was never established"
                        .to_string(),
                ),
                "nothing: neither test could be applied.",
            ),
        },
    };

    if matches!(is_kernel_thread, Assessment::Excluded(_)) {
        *user_threads += 1;
        return None;
    }

    let ownership = modules.attribute(start);
    // Only an address in NO loaded module is a candidate. An `Undetermined`
    // one is the map failing to answer, and treating that as "outside every
    // module" would manufacture a finding out of an incomplete acquisition.
    if !ownership.is_outside_any_module() {
        return None;
    }

    // (2) Had it terminated?
    let not_terminated = match record.is_terminated() {
        Some(false) => Assessment::Satisfied,
        Some(true) => Assessment::Excluded(
            "the thread had terminated, and a terminated thread's start address is a stale \
             value rather than a routine anything is about to run"
                .to_string(),
        ),
        None => Assessment::NotAssessed(
            "neither the exit time nor the scheduler state could be read, so whether the thread \
             had terminated was never established -- which is not the same as it still running"
                .to_string(),
        ),
    };

    // (3) Is the start address meaningful?
    let start_address_valid = match symbols.start_address_invalid.as_deref() {
        Some(path) => match thread.unsigned(path) {
            Ok(0) => Assessment::Satisfied,
            Ok(_) => Assessment::Excluded(
                "`_ETHREAD.StartAddressInvalid` is set: the kernel itself says this start \
                 address is not meaningful"
                    .to_string(),
            ),
            Err(err) => Assessment::NotAssessed(format!(
                "`_ETHREAD.StartAddressInvalid` is declared on this build and would not read: \
                 {err}"
            )),
        },
        None => Assessment::NotAssessed(
            "this build does not declare `_ETHREAD.StartAddressInvalid` (1,493 of the 1,724 \
             ISFs measured do), so whether the kernel had already marked this start address \
             meaningless could not be assessed"
                .to_string(),
        ),
    };

    // (4) Is the address inside a driver the kernel unloaded?
    let not_in_an_unloaded_range = match unloaded {
        Some(table) => match table.drivers.iter().find(|d| d.contains(start)) {
            Some(driver) => Assessment::Excluded(format!(
                "the start address is inside the range `{}` occupied before the kernel unloaded \
                 it, which explains an address in no loaded module without anything being wrong",
                driver
                    .name
                    .clone()
                    .unwrap_or_else(|| format!("(unnamed, slot {})", driver.slot))
            )),
            None => Assessment::Satisfied,
        },
        None => Assessment::NotAssessed(
            "the unloaded-driver table was not read on this image, so the one explanation that \
             accounts for a kernel thread starting outside every loaded module WITHOUT anything \
             being wrong could not be ruled out. `MmUnloadedDrivers` is absent from 3 of 60 \
             ISFs sampled, and on such a build this group grades nothing."
                .to_string(),
        ),
    };

    Some(OrphanCandidate {
        who: who.clone(),
        start_address: start,
        ownership,
        kernel_thread_basis,
        exclusions: Exclusions {
            is_kernel_thread,
            not_terminated,
            start_address_valid,
            not_in_an_unloaded_range,
        },
    })
}

/// One pass over every process's threads, feeding all three groups.
///
/// # Errors
///
/// [`TamperError::Unsupported`] only when no thread can be read at all — a
/// build with no `_ETHREAD`, or one whose thread lists cannot be walked. A
/// member some builds lack is never an error: the group that needed it says so
/// per row.
pub fn examine_threads(
    profile: &WindowsProfile,
    thread_symbols: &ThreadSymbols,
    processes: &ProcessList,
    modules: &ModuleMap,
    unloaded: Option<&UnloadedTable>,
    max_threads: usize,
) -> Result<ThreadTamperOutcome, TamperError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let symbols = ThreadTamperSymbols::from_profile(profile);
    let system_process = symbols
        .system_process_pointer
        .and_then(|at| reader.read_pointer_at(at).ok())
        .filter(|p| *p != 0);

    let mut out = ThreadTamperOutcome {
        symbols,
        threads_examined: 0,
        processes_walked: 0,
        incomplete_lists: 0,
        suspended: Vec::new(),
        debug: Vec::new(),
        orphans: Vec::new(),
        user_threads_set_aside: 0,
        threads_claiming_debug_state: 0,
        suspend_counts_read: 0,
        notes: Vec::new(),
        capped: None,
    };
    if system_process.is_none() {
        out.notes.push(
            "`PsInitialSystemProcess` could not be read, so the fallback test for kernel-thread \
             identity is unavailable on this image. It is only needed where \
             `_KTHREAD.SystemThread` is not declared."
                .to_string(),
        );
    }

    let names: std::collections::BTreeMap<u64, Option<String>> = processes
        .processes
        .iter()
        .map(|p| (p.address, p.image_file_name.known().cloned()))
        .collect();

    'processes: for process in &processes.processes {
        out.processes_walked += 1;
        let list = match list_process_threads(
            profile,
            thread_symbols,
            process.address,
            &ThreadListConfig::default(),
        ) {
            Ok(list) => list,
            Err(err) => {
                out.incomplete_lists += 1;
                if out.notes.len() < 64 {
                    out.notes.push(format!(
                        "the thread list of the process at {:#018x} could not be walked: {err}. \
                         Its threads are absent from all three groups below.",
                        process.address
                    ));
                }
                continue;
            }
        };
        if !list.is_complete() {
            out.incomplete_lists += 1;
        }

        for record in &list.threads {
            if out.threads_examined as usize >= max_threads {
                out.capped = Some(format!(
                    "the thread cap of {max_threads} was reached after {} process(es); the \
                     machine has more threads than were examined, and this is a cap rather than \
                     the end of the list.",
                    out.processes_walked
                ));
                break 'processes;
            }
            out.threads_examined += 1;

            let who = ThreadIdentity {
                thread: record.address,
                tid: record.tid.known().copied(),
                pid: record.pid.known().copied(),
                process: process.address,
                process_name: names.get(&process.address).cloned().flatten(),
            };
            let Ok(thread) = reader.object(record.address, "_ETHREAD") else {
                continue;
            };

            // Group: suspended_threads.
            //
            // `SuspendCount` is declared SIGNED on real builds (`CHAR` on the
            // older ones, `LONG` on the newer), and this crate's reader
            // refuses to hand a signed member back as unsigned rather than
            // reinterpreting it. So it is read as the integer it is declared
            // to be: a negative value is not a suspend count and is recorded
            // as a note rather than published as a very large one.
            if let Some(path) = out.symbols.suspend_count.as_deref() {
                if let Ok(count) = thread.int(path).map(|v| v.as_i128()) {
                    out.suspend_counts_read += 1;
                    if count > 0 {
                        out.suspended.push(SuspendedThread {
                            who: who.clone(),
                            suspend_count: count as u64,
                        });
                    } else if count < 0 && out.notes.len() < 64 {
                        out.notes.push(format!(
                            "the thread at {:#018x} declares a suspend count of {count}, which \
                             is not a count. It is not reported as suspended and the value is \
                             not republished as an unsigned number.",
                            record.address
                        ));
                    }
                }
            }

            // Group: debugregisters.
            let mut claiming = out.threads_claiming_debug_state;
            if let Some(row) =
                read_debug_registers(&reader, &out.symbols, &thread, &who, modules, &mut claiming)
            {
                out.debug.push(row);
            }
            out.threads_claiming_debug_state = claiming;

            // Group: orphan_kernel_threads.
            let mut user_threads = out.user_threads_set_aside;
            let candidate = assess_orphan(
                &OrphanContext {
                    symbols: &out.symbols,
                    modules,
                    unloaded,
                    system_process,
                },
                &thread,
                record,
                &who,
                &mut user_threads,
            );
            out.user_threads_set_aside = user_threads;
            if let Some(candidate) = candidate {
                out.orphans.push(candidate);
            }
        }
    }

    Ok(out)
}
