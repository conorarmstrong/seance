//! Kernel-side tamper checks (`ROADMAP` §5.3).
//!
//! Seven groups, one stage. Each answers a question Volatility 3 has a plugin
//! for and this build had no answer to: which drivers the kernel has unloaded,
//! what the per-processor timer tables point at, which threads carry hardware
//! debug registers, which are suspended, which kernel threads start outside
//! every loaded module, whether the ETW write path has been patched, and
//! whether the LSA has a skeleton key.
//!
//! # Which groups are written, and how a reader knows
//!
//! [`IMPLEMENTED_GROUPS`] is the list, and every sentence this stage emits
//! about how much of itself is written counts from it. The groups not on it
//! report that they did not run and why — which is the honest state of a
//! seven-group stage most of whose groups are not written. The alternative
//! shape, a stage that appears when its first group lands, would have the
//! earlier groups' silence read as their absence from the evidence rather than
//! from the build.
//!
//! A group that is written and a group that is not give **different reasons**
//! for not running, and the record carries whichever is true: a landed group
//! whose symbols are absent names the absent symbol and nothing more, because
//! telling an examiner the check was unwritten after it had been written is
//! the same class of wrong claim in the other direction.
//!
//! Neither shape of overstatement is theoretical here. `HUNT-051` is this
//! project's own: 4,054 false timestomps on a stock XP machine, from a rule
//! that fired before anybody measured what a clean capture looks like. So a
//! group here does not render as a finding until the clean-baseline pass
//! agrees, and until then it is a listing with its own status beside it.
//!
//! # One pass where the groups share one
//!
//! The three thread groups (`debugregisters`, `suspended_threads`,
//! `orphan_kernel_threads`) are answered from **one** walk of the threads
//! rather than three, for the same reason the module map is shared: three
//! walks are three chances for three records to disagree about the same
//! thread. The walk needs the caller's process list, and where there is none
//! the three report that — not that the machine had no threads.
//!
//! # One stage, not seven
//!
//! `GroupStatus` already carries per-group ran / did-not-run / found / capped,
//! so the API's stage table gains one row and the Findings lens gains one
//! source rather than seven. And the `ModuleMap` is **shared** with
//! `kernel_hooks` rather than rebuilt: two independent walks are two chances
//! for two records to disagree about which driver owns an address, which
//! `ModuleMap::from_listing` exists to prevent. The pointers that stage could
//! attribute to no loaded module come across the same seam
//! ([`TamperConfig::candidates`], filled by
//! `KernelHookOutcome::unattributed_candidates`), because the unloaded-driver
//! table is the second source for exactly that question.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::Incomplete;

use crate::kernel_hooks::{GroupStatus, ModuleMap};
use crate::profile::WindowsProfile;
use crate::tamper_etw::EtwOutcome;
use crate::tamper_skeleton::SkeletonOutcome;
use crate::tamper_threads::ThreadTamperOutcome;
use crate::tamper_timers::TimerTable;
use crate::tamper_unloaded::UnloadedTable;

/// Drivers the kernel has unloaded, from `MmUnloadedDrivers`.
pub const GROUP_UNLOADED_MODULES: &str = "unloaded_modules";
/// The per-processor timer tables and their DPC routines.
pub const GROUP_TIMERS: &str = "timers";
/// Threads carrying hardware debug registers.
pub const GROUP_DEBUG_REGISTERS: &str = "debug_registers";
/// Threads the scheduler is holding suspended.
pub const GROUP_SUSPENDED_THREADS: &str = "suspended_threads";
/// Kernel threads whose start address is in no loaded module.
pub const GROUP_ORPHAN_KERNEL_THREADS: &str = "orphan_kernel_threads";
/// A patched ETW write path.
pub const GROUP_ETW_PATCH: &str = "etw_patch";
/// A skeleton key in the LSA.
pub const GROUP_SKELETON_KEY: &str = "skeleton_key";

/// Every group this stage has, in the order it reports them.
pub const GROUPS: &[&str] = &[
    GROUP_UNLOADED_MODULES,
    GROUP_TIMERS,
    GROUP_DEBUG_REGISTERS,
    GROUP_SUSPENDED_THREADS,
    GROUP_ORPHAN_KERNEL_THREADS,
    GROUP_ETW_PATCH,
    GROUP_SKELETON_KEY,
];

/// The groups whose detection this build actually has.
///
/// Every sentence about how much of the stage is written is generated from
/// this list rather than typed. A group landing without its prose moving is
/// exactly how a stage comes to claim more than it does, and the number in a
/// record is never a number somebody remembered to change.
pub const IMPLEMENTED_GROUPS: &[&str] = &[
    GROUP_UNLOADED_MODULES,
    GROUP_TIMERS,
    GROUP_DEBUG_REGISTERS,
    GROUP_SUSPENDED_THREADS,
    GROUP_ORPHAN_KERNEL_THREADS,
    GROUP_ETW_PATCH,
    GROUP_SKELETON_KEY,
];

/// Whether a group's detection is written in this build.
pub fn group_is_implemented(group: &str) -> bool {
    IMPLEMENTED_GROUPS.contains(&group)
}

/// Notes recorded before the stage stops recording them.
pub const MAX_RECORDED_NOTES: usize = 512;

/// Unloaded-driver records read. The table's documented capacity is 50, and a
/// ceiling an order of magnitude above it is generous and finite.
pub const MAX_UNLOADED_DRIVERS: usize = 512;

/// Timers read across every processor.
pub const MAX_TIMERS: usize = 65_536;

/// Threads examined for the three thread-walk groups.
pub const MAX_THREADS: usize = 262_144;

/// Processes the ETW check will assess.
///
/// Each one costs a per-process address space, a loader walk, a VAD walk and a
/// PE export-table read, so this is a real ceiling rather than a formality. A
/// busy Windows machine runs a few hundred processes; the clean capture here
/// has 129.
pub const MAX_ETW_PROCESSES: usize = 4096;

/// What went wrong with the whole stage, as opposed to one group.
#[derive(Debug, Clone)]
pub enum TamperError {
    /// Not one group can run on this build, with every group's reason.
    ///
    /// A stage that returned an empty result here would be asserting that the
    /// kernel has unloaded no drivers, holds no timers and runs no threads,
    /// which no Windows kernel has ever been true of.
    Unsupported { detail: String },
    /// The address space would not answer.
    Read { detail: String },
}

impl TamperError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn read(detail: impl Into<String>) -> Self {
        Self::Read {
            detail: detail.into(),
        }
    }

    /// The stable class name a record carries.
    pub fn class(&self) -> &'static str {
        match self {
            Self::Unsupported { .. } => "unsupported_build",
            Self::Read { .. } => "address_space_unreadable",
        }
    }

    pub fn detail(&self) -> &str {
        match self {
            Self::Unsupported { detail } | Self::Read { detail } => detail,
        }
    }

    /// Which incompleteness vocabulary word this is.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            // The structures were not declared, so nothing was resolved.
            Self::Unsupported { .. } => IncompleteReason::UnresolvedStructure,
            Self::Read { .. } => IncompleteReason::ShortRead,
        }
    }

    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.detail())
    }
}

impl std::fmt::Display for TamperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail())
    }
}

/// Which of the seven groups this build's symbols can support.
///
/// One `Option` per group with a written reason beside it, so a report can say
/// "the timer tables were not read because this build's symbols do not name
/// `KiProcessorBlock`" rather than showing an empty table.
///
/// # The per-group symbol sets are provisional
///
/// No group's detection is written yet, so the symbols each group is declared
/// to need are the ones its detection is **expected** to read. Each group's own
/// landing commit replaces its set with what that group actually reads, and
/// until then a group reporting "available" means its entry symbols resolve and
/// nothing more. That is stated here rather than discovered later, because a
/// provisional requirement that reads as a settled one is how a stage comes to
/// claim a capability it does not have.
#[derive(Debug, Clone, Default)]
pub struct TamperSymbols {
    /// `MmUnloadedDrivers` and `MmLastUnloadedDriver`, when declared.
    pub unloaded: Option<UnloadedSymbols>,
    pub unloaded_unavailable: Option<String>,
    /// The per-processor timer table.
    pub timers: Option<TimerSymbols>,
    pub timers_unavailable: Option<String>,
    /// The thread walk the three thread groups share.
    pub threads: Option<ThreadWalkSymbols>,
    pub threads_unavailable: Option<String>,
    /// The ETW write path.
    pub etw: Option<EtwSymbols>,
    pub etw_unavailable: Option<String>,
    /// The LSA structures a skeleton key would be in.
    pub skeleton: Option<SkeletonSymbols>,
    pub skeleton_unavailable: Option<String>,
}

/// `MmUnloadedDrivers` and its write counter.
#[derive(Debug, Clone)]
pub struct UnloadedSymbols {
    /// Virtual address of the pointer to the table.
    pub table_pointer: u64,
    /// Virtual address of the monotonic write counter.
    pub counter: u64,
}

/// What the timer walk needs from this build.
#[derive(Debug, Clone)]
pub struct TimerSymbols {
    /// Virtual address of the processor block array.
    pub prcb_array: u64,
    /// Virtual address of the processor count.
    ///
    /// Read and then validated against the array rather than trusted: the
    /// symbol carries no declared type in any of the 1,724 ISFs measured, so
    /// its width is not knowable from the symbols, and on the smeared captures
    /// in this corpus it reads 0 on machines that plainly had processors.
    pub processor_count: u64,
    /// Virtual address of the legacy global timer table, on the 427 of 1,724
    /// builds that have one instead of `_KPRCB.TimerTable`.
    pub legacy_table_head: Option<u64>,
    /// Virtual addresses of `KiWaitNever` and `KiWaitAlways`, when this build
    /// declares both: the keys the x64 kernel encodes `_KTIMER.Dpc` with
    /// (`MEM-052`). `None` on a build declaring neither.
    pub dpc_keys: Option<DpcKeySymbols>,
}

/// The two globals the kernel's timer-DPC obfuscation keys on.
#[derive(Debug, Clone, Copy)]
pub struct DpcKeySymbols {
    pub wait_never: u64,
    pub wait_always: u64,
}

/// What the three thread-walk groups share.
#[derive(Debug, Clone)]
pub struct ThreadWalkSymbols {
    /// Virtual address of the kernel process list head.
    pub process_list: u64,
}

/// What the ETW check needs from this build.
///
/// The route is user-mode — the four `Etw*` exports in each process's own
/// `ntdll` — so this is not a kernel symbol. It is the loader-entry type the
/// per-process module walk resolves, kept so the record can say which one
/// answered on this build.
#[derive(Debug, Clone)]
pub struct EtwSymbols {
    pub loader_entry_type: String,
}

/// What the skeleton-key check needs from this build.
///
/// Like the ETW check, the route this build runs is **user-mode**:
/// `CDLocateCSystem` is read out of the `cryptdll.dll` mapped inside each
/// `lsass.exe`, from that module's own export table. So this is the
/// loader-entry type the per-process walk resolved, not a kernel symbol — and
/// the `PsLoadedModuleList` the stage's floor required was never the right
/// requirement for it. (The kernel-side structures a skeleton key touches are
/// not what either route reads; see `tamper_skeleton` for the route that does
/// not run and why.)
#[derive(Debug, Clone)]
pub struct SkeletonSymbols {
    pub loader_entry_type: String,
}

/// Resolve a symbol to a virtual address, or say which symbol is missing.
fn symbol(profile: &WindowsProfile, name: &str) -> Result<u64, String> {
    let rva = profile
        .symbols
        .symbol_address(name)
        .map_err(|_| format!("this build's symbol table has no '{name}'"))?;
    profile
        .kernel_base
        .value
        .checked_add(rva)
        .ok_or_else(|| format!("the address of '{name}' does not fit in 64 bits"))
}

/// Resolve every symbol a group needs, or the sentence saying which is absent.
fn group<T>(
    names: &[&str],
    build: impl FnOnce(&[u64]) -> T,
    profile: &WindowsProfile,
    without_it: &str,
) -> (Option<T>, Option<String>) {
    let mut addresses = Vec::with_capacity(names.len());
    for name in names {
        match symbol(profile, name) {
            Ok(a) => addresses.push(a),
            Err(why) => return (None, Some(format!("{why}. {without_it}"))),
        }
    }
    (Some(build(&addresses)), None)
}

impl TamperSymbols {
    /// Resolve what each group needs from this build.
    ///
    /// # Errors
    ///
    /// [`TamperError::Unsupported`] when not one group can run, listing every
    /// group's reason — see that variant for why an empty result would be a
    /// false statement rather than an empty one.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, TamperError> {
        let (unloaded, unloaded_unavailable) = group(
            &["MmUnloadedDrivers", "MmLastUnloadedDriver"],
            |a| UnloadedSymbols {
                table_pointer: a[0],
                counter: a[1],
            },
            profile,
            "Without it the table of drivers the kernel has unloaded cannot be located at all, \
             so a driver that loaded and unloaded to run once leaves no trace this stage can \
             report.",
        );
        let (timers, timers_unavailable) = group(
            &["KiProcessorBlock", "KeNumberProcessors"],
            |a| TimerSymbols {
                prcb_array: a[0],
                processor_count: a[1],
                // Optional by measurement, not by hedging: the two table
                // shapes are exactly complementary across the pack, so a
                // build with `_KPRCB.TimerTable` never has this symbol and a
                // build without it always does.
                legacy_table_head: symbol(profile, "KiTimerTableListHead").ok(),
                // Both or neither: one key without the other decodes nothing.
                dpc_keys: match (
                    symbol(profile, "KiWaitNever").ok(),
                    symbol(profile, "KiWaitAlways").ok(),
                ) {
                    (Some(wait_never), Some(wait_always)) => Some(DpcKeySymbols {
                        wait_never,
                        wait_always,
                    }),
                    _ => None,
                },
            },
            profile,
            "Without it the per-processor blocks cannot be reached, so no timer table can be \
             walked and a timer whose DPC routine points outside every loaded module cannot be \
             found.",
        );
        let (threads, threads_unavailable) = group(
            &["PsActiveProcessHead"],
            |a| ThreadWalkSymbols { process_list: a[0] },
            profile,
            "Without it no thread can be reached, so none of the three thread groups -- debug \
             registers, suspended threads and orphan kernel threads -- can run.",
        );
        // The ETW check is a USER-MODE route: it reads the four `Etw*` exports
        // out of each process's own `ntdll`, so it needs no kernel symbol at
        // all -- what it needs is this build's loader entries, without which
        // no process's `ntdll` can be located. (`EtwpHostSiloState` is the
        // kernel-side route, which is not in scope and is named in
        // `tamper_etw`'s module comment rather than required here.)
        let (etw, etw_unavailable) = match crate::modules::ModuleSymbols::from_profile(profile) {
            Ok(symbols) => (
                Some(EtwSymbols {
                    loader_entry_type: symbols.user_entry_type.clone(),
                }),
                None,
            ),
            Err(err) => (
                None,
                Some(format!(
                    "this build's loader entries cannot be described: {err}. Without them no \
                     process's ntdll can be located, so the four ETW write exports cannot be \
                     read and a process that had disabled its own event logging is \
                     indistinguishable from one that had not."
                )),
            ),
        };
        // Like the ETW check, this is a USER-MODE route: `CDLocateCSystem` is
        // read out of the `cryptdll` mapped in each `lsass.exe`, so what it
        // needs is this build's loader entries and not a kernel symbol. The
        // `PsLoadedModuleList` the floor required was never the right
        // requirement for it. Resolved through the same call the ETW group
        // uses so the two cannot disagree about whether this build's loader
        // entries can be described.
        let (skeleton, skeleton_unavailable) = match etw.as_ref() {
            Some(etw) => (
                Some(SkeletonSymbols {
                    loader_entry_type: etw.loader_entry_type.clone(),
                }),
                None,
            ),
            None => (
                None,
                Some(
                    "this build's loader entries cannot be described, so cryptdll cannot be \
                     located inside lsass.exe. Without it neither skeleton-key route can run, \
                     and nothing is said about whether this machine's domain authentication had \
                     been subverted -- which is the question this check exists for."
                        .to_string(),
                ),
            ),
        };

        let out = Self {
            unloaded,
            unloaded_unavailable,
            timers,
            timers_unavailable,
            threads,
            threads_unavailable,
            etw,
            etw_unavailable,
            skeleton,
            skeleton_unavailable,
        };
        if !out.any_group_available() {
            return Err(TamperError::unsupported(format!(
                "not one of this stage's {} groups can run on this build. {}",
                GROUPS.len(),
                out.unavailable_reasons().join(" ")
            )));
        }
        Ok(out)
    }

    /// Whether any group can run at all.
    pub fn any_group_available(&self) -> bool {
        self.unloaded.is_some()
            || self.timers.is_some()
            || self.threads.is_some()
            || self.etw.is_some()
            || self.skeleton.is_some()
    }

    /// Every reason a group is unavailable, in group order.
    pub fn unavailable_reasons(&self) -> Vec<String> {
        [
            &self.unloaded_unavailable,
            &self.timers_unavailable,
            &self.threads_unavailable,
            &self.etw_unavailable,
            &self.skeleton_unavailable,
        ]
        .into_iter()
        .flatten()
        .cloned()
        .collect()
    }

    /// The reason a named group cannot run, when it cannot.
    pub fn unavailable_for(&self, group: &str) -> Option<&str> {
        match group {
            GROUP_UNLOADED_MODULES => self.unloaded_unavailable.as_deref(),
            GROUP_TIMERS => self.timers_unavailable.as_deref(),
            GROUP_DEBUG_REGISTERS | GROUP_SUSPENDED_THREADS | GROUP_ORPHAN_KERNEL_THREADS => {
                self.threads_unavailable.as_deref()
            }
            GROUP_ETW_PATCH => self.etw_unavailable.as_deref(),
            GROUP_SKELETON_KEY => self.skeleton_unavailable.as_deref(),
            _ => None,
        }
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "unloaded_modules_available": self.unloaded.is_some(),
            "unloaded_modules_unavailable_reason": self.unloaded_unavailable,
            "timers_available": self.timers.is_some(),
            "timers_unavailable_reason": self.timers_unavailable,
            "thread_walk_available": self.threads.is_some(),
            "thread_walk_unavailable_reason": self.threads_unavailable,
            "etw_available": self.etw.is_some(),
            "etw_unavailable_reason": self.etw_unavailable,
            "skeleton_key_available": self.skeleton.is_some(),
            "skeleton_key_unavailable_reason": self.skeleton_unavailable,
        })
    }
}

/// The caps and the shared state one examination runs with.
#[derive(Clone, Default)]
pub struct TamperConfig {
    pub max_unloaded_drivers: usize,
    pub max_timers: usize,
    pub max_threads: usize,
    pub max_notes: usize,
    /// The loaded-module map every attribution is made against.
    ///
    /// Shared with `kernel_hooks` rather than rebuilt: see the module comment.
    pub modules: Option<Arc<ModuleMap>>,
    /// Processes the ETW check will assess before it stops.
    pub max_processes: usize,
    /// `(what, address)` pairs to cross-reference against the unloaded
    /// drivers' ranges — the callback targets, service entries and IRP
    /// handlers the kernel-hook stage could not attribute to a loaded module.
    ///
    /// Supplied by the caller rather than re-derived here: the addresses are
    /// already attributed once, and a second walk is a second chance for two
    /// records to disagree about the same pointer.
    pub candidates: Vec<(String, u64)>,
}

impl TamperConfig {
    /// The caps this build ships with.
    pub fn defaults() -> Self {
        Self {
            max_unloaded_drivers: MAX_UNLOADED_DRIVERS,
            max_timers: MAX_TIMERS,
            max_threads: MAX_THREADS,
            max_notes: MAX_RECORDED_NOTES,
            max_processes: MAX_ETW_PROCESSES,
            modules: None,
            candidates: Vec::new(),
        }
    }
}

/// What one examination found, and everything it could not do.
#[derive(Debug, Clone)]
pub struct TamperOutcome {
    /// The loaded modules every attribution was made against.
    pub modules: Arc<ModuleMap>,
    /// One status per group, in [`GROUPS`] order, whether or not it ran.
    pub groups: Vec<GroupStatus>,
    /// The unloaded-driver table, when that group ran.
    ///
    /// `None` means the group did not run, and its status carries why. It
    /// never means the kernel has unloaded nothing: that is an empty
    /// `drivers` list inside a table that was read.
    pub unloaded: Option<UnloadedTable>,
    /// The timer tables, when that group ran. `None` carries the same
    /// distinction as `unloaded`.
    pub timers: Option<TimerTable>,
    /// The one pass over the threads that feeds the three thread groups.
    /// `None` means it did not run — most often because there was no process
    /// list to walk — and never that the machine had no threads.
    pub threads: Option<ThreadTamperOutcome>,
    /// The ETW write path, when that group ran.
    pub etw: Option<EtwOutcome>,
    /// The skeleton-key check, when that group ran. Its own record says which
    /// of its two routes ran; one of them never does.
    pub skeleton: Option<SkeletonOutcome>,
    /// Everything the stage could not do, in the order it met them.
    pub notes: Vec<String>,
    /// How many notes there were, which may exceed those recorded.
    pub notes_total: usize,
    /// Set when a cap or an unreadable structure stopped the stage.
    pub incomplete: Option<Incomplete>,
}

impl TamperOutcome {
    /// Groups that ran.
    pub fn ran(&self) -> usize {
        self.groups.iter().filter(|g| g.ran).count()
    }

    /// Whether the stage established anything at all.
    ///
    /// **A stage where no group ran is not a clean machine.** It is a stage
    /// that did not look, and the difference is the whole reason this method
    /// exists rather than a reader inferring it from `found == 0`.
    pub fn established_nothing(&self) -> bool {
        self.ran() == 0
    }

    /// The sentence a record carries.
    pub fn describe(&self) -> String {
        if self.established_nothing() {
            return format!(
                "None of this stage's {} tamper-check groups ran on this image, so nothing here \
                 is a statement about whether the kernel was tampered with. Each group's own \
                 reason is beside it.",
                self.groups.len()
            );
        }
        let found: usize = self.groups.iter().map(|g| g.found).sum();
        format!(
            "{} of {} tamper-check groups ran and recorded {found} row(s). {} of the {} have a \
             detection written in this build at all. A group that did not run is named with its \
             reason, and its silence is not a finding that the machine was clean.",
            self.ran(),
            self.groups.len(),
            IMPLEMENTED_GROUPS.len(),
            GROUPS.len()
        )
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "groups": self.groups.iter().map(GroupStatus::to_json).collect::<Vec<_>>(),
            "groups_total": self.groups.len(),
            "groups_ran": self.ran(),
            "established_nothing": self.established_nothing(),
            "statement": self.describe(),
            "modules": self.modules.to_json(),
            "notes": self.notes,
            "notes_total": self.notes_total,
            "groups_implemented": IMPLEMENTED_GROUPS,
            "unloaded_modules": self.unloaded.as_ref().map(UnloadedTable::to_json),
            "timers": self.timers.as_ref().map(TimerTable::to_json),
            "threads": self.threads.as_ref().map(ThreadTamperOutcome::to_json),
            "etw": self.etw.as_ref().map(EtwOutcome::to_json),
            "skeleton_key": self.skeleton.as_ref().map(SkeletonOutcome::to_json),
            "content_incomplete": self.incomplete.is_some(),
            "content_incomplete_reason": self
                .incomplete
                .as_ref()
                .map(|i| i.reason.as_str()),
            // The reason WORD says which kind of incompleteness; only the
            // detail says which groups are missing, and a consumer that shows
            // one without the other shows an examiner a stage that looks
            // merely "unvalidated".
            "content_incomplete_detail": self.incomplete.as_ref().map(|i| i.detail.clone()),
        })
    }
}

/// Run the tamper checks.
///
/// # What an examiner learns
///
/// Which of the seven kernel-side tamper questions this image could be asked,
/// and — for each one that could not be — why not. One group's detection is
/// written ([`IMPLEMENTED_GROUPS`]); the other six report that they did not
/// run, and each says whether that is because this build's symbols do not
/// carry what it needs or because its detection is not written yet. Those are
/// different sentences and the record carries whichever is true.
///
/// # Errors
///
/// [`TamperError::Unsupported`] when not one group's symbols are present.
pub fn examine_tamper(
    profile: &WindowsProfile,
    config: &TamperConfig,
    processes: Option<&crate::process::ProcessList>,
) -> Result<TamperOutcome, TamperError> {
    let symbols = TamperSymbols::from_profile(profile)?;
    let modules = config
        .modules
        .clone()
        .unwrap_or_else(|| Arc::new(ModuleMap::from_profile(profile)));

    let mut notes: Vec<String> = Vec::new();
    let mut notes_total = 0usize;
    let note = |notes: &mut Vec<String>, total: &mut usize, text: String| {
        *total += 1;
        if notes.len() < config.max_notes {
            notes.push(text);
        }
    };

    // The groups whose detection is written. A read failure inside one is
    // that GROUP's failure: the stage still reports the others, because a
    // stage failure here would take their reasons down with it.
    //
    // The unloaded-driver table is read FIRST and cross-referenced LAST,
    // because the addresses to ask it about come from the groups that run
    // after it — the timer DPC routines below, and the caller's own
    // unattributed pointers.
    let mut unloaded: Option<UnloadedTable> = None;
    let mut unloaded_status: Option<GroupStatus> = None;
    if let Some(unloaded_symbols) = symbols.unloaded.as_ref() {
        match crate::tamper_unloaded::read_table(
            profile,
            unloaded_symbols,
            config.max_unloaded_drivers,
        ) {
            Ok(table) => {
                if let Some(capped) = table.capped.clone() {
                    note(&mut notes, &mut notes_total, capped);
                }
                for text in table.notes.clone() {
                    note(&mut notes, &mut notes_total, text);
                }
                if !table.layout.is_validated() {
                    note(
                        &mut notes,
                        &mut notes_total,
                        format!(
                            "the unloaded-driver records were read through an unvalidated \
                             layout. {}",
                            table.layout.basis()
                        ),
                    );
                }
                unloaded_status = Some(GroupStatus::performed(
                    GROUP_UNLOADED_MODULES,
                    table.drivers.len(),
                    table.capped.is_some(),
                ));
                unloaded = Some(table);
            }
            Err(err) => {
                let detail = format!(
                    "`MmUnloadedDrivers` is named by this build and the table it points at \
                     could not be read: {}. No statement is made about what the kernel has \
                     unloaded.",
                    err.detail()
                );
                note(&mut notes, &mut notes_total, detail.clone());
                unloaded_status = Some(GroupStatus::did_not_run(
                    GROUP_UNLOADED_MODULES,
                    Some(detail),
                ));
            }
        }
    }

    // The timer walk. Its signals — DPC routines the module map cannot account
    // for, PatchGuard-shaped rows included — become candidates for the unloaded-driver cross-reference below.
    let mut timers: Option<TimerTable> = None;
    let mut timers_status: Option<GroupStatus> = None;
    let mut candidates: Vec<(String, u64)> = config.candidates.clone();
    if let Some(timer_symbols) = symbols.timers.as_ref() {
        match crate::tamper_timers::read_timers(profile, timer_symbols, &modules, config.max_timers)
        {
            Ok(table) => {
                if let Some(capped) = table.capped.clone() {
                    note(&mut notes, &mut notes_total, capped);
                }
                for text in table.notes.clone() {
                    note(&mut notes, &mut notes_total, text);
                }
                // Graded rows and PatchGuard-shaped rows alike (`MEM-054`):
                // not grading the shape does not exempt it from this check.
                candidates.extend(table.unloaded_cross_reference_candidates());
                timers_status = Some(GroupStatus::performed(
                    GROUP_TIMERS,
                    table.timers.len(),
                    table.capped.is_some(),
                ));
                timers = Some(table);
            }
            Err(err) => {
                let detail = format!(
                    "the timer tables could not be walked on this build: {}. No statement is \
                     made about what its timers point at.",
                    err.detail()
                );
                note(&mut notes, &mut notes_total, detail.clone());
                timers_status = Some(GroupStatus::did_not_run(GROUP_TIMERS, Some(detail)));
            }
        }
    }

    // One pass over the threads, feeding three groups. It needs the process
    // list, which is the caller's — the stage runs before the process list is
    // *required* downstream so that the kernel-side groups still run on an
    // image whose list could not be walked, and these three then report the
    // absent list as their reason.
    let mut threads: Option<ThreadTamperOutcome> = None;
    let mut thread_statuses: Vec<(&'static str, GroupStatus)> = Vec::new();
    let thread_groups = [
        GROUP_DEBUG_REGISTERS,
        GROUP_SUSPENDED_THREADS,
        GROUP_ORPHAN_KERNEL_THREADS,
    ];
    match processes {
        None => {
            let detail = "there was no process list to walk, so no thread was examined. The \
                          detection is written; what is missing is the list, and a thread group \
                          cannot run without one. Nothing here is a statement about this \
                          machine's threads."
                .to_string();
            note(&mut notes, &mut notes_total, detail.clone());
            for name in thread_groups {
                thread_statuses.push((name, GroupStatus::did_not_run(name, Some(detail.clone()))));
            }
        }
        Some(list) => match crate::psxview::threads::ThreadSymbols::from_profile(profile) {
            Err(err) => {
                let detail = format!(
                    "this build's threads cannot be read: {err}. All three thread groups are \
                     silent for that reason and not because the machine had nothing to show."
                );
                note(&mut notes, &mut notes_total, detail.clone());
                for name in thread_groups {
                    thread_statuses
                        .push((name, GroupStatus::did_not_run(name, Some(detail.clone()))));
                }
            }
            Ok(thread_symbols) => {
                match crate::tamper_threads::examine_threads(
                    profile,
                    &thread_symbols,
                    list,
                    &modules,
                    unloaded.as_ref(),
                    config.max_threads,
                ) {
                    Ok(pass) => {
                        if let Some(capped) = pass.capped.clone() {
                            note(&mut notes, &mut notes_total, capped);
                        }
                        for text in pass.notes.clone() {
                            note(&mut notes, &mut notes_total, text);
                        }
                        for text in pass.symbols.unavailable.clone() {
                            note(&mut notes, &mut notes_total, text);
                        }
                        // An orphan's start address is a pointer no loaded
                        // module accounts for, so it belongs in the same
                        // cross-reference as the callback targets and DPC
                        // routines.
                        for orphan in &pass.orphans {
                            candidates.push((
                                format!(
                                    "a kernel thread's start address (thread {:#018x})",
                                    orphan.who.thread
                                ),
                                orphan.start_address,
                            ));
                        }
                        let capped = pass.capped.is_some();
                        thread_statuses.push((
                            GROUP_DEBUG_REGISTERS,
                            GroupStatus::performed(GROUP_DEBUG_REGISTERS, pass.debug.len(), capped),
                        ));
                        thread_statuses.push((
                            GROUP_SUSPENDED_THREADS,
                            GroupStatus::performed(
                                GROUP_SUSPENDED_THREADS,
                                pass.suspended.len(),
                                capped,
                            ),
                        ));
                        thread_statuses.push((
                            GROUP_ORPHAN_KERNEL_THREADS,
                            GroupStatus::performed(
                                GROUP_ORPHAN_KERNEL_THREADS,
                                pass.orphans.len(),
                                capped,
                            ),
                        ));
                        threads = Some(pass);
                    }
                    Err(err) => {
                        let detail = format!(
                            "the thread pass could not run: {}. All three thread groups are \
                             silent for that reason.",
                            err.detail()
                        );
                        note(&mut notes, &mut notes_total, detail.clone());
                        for name in thread_groups {
                            thread_statuses
                                .push((name, GroupStatus::did_not_run(name, Some(detail.clone()))));
                        }
                    }
                }
            }
        },
    }

    // The ETW write path. Also needs the process list, and for the same
    // reason: the route is each process's own `ntdll`.
    let mut etw: Option<EtwOutcome> = None;
    let mut etw_status: Option<GroupStatus> = None;
    match (processes, symbols.etw.as_ref()) {
        (Some(list), Some(_)) => {
            match crate::tamper_etw::examine_etw(profile, list, config.max_processes) {
                Ok(outcome) => {
                    if let Some(capped) = outcome.capped.clone() {
                        note(&mut notes, &mut notes_total, capped);
                    }
                    for text in outcome.notes.clone() {
                        note(&mut notes, &mut notes_total, text);
                    }
                    if !outcome.unassessed.is_empty() {
                        note(
                            &mut notes,
                            &mut notes_total,
                            format!(
                                "{} process(es) could not be assessed for a patched ETW write \
                                 path; each is listed with its reason, and none of them is \
                                 reported as unpatched.",
                                outcome.unassessed.len()
                            ),
                        );
                    }
                    etw_status = Some(GroupStatus::performed(
                        GROUP_ETW_PATCH,
                        outcome.exports.len(),
                        outcome.capped.is_some(),
                    ));
                    etw = Some(outcome);
                }
                Err(err) => {
                    let detail = format!(
                        "the ETW write path could not be examined: {}. Nothing is said about \
                         whether any process had disabled its own event logging.",
                        err.detail()
                    );
                    note(&mut notes, &mut notes_total, detail.clone());
                    etw_status = Some(GroupStatus::did_not_run(GROUP_ETW_PATCH, Some(detail)));
                }
            }
        }
        (None, _) => {
            let detail = "there was no process list to walk, and this check reads each \
                          process's own ntdll. The detection is written; what is missing is the \
                          list."
                .to_string();
            note(&mut notes, &mut notes_total, detail.clone());
            etw_status = Some(GroupStatus::did_not_run(GROUP_ETW_PATCH, Some(detail)));
        }
        (Some(_), None) => {}
    }

    // The skeleton-key check. Same shape as the ETW group: it reads a module
    // inside a process, so it needs the process list.
    let mut skeleton: Option<SkeletonOutcome> = None;
    let mut skeleton_status: Option<GroupStatus> = None;
    match (processes, symbols.skeleton.as_ref()) {
        (Some(list), Some(_)) => {
            match crate::tamper_skeleton::examine_skeleton_key(profile, list) {
                Ok(outcome) => {
                    for text in outcome.notes.clone() {
                        note(&mut notes, &mut notes_total, text);
                    }
                    for (process, reason) in outcome.unassessed.clone() {
                        note(
                            &mut notes,
                            &mut notes_total,
                            format!(
                                "the lsass.exe at {process:#018x} could not be assessed for a \
                                 skeleton key: {reason}"
                            ),
                        );
                    }
                    skeleton_status = Some(GroupStatus::performed(
                        GROUP_SKELETON_KEY,
                        outcome.examined.len(),
                        false,
                    ));
                    skeleton = Some(outcome);
                }
                Err(err) => {
                    let detail = format!(
                        "the LSA could not be examined: {}. Nothing is said about whether this \
                         machine's domain authentication had been subverted.",
                        err.detail()
                    );
                    note(&mut notes, &mut notes_total, detail.clone());
                    skeleton_status =
                        Some(GroupStatus::did_not_run(GROUP_SKELETON_KEY, Some(detail)));
                }
            }
        }
        (None, _) => {
            let detail = "there was no process list to walk, and this check reads cryptdll \
                          inside lsass.exe. The detection is written; what is missing is the \
                          list."
                .to_string();
            note(&mut notes, &mut notes_total, detail.clone());
            skeleton_status = Some(GroupStatus::did_not_run(GROUP_SKELETON_KEY, Some(detail)));
        }
        (Some(_), None) => {}
    }

    // Now the cross-reference, with every address any group could not
    // attribute.
    if let Some(table) = unloaded.as_mut() {
        crate::tamper_unloaded::cross_reference(table, &candidates, &modules);
    }

    let groups: Vec<GroupStatus> = GROUPS
        .iter()
        .map(|name| {
            if *name == GROUP_UNLOADED_MODULES {
                if let Some(status) = unloaded_status.take() {
                    return status;
                }
            }
            if *name == GROUP_TIMERS {
                if let Some(status) = timers_status.take() {
                    return status;
                }
            }
            if let Some(index) = thread_statuses.iter().position(|(n, _)| n == name) {
                return thread_statuses.remove(index).1;
            }
            if *name == GROUP_ETW_PATCH {
                if let Some(status) = etw_status.take() {
                    return status;
                }
            }
            if *name == GROUP_SKELETON_KEY {
                if let Some(status) = skeleton_status.take() {
                    return status;
                }
            }
            // Two different sentences, and the record must carry whichever is
            // true: this build cannot support the group, or the detection is
            // not written yet. Conflating them would let "not implemented"
            // read as "your image does not support this".
            let implemented = group_is_implemented(name);
            let detail = match (symbols.unavailable_for(name), implemented) {
                (Some(why), true) => why.to_string(),
                (Some(why), false) => format!(
                    "{why} (And this group's detection is not implemented in this build either \
                     -- ROADMAP §5.3.)"
                ),
                (None, true) => format!(
                    "This build's symbols carry what the `{name}` group needs and its detection \
                     is written, and it still did not run. That is a defect rather than a \
                     limitation; treat the group as having established nothing."
                ),
                (None, false) => format!(
                    "This build's symbols carry what the `{name}` group needs, and the group's \
                     detection is not implemented yet (ROADMAP §5.3). Its silence here is the \
                     absence of a check, not the absence of a signal."
                ),
            };
            GroupStatus::did_not_run(name, Some(detail))
        })
        .collect();

    // What the stage is incomplete about, in the order that matters most.
    //
    // Three different reasons, and the record carries the one that is true
    // rather than a single flag:
    //
    // 1. a group whose detection is not written at all (none, today -- kept
    //    because the next group to be added is unwritten by definition, and
    //    this is the sentence it needs);
    // 2. a group that did not run on this image, which is the ordinary case:
    //    its own status names why;
    // 3. every group having run, which is still not "complete", because the
    //    skeleton-key check's second route does not run on any build.
    let unwritten: Vec<&str> = GROUPS
        .iter()
        .copied()
        .filter(|g| !group_is_implemented(g))
        .collect();
    let did_not_run: Vec<&str> = groups.iter().filter(|g| !g.ran).map(|g| g.group).collect();
    let incomplete = if !unwritten.is_empty() {
        Some(Incomplete::new(
            IncompleteReason::Unvalidated,
            format!(
                "{} of this stage's {} tamper-check groups has a detection written (ROADMAP \
                 §5.3); the other {} report that they did not run. Those {} are: {}. Their \
                 silence is the absence of a check and not evidence the kernel was clean.",
                IMPLEMENTED_GROUPS.len(),
                GROUPS.len(),
                unwritten.len(),
                unwritten.len(),
                unwritten.join(", ")
            ),
        ))
    } else if !did_not_run.is_empty() {
        Some(Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{} of this stage's {} groups did not run on this image: {}. Each names its own \
                 reason beside it -- an absent symbol, an absent process list, or a structure \
                 that would not read. A group that did not run establishes NOTHING, and its \
                 silence must not be read as a clean machine.",
                did_not_run.len(),
                GROUPS.len(),
                did_not_run.join(", ")
            ),
        ))
    } else {
        Some(Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            format!(
                "every one of this stage's {} groups ran, and the stage is still not complete: \
                 the skeleton-key check's second route -- the `CSystems` descriptor table -- \
                 does not run on any build, because nobody publishes that structure's layout. \
                 The group's own record carries what that route would have established.",
                GROUPS.len()
            ),
        ))
    };

    Ok(TamperOutcome {
        modules,
        groups,
        unloaded,
        timers,
        threads,
        etw,
        skeleton,
        notes,
        notes_total,
        incomplete,
    })
}
