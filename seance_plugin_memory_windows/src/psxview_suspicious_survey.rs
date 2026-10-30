//! Suspicious threads across a whole image: [`suspicious_threads`] run over
//! every process on the shared process list (MEM-024).
//!
//! The per-process analysis says where one process's threads started running
//! and whether anything was ever loaded there. This is the stage around it:
//! symbols resolved once, the protection table loaded once, every process on
//! the list either judged, declared out of scope with the reason, or recorded
//! as skipped with the error that stopped it. A process missing from this
//! result would be indistinguishable from one judged and found ordinary, so
//! none is dropped.
//!
//! # Out of scope is not skipped
//!
//! Two kinds of process are not judged, and neither makes the survey
//! incomplete, because there is nothing there this analysis could test:
//!
//! * a process whose **Peb is null** (System, Registry, Memory Compression).
//!   That null Peb is all that is observed and all the reason claims: a WSL1
//!   pico process also has a null Peb and does have user threads, and it is
//!   set aside unjudged like the rest, so an out-of-scope process is "not
//!   looked at", never "clean";
//! * a process that had **already exited** has had its address space torn
//!   down, and every comparison would describe the teardown.
//!
//! A process whose analysis *failed* — its `_EPROCESS` could not be read, its
//! VAD root could not be followed — is different: it is on the list, it may
//! have been the injected one, and it is recorded in
//! [`SuspiciousThreadsSurvey::skipped`] and makes the survey incomplete.

use std::collections::BTreeMap;

use seance_core::io::IncompleteReason;
use seance_memory::Incomplete;

use crate::hollow::ScanStop;
use crate::process::{Field, ProcessInventory, ProcessList, ProcessRecord, ProcessSymbols};
use crate::profile::WindowsProfile;
use crate::psxview::suspicious::{suspicious_threads, SuspiciousThreads, SuspiciousThreadsConfig};
use crate::psxview::threads::ThreadSymbols;
use crate::psxview::PsXViewError;
use crate::vad::VadSymbols;

/// The three symbol sets the analysis reads, resolved once per image.
#[derive(Debug, Clone)]
pub struct SuspiciousThreadSymbols {
    /// `_EPROCESS` members.
    pub process: ProcessSymbols,
    /// `_ETHREAD` members.
    pub threads: ThreadSymbols,
    /// VAD-tree members.
    pub vad: VadSymbols,
}

impl SuspiciousThreadSymbols {
    /// Resolve every symbol set the analysis needs.
    ///
    /// # Errors
    ///
    /// When this build's processes, threads or VAD tree cannot be described.
    /// That is a stage that could not run, not a process that was clean.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, PsXViewError> {
        Ok(Self {
            process: ProcessSymbols::from_profile(profile)?,
            threads: ThreadSymbols::from_profile(profile)?,
            vad: VadSymbols::from_profile(profile)?,
        })
    }
}

/// A process the survey did not judge, and why.
#[derive(Debug, Clone)]
pub struct UnjudgedProcess {
    /// The `_EPROCESS`.
    pub process: u64,
    /// The process id, when the list read it.
    pub pid: Option<u64>,
    /// The image name, when the list read it.
    pub image_file_name: Option<String>,
    /// Why it was not judged.
    pub reason: String,
}

impl UnjudgedProcess {
    fn of(record: &ProcessRecord, reason: String) -> Self {
        Self {
            process: record.address,
            pid: record.pid.known().copied(),
            image_file_name: record.image_file_name.known().cloned(),
            reason,
        }
    }

    /// Serializable form.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "reason": self.reason,
        })
    }
}

/// Every process on one list, judged or accounted for.
#[derive(Debug, Clone)]
pub struct SuspiciousThreadsSurvey {
    /// One entry per process the analysis ran on, clean or not. A clean entry
    /// is how a report says which processes were actually cleared.
    pub processes: Vec<SuspiciousThreads>,
    /// Processes there was nothing to judge in, with the reason. Capped by
    /// [`SuspiciousThreadsConfig::max_recorded_skips`].
    pub out_of_scope: Vec<UnjudgedProcess>,
    /// How many were out of scope. Exact.
    pub out_of_scope_total: usize,
    /// Processes whose analysis failed, with the error. Capped likewise.
    pub skipped: Vec<UnjudgedProcess>,
    /// How many failed. Exact.
    pub skipped_total: usize,
    /// Why the survey ended.
    pub stop: ScanStop,
    /// Whether the kernel's protection table was loaded. Without it every
    /// protection comparison is a gap.
    pub protections_available: bool,
    /// How complete the list this survey walked was.
    pub inventory: ProcessInventory,
}

/// Why this process is out of scope, if it is.
fn out_of_scope_reason(record: &ProcessRecord) -> Option<String> {
    // `NotApplicable` means this process's Peb is null. A build with no `Peb`
    // member yields `NotDeclared`, which is a fact about the build, and such a
    // process is judged rather than waved through.
    if matches!(record.peb, Field::NotApplicable) {
        return Some(
            "this process's Peb is null, which is how System, Registry, Memory Compression \
             and the other minimal processes read, so it was not judged. A null Peb is all that \
             was observed: a process with a null Peb that nevertheless has user threads (a WSL1 \
             pico process) is not judged here either, and nothing is claimed about its threads"
                .to_string(),
        );
    }
    if record.has_exited() == Some(true) {
        return Some(
            "this process had already exited when the image was taken, so its address space has \
             been torn down and every comparison would describe the teardown"
                .to_string(),
        );
    }
    None
}

/// Run [`suspicious_threads`] over every process on a list.
///
/// Never fails as a whole: a process whose analysis errors is recorded in
/// [`SuspiciousThreadsSurvey::skipped`] with the error.
pub fn survey_suspicious_threads(
    profile: &WindowsProfile,
    symbols: &SuspiciousThreadSymbols,
    list: &ProcessList,
    config: &SuspiciousThreadsConfig,
) -> SuspiciousThreadsSurvey {
    let mut survey = SuspiciousThreadsSurvey {
        processes: Vec::new(),
        out_of_scope: Vec::new(),
        out_of_scope_total: 0,
        skipped: Vec::new(),
        skipped_total: 0,
        stop: ScanStop::Exhausted,
        protections_available: config.vad.protections.is_some(),
        inventory: list.inventory(),
    };
    let cap = config.max_recorded_skips;

    for record in &list.processes {
        if let Some(reason) = out_of_scope_reason(record) {
            survey.out_of_scope_total = survey.out_of_scope_total.saturating_add(1);
            if survey.out_of_scope.len() < cap {
                survey
                    .out_of_scope
                    .push(UnjudgedProcess::of(record, reason));
            }
            continue;
        }
        if survey.processes.len() >= config.max_processes {
            survey.stop = ScanStop::CapReached {
                cap: config.max_processes,
            };
            break;
        }
        match suspicious_threads(
            profile,
            &symbols.process,
            &symbols.threads,
            &symbols.vad,
            record.address,
            config,
        ) {
            Ok(judged) => survey.processes.push(judged),
            Err(err) => {
                survey.skipped_total = survey.skipped_total.saturating_add(1);
                if survey.skipped.len() < cap {
                    survey.skipped.push(UnjudgedProcess::of(
                        record,
                        format!("the analysis of this process failed: {err}"),
                    ));
                }
            }
        }
    }
    survey
}

impl SuspiciousThreadsSurvey {
    /// Findings that are statements about a process, across every process.
    pub fn evidence_count(&self) -> usize {
        self.processes.iter().map(|p| p.evidence().count()).sum()
    }

    /// Findings that record only that a check could not be made.
    pub fn gap_count(&self) -> usize {
        self.processes.iter().map(|p| p.gaps().count()).sum()
    }

    /// Distinct start addresses that fell in no range, across every process.
    pub fn starts_outside_the_tree(&self) -> usize {
        self.processes
            .iter()
            .map(|p| p.starts_outside_the_tree)
            .sum()
    }

    /// Distinct start addresses tested, summed per process.
    pub fn starts_tested(&self) -> usize {
        self.processes.iter().map(|p| p.starts_tested).sum()
    }

    /// Threads whose Win32StartAddress held an LPC message id, across every
    /// process.
    pub fn win32_starts_holding_an_lpc_message_id(&self) -> usize {
        self.processes
            .iter()
            .map(|p| p.win32_starts_holding_an_lpc_message_id)
            .sum()
    }

    /// Distinct kernel-mode start addresses, across every process.
    pub fn starts_in_kernel_space(&self) -> usize {
        self.processes
            .iter()
            .map(|p| p.starts_in_kernel_space)
            .sum()
    }

    /// Distinct kernel-mode start addresses on threads not known to be kernel
    /// threads, across every process. Judged by no stage.
    pub fn kernel_starts_on_threads_not_known_as_system(&self) -> usize {
        self.processes
            .iter()
            .map(|p| p.kernel_starts_on_threads_not_known_as_system)
            .sum()
    }

    /// Processes the analysis ran on and judged (VAD tree large enough).
    pub fn processes_analysed(&self) -> usize {
        self.processes.iter().filter(|p| p.analysed).count()
    }

    /// Evidence findings by the kind of suspicion they carry. A finding with
    /// two suspicions counts under both, so the values need not sum to
    /// [`Self::evidence_count`].
    pub fn evidence_by_kind(&self) -> BTreeMap<&'static str, usize> {
        let mut out = BTreeMap::new();
        for finding in self.processes.iter().flat_map(|p| p.evidence()) {
            for suspicion in &finding.suspicions {
                *out.entry(suspicion.kind.as_str()).or_insert(0) += 1;
            }
        }
        out
    }

    /// Whether the survey can support "no thread on this machine started
    /// outside a mapped image": the whole list, no cap, no failure, every
    /// process judged over a whole tree and thread list, no start outside
    /// every range, and no check that could not be made.
    pub fn is_complete(&self) -> bool {
        self.inventory.is_complete()
            && self.protections_available
            && self.stop.is_complete()
            && self.skipped_total == 0
            && self.gap_count() == 0
            && self.processes.iter().all(SuspiciousThreads::is_complete)
    }

    /// Everything a report must declare about the survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        out.extend(self.inventory.incomplete.iter().cloned());
        if let ScanStop::CapReached { cap } = self.stop {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the suspicious-thread survey stopped at its cap of {cap} process(es); the \
                     process list continued"
                ),
            ));
        }
        if self.skipped_total > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} process(es) could not be judged because their analysis failed; each is \
                     listed with its error",
                    self.skipped_total
                ),
            ));
        }
        if !self.protections_available {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "this image's protection table was not available, so no range's protection could \
                 be compared against the one an image section is mapped with",
            ));
        }
        let unjudged = self.processes.iter().filter(|p| !p.is_complete()).count();
        if unjudged > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{unjudged} process(es) were judged over a partial VAD tree or thread list, \
                     had a start address that fell in no range, had a kernel start address on a \
                     thread not known to be a kernel thread, had an unreadable LPC flag, or had \
                     too few ranges to judge; each process's own entry says which"
                ),
            ));
        }
        let kernel_unexamined = self.kernel_starts_on_threads_not_known_as_system();
        if kernel_unexamined > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{kernel_unexamined} kernel start address(es) are on threads whose \
                     _KTHREAD.SystemThread is clear, unreadable or not declared; neither this \
                     stage nor the tamper_checks orphan-thread group judged whether they lie in \
                     a loaded module"
                ),
            ));
        }
        out
    }

    /// Serializable form for the stage record. Stamped with the inventory it
    /// rests on.
    pub fn to_json(&self) -> serde_json::Value {
        let complete = self.is_complete();
        let mut value = serde_json::json!({
            "processes": self.processes.iter().map(SuspiciousThreads::to_json).collect::<Vec<_>>(),
            "processes_judged": self.processes.len(),
            "processes_analysed": self.processes_analysed(),
            "out_of_scope": self.out_of_scope.iter().map(UnjudgedProcess::to_json).collect::<Vec<_>>(),
            "out_of_scope_total": self.out_of_scope_total,
            "skipped": self.skipped.iter().map(UnjudgedProcess::to_json).collect::<Vec<_>>(),
            "skipped_total": self.skipped_total,
            "stop": self.stop.as_str(),
            "protections_available": self.protections_available,
            "evidence_count": self.evidence_count(),
            "evidence_by_kind": self.evidence_by_kind(),
            "gap_count": self.gap_count(),
            "starts_tested": self.starts_tested(),
            "starts_outside_the_tree": self.starts_outside_the_tree(),
            "starts_in_kernel_space": self.starts_in_kernel_space(),
            "kernel_starts_on_threads_not_known_as_system":
                self.kernel_starts_on_threads_not_known_as_system(),
            "win32_starts_holding_an_lpc_message_id": self.win32_starts_holding_an_lpc_message_id(),
            "complete": complete,
            "content_complete": complete,
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
            "meaning": "Each live thread's two start addresses, placed in the VAD that covers \
                        them. A start in a range backed by no file, in a range not created with \
                        PAGE_EXECUTE_WRITECOPY, or in another application's executable is \
                        evidence; a range whose protection or file could not be read is a gap, \
                        not a finding. A start in no range is counted and not attributed.",
        });
        self.inventory.stamp(&mut value);
        value
    }
}
