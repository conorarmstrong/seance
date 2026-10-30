//! Leads from the kernel-side tamper checks (§2.2, and `ROADMAP` §5.3's last
//! subtask).
//!
//! # This module detects nothing, and here that matters more than usual
//!
//! Every signal it raises was already decided by
//! `seance_plugin_memory_windows`'s `tamper_checks` stage, which read the
//! structures, applied the exclusions and — for each of its seven groups —
//! **measured its false-positive count on a clean Windows 11 capture before the
//! rule shipped** (`seance_memory/tests/KNOWN_ANSWERS.md`). Re-deriving any of
//! it here would produce a second rule with no measurement behind it, and two
//! numbers for one fact from one tool.
//!
//! So this reads the stage's own record and turns the rows it already marked as
//! signals into ranked leads. What it adds is the grade and the qualification,
//! which is what a triage screen needs and a stage record does not carry.
//!
//! # Why nothing here is `Strong`
//!
//! Not one of these signals is hard to produce innocently, and three of them
//! have a documented innocent cause:
//!
//! * An address inside the range of a driver the kernel **unloaded** is a lead
//!   and never a verdict: that range was freed when the driver went and may
//!   have been reused by anything since. The stage stamps every one
//!   `is_a_verdict: false`, and this module keeps it at [`Confidence::Weak`].
//! * A DPC routine or a kernel thread start in no loaded module is
//!   [`Confidence::Notable`]: a legitimately unloaded driver produces it, which
//!   is why the stage cross-references the unloaded table before grading.
//! * A hardware breakpoint is [`Confidence::Notable`]: debuggers set them, and
//!   so does legitimate instrumentation.
//! * A patched `EtwEventWrite` or `CDLocateCSystem` is the closest thing here
//!   to a hard signal, and it is still [`Confidence::Notable`]: a hooking
//!   product patches the same bytes for its own reasons, and the stage says so.
//!
//! **A suspended thread raises nothing at all.** The stage reports it as a
//! listing with `is_a_finding: false`, because the platform suspends packaged
//! apps, debuggers suspend, and `CREATE_SUSPENDED` is how nearly every
//! injector starts a thread. Promoting it to the triage list is precisely the
//! `HUNT-051` mistake, and the stage has already said so on every row.

use crate::prelude::*;

/// Raises leads from a `MemoryTamperChecks` record.
#[derive(Debug, Default)]
pub struct KernelTamperFindings;

/// The module id, cited in `seance_api::FINDING_DETECTIONS`.
pub const MODULE_ID: &str = "plugin.findings.kernel_tamper";

/// What the stage's record is called.
const RECORD_TYPE: &str = "MemoryTamperChecks";

/// Read an array from the record, or an empty slice.
fn array<'a>(value: &'a serde_json::Value, key: &str) -> &'a [serde_json::Value] {
    value
        .get(key)
        .and_then(|v| v.as_array())
        .map(|a| a.as_slice())
        .unwrap_or_default()
}

fn text(value: &serde_json::Value, key: &str) -> Option<String> {
    value
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

impl KernelTamperFindings {
    pub fn new() -> Self {
        Self
    }

    /// The findings for one stage record, or none.
    pub fn findings_for(&self, artifact: &Artifact) -> Vec<Finding> {
        if artifact
            .metadata
            .get("record_type")
            .and_then(|v| v.as_str())
            != Some(RECORD_TYPE)
        {
            return Vec::new();
        }
        let subject = subject_of(artifact);
        let offset = device_offset_of(artifact);
        let mut out = Vec::new();

        self.unloaded_range_hits(artifact, subject, offset, &mut out);
        self.timer_routines(artifact, subject, offset, &mut out);
        self.orphan_threads(artifact, subject, offset, &mut out);
        self.debug_registers(artifact, subject, offset, &mut out);
        self.etw(artifact, subject, offset, &mut out);
        self.skeleton_key(artifact, subject, offset, &mut out);
        out
    }

    /// An address inside the range of a driver the kernel unloaded.
    fn unloaded_range_hits(
        &self,
        artifact: &Artifact,
        subject: uuid::Uuid,
        offset: Option<u64>,
        out: &mut Vec<Finding>,
    ) {
        let table = match artifact.metadata.get("unloaded_modules") {
            Some(table) if table.is_object() => table,
            _ => return,
        };
        for hit in array(table, "range_hits") {
            let driver = text(hit, "unloaded_driver").unwrap_or_else(|| "a driver".to_string());
            let what = text(hit, "what").unwrap_or_else(|| "an address".to_string());
            let address = text(hit, "address").unwrap_or_default();
            let mut evidence = vec![
                EvidenceItem::new("address", address.clone()),
                EvidenceItem::new("unloaded_driver", driver.clone()),
            ];
            for key in [
                "unloaded_driver_start",
                "unloaded_driver_end",
                "unloaded_at",
            ] {
                if let Some(v) = text(hit, key) {
                    evidence.push(EvidenceItem::new(key, v));
                }
            }
            if let Some(owner) = hit.get("also_owned_by").and_then(|v| v.get("kind")) {
                evidence.push(EvidenceItem::new(
                    "loaded_modules_say",
                    owner.as_str().unwrap_or("unknown").to_string(),
                ));
            }
            out.push(Finding {
                kind: "pointer_into_unloaded_driver".to_string(),
                title: format!("{what} points into unloaded {driver}"),
                subject_artifact: subject,
                // Weak, and the stage says why on every row: the range was
                // freed the moment the driver unloaded.
                confidence: Confidence::Weak,
                observation: format!(
                    "{what} at {address} falls inside the address range {driver} occupied before \
                     the kernel unloaded it."
                ),
                evidence,
                inference: Some(
                    "A pointer the loaded-module list cannot account for, landing in a range a \
                     driver held until it unloaded, is where a driver that loaded, acted and \
                     unloaded would leave one."
                        .to_string(),
                ),
                qualification:
                    "This establishes nothing on its own and the stage marks it `is_a_verdict: \
                     false`. That range was FREED when the driver unloaded and the kernel may \
                     have reused it for anything since, so an address inside it need have no \
                     connection to the driver named. Both sides are reported so the two can be \
                     weighed: read the loaded-module attribution beside it, and the unload time."
                        .to_string(),
                device_offset: offset,
                source_module: MODULE_ID.to_string(),
            });
        }
    }

    /// A timer whose DPC routine lands in no loaded module.
    fn timer_routines(
        &self,
        artifact: &Artifact,
        subject: uuid::Uuid,
        offset: Option<u64>,
        out: &mut Vec<Finding>,
    ) {
        let timers = match artifact.metadata.get("timers") {
            Some(timers) if timers.is_object() => timers,
            _ => return,
        };
        // `MEM-055`: one lead per `_KTIMER`. The stage publishes a timer
        // reached from several bucket lists as one row; a record from a
        // producer that published one row per sighting still raises one lead.
        let mut seen_timers = std::collections::HashSet::new();
        for row in array(timers, "timers") {
            if row.get("is_signal") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            // `MEM-054`: a row the stage names as PatchGuard-shaped is
            // published ungraded and never becomes a lead, even from a
            // producer that still marks it a signal.
            if row.get("patchguard_shaped") == Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let routine = text(row, "deferred_routine").unwrap_or_default();
            let timer = text(row, "timer_address").unwrap_or_default();
            if !timer.is_empty() && !seen_timers.insert(timer.clone()) {
                continue;
            }
            let mut evidence = vec![
                EvidenceItem::new("deferred_routine", routine.clone()),
                EvidenceItem::new("timer", timer.clone()),
            ];
            for key in [
                "dpc_address",
                "period_ms",
                "bucket",
                "processor",
                "reached_from",
            ] {
                if let Some(v) = row.get(key).filter(|v| !v.is_null()) {
                    evidence.push(EvidenceItem::new(key, v.to_string()));
                }
            }
            out.push(Finding {
                kind: "kernel_timer_routine_unattributed".to_string(),
                title: format!("Kernel timer will call {routine}, which no loaded driver owns"),
                subject_artifact: subject,
                confidence: Confidence::Notable,
                observation: format!(
                    "The timer at {timer} carries a DPC whose routine is {routine}, and that \
                     address lies inside no module on the kernel's loaded-module list."
                ),
                evidence,
                inference: Some(
                    "A kernel timer is how code arranges to run later without a thread of its \
                     own, and a routine the loader cannot account for is where code that does \
                     not want to be listed would put one."
                        .to_string(),
                ),
                qualification:
                    "A driver that has since unloaded produces this, which is why the stage \
                     cross-references the unloaded-driver table — check whether a \
                     `pointer_into_unloaded_driver` lead names the same address. So does a \
                     hot-patched routine and a legitimately pool-allocated thunk. The stage \
                     reports this only when the loaded-module list was complete enough for \
                     'in no module' to be a statement about the machine. A timer with the \
                     shape of PatchGuard's own (an unaligned `_KTIMER`, a routine in no module \
                     and a non-canonical context, all three) is published ungraded and raises \
                     no lead; a rootkit could imitate that shape, so read those rows too. Only a \
                     timer whose DPC routine was located can be graded, so the clean baseline \
                     is counted in those, as distinct timers: on the clean captures measured \
                     it raises nothing, 0 of 52 on Windows 11 26200, 0 of 39 on DFIR Madness \
                     Case 001's domain controller, 0 of 38 on the Case 001 desktop (whose one \
                     timer outside every module has the PatchGuard shape), 0 of 49 on \
                     13Cubed's and 0 of 50 on Lone Wolf's. No capture held shows a timer \
                     rootkit, so it has not been measured against one."
                        .to_string(),
                device_offset: offset,
                source_module: MODULE_ID.to_string(),
            });
        }
    }

    /// A kernel thread starting outside every loaded module — graded rows only.
    fn orphan_threads(
        &self,
        artifact: &Artifact,
        subject: uuid::Uuid,
        offset: Option<u64>,
        out: &mut Vec<Finding>,
    ) {
        let threads = match artifact.metadata.get("threads") {
            Some(threads) if threads.is_object() => threads,
            _ => return,
        };
        for row in array(threads, "orphan_kernel_threads") {
            // **Graded rows only.** An observation is a row one of whose four
            // exclusions could not be assessed, and promoting it here would
            // publish a claim with one of its own controls unapplied.
            if row.get("is_graded_finding") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let start = text(row, "start_address").unwrap_or_default();
            let tid = row
                .get("tid")
                .filter(|v| !v.is_null())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".to_string());
            let mut evidence = vec![
                EvidenceItem::new("start_address", start.clone()),
                EvidenceItem::new("tid", tid.clone()),
            ];
            if let Some(v) = text(row, "thread_address") {
                evidence.push(EvidenceItem::new("thread", v));
            }
            if let Some(v) = text(row, "kernel_thread_basis") {
                evidence.push(EvidenceItem::new("kernel_thread_established_by", v));
            }
            out.push(Finding {
                kind: "orphan_kernel_thread".to_string(),
                title: format!(
                    "Kernel thread {tid} starts at {start}, which no loaded driver owns"
                ),
                subject_artifact: subject,
                confidence: Confidence::Notable,
                observation: format!(
                    "Kernel thread {tid} was started at {start}, an address inside no module on \
                     the kernel's loaded-module list. The thread had not terminated, the kernel \
                     had not marked its start address meaningless, and the address is not inside \
                     the range of any driver the kernel has unloaded."
                ),
                evidence,
                inference: Some(
                    "A kernel thread running from memory the loader cannot account for is what a \
                     reflectively-loaded driver leaves behind."
                        .to_string(),
                ),
                qualification:
                    "All four of the stage's exclusions were applied and satisfied for this row, \
                     which is what makes it a graded finding rather than an observation — but a \
                     satisfied exclusion is not a proof. A driver unloaded before this capture \
                     whose entry the fifty-slot table had already overwritten would produce \
                     exactly this, and so would a hot-patch. On the clean capture this project \
                     measures against, no thread of 1,514 produced it."
                        .to_string(),
                device_offset: offset,
                source_module: MODULE_ID.to_string(),
            });
        }
    }

    /// A thread carrying an armed hardware breakpoint.
    fn debug_registers(
        &self,
        artifact: &Artifact,
        subject: uuid::Uuid,
        offset: Option<u64>,
        out: &mut Vec<Finding>,
    ) {
        let threads = match artifact.metadata.get("threads") {
            Some(threads) if threads.is_object() => threads,
            _ => return,
        };
        for row in array(threads, "debug_register_threads") {
            if row.get("has_breakpoint") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let tid = row
                .get("tid")
                .filter(|v| !v.is_null())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".to_string());
            let process = text(row, "process_name").unwrap_or_else(|| "a process".to_string());
            let armed = row
                .get("armed_slots")
                .and_then(|v| v.as_u64())
                .unwrap_or_default();
            let mut evidence = vec![
                EvidenceItem::new("armed_slots", armed.to_string()),
                EvidenceItem::new("dr7", text(row, "dr7").unwrap_or_default()),
            ];
            for slot in array(row, "breakpoints") {
                let address = text(slot, "address").unwrap_or_default();
                let enable = text(slot, "enable").unwrap_or_default();
                let owner = slot
                    .get("ownership")
                    .and_then(|v| v.get("kind"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                evidence.push(EvidenceItem::new(
                    format!(
                        "slot {}",
                        slot.get("slot").map(|v| v.to_string()).unwrap_or_default()
                    ),
                    format!("{address} ({enable}, {owner})"),
                ));
            }
            if let Some(v) = text(row, "claim") {
                evidence.push(EvidenceItem::new("claim", v));
            }
            out.push(Finding {
                kind: "thread_hardware_breakpoint".to_string(),
                title: format!("Thread {tid} of {process} carries {armed} armed debug register(s)"),
                subject_artifact: subject,
                confidence: Confidence::Notable,
                observation: format!(
                    "Thread {tid} of {process} has {armed} debug-register slot(s) that `Dr7`'s \
                     own enable bits arm, and the thread's own `DebugActive`/`ActiveDR7` flags \
                     say its registers are live."
                ),
                evidence,
                inference: Some(
                    "Hardware breakpoints are how execution is intercepted without modifying \
                     any code, which is what makes them attractive to a hooking technique that \
                     wants to leave the bytes alone."
                        .to_string(),
                ),
                qualification:
                    "A debugger sets these, and so does legitimate instrumentation and some \
                     anti-cheat and DRM. The stage reports a slot as armed only when `Dr7` \
                     enables it — a stale address in an unarmed slot is listed separately and \
                     claimed as nothing — and only when the thread itself claims its registers \
                     are live, because the `Dr` fields share their storage with unrelated \
                     members. On the clean capture this project measures against, no thread of \
                     1,514 claimed debug state at all."
                        .to_string(),
                device_offset: offset,
                source_module: MODULE_ID.to_string(),
            });
        }
    }

    /// An ETW write export that either route marked.
    fn etw(
        &self,
        artifact: &Artifact,
        subject: uuid::Uuid,
        offset: Option<u64>,
        out: &mut Vec<Finding>,
    ) {
        let etw = match artifact.metadata.get("etw") {
            Some(etw) if etw.is_object() => etw,
            _ => return,
        };
        for row in array(etw, "exports") {
            if row.get("is_signal") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let export = text(row, "export").unwrap_or_else(|| "an ETW export".to_string());
            let process = text(row, "process_name").unwrap_or_else(|| "a process".to_string());
            let route = text(row, "route").unwrap_or_else(|| "one route".to_string());
            let mut evidence = vec![
                EvidenceItem::new("export", export.clone()),
                EvidenceItem::new("route", route.clone()),
                EvidenceItem::new("prologue", text(row, "prologue").unwrap_or_default()),
                EvidenceItem::new(
                    "classification",
                    text(row, "classification").unwrap_or_default(),
                ),
            ];
            if let Some(v) = text(row, "classification_detail") {
                evidence.push(EvidenceItem::new("decoded", v));
            }
            for key in ["mode_agreed", "mode_population"] {
                if let Some(v) = row.get(key).filter(|v| !v.is_null()) {
                    evidence.push(EvidenceItem::new(key, v.to_string()));
                }
            }
            out.push(Finding {
                kind: "etw_write_path_patched".to_string(),
                title: format!("{export} in {process} does not match the rest of the machine"),
                subject_artifact: subject,
                confidence: Confidence::Notable,
                observation: format!(
                    "{export} in {process} was marked by the {route} route: its first bytes \
                     either decode to a function that does nothing, or differ from the value \
                     every other process on this machine holds for the same export."
                ),
                evidence,
                inference: Some(
                    "Overwriting the first bytes of `EtwEventWrite` stops a process producing \
                     event-tracing records while every API call it makes still succeeds. The \
                     effect is an absence of log entries rather than an entry, so nothing in an \
                     event log records it."
                        .to_string(),
                ),
                qualification:
                    "A hooking product — endpoint protection, an application-compatibility \
                     shim, an instrumentation framework — patches these bytes for its own \
                     reasons and looks the same. `ordinary` on the other rows is not a claim \
                     that they are unpatched either: a patch further into the function, or one \
                     that preserves the prologue, is invisible to both routes. Read the decoded \
                     instructions and the count that agreed with the mode."
                        .to_string(),
                device_offset: offset,
                source_module: MODULE_ID.to_string(),
            });
        }
    }

    /// A patched `CDLocateCSystem` in `lsass.exe`.
    fn skeleton_key(
        &self,
        artifact: &Artifact,
        subject: uuid::Uuid,
        offset: Option<u64>,
        out: &mut Vec<Finding>,
    ) {
        let skeleton = match artifact.metadata.get("skeleton_key") {
            Some(skeleton) if skeleton.is_object() => skeleton,
            _ => return,
        };
        for row in array(skeleton, "lsass_processes") {
            if row.get("is_signal") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let pid = row
                .get("pid")
                .filter(|v| !v.is_null())
                .map(|v| v.to_string())
                .unwrap_or_else(|| "?".to_string());
            let mut evidence = vec![
                EvidenceItem::new("export", text(row, "export").unwrap_or_default()),
                EvidenceItem::new("module", text(row, "module").unwrap_or_default()),
                EvidenceItem::new("prologue", text(row, "prologue").unwrap_or_default()),
                EvidenceItem::new(
                    "classification",
                    text(row, "classification").unwrap_or_default(),
                ),
            ];
            if let Some(v) = text(row, "export_address") {
                evidence.push(EvidenceItem::new("export_address", v));
            }
            out.push(Finding {
                kind: "lsa_crypto_export_patched".to_string(),
                title: format!("cryptdll!CDLocateCSystem is patched in lsass.exe (pid {pid})"),
                subject_artifact: subject,
                confidence: Confidence::Notable,
                observation: format!(
                    "In the `lsass.exe` at pid {pid}, `cryptdll.dll`'s exported \
                     `CDLocateCSystem` does not begin with an ordinary function prologue."
                ),
                evidence,
                inference: Some(
                    "A skeleton key is a patch inside `lsass.exe` that makes one \
                     attacker-chosen password work for every domain account while each \
                     account's real password keeps working. `CDLocateCSystem` is one of the two \
                     places the published implementation patches."
                        .to_string(),
                ),
                qualification:
                    "This is one of the check's two routes and the other DOES NOT RUN on any \
                     build — the `CSystems` descriptor table needs a structure layout nobody \
                     publishes — so a clean result from the same check is not an absence of a \
                     skeleton key. Anything that hooks cryptographic APIs inside `lsass` \
                     produces the same shape. Read the prologue bytes and the decoded \
                     instructions before relying on it."
                        .to_string(),
                device_offset: offset,
                source_module: MODULE_ID.to_string(),
            });
        }
    }
}

impl ForensicsModule for KernelTamperFindings {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Subscribes to parsed records: the `tamper_checks` stage's record is one.
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord]
    }

    /// Reads no bytes at all — only the metadata the stage already wrote. See
    /// `TimestompFindings::input_capability` for why `Stream` is the
    /// declaration.
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        emit(artifact, self.findings_for(artifact))
    }
}
