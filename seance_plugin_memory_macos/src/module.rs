//! The `ForensicsModule` that makes this crate reachable from the orchestrator.
//!
//! Everything else here is analysis. This file is the only part that knows about
//! artifacts and subscriptions, and it is deliberately thin, because the seam it
//! plugs into ([`seance_memory::analysis`]) already owns the parts that are easy
//! to get wrong — which artifact type to subscribe to, how to tell a real memory
//! image from any other `ParsedRecord`, and how to turn the carried `DataSource`
//! back into a layer.
//!
//! ## Reachability, so it can be checked rather than believed
//!
//! ```text
//! seance_api::modules         registers Arc::new(macos_memory_module())
//!   (build_module_set, the one list both binaries build their pipeline from)
//!        │
//!        ▼
//! MemoryAnalysisModule<MacMemoryAnalysis>   (seance_memory::analysis)
//!        │  filters ParsedRecord → type == "MemoryImage"
//!        ▼
//! MacMemoryAnalysis::analyse
//!        │
//!        ├── automagic::discover_reported  → MemoryProfile record
//!        └── run_stages                    → one record per stage in STAGES
//! ```
//!
//! That registration is the one link this crate cannot make for itself, and it
//! is made: `seance_api::modules::build_module_set` holds it, and both binaries
//! register from that list. Until it existed, everything below compiled, tested
//! green, and never ran.
//!
//! ## What an examiner gets
//!
//! Discovery runs first and its result is always emitted — including when it
//! fails, because a macOS image Séance cannot profile is a fact about the
//! evidence, and the reason (the kernel banner whose symbols are missing) is
//! exactly what tells an examiner what to fetch. The one exception is an image
//! that is not macOS at all: a complete sweep that found no Darwin banner
//! produces nothing, because filing "macOS analysis failed" against every
//! Windows dump in a case is noise, not evidence.
//!
//! Every record carries [`crate::unvalidated`]'s marker.
//!
//! ## Symbol locations
//!
//! First hit wins:
//!
//! 1. `SEANCE_SYMBOL_DIRS`, a `:`-separated list.
//! 2. `<exe dir>/symbols` and `./symbols`, for a normal install.
//! 3. `reference/volatility3/volatility3/symbols`, which is where this
//!    repository already holds 129 Kernel Debug Kit packs.

use std::path::PathBuf;
use std::sync::Arc;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    module::ModuleError,
};
use seance_memory::analysis::{analysed_stamp, MemoryAnalysis, MemoryAnalysisModule};
use seance_memory::MemoryLayer;
use serde_json::json;
use tracing::{info, warn};

use crate::automagic::{self, DiscoveryError, DiscoveryOptions, DiscoveryReport};
use crate::kext;
use crate::process;
use crate::profile::MacProfile;
use crate::unvalidated::stamp_unvalidated;

/// Module id, following the tree's `plugin.<category>.<name>` convention.
pub const MODULE_ID: &str = "plugin.memory.macos";

/// Module version.
///
/// `0.1.0` and not higher on purpose: nothing here has been validated against a
/// real capture, and a version number is the first thing anyone reads as a
/// maturity claim.
pub const MODULE_VERSION: &str = "0.1.0";

/// Stage identity and the manifest record type.
///
/// Re-exported from [`seance_memory::binding`] rather than redeclared, so this
/// tier files its findings under the same identity as the Windows and Linux
/// tiers and the coverage endpoint reads all three the same way. Declaring a
/// parallel copy here is exactly the drift that once made seven stages that ran
/// report `did_not_run`.
pub use seance_memory::binding::{StageId, MEMORY_STAGE_MANIFEST_RECORD};

/// The BSD process list, walked from `allproc`.
///
/// Keyed `macos_processes` and not `processes`: `processes` is the Windows
/// tier's key, and the coverage endpoint matches a stage's records by the record
/// type its own table pairs with that key. Sharing the key while emitting a
/// different record type would make this stage report `did_not_run` on every
/// image it ran on.
pub const STAGE_PROCESSES: StageId = StageId::new(
    "macos_processes",
    "MemoryMacProcessList",
    false,
    "The BSD process list, walked from the kernel's `allproc` chain: one row per process with \
     its pid, parent, owner, name and start time.",
);

/// The Mach task queue, resolved to the processes behind it.
pub const STAGE_TASK_PROCESSES: StageId = StageId::new(
    "macos_task_processes",
    "MemoryMacTaskList",
    false,
    "The Mach task queue, resolved through each task's `bsd_info` to the process it belongs to — \
     the second, independent listing of what was running.",
);

/// Which of the two listings saw each process.
pub const STAGE_PROCESS_CROSS_VIEW: StageId = StageId::new(
    "macos_process_cross_view",
    "MemoryMacProcessCrossView",
    false,
    "Which of the two process listings saw each process and which did not. A process on one and \
     not the other has been unlinked from one of them; this stage reports the difference and \
     does not interpret it.",
);

/// Loaded kernel extensions.
pub const STAGE_KERNEL_EXTENSIONS: StageId = StageId::new(
    "macos_kernel_extensions",
    "MemoryMacKernelExtensions",
    false,
    "Loaded kernel extensions, walked from the kernel's `kmod` chain: bundle identifier, \
     version, load address, size and reference count.",
);

/// Every stage this build can run, in the order an examiner reads them.
///
/// `run_stages` emits nothing that is not in here — `stage_record` and
/// `stage_failure` take a `&StageId`, so there is no way to write a record under
/// a stage name this table does not hold — and `stage_manifest_record`
/// publishes the table alongside the analysis, so the case itself records what
/// this build could have run.
pub const STAGES: &[StageId] = &[
    STAGE_PROCESSES,
    STAGE_TASK_PROCESSES,
    STAGE_PROCESS_CROSS_VIEW,
    STAGE_KERNEL_EXTENSIONS,
];

/// macOS memory analysis.
///
/// Wrap in [`macos_memory_module`] to obtain the `ForensicsModule` the
/// orchestrator registers.
#[derive(Debug, Default)]
pub struct MacMemoryAnalysis {
    /// Directories searched for ISF symbol packs. Empty means "resolve from the
    /// environment and the usual locations at analysis time".
    symbol_dirs: Vec<PathBuf>,
    /// Discovery tuning. Defaults are the shipped caps.
    options: DiscoveryOptions,
}

impl MacMemoryAnalysis {
    /// Analysis with the default caps and the usual symbol locations.
    pub fn new() -> Self {
        Self::default()
    }

    /// Analysis that searches exactly these directories for symbols.
    pub fn with_symbol_dirs(mut self, dirs: Vec<PathBuf>) -> Self {
        self.symbol_dirs = dirs;
        self
    }

    /// Analysis with non-default discovery options.
    pub fn with_options(mut self, options: DiscoveryOptions) -> Self {
        self.options = options;
        self
    }

    /// Directories to search for ISF files, in precedence order.
    fn resolved_symbol_dirs(&self) -> Vec<PathBuf> {
        if !self.symbol_dirs.is_empty() {
            return self.symbol_dirs.clone();
        }
        let mut dirs = Vec::new();
        if let Ok(list) = std::env::var("SEANCE_SYMBOL_DIRS") {
            dirs.extend(list.split(':').filter(|s| !s.is_empty()).map(PathBuf::from));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent() {
                dirs.push(parent.join("symbols"));
            }
        }
        dirs.push(PathBuf::from("symbols"));
        dirs.push(PathBuf::from("reference/volatility3/volatility3/symbols"));
        dirs.retain(|d| d.is_dir());
        dirs
    }
}

/// The registrable module. This is what `seance_api::modules` puts in the module
/// list both binaries build their pipeline from.
pub fn macos_memory_module() -> MemoryAnalysisModule<MacMemoryAnalysis> {
    MemoryAnalysisModule::new(MacMemoryAnalysis::new())
}

impl MemoryAnalysis for MacMemoryAnalysis {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        MODULE_VERSION
    }

    fn os(&self) -> &str {
        "macos"
    }

    fn analyse(
        &self,
        physical: Arc<dyn MemoryLayer>,
        image_record: &Artifact,
    ) -> Result<Vec<Artifact>, ModuleError> {
        let dirs = self.resolved_symbol_dirs();
        match automagic::discover_reported(Arc::clone(&physical), &dirs, &self.options) {
            Ok((profile, report)) => {
                info!(
                    "{}: Darwin {} kernel, slide {:#x}, page-table base {:#x} (UNVALIDATED \
                     analysis: never run against a real macOS capture)",
                    MODULE_ID, profile.version, profile.slide.value, profile.dtb.value
                );
                let mut out = vec![
                    stage_manifest_record(image_record),
                    profile_record(image_record, &profile, &report),
                ];
                out.extend(run_stages(&profile, image_record));
                Ok(out)
            }
            // Not a macOS image at all. The trait's contract for "this analysis
            // does not apply" is an empty result, and it is the right answer:
            // every Windows dump in a case would otherwise carry a macOS
            // failure record.
            Err(err) if err.means_not_macos() => Ok(Vec::new()),
            Err(err) => {
                // Not an `Err`: a macOS image this build cannot profile is a
                // finding about the evidence, and the reason is what tells an
                // examiner what to do. Returning `Err` would abort the artifact
                // and leave the case silent about an image that plainly exists.
                //
                // The manifest still goes out: "these stages exist and none of
                // them ran" is a different and more useful statement than a
                // coverage view with no stages on it at all.
                warn!("{}: discovery failed: {}", MODULE_ID, err);
                Ok(vec![
                    stage_manifest_record(image_record),
                    discovery_failure_record(image_record, &err, &dirs),
                ])
            }
        }
    }
}

/// Run every analysis stage against a discovered profile.
///
/// A stage that fails is recorded and the rest still run: a kext chain that will
/// not walk must not cost the examiner the process list. Every failure becomes a
/// record of its own, because a stage that could not run and a stage that ran
/// and found nothing are opposite findings and must never render the same way.
fn run_stages(profile: &MacProfile, image_record: &Artifact) -> Vec<Artifact> {
    let mut out = Vec::new();
    let walk = process::ProcessWalkConfig::default();

    let proc_symbols = match process::ProcessSymbols::from_profile(profile) {
        Ok(symbols) => Some(symbols),
        Err(err) => {
            // Three stages rest on the `proc` layout, and all three are
            // reported: silence on the other two would read as "there was
            // nothing to find" rather than "nothing looked".
            for stage in [
                &STAGE_PROCESSES,
                &STAGE_TASK_PROCESSES,
                &STAGE_PROCESS_CROSS_VIEW,
            ] {
                out.push(stage_failure(image_record, profile, stage, &err));
            }
            None
        }
    };

    let mut allproc_list = None;
    let mut task_list = None;

    if let Some(symbols) = &proc_symbols {
        match process::list_allproc(profile, symbols, &walk) {
            Ok(list) => {
                out.push(stage_record(
                    image_record,
                    profile,
                    &STAGE_PROCESSES,
                    with_symbol_binding(list.to_json(), symbols.to_json()),
                    list.is_complete(),
                ));
                allproc_list = Some(list);
            }
            Err(err) => out.push(stage_failure(image_record, profile, &STAGE_PROCESSES, &err)),
        }

        // Not `from_profile().and_then(list_tasks)`: the binding the task
        // declarations resolved to is evidence in its own right, and chaining
        // consumes it before it can be recorded.
        match process::TaskSymbols::from_profile(profile) {
            Ok(tasks) => match process::list_tasks(profile, &tasks, symbols, &walk) {
                Ok(list) => {
                    out.push(stage_record(
                        image_record,
                        profile,
                        &STAGE_TASK_PROCESSES,
                        with_symbol_binding(list.to_json(), tasks.to_json()),
                        list.is_complete(),
                    ));
                    task_list = Some(list);
                }
                Err(err) => out.push(stage_failure(
                    image_record,
                    profile,
                    &STAGE_TASK_PROCESSES,
                    &err,
                )),
            },
            Err(err) => out.push(stage_failure(
                image_record,
                profile,
                &STAGE_TASK_PROCESSES,
                &err,
            )),
        }

        match (&allproc_list, &task_list) {
            (Some(allproc), Some(tasks)) => {
                let view = process::cross_view(allproc, tasks);
                out.push(stage_record(
                    image_record,
                    profile,
                    &STAGE_PROCESS_CROSS_VIEW,
                    view.to_json(),
                    // The cross-view is only as good as the two listings behind
                    // it. A difference computed from a walk that stopped early
                    // is not a finding, and stamping this complete would make
                    // it read as one.
                    view.both_listings_complete,
                ));
            }
            _ => out.push(stage_failure(
                image_record,
                profile,
                &STAGE_PROCESS_CROSS_VIEW,
                &"one of the two process listings could not be walked, so there is nothing to \
                  compare the other against; a single listing cannot show that a process was \
                  hidden from it",
            )),
        }
    }

    match kext::KextSymbols::from_profile(profile) {
        Ok(symbols) => {
            match kext::list_kexts(profile, &symbols, &kext::KextWalkConfig::default()) {
                Ok(list) => out.push(stage_record(
                    image_record,
                    profile,
                    &STAGE_KERNEL_EXTENSIONS,
                    with_symbol_binding(list.to_json(), symbols.to_json()),
                    list.is_complete(),
                )),
                Err(err) => out.push(stage_failure(
                    image_record,
                    profile,
                    &STAGE_KERNEL_EXTENSIONS,
                    &err,
                )),
            }
        }
        Err(err) => out.push(stage_failure(
            image_record,
            profile,
            &STAGE_KERNEL_EXTENSIONS,
            &err,
        )),
    }

    out
}

/// Attach the stage's symbol binding to the record it produced.
///
/// [`seance_memory::binding::BuildBinding::to_json`] says which of the members
/// the stage declared this kernel build actually has, which spelling each
/// resolved to, and what was left unbound. Every row in this crate can carry
/// `not_declared` for a column, and without the binding beside it that cell is
/// an assertion an examiner cannot check against the pack — the difference
/// between "this build has no `p_name`" and "the analysis did not look" is
/// exactly what it settles.
///
/// Three stages produce this and, until it was attached here, nothing consumed
/// it: the evidence was computed on every run and thrown away.
fn with_symbol_binding(
    mut value: serde_json::Value,
    binding: serde_json::Value,
) -> serde_json::Value {
    if let Some(object) = value.as_object_mut() {
        object.insert("symbol_binding".into(), binding);
    }
    value
}

/// The reasons a record itself gives for being short, as one sentence.
///
/// Every analysis type in this crate carries an `incomplete` array of
/// `{reason, detail}`. Promoting the details to the standard
/// `content_incomplete_reason` key means a consumer that reads only the two
/// standard keys still learns *why* a count is a floor, rather than having to
/// know each stage's own blob shape.
fn incomplete_reason(value: &serde_json::Value) -> Option<String> {
    let details: Vec<&str> = value
        .get("incomplete")
        .and_then(serde_json::Value::as_array)
        .map(|entries| {
            entries
                .iter()
                .filter_map(|entry| entry.get("detail").and_then(serde_json::Value::as_str))
                .collect()
        })
        .unwrap_or_default();
    if details.is_empty() {
        return None;
    }
    Some(details.join("; "))
}

/// A record carrying one stage's results.
pub(crate) fn stage_record(
    parent: &Artifact,
    profile: &MacProfile,
    stage: &StageId,
    mut value: serde_json::Value,
    complete: bool,
) -> Artifact {
    let reason = incomplete_reason(&value);
    // `expect`, and not `if let`: every stage's `to_json` builds an object, and
    // the identity, the completeness and the unvalidated marker are all applied
    // *inside* it. Skipping the block for a non-object would emit a record with
    // no `validated_against_real_capture` on it at all — the one thing this
    // crate must never do — and it would do it silently. The three other record
    // builders here already fail loudly on the same question; this one used to
    // fail open.
    let object = value
        .as_object_mut()
        .expect("a stage result is a JSON object");
    object.insert("type".into(), json!(stage.record_type));
    object.insert("record_type".into(), json!(stage.record_type));
    object.insert("stage".into(), json!(stage.key));
    object.insert("stage_ran".into(), json!(true));
    // A stage that stopped early has produced a floor, not a total, and a
    // report that quotes its counts has to say so.
    object.insert("content_complete".into(), json!(complete));
    if !complete {
        object.insert("content_incomplete".into(), json!(true));
        object.insert(
            "content_incomplete_reason".into(),
            json!(reason.unwrap_or_else(|| format!(
                "the {} stage did not establish this result in full and recorded no reason",
                stage.key
            ))),
        );
    }
    stamp(object, Some(profile));
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

/// A record saying a stage could not run, and why.
///
/// Emitted rather than logged because the absence of a stage's findings is not
/// evidence that there was nothing to find.
pub(crate) fn stage_failure(
    parent: &Artifact,
    profile: &MacProfile,
    stage: &StageId,
    err: &dyn std::fmt::Display,
) -> Artifact {
    let key = stage.key;
    warn!("{}: stage '{}' did not run: {}", MODULE_ID, key, err);
    let mut value = json!({
        "type": "MemoryStageFailure",
        "record_type": "MemoryStageFailure",
        "name": format!("macOS memory analysis: {key} did not run"),
        "stage": key,
        "stage_ran": false,
        "content_complete": false,
        "content_incomplete": true,
        "content_incomplete_reason": err.to_string(),
        "failure": err.to_string(),
    });
    stamp(
        value.as_object_mut().expect("object literal"),
        Some(profile),
    );
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

/// The stage manifest: every stage this build of the analysis can run.
///
/// Emitted whether or not discovery succeeds, and before any stage runs, so the
/// case holds the analysis's own account of what it was capable of.
pub(crate) fn stage_manifest_record(parent: &Artifact) -> Artifact {
    let mut value = json!({
        "type": MEMORY_STAGE_MANIFEST_RECORD,
        "record_type": MEMORY_STAGE_MANIFEST_RECORD,
        "name": "macOS memory analysis: stages this build can run",
        "stages": STAGES.iter().map(StageId::to_json).collect::<Vec<_>>(),
        "stage_count": STAGES.len(),
        "content_complete": true,
    });
    stamp(value.as_object_mut().expect("object literal"), None);
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

/// Fields every record carries, so a finding can be traced back to the profile —
/// and the evidence grade — it rests on, and so no record can leave this crate
/// without saying it has never been validated.
fn stamp(object: &mut serde_json::Map<String, serde_json::Value>, profile: Option<&MacProfile>) {
    for (key, value) in analysed_stamp("macos", MODULE_ID, MODULE_VERSION)
        .as_object()
        .expect("stamp is an object")
    {
        object.insert(key.clone(), value.clone());
    }
    if let Some(profile) = profile {
        object.insert(
            "profile_evidence".into(),
            json!(profile.weakest_evidence().as_str()),
        );
        object.insert("symbols_verified".into(), json!(profile.symbols_verified()));
        object.insert("kernel_banner".into(), json!(profile.banner));
    }
    // Last, so nothing above can weaken it.
    stamp_unvalidated(object);
}

/// The image-profile record: what discovery established, and how.
fn profile_record(parent: &Artifact, profile: &MacProfile, report: &DiscoveryReport) -> Artifact {
    let mut value = profile.to_json();
    let object = value.as_object_mut().expect("profile.to_json is an object");
    object.insert("type".into(), json!("MemoryProfile"));
    object.insert("subtype".into(), json!("macos_memory_profile"));
    object.insert(
        "name".into(),
        json!(format!("macOS (Darwin {}) memory profile", profile.version)),
    );
    object.insert("profile_established".into(), json!(true));
    object.insert("discovery".into(), report.to_json());
    stamp(object, Some(profile));
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

/// Emitted when discovery could not profile an image that is plainly a macOS
/// capture, or that may be one.
///
/// Carries the reason in a form an examiner can act on — most usefully the
/// kernel banner whose symbol pack is missing, which is the one thing that turns
/// a failed analysis into a successful one.
fn discovery_failure_record(
    parent: &Artifact,
    err: &DiscoveryError,
    searched: &[PathBuf],
) -> Artifact {
    let mut value = json!({
        "type": "MemoryProfile",
        "subtype": "macos_memory_profile",
        "name": "macOS memory profile (not established)",
        "analysis_stage": "discovery_failed",
        "analysed_os": "macos",
        "analysed_by": MODULE_ID,
        "analysed_by_version": MODULE_VERSION,
        "profile_established": false,
        "content_complete": false,
        "content_incomplete": true,
        "content_incomplete_reason": err.to_string(),
        "failure": err.to_string(),
        "symbol_dirs_searched": searched
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>(),
        // Where a symbol file may be placed, on every OS tier alike (LIVE-026).
        "symbol_dirs_accepted": seance_memory::analysis::SYMBOL_DIR_GUIDANCE,
    });
    // The banner is the actionable half of most of these failures, so it is
    // lifted into a field of its own rather than left inside a sentence.
    if let DiscoveryError::NoSymbols { banner, .. } = err {
        value["kernel_banner_wanted"] = json!(banner);
    }
    stamp_unvalidated(value.as_object_mut().expect("object literal"));
    Artifact::new(parent.case_id, ArtifactType::ParsedRecord, None, value).with_parent(parent.id)
}

#[cfg(test)]
mod tests {

    /// LIVE-026 applies to every OS tier, not just Windows: a failure that
    /// lists only the directories that happen to exist tells an examiner where
    /// this build looked, not where they may put the symbols it asked for.
    #[test]
    fn a_discovery_failure_says_where_symbols_may_be_placed_macos() {
        let accepted = seance_memory::analysis::SYMBOL_DIR_GUIDANCE;
        let joined = accepted.join(" | ");
        assert!(joined.contains("SEANCE_SYMBOL_DIRS"), "got {joined}");
        assert!(joined.contains("symbols"), "got {joined}");
    }
    use super::*;
    use seance_core::module::ForensicsModule;

    fn image() -> Artifact {
        Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            None,
            json!({"type": "MemoryImage"}),
        )
    }

    #[test]
    fn the_module_carries_the_conventional_id() {
        let m = macos_memory_module();
        assert_eq!(m.id(), "plugin.memory.macos");
        assert!(m.id().starts_with("plugin."));
    }

    #[test]
    fn the_module_subscribes_to_the_record_the_container_stage_emits() {
        let m = macos_memory_module();
        assert_eq!(m.subscribes_to(), vec![ArtifactType::ParsedRecord]);
    }

    #[test]
    fn explicit_symbol_dirs_win_over_the_environment() {
        let a = MacMemoryAnalysis::new().with_symbol_dirs(vec![PathBuf::from("/nonexistent")]);
        assert_eq!(
            a.resolved_symbol_dirs(),
            vec![PathBuf::from("/nonexistent")]
        );
    }

    #[test]
    fn every_stage_identity_is_unique_in_both_its_key_and_its_record_type() {
        // Two stages sharing a key would make coverage report one over the
        // other; two sharing a record type would make one stage's rows count as
        // the other's, so a stage that never ran could read as complete.
        for stage in STAGES {
            assert_eq!(
                STAGES.iter().filter(|s| s.key == stage.key).count(),
                1,
                "duplicate stage key {}",
                stage.key
            );
            assert_eq!(
                STAGES
                    .iter()
                    .filter(|s| s.record_type == stage.record_type)
                    .count(),
                1,
                "duplicate record type {}",
                stage.record_type
            );
            assert!(
                !stage.key.is_empty() && !stage.describes.is_empty(),
                "{stage:?}"
            );
            assert!(
                stage.record_type.starts_with("Memory"),
                "{} does not follow the Memory* record naming",
                stage.record_type
            );
        }
    }

    #[test]
    fn no_stage_key_collides_with_the_windows_tiers_keys() {
        // The coverage endpoint keys a stage's records on the record type its
        // own table pairs with that key. A macOS stage sharing a Windows key
        // would be looked up under the Windows record type, find none, and be
        // reported as `did_not_run` on every image it ran on.
        const WINDOWS_KEYS: [&str; 6] = [
            "processes",
            "process_tree",
            "kernel_modules",
            "cross_view",
            "pool_scan",
            "handles",
        ];
        for stage in STAGES {
            assert!(
                !WINDOWS_KEYS.contains(&stage.key),
                "{} collides with the Windows tier's stage key of the same name",
                stage.key
            );
            assert!(
                stage.key.starts_with("macos_"),
                "{} does not carry the tier prefix that keeps it distinct",
                stage.key
            );
        }
    }

    #[test]
    fn the_manifest_publishes_every_stage_this_build_can_run() {
        let parent = image();
        let manifest = stage_manifest_record(&parent);
        assert_eq!(manifest.metadata["type"], json!("MemoryStageManifest"));
        assert_eq!(manifest.metadata["stage_count"], json!(STAGES.len()));
        assert_eq!(manifest.parent_id, Some(parent.id));

        let declared = manifest.metadata["stages"].as_array().expect("an array");
        assert_eq!(declared.len(), STAGES.len());
        for stage in STAGES {
            let row = declared
                .iter()
                .find(|row| row["stage"] == json!(stage.key))
                .unwrap_or_else(|| panic!("{} is missing from the manifest", stage.key));
            // The four names `seance_api::memory::declared_stages` reads. A
            // rename on either side does not fail a build; it blanks a coverage
            // row, which an examiner reads as "nothing to find here".
            assert_eq!(row["record_type"], json!(stage.record_type));
            assert_eq!(row["per_process"], json!(stage.per_process));
            assert!(row["describes"].as_str().is_some_and(|d| !d.is_empty()));
        }
    }

    #[test]
    fn the_manifest_carries_the_unvalidated_marker() {
        // The manifest is the first record a coverage view reads, so it is the
        // first place the claim has to appear.
        let manifest = stage_manifest_record(&image());
        assert_eq!(
            manifest.metadata["validated_against_real_capture"],
            json!(false)
        );
        assert_eq!(
            manifest.metadata["validation_state"],
            json!(crate::unvalidated::VALIDATION_STATE)
        );
        assert_eq!(manifest.metadata["analysed_os"], json!("macos"));
    }

    #[test]
    fn the_single_stamping_point_applies_the_marker_and_applies_it_last() {
        // `stage_record` and `stage_failure` have no stamping code of their own;
        // they call this. Testing it here covers them, and the "last" half is
        // what stops a stage body that set one of these keys from weakening the
        // claim.
        let mut object = serde_json::Map::new();
        object.insert("validated_against_real_capture".into(), json!(true));
        object.insert("validation_state".into(), json!("looks fine to me"));
        stamp(&mut object, None);
        assert_eq!(object["validated_against_real_capture"], json!(false));
        assert_eq!(
            object["validation_state"],
            json!(crate::unvalidated::VALIDATION_STATE)
        );
        assert_eq!(object["analysed_by"], json!(MODULE_ID));
        assert_eq!(object["analysis_stage"], json!("analysed"));
    }

    #[test]
    fn a_stage_record_carries_the_binding_its_not_declared_cells_rest_on() {
        // A row saying `not_declared` for `p_name` is a claim about the kernel
        // build. The binding is the only thing in the record that lets an
        // examiner check that claim against the symbol pack, so it travels with
        // the rows rather than being computed and discarded.
        let value = with_symbol_binding(
            json!({"process_count": 1}),
            json!({"stage": "macos_processes", "members": []}),
        );
        assert_eq!(value["process_count"], json!(1));
        assert_eq!(value["symbol_binding"]["stage"], json!("macos_processes"));
    }

    #[test]
    fn a_discovery_failure_record_names_the_banner_to_fetch_symbols_for() {
        let err = DiscoveryError::NoSymbols {
            banner: "Darwin Kernel Version 19.6.0: x".to_string(),
            version: "19.6.0".to_string(),
            packs_indexed: 3,
            skipped_no_banner: 12,
        };
        let record = discovery_failure_record(&image(), &err, &[PathBuf::from("/symbols")]);
        assert_eq!(record.metadata["profile_established"], json!(false));
        assert_eq!(
            record.metadata["kernel_banner_wanted"],
            json!("Darwin Kernel Version 19.6.0: x")
        );
        assert_eq!(
            record.metadata["validated_against_real_capture"],
            json!(false)
        );
        assert!(record.metadata["failure"]
            .as_str()
            .is_some_and(|f| f.contains("12 macOS pack(s) declared no banner")));
    }

    #[test]
    fn an_image_with_no_darwin_banner_produces_nothing_rather_than_a_failure_record() {
        // A Windows crash dump handed to this tier is not a macOS analysis
        // failure. Filing one against every non-Mac image in a case is noise,
        // and noise is what stops an examiner reading the real ones.
        let complete = DiscoveryError::NoBanner {
            bytes_scanned: 0x4000,
            completeness: "complete",
        };
        assert!(complete.means_not_macos());

        // But a sweep that could not look at everything has established
        // nothing, and must not be silently treated as "not a Mac".
        let partial = DiscoveryError::NoBanner {
            bytes_scanned: 0x1000,
            completeness: "incomplete",
        };
        assert!(!partial.means_not_macos());
    }
}
