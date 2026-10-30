#![forbid(unsafe_code)]
//! **Windows autostart extensibility points (ASEPs).**
//!
//! This crate answers one question, once, for a whole machine: *what will
//! Windows execute at boot or at logon, and why?* It reads the evidence Séance
//! has already parsed — registry hives, task definitions, the filesystem — and
//! emits one `AsepEntry` record per autostart location, each stating where the
//! entry lives, what it points at, whether that target was found in the
//! evidence, and a plain sentence describing what would run and when.
//!
//! # Completeness is the deliverable
//!
//! An examiner asks this question once. If a whole family of autostart
//! locations is missing from the answer, the omission is invisible, and an
//! implant that survives reboot through that family survives the examination
//! too. So every category in [`rules::CATEGORIES`] is reported for every hive
//! examined, and an `AsepCoverage` record states, per category:
//!
//! * **examined** with a count — including a count of zero, which means the
//!   locations were read and were empty;
//! * **examined_partial** — read, but a cap or an undecoded payload means the
//!   count is a lower bound;
//! * **not_applicable_to_hive** — this hive cannot carry the category, and the
//!   hive that can is named;
//! * **unexamined** — not read at all.
//!
//! WMI event subscriptions live in the CIM repository (`OBJECTS.DATA`), not
//! in a hive. When that file is in the evidence it is read by a record-level
//! scan ([`wmi`]) and gets a coverage record of its own stating the bytes
//! scanned and the records matched, decoded and undecodable; the per-hive
//! coverage rows point at it. The scan does not read the repository's index
//! or page mapping, and every record it emits says so.
//!
//! "Checked and empty" and "never checked" must never render the same, and an
//! item that could not be decoded is emitted with `read_status: "unread"`
//! rather than dropped.
//!
//! # This module does not accuse
//!
//! An ASEP entry is a fact about how a machine is configured. Whether a given
//! entry is unwanted is the examiner's determination, so records carry neutral
//! `observations` — the image resolves outside the system directories, the
//! Winlogon value differs from the one Windows ships — and no score, no verdict
//! and no "suspicious" flag.
//!
//! # Wiring
//!
//! [`AsepEnumerator`] is the single [`ForensicsModule`]. It subscribes to
//! `FileEntry` and `SystemArtifact` (so it sees the volume as it is walked, and
//! the task and Startup-folder files and the WMI repository on it) and to
//! `ParsedRecord` (so it sees the `RegistryHive` records the registry plugin
//! produces). Its own output is
//! also a `ParsedRecord`; those are ignored on re-entry, so there is no
//! fan-out loop.

pub mod coverage;
pub mod index;
pub mod normalize;
pub mod record;
pub mod registry;
pub mod rules;
pub mod services;
pub mod startup;
pub mod task_xml;
pub mod wmi;
pub mod wmi_entries;
pub mod wmi_index;
pub mod wmi_mapping;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod wmi_index_tests;
#[cfg(test)]
mod wmi_mapping_tests;
#[cfg(test)]
mod wmi_tests;

use crate::coverage::{
    build_coverage_artifact, build_wmi_coverage_artifact, HiveScanSummary, WmiCoverageInput,
};
use crate::index::EvidenceIndex;
use crate::normalize::{basename, normalize_evidence_path};
use crate::record::{
    attach_target_resolution, build_entry_artifacts, AsepEntry, EmitContext, LocationKind,
    ReadStatus, MODULE_ID,
};
use crate::registry::{RegistryScanInput, RegistryScanOutput};
use crate::rules::HiveKind;
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::read_capped;
use seance_core::module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError};
use serde_json::{json, Value};
use std::sync::Mutex;
use tracing::debug;

/// Why a registry-backed entry has no install timestamp.
///
/// The parsed hive record carries key paths and values but not per-key
/// last-write times, so there is nothing to read. Stating that plainly is the
/// fail-closed answer; emitting the hive's own timestamp, or an epoch value,
/// would put a moment in the case timeline that no evidence supports.
pub const KEY_TIME_UNAVAILABLE: &str =
    "The parsed registry record does not carry per-key last-write times, so when this \
     entry was installed or last modified could not be established from the hive.";

/// Ceiling on a task definition read into memory. Task XML is kilobyte-scale.
pub const MAX_TASK_BYTES: u64 = 8 * 1024 * 1024;

/// Enumerates Windows autostart extensibility points across registry,
/// scheduled tasks and Startup folders.
///
/// Register one instance in the module list. It keeps a small index of the
/// executable files seen during the run so that each entry can state whether
/// its target was observed in the evidence; that index is the only state it
/// holds, and it is never used to claim a file is absent.
pub struct AsepEnumerator {
    index: Mutex<EvidenceIndex>,
}

impl AsepEnumerator {
    /// A fresh enumerator with an empty evidence index.
    pub fn new() -> Self {
        Self {
            index: Mutex::new(EvidenceIndex::new()),
        }
    }

    /// Lock the index, recovering from a poisoned mutex rather than panicking.
    /// A panic in one artifact's processing must not take the rest of the
    /// evidence down with it.
    fn index(&self) -> std::sync::MutexGuard<'_, EvidenceIndex> {
        self.index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Default for AsepEnumerator {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for AsepEnumerator {
    fn id(&self) -> &str {
        MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            ArtifactType::SystemArtifact,
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        match artifact.artifact_type {
            ArtifactType::FileEntry | ArtifactType::SystemArtifact => {
                Ok(self.process_file(artifact))
            }
            ArtifactType::ParsedRecord => Ok(self.process_parsed_record(artifact)),
            _ => Ok(Vec::new()),
        }
    }
}

impl AsepEnumerator {
    /// Index a file, and emit an entry when the file *is* an autostart item —
    /// a Startup-folder item or a scheduled task definition.
    fn process_file(&self, artifact: &Artifact) -> Vec<Artifact> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or("");
        let path = artifact
            .metadata
            .get("path")
            .or_else(|| artifact.metadata.get("source_path"))
            .and_then(Value::as_str)
            .unwrap_or("");
        if path.is_empty() && name.is_empty() {
            return Vec::new();
        }
        let is_directory = artifact
            .metadata
            .get("is_directory")
            .and_then(Value::as_bool)
            == Some(true);
        let effective_path = if path.is_empty() { name } else { path };

        if is_directory {
            return Vec::new();
        }

        {
            let mut index = self.index();
            index.note_file(effective_path);
            index.note_created(
                effective_path,
                artifact.metadata.get("created").and_then(Value::as_str),
            );
            if is_registry_hive_name(basename(effective_path)) {
                index.note_hive_file(artifact.id, effective_path);
            }
        }

        let normalized = normalize_evidence_path(effective_path);
        let created = artifact
            .metadata
            .get("created")
            .and_then(Value::as_str)
            .map(str::to_string);

        if let Some(location) = startup::classify_startup_path(&normalized) {
            let base = basename(effective_path).to_ascii_lowercase();
            // desktop.ini configures the folder's appearance; Windows does not
            // execute it, so it is not an autostart item.
            if base == "desktop.ini" {
                return Vec::new();
            }
            let shortcut = if base.ends_with(".lnk") {
                Some(match artifact.data.as_ref() {
                    Some(ds) => {
                        let buf = read_capped(ds.as_ref(), startup::MAX_LNK_BYTES);
                        startup::parse_lnk(&buf)
                    }
                    None => Err(startup::LnkError::ContentUnavailable),
                })
            } else {
                None
            };
            let mut entry = startup::startup_entry(
                effective_path,
                basename(effective_path),
                &location,
                shortcut,
                created,
            );
            return self.emit(
                &mut entry,
                EmitContext {
                    case_id: artifact.case_id,
                    parent_id: artifact.id,
                    registry_record_id: None,
                    file_artifact_id: Some(artifact.id),
                },
            );
        }

        if is_task_store_path(&normalized) {
            return self.process_task_file(artifact, effective_path, created);
        }

        if is_wmi_repository_objects_path(&normalized) {
            return self.process_wmi_repository(artifact, effective_path);
        }

        Vec::new()
    }

    /// Scan the CIM repository's `OBJECTS.DATA` for event subscriptions.
    ///
    /// The file that could not be read still produces a coverage record, with
    /// the category marked unexamined: the repository was in the evidence and
    /// was not looked at, which is not the same as looked at and empty.
    fn process_wmi_repository(&self, artifact: &Artifact, path: &str) -> Vec<Artifact> {
        let ctx = EmitContext {
            case_id: artifact.case_id,
            parent_id: artifact.id,
            registry_record_id: None,
            file_artifact_id: Some(artifact.id),
        };
        let unread = |reason: &str| {
            vec![build_wmi_coverage_artifact(WmiCoverageInput {
                path,
                outcome: None,
                unread_reason: Some(reason),
                capped_note: None,
                entries_emitted: 0,
                mapping: None,
                case_id: ctx.case_id,
                parent_id: ctx.parent_id,
                file_artifact_id: artifact.id,
            })]
        };
        let Some(ds) = artifact.data.as_ref() else {
            return unread(
                "The repository file's content was not available to this module, so no \
                 subscription record was read. Nothing can be concluded about what the \
                 repository does or does not contain.",
            );
        };
        let declared = ds.size();
        let buf = read_capped(ds.as_ref(), wmi::MAX_OBJECTS_DATA_BYTES);
        if buf.is_empty() {
            return unread(
                "The repository file is empty or could not be read, so no subscription \
                 record was read.",
            );
        }
        let over_cap = declared > wmi::MAX_OBJECTS_DATA_BYTES;
        let short_read = !over_cap && (buf.len() as u64) < declared;
        let capped_note = if over_cap {
            Some(format!(
                "The file declares {declared} bytes; only the first {} were read (the \
                 {}-byte ceiling), so records beyond that were not scanned.",
                buf.len(),
                wmi::MAX_OBJECTS_DATA_BYTES
            ))
        } else if short_read {
            Some(format!(
                "Only {} of the file's {declared} declared bytes could be read, so records \
                 beyond that were not scanned.",
                buf.len()
            ))
        } else {
            None
        };

        // The page mapping beside the file (HUNT-195): MAPPING1/2/3.MAP, or
        // OBJECTS.MAP on XP, reached by name through the neighbour bundle a
        // filesystem walker attaches, or on disk beside a loose file.
        let mapping = wmi_mapping::read_beside(ds.as_ref(), buf.len() / wmi::PAGE_SIZE);
        let mut outcome =
            wmi::scan_with_mapping(&buf, mapping.used.as_ref().map(|(_, m)| &m.objects));
        outcome.mapping_file = mapping
            .used
            .as_ref()
            .map(|(name, m)| (name.clone(), m.sequence));
        outcome.apply_index(mapping.index.clone());
        let entries = wmi_entries::entries_from_scan(&outcome, path);
        let mut out = Vec::with_capacity(entries.len().saturating_add(1));
        let emitted = entries.len();
        for mut entry in entries {
            out.extend(self.emit(&mut entry, ctx));
        }
        out.push(build_wmi_coverage_artifact(WmiCoverageInput {
            path,
            outcome: Some(&outcome),
            unread_reason: None,
            capped_note: capped_note.as_deref(),
            entries_emitted: emitted,
            mapping: Some(&mapping),
            case_id: ctx.case_id,
            parent_id: ctx.parent_id,
            file_artifact_id: artifact.id,
        }));
        out
    }

    /// Read a file that sits in the Task Scheduler's store.
    ///
    /// Anything in that store is a task definition by construction, so a file
    /// this build cannot decode produces an entry marked unread rather than
    /// nothing. A scheduled task that vanishes from the report because its
    /// encoding was unexpected is precisely the silent omission this crate
    /// exists to prevent.
    fn process_task_file(
        &self,
        artifact: &Artifact,
        path: &str,
        created: Option<String>,
    ) -> Vec<Artifact> {
        let name = basename(path).to_string();
        let ctx = EmitContext {
            case_id: artifact.case_id,
            parent_id: artifact.id,
            registry_record_id: None,
            file_artifact_id: Some(artifact.id),
        };

        // One exit point, so that the file-creation-time fallback below applies
        // to every outcome — including the ones this build cannot decode.
        let mut entry = if name.to_ascii_lowercase().ends_with(".job") {
            unread_task_entry(
                path,
                &name,
                "This is a Task Scheduler 1.0 `.job` file, a binary format this build does \
                 not decode. The task exists and is scheduled; its triggers and its action \
                 were not read.",
            )
        } else {
            match artifact.data.as_ref() {
                None => unread_task_entry(
                    path,
                    &name,
                    "The task file's content was not available to this module, so its \
                     triggers and action were not read.",
                ),
                Some(ds) => {
                    let declared = ds.size();
                    let buf = read_capped(ds.as_ref(), MAX_TASK_BYTES);
                    // A file larger than the ceiling was capped; a file the
                    // source could not deliver in full was short-read. A file
                    // that is exactly the ceiling and came back whole is
                    // neither, and must not be reported as truncated (B7-017).
                    let over_cap = declared > MAX_TASK_BYTES;
                    let short_read = !over_cap && (buf.len() as u64) < declared;
                    if buf.is_empty() {
                        unread_task_entry(
                            path,
                            &name,
                            "This file in the Task Scheduler store is empty or could not be \
                             read, so no task definition was recovered from it.",
                        )
                    } else if !task_xml::looks_like_task_xml(&buf) {
                        unread_task_entry(
                            path,
                            &name,
                            "This file sits in the Task Scheduler store but does not carry a \
                             Task Scheduler 2.0 definition, so no triggers or actions could \
                             be read from it.",
                        )
                    } else {
                        match task_xml::decode(&buf).and_then(|text| task_xml::parse(&text)) {
                            Ok(task) => {
                                let mut entry = task_xml::task_entry(&task, path, &name);
                                if over_cap {
                                    entry.incomplete_reason = Some(format!(
                                        "The task file was read up to the \
                                         {MAX_TASK_BYTES}-byte ceiling; anything beyond that \
                                         was not parsed."
                                    ));
                                    entry.incomplete_code =
                                        Some(seance_core::io::IncompleteReason::CapReached);
                                } else if short_read {
                                    entry.incomplete_reason = Some(format!(
                                        "Only {} of the task file's {} declared bytes could \
                                         be read, so triggers or actions declared later in \
                                         the definition may be missing.",
                                        buf.len(),
                                        declared
                                    ));
                                    entry.incomplete_code =
                                        Some(seance_core::io::IncompleteReason::ShortRead);
                                }
                                entry
                            }
                            Err(err) => {
                                debug!("ASEP: task definition at {} did not parse: {}", path, err);
                                unread_task_entry(
                                    path,
                                    &name,
                                    &format!(
                                        "The task definition could not be parsed ({err}). The \
                                         file is present in the Task Scheduler store, so a \
                                         task is scheduled; what it runs was not read."
                                    ),
                                )
                            }
                        }
                    }
                }
            }
        };
        // A definition with no RegistrationInfo/Date falls back to the task
        // file's own creation time, under its own provenance label so the two
        // are never confused in the timeline.
        if entry.installed_time.is_none() {
            entry.installed_time = created.map(|ts| record::InstalledTime {
                value: ts,
                source: "task_file_created",
                timezone: None,
            });
            if entry.installed_time.is_some() {
                entry.installed_time_unavailable_reason = None;
            }
        }
        self.emit(&mut entry, ctx)
    }

    /// Enumerate the registry ASEPs in a parsed hive record and emit the
    /// coverage statement that goes with it.
    fn process_parsed_record(&self, artifact: &Artifact) -> Vec<Artifact> {
        if artifact.metadata.get("type").and_then(Value::as_str) != Some("RegistryHive") {
            return Vec::new();
        }
        let hive_name = artifact
            .metadata
            .get("hive_type")
            .and_then(Value::as_str)
            .unwrap_or("(unnamed hive)");
        let hive_kind = HiveKind::from_hive_name(hive_name);

        // Only the live SOFTWARE hive: its setup-time backup (`SOFTWARE.SAV`) is the same kind to the
        // enumerator and records an InstallDate of 0.
        if hive_kind == HiveKind::Software && hive_name.eq_ignore_ascii_case("SOFTWARE") {
            if let Some(epoch) = artifact
                .metadata
                .get("all_values")
                .and_then(Value::as_array)
                .and_then(|v| registry::os_install_epoch(v))
            {
                self.index().note_os_install(epoch);
            }
        }

        let (hive_path, hive_index_capped) = {
            let index = self.index();
            let path = artifact
                .parent_id
                .and_then(|parent| index.hive_path(&parent).map(str::to_string));
            (path, index.hives_capped())
        };
        let user = hive_path
            .as_deref()
            .and_then(|p| profile_from_hive_path(p, hive_name));

        let values_total = artifact
            .metadata
            .get("total_values")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;
        let keys_total = artifact
            .metadata
            .get("total_keys")
            .and_then(Value::as_u64)
            .unwrap_or(0) as usize;

        let values = artifact
            .metadata
            .get("all_values")
            .and_then(Value::as_array);

        let RegistryScanOutput {
            entries,
            mut summary,
        } = match values {
            Some(values) => registry::scan(&RegistryScanInput {
                hive_name,
                hive_kind,
                hive_path: hive_path.clone(),
                user: user.clone(),
                values,
                values_total,
                keys_total,
            }),
            None => {
                let mut summary = HiveScanSummary::new(hive_name.to_string(), hive_kind);
                summary.hive_path = hive_path.clone();
                summary.user = user.clone();
                summary.values_total = values_total;
                summary.keys_total = keys_total;
                summary.values_unavailable_reason = Some(
                    "The parsed hive record carried no `all_values` array, so no registry \
                     autostart location in this hive was read. Nothing can be concluded \
                     about what this hive does or does not contain."
                        .to_string(),
                );
                RegistryScanOutput {
                    entries: Vec::new(),
                    summary,
                }
            }
        };

        // A per-user hive that could not be tied back to its own file cannot be
        // attributed to a profile, and the reason has to travel with the record:
        // an unattributed HKCU Run key reads as if it applied to everyone.
        if hive_path.is_none() {
            summary.scan_notes.push(if hive_index_capped {
                format!(
                    "The hive file's own path was not recorded because the hive-path index \
                     reached its ceiling of {} entries, so this hive could not be attributed \
                     to a user profile.",
                    index::MAX_TRACKED_HIVES
                )
            } else {
                "The hive file's own path was not seen during this ingest, so this hive \
                 could not be attributed to a user profile."
                    .to_string()
            });
        }

        let ctx = EmitContext {
            case_id: artifact.case_id,
            parent_id: artifact.id,
            registry_record_id: Some(artifact.id),
            file_artifact_id: artifact.parent_id,
        };

        let mut out = Vec::with_capacity(entries.len().saturating_add(1));
        for mut entry in entries {
            // Which hive file this came from, so the live hive can be told from a copy (`HUNT-276`).
            if let Some(path) = &hive_path {
                entry.put("hive_path", json!(path));
            }
            out.extend(self.emit(&mut entry, ctx));
        }
        out.push(build_coverage_artifact(
            &summary,
            artifact.case_id,
            artifact.id,
            artifact.id,
        ));
        out
    }

    /// Resolve the entry's target against the evidence index and turn it into
    /// artifacts.
    fn emit(&self, entry: &mut AsepEntry, ctx: EmitContext) -> Vec<Artifact> {
        let (resolution, install_time) = {
            let index = self.index();
            (
                index.resolve_in(entry.image.as_deref(), &entry.search_context),
                index.os_install_time(),
            )
        };
        attach_target_resolution(entry, &resolution);
        if resolution.status != index::TargetStatus::NotApplicable {
            // When the system was installed, so a file created before it can be told from one created after
            // (`HUNT-276`). Stamped only if the SOFTWARE hive had been read when this entry was made.
            match install_time {
                Some(t) => {
                    entry.put("os_install_time", json!(t));
                    entry.put("os_install_time_basis", json!(index::OS_INSTALL_BASIS));
                }
                None => entry.put("os_install_time_basis", json!(index::OS_INSTALL_UNSEEN)),
            }
        }
        build_entry_artifacts(entry, &ctx)
    }
}

/// A file in the Task Scheduler store whose definition could not be read.
fn unread_task_entry(path: &str, name: &str, reason: &str) -> AsepEntry {
    let mut entry = AsepEntry::new("scheduled_task", name, path, LocationKind::File);
    entry.scope = "filesystem".to_string();
    entry.enabled = None;
    entry.enabled_basis =
        "The task definition was not read, so whether the task is enabled is unknown.".to_string();
    entry.runs_when =
        "A task is registered at this path in the Task Scheduler store. Its triggers were \
         not read, so when it runs could not be stated."
            .to_string();
    entry.read_status = ReadStatus::Unread(reason.to_string());
    entry.incomplete_reason = Some(reason.to_string());
    // The definition was not decoded at all, so nothing about the task is known
    // beyond its presence — an unresolved structure, not a cap.
    entry.incomplete_code = Some(seance_core::io::IncompleteReason::UnresolvedStructure);
    entry.installed_time_unavailable_reason =
        Some("The task definition was not read, so it yielded no registration date.");
    entry.put("task_definition_read", json!(false));
    entry
}

/// True for the CIM repository's object store: `\wbem\Repository\OBJECTS.DATA`,
/// or `\wbem\Repository\FS\OBJECTS.DATA`, the form observed on Windows XP
/// (documentation gives the same path for Server 2003, which was not
/// observed). The
/// directory is the gate, as for tasks: the same file name elsewhere is not
/// the repository the WMI service reads.
fn is_wmi_repository_objects_path(normalized: &str) -> bool {
    normalized.contains("/wbem/repository/") && normalized.ends_with("/objects.data")
}

/// True for the Task Scheduler 2.0 store and the legacy 1.0 store.
///
/// Task definitions have no extension, so the store's path is the gate. That is
/// also the correct forensic gate: the Task Scheduler only executes definitions
/// it finds in these directories, so an identical XML file elsewhere on the
/// volume is not an autostart entry.
fn is_task_store_path(normalized: &str) -> bool {
    normalized.contains("/windows/system32/tasks/")
        || normalized.contains("/windows/syswow64/tasks/")
        || normalized.contains("/windows/tasks/")
}

/// File names this build treats as registry hives when remembering hive paths.
fn is_registry_hive_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "software"
            | "system"
            | "sam"
            | "security"
            | "default"
            | "components"
            | "drivers"
            | "ntuser.dat"
            | "usrclass.dat"
    )
}

/// The profile a hive belongs to, from the hive file's own path.
///
/// Returns `None` when the path does not name a profile — a machine-wide hive,
/// or a per-user hive recovered from a location the profile cannot be read
/// from. A guessed profile name attached to a Run key would attribute one
/// user's autostart entry to another.
fn profile_from_hive_path(path: &str, hive_name: &str) -> Option<String> {
    let normalized = normalize_evidence_path(path);
    for marker in ["/users/", "/documents and settings/"] {
        if let Some(pos) = normalized.find(marker) {
            let start = pos.checked_add(marker.len())?;
            let rest = normalized.get(start..)?;
            let seg = match rest.find('/') {
                Some(end) => rest.get(..end)?,
                None => rest,
            };
            if !seg.is_empty() {
                return Some(seg.to_string());
            }
        }
    }
    if normalized.contains("/config/systemprofile/") {
        return Some("SYSTEM profile".to_string());
    }
    if hive_name.eq_ignore_ascii_case("DEFAULT") && normalized.contains("/config/") {
        return Some(".DEFAULT profile".to_string());
    }
    None
}
