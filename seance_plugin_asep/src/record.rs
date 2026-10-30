//! The `AsepEntry` record: one autostart extensibility point, as a fact.
//!
//! Every enumerator in this crate funnels into [`AsepEntry`] so there is one
//! definition of the record shape and one place where the forensic rules about
//! it are enforced:
//!
//! * a timestamp is written only when it was read from evidence, and it carries
//!   the source it was read from and whether it is UTC or local wall clock;
//! * an entry that could not be read is emitted with `read_status: "unread"`
//!   and a reason, never dropped — a category that silently loses its
//!   unreadable members reports as complete when it is not;
//! * anything that was capped or only partly decoded sets `incomplete` and a
//!   reason, and both reach the record;
//! * `observations` are neutral statements of fact. Nothing in this crate
//!   asserts that an entry is malicious. That an image sits in a temporary
//!   directory is a fact; that it is unwanted is the examiner's call.

use crate::index::TargetResolution;
use crate::normalize::{EncodedCommand, SplitBasis};
use crate::rules::{category, CategorySource, MITRE_TACTIC};
use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::io::IncompleteReason;
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// Module id stamped onto every record and timeline event this crate emits.
pub const MODULE_ID: &str = "plugin.windows.asep";

/// What kind of thing backs an ASEP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocationKind {
    /// A registry key (and usually a named value under it).
    RegistryKey,
    /// A file on the volume.
    File,
}

impl LocationKind {
    /// Stable string form written into the record.
    pub fn as_str(self) -> &'static str {
        match self {
            LocationKind::RegistryKey => "registry_key",
            LocationKind::File => "file",
        }
    }
}

/// Whether the ASEP's backing evidence was successfully read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadStatus {
    /// The backing key or file was read and decoded.
    Parsed,
    /// The location is an ASEP but its contents could not be decoded. The
    /// entry is still emitted, carrying this reason, so the category is not
    /// silently reported as smaller than it is.
    Unread(String),
}

/// A timestamp read from evidence, with its provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledTime {
    /// The timestamp as read.
    pub value: String,
    /// Where it came from, e.g. `task_registration_date`.
    pub source: &'static str,
    /// `Some("local")` when the source records local wall clock with no offset,
    /// which must never be presented as UTC. `None` means UTC.
    pub timezone: Option<&'static str>,
}

/// A neutral, factual observation about an entry.
///
/// These exist so a reviewer can filter, not so the tool can accuse. Each one
/// states a checkable property of the entry — where its image sits, whether it
/// differs from the shipped Windows default — and nothing about intent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    /// Stable machine code, e.g. `differs_from_windows_default`.
    pub code: &'static str,
    /// One plain sentence stating the fact.
    pub statement: String,
}

impl Observation {
    /// Build an observation.
    pub fn new(code: &'static str, statement: impl Into<String>) -> Self {
        Self {
            code,
            statement: statement.into(),
        }
    }
}

/// One autostart extensibility point.
#[derive(Debug, Clone)]
pub struct AsepEntry {
    /// Category id from [`crate::rules::CATEGORIES`].
    pub category: &'static str,
    /// The entry's own name: a registry value name, a service name, a task
    /// name, a shortcut file name.
    pub entry_name: String,
    /// The backing registry key path or file path, verbatim.
    pub location: String,
    /// Whether `location` is a key or a file.
    pub location_kind: LocationKind,
    /// The registry value under `location` that holds the target, if any.
    pub value_name: Option<String>,
    /// Hive the entry was read from (`SOFTWARE`, `SYSTEM`, `NTUSER`, ...).
    pub hive: Option<String>,
    /// `HKLM`, `HKCU` or `filesystem`.
    pub scope: String,
    /// Profile the entry belongs to, when it is per-user and the profile could
    /// be established.
    pub user: Option<String>,
    /// The image that would execute, exactly as stored in evidence.
    pub image: Option<String>,
    /// The full command line as stored.
    pub command: Option<String>,
    /// Arguments, when they could be separated from the image.
    pub arguments: Option<String>,
    /// Working directory, when the source records one.
    pub working_dir: Option<String>,
    /// How a bare program name in `image` is searched for: the extension rule
    /// and the working directory tried first (`HUNT-244`). The default is the
    /// shell's `PATHEXT` rule with no working directory.
    pub search_context: crate::normalize::SearchContext,
    /// How image and arguments were separated.
    pub split_basis: Option<SplitBasis>,
    /// Plain statement of what would run and when.
    pub runs_when: String,
    /// Whether the entry is currently effective, when that is determinable.
    pub enabled: Option<bool>,
    /// What `enabled` was decided on.
    pub enabled_basis: String,
    /// When the entry was installed or last modified, when evidence records it.
    pub installed_time: Option<InstalledTime>,
    /// Why no `installed_time` is present. Set whenever `installed_time` is
    /// `None`, so "no timestamp" is never mistaken for "no activity".
    pub installed_time_unavailable_reason: Option<&'static str>,
    /// A time the evidence carries that is **not** the time the entry was made, only a
    /// bound on it. A WMI record's header time is the repository's previous commit, so the
    /// subscription was made no earlier than it (`HUNT-195`). Never read as an install time.
    pub record_time: Option<InstalledTime>,
    /// Whether the backing evidence was read.
    pub read_status: ReadStatus,
    /// Set when the entry is known to be partial (a cap, an undecoded payload).
    pub incomplete_reason: Option<String>,
    /// The standard machine-readable classification of `incomplete_reason`.
    ///
    /// `incomplete_reason` is an examiner-facing sentence; nothing can filter on
    /// it. This is the code the API, export and cross-plugin honesty paths read,
    /// emitted as `content_incomplete_reason` (B3-025). Always set alongside
    /// `incomplete_reason` — an entry that is partial but cannot say in which
    /// way would be worse than one that says nothing.
    pub incomplete_code: Option<IncompleteReason>,
    /// Neutral observations.
    pub observations: Vec<Observation>,
    /// Category-specific fields (service start type, task triggers, ...).
    pub extra: Map<String, Value>,
    /// Whether the backing bytes are live evidence or recovered from bytes
    /// the evidence no longer references.
    pub evidence_state: EvidenceState,
}

/// The standing of the bytes an entry was read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvidenceState {
    /// Read from a live structure: a parsed hive, a file on the volume.
    Live,
    /// Read from a record a repository page's own table lists. Whether the
    /// repository still mapped that page was not established, which is why
    /// this is not `Live`.
    AllocatedRecord,
    /// Recovered from bytes nothing references (page slack, say). Published
    /// under its own record type, `RecoveredAsepEntry`, so it can never be
    /// counted as live by a consumer that filters on type alone.
    Recovered,
    /// Read from a record a repository page's own table lists, in a page the
    /// repository's page mapping maps to no logical page (HUNT-195): a free
    /// page, so the record is a superseded or free-page copy. Published under
    /// `RecoveredAsepEntry`, like `Recovered`, so it is never counted as live.
    Superseded,
    /// Read from a record a current page's descriptor table lists, which the
    /// repository's index (`INDEX.BTR`), walked from its root, does not name
    /// (HUNT-195): deleted or unlinked, so not a record the repository
    /// resolves. Published under `RecoveredAsepEntry`, like `Superseded`, so
    /// it is never counted as live.
    Unlinked,
}

impl EvidenceState {
    /// Stable string form.
    pub fn as_str(self) -> &'static str {
        match self {
            EvidenceState::Live => "live",
            EvidenceState::AllocatedRecord => "allocated_record",
            EvidenceState::Recovered => "recovered",
            EvidenceState::Superseded => "superseded",
            EvidenceState::Unlinked => "unlinked",
        }
    }

    /// True for the forms published as `RecoveredAsepEntry`: recovered bytes,
    /// superseded copies and records the index does not name.
    pub fn is_recovered(self) -> bool {
        matches!(
            self,
            EvidenceState::Recovered | EvidenceState::Superseded | EvidenceState::Unlinked
        )
    }
}

impl AsepEntry {
    /// A minimally-populated entry. Callers fill in what the evidence supports
    /// and leave the rest — every optional field has a defined "absent"
    /// meaning, and none of them default to a fabricated value.
    pub fn new(
        category: &'static str,
        entry_name: impl Into<String>,
        location: impl Into<String>,
        location_kind: LocationKind,
    ) -> Self {
        Self {
            category,
            entry_name: entry_name.into(),
            location: location.into(),
            location_kind,
            value_name: None,
            hive: None,
            scope: String::new(),
            user: None,
            image: None,
            command: None,
            arguments: None,
            working_dir: None,
            search_context: crate::normalize::SearchContext::default(),
            split_basis: None,
            runs_when: String::new(),
            enabled: None,
            enabled_basis: String::new(),
            installed_time: None,
            installed_time_unavailable_reason: None,
            record_time: None,
            read_status: ReadStatus::Parsed,
            incomplete_reason: None,
            incomplete_code: None,
            observations: Vec::new(),
            extra: Map::new(),
            evidence_state: EvidenceState::Live,
        }
    }

    /// Add a neutral observation.
    pub fn observe(&mut self, code: &'static str, statement: impl Into<String>) {
        self.observations.push(Observation::new(code, statement));
    }

    /// Set a category-specific field.
    pub fn put(&mut self, key: &str, value: Value) {
        self.extra.insert(key.to_string(), value);
    }
}

/// How `powershell_encoded_command_decoded` was read, published beside it.
pub const ENCODED_COMMAND_BASIS: &str =
    "The argument after the PowerShell encoded-command parameter, decoded as PowerShell \
     decodes it: base64 of UTF-16LE text. The decoded text is what the stored command line \
     carries; it is not evidence that the command ran.";

/// Chain-of-custody identifiers attached to every emitted record.
#[derive(Debug, Clone, Copy)]
pub struct EmitContext {
    /// The case the evidence belongs to.
    pub case_id: Uuid,
    /// The artifact the entry was derived from; becomes the record's parent.
    pub parent_id: Uuid,
    /// The parsed-hive record backing a registry entry, for the cross-link that
    /// opens the key in the registry viewer.
    pub registry_record_id: Option<Uuid>,
    /// The file entry backing a filesystem entry, for the cross-link that opens
    /// the task XML or the shortcut.
    pub file_artifact_id: Option<Uuid>,
}

/// Turn an entry into the artifacts that carry it: the `AsepEntry` record and,
/// when a real timestamp was read, one timeline event.
///
/// The timeline event is emitted only for a timestamp that came out of
/// evidence. An ASEP with no readable install time contributes nothing to the
/// timeline rather than an event at the epoch — a fabricated 1970 entry would
/// corrupt every "what happened when" question asked of the case.
pub fn build_entry_artifacts(entry: &AsepEntry, ctx: &EmitContext) -> Vec<Artifact> {
    let mut out = Vec::with_capacity(2);
    let metadata = entry_metadata(entry, ctx);
    let record = Artifact::new(
        ctx.case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(metadata),
    )
    .with_parent(ctx.parent_id);
    let record_id = record.id;
    out.push(record);

    // An install time, or, where the evidence only bounds it, a record time under a label
    // that says so: a record time must not sit in the timeline as "installed".
    let timed = entry
        .installed_time
        .as_ref()
        .map(|t| (t, "Autostart Entry Installed/Modified"))
        .or_else(|| {
            entry.record_time.as_ref().map(|t| {
                (
                    t,
                    "WMI repository record time (the subscription was made no earlier than this)",
                )
            })
        });
    if let Some((time, desc)) = timed {
        let mut event = Map::new();
        event.insert("timestamp".to_string(), json!(time.value));
        event.insert("timestamp_desc".to_string(), json!(desc));
        event.insert("source_module".to_string(), json!(MODULE_ID));
        event.insert("short_desc".to_string(), json!(short_desc(entry)));
        if let Some(tz) = time.timezone {
            event.insert("timezone".to_string(), json!(tz));
        }
        event.insert(
            "full_details".to_string(),
            json!(json!({
                "category": entry.category,
                "entry_name": entry.entry_name,
                "asep_location": entry.location,
                "image": entry.image,
                "runs_when": entry.runs_when,
                "installed_time_source": time.source,
            })
            .to_string()),
        );
        out.push(
            Artifact::new(
                ctx.case_id,
                ArtifactType::TimelineEvent,
                None,
                Value::Object(event),
            )
            .with_parent(record_id),
        );
    }

    out
}

/// One-line summary used as the record name and the timeline description.
pub fn short_desc(entry: &AsepEntry) -> String {
    let prefix = if entry.evidence_state.is_recovered() {
        "recovered "
    } else {
        ""
    };
    match entry.image.as_deref() {
        Some(image) => format!(
            "{prefix}{}: {} -> {}",
            entry.category, entry.entry_name, image
        ),
        None => format!("{prefix}{}: {}", entry.category, entry.entry_name),
    }
}

fn entry_metadata(entry: &AsepEntry, ctx: &EmitContext) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert(
        "type".to_string(),
        json!(if entry.evidence_state.is_recovered() {
            "RecoveredAsepEntry"
        } else {
            "AsepEntry"
        }),
    );
    m.insert(
        "evidence_state".to_string(),
        json!(entry.evidence_state.as_str()),
    );
    m.insert("category".to_string(), json!(entry.category));

    match category(entry.category) {
        Some(info) => {
            m.insert("category_label".to_string(), json!(info.label));
            m.insert("mitre_technique".to_string(), json!(info.technique));
            m.insert(
                "mitre_technique_name".to_string(),
                json!(info.technique_name),
            );
            m.insert("mitre_tactic".to_string(), json!(MITRE_TACTIC));
            if let Some(note) = info.technique_note {
                m.insert("mitre_note".to_string(), json!(note));
            }
            m.insert(
                "category_source".to_string(),
                json!(match info.source {
                    CategorySource::Registry => "registry",
                    CategorySource::FileSystem => "filesystem",
                    CategorySource::WmiRepository => "wmi_repository",
                }),
            );
            m.insert("category_locations".to_string(), json!(info.locations));
        }
        None => {
            // Unreachable via the enumerators (a test asserts every emitted id
            // is in the table), but a record must never silently lose its
            // ATT&CK mapping if that ever stops being true.
            m.insert("category_label".to_string(), json!(entry.category));
            m.insert("mitre_technique".to_string(), Value::Null);
            m.insert("mitre_technique_name".to_string(), Value::Null);
            m.insert("mitre_tactic".to_string(), json!(MITRE_TACTIC));
            m.insert(
                "mitre_note".to_string(),
                json!("No ATT&CK mapping is registered for this category id."),
            );
        }
    }

    m.insert("name".to_string(), json!(short_desc(entry)));
    m.insert("entry_name".to_string(), json!(entry.entry_name));
    m.insert("asep_location".to_string(), json!(entry.location));
    m.insert(
        "asep_location_kind".to_string(),
        json!(entry.location_kind.as_str()),
    );
    m.insert("asep_value_name".to_string(), json!(entry.value_name));
    m.insert("hive".to_string(), json!(entry.hive));
    m.insert("scope".to_string(), json!(entry.scope));
    m.insert("user".to_string(), json!(entry.user));

    m.insert("image_path".to_string(), json!(entry.image));
    m.insert("command".to_string(), json!(entry.command));
    m.insert("arguments".to_string(), json!(entry.arguments));
    m.insert("working_dir".to_string(), json!(entry.working_dir));
    m.insert(
        "command_split_basis".to_string(),
        json!(entry.split_basis.map(SplitBasis::as_str)),
    );
    if let Some(enc) = entry
        .command
        .as_deref()
        .and_then(crate::normalize::powershell_encoded_command)
    {
        match enc {
            EncodedCommand::Decoded { parameter, script } => {
                m.insert(
                    "powershell_encoded_command_parameter".to_string(),
                    json!(parameter),
                );
                m.insert(
                    "powershell_encoded_command_decoded".to_string(),
                    json!(script),
                );
                m.insert(
                    "powershell_encoded_command_basis".to_string(),
                    json!(ENCODED_COMMAND_BASIS),
                );
            }
            EncodedCommand::Undecodable { parameter, reason } => {
                m.insert(
                    "powershell_encoded_command_parameter".to_string(),
                    json!(parameter),
                );
                m.insert(
                    "powershell_encoded_command_undecodable".to_string(),
                    json!(reason),
                );
            }
        }
    }

    m.insert("runs_when".to_string(), json!(entry.runs_when));
    m.insert("enabled".to_string(), json!(entry.enabled));
    m.insert("enabled_basis".to_string(), json!(entry.enabled_basis));

    match entry.installed_time.as_ref() {
        Some(t) => {
            m.insert("installed_time".to_string(), json!(t.value));
            m.insert("installed_time_source".to_string(), json!(t.source));
            m.insert("installed_time_status".to_string(), json!("recorded"));
            if let Some(tz) = t.timezone {
                m.insert("timezone".to_string(), json!(tz));
            }
        }
        None => {
            m.insert("installed_time".to_string(), Value::Null);
            m.insert("installed_time_source".to_string(), Value::Null);
            m.insert("installed_time_status".to_string(), json!("unavailable"));
            m.insert(
                "installed_time_unavailable_reason".to_string(),
                json!(entry.installed_time_unavailable_reason),
            );
        }
    }

    if let Some(t) = entry.record_time.as_ref() {
        m.insert("record_time".to_string(), json!(t.value));
        m.insert("record_time_source".to_string(), json!(t.source));
    }

    match &entry.read_status {
        ReadStatus::Parsed => {
            m.insert("read_status".to_string(), json!("parsed"));
            m.insert("read_status_reason".to_string(), Value::Null);
        }
        ReadStatus::Unread(reason) => {
            m.insert("read_status".to_string(), json!("unread"));
            m.insert("read_status_reason".to_string(), json!(reason));
        }
    }

    // `incomplete` / `incomplete_reason` are ASEP-local: the sentence is for the
    // examiner and nothing downstream keys on either name. `content_incomplete`
    // and `content_incomplete_reason` are the standard pair the API, export and
    // cross-plugin incompleteness tooling read, so a partially decoded autostart
    // entry is no longer invisible to them (B3-025). Both are emitted; the
    // bespoke keys stay for any existing consumer.
    let is_incomplete = entry.incomplete_reason.is_some();
    m.insert("incomplete".to_string(), json!(is_incomplete));
    m.insert(
        "incomplete_reason".to_string(),
        json!(entry.incomplete_reason),
    );
    if is_incomplete {
        m.insert("content_incomplete".to_string(), json!(true));
        m.insert(
            "content_incomplete_reason".to_string(),
            json!(entry
                .incomplete_code
                .unwrap_or(IncompleteReason::UnresolvedStructure)
                .as_str()),
        );
    }

    m.insert(
        "observations".to_string(),
        Value::Array(
            entry
                .observations
                .iter()
                .map(|o| json!({"code": o.code, "statement": o.statement}))
                .collect(),
        ),
    );
    m.insert(
        "assessment_note".to_string(),
        json!(
            "Observations are neutral statements of fact. This module does not \
               determine whether an autostart entry is unwanted."
        ),
    );

    m.insert(
        "registry_record_artifact_id".to_string(),
        json!(ctx.registry_record_id.map(|id| id.to_string())),
    );
    m.insert(
        "file_artifact_id".to_string(),
        json!(ctx.file_artifact_id.map(|id| id.to_string())),
    );
    m.insert("source_module".to_string(), json!(MODULE_ID));

    for (k, v) in &entry.extra {
        m.insert(k.clone(), v.clone());
    }

    m.insert("short_desc".to_string(), json!(short_desc(entry)));
    m
}

/// Write a [`TargetResolution`] onto an entry's category-specific fields.
///
/// Kept separate from the entry constructors because the answer depends on how
/// much of the volume had been enumerated when the entry was built, which is a
/// property of the run rather than of the ASEP.
pub fn attach_target_resolution(entry: &mut AsepEntry, res: &TargetResolution) {
    entry.put("target_exists", json!(res.status.as_str()));
    entry.put("target_exists_basis", json!(res.basis));
    entry.put("target_lookup_path", json!(res.lookup_path));
    if let Some(created) = &res.target_created {
        entry.put("target_created", json!(created));
    }
    entry.put("target_path_expansion", json!(res.expansion));
    entry.put("target_observed_paths", json!(res.observed_paths));
    entry.put(
        "target_observed_paths_truncated",
        json!(res.observed_paths_truncated),
    );
    entry.put("target_index_executable_names", json!(res.index_size));
    entry.put("target_index_capped", json!(res.index_capped));
    // A bare program name (`HUNT-241`): what the search path tried, which
    // directory answered, and whether `target_lookup_path` was observed or is
    // the first candidate by convention.
    if !res.search_path_candidates.is_empty() {
        entry.put(
            "target_search_path_candidates",
            json!(res.search_path_candidates),
        );
        entry.put(
            "target_search_path_directory",
            json!(res.search_path_directory),
        );
        entry.put(
            "target_search_path_resolution",
            json!(res.search_path_resolution),
        );
        entry.put("target_search_rule", json!(res.search_rule));
    }
}
