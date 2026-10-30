//! What each process was told about the machine, who was logged on, and which
//! desktop a process could draw on.
//!
//! Three questions that look unrelated and are answered from the same place.
//!
//! # The environment block
//!
//! Every process is handed a block of `NAME=VALUE` text at creation, reached
//! through `_EPROCESS.Peb → _RTL_USER_PROCESS_PARAMETERS.Environment` and laid
//! out as UTF-16LE strings separated by single NULs and terminated by a double
//! NUL. It is not decoration. It carries:
//!
//! * `HTTP_PROXY`, `HTTPS_PROXY` and `NO_PROXY` — where this process's traffic
//!   was pointed, which is frequently not where the machine's traffic went;
//! * `COR_ENABLE_PROFILING` and `COR_PROFILER_PATH` — the supported, documented
//!   way to make the .NET runtime load an arbitrary DLL into a process, and one
//!   of the most common persistence mechanisms that leaves nothing on the
//!   module list to look at;
//! * `APPDATA`, `TEMP` and `USERPROFILE` overrides — a process pointed at
//!   somebody else's profile directory;
//! * `USERNAME`, `USERDOMAIN` and `SESSIONNAME` — which human this process was
//!   running on behalf of, and whether they were sitting at the console or came
//!   in over RDP.
//!
//! Because those are the findings, the failure modes matter more than usual. A
//! block whose second page was not captured decodes into a *shorter* list of
//! variables that is otherwise perfectly well formed, and a shorter list is
//! indistinguishable from a process that simply had fewer variables — unless
//! the reader says so. So every block records whether it reached its
//! double-NUL terminator, how many bytes were actually read, and where reading
//! stopped. [`vars::EnvironmentBlock::Unavailable`] is never rendered as an
//! empty environment, and a block that was read short is not "complete but
//! small".
//!
//! The block is read in the **process's own** address space, through
//! [`crate::process::process_address_space`]. Reading a user-space address in
//! the kernel address space does not fail; it returns whatever the kernel has
//! mapped there, and it decodes.
//!
//! # Sessions
//!
//! `_EPROCESS.Session` points at an `_MM_SESSION_SPACE`, whose `SessionId` is
//! the terminal-services session the process belongs to. Session 0 is where
//! services live from Windows Vista onwards; interactive logons get session 1
//! and up. The distinction is the whole of "is this `powershell.exe` a service
//! doing its job, or somebody typing at a console" — a question a process list
//! alone cannot answer, because both rows say `powershell.exe`.
//!
//! On Windows 11 24H2 the type was replaced by `_PSP_SESSION_SPACE`, whose
//! members the kernel PDB does not describe. Upstream Volatility reads the
//! session id from offset 8 anyway. This module does not: an offset that is not
//! in the symbol table is a guess, and a guessed session id turns a service
//! into an interactive logon or the other way round. The session part of the
//! survey reports itself unsupported, naming the type and member that are
//! missing, and everything else still runs.
//!
//! Where this build declares them, `_MM_SESSION_SPACE.ProcessList` is also
//! walked and cross-checked against the active process list. A process on the
//! session's own list that is *not* on the active process list has been
//! unlinked, which is a finding in its own right.
//!
//! # Desktops and window stations
//!
//! A window station (`tagWINDOWSTATION`) owns a clipboard, an atom table and a
//! set of desktops (`tagDESKTOP`); a thread is attached to exactly one desktop
//! and can only see windows on it. Creating a second desktop and running there
//! is a classic way to be invisible: the process is on every process list, its
//! windows exist, and nobody at the console can see any of it.
//!
//! These are win32k structures, and **they are not in the kernel PDB**. Upstream
//! Volatility ships hand-written symbol files for them, one per build. This
//! crate resolves structures from the symbol table it was given, so on an image
//! profiled from `ntkrnlmp.pdb` alone the desktop survey reports itself
//! unsupported, naming `tagWINDOWSTATION` and `tagDESKTOP`. That is the honest
//! answer, and it is deliberately not the same answer as "there were no hidden
//! desktops". When a symbol table that does describe them is supplied, the walk
//! runs: window stations are found by their `Wind` pool tag through the shared
//! [`crate::poolscan`] sweep, and each one's desktops and their attached
//! threads are followed in the address space of the session the station belongs
//! to, because session-space pointers mean nothing in the system process's
//! address space.

#[path = "environment_desktops.rs"]
pub mod desktops;
#[path = "environment_persistent.rs"]
pub mod persistent;
#[path = "environment_sessions.rs"]
pub mod sessions;
#[path = "environment_vars.rs"]
pub mod vars;

pub use desktops::{
    is_standard_desktop_name, Desktop, DesktopListing, DesktopSurvey, DesktopThread, GuiSymbols,
    UnreadableStation, WindowStation, MAX_DESKTOPS_PER_STATION, MAX_DESKTOP_THREADS,
    MAX_WINDOW_STATIONS, STANDARD_DESKTOP_NAMES, TAG_WINDOW_STATION, TYPE_DESKTOP,
    TYPE_WINDOW_STATION,
};
pub use persistent::{
    is_commonly_inherited, PersistentSource, PersistentState, PersistentVariables,
};
pub use sessions::{
    MemberSource, Session, SessionKind, SessionListing, SessionMember, SessionSurvey,
    SessionSymbols, UnreadableSession, MAX_PLAUSIBLE_SESSION_ID, TYPE_MM_SESSION_SPACE,
    TYPE_PSP_SESSION_SPACE,
};
pub use vars::{
    decode_environment_block, read_environment, read_environment_in, DecodedBlock, EnvVar,
    EnvironmentBlock, EnvironmentRecord, LengthSource, MalformedEntry, MAX_ENVIRONMENT_BYTES,
    MAX_ENVIRONMENT_VARIABLES, TYPE_PEB, TYPE_PROCESS_PARAMETERS,
};

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{ListStop, ObjError, StructReader};
use seance_memory::translate::TableCache;
use seance_memory::{Incomplete, MemoryLayer};

use crate::poolscan::PoolScanConfig;
use crate::process::{self, ProcessListConfig, ProcessSymbols};
use crate::profile::WindowsProfile;

// ── Names this module knows ─────────────────────────────────────────────────

/// The process structure everything here starts from.
pub const TYPE_EPROCESS: &str = "_EPROCESS";

/// Ceiling on processes whose environment one survey reads.
///
/// A machine with more running processes than this does not exist; reaching it
/// means the process list walk produced entries that are not processes, and it
/// is reported as a cap rather than as the end of the list.
pub const MAX_SURVEYED_PROCESSES: usize = 65_536;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops the survey before it can produce a result worth
/// reading.
///
/// Note what is *not* here: a build that cannot describe sessions, or one that
/// cannot describe the win32k desktop structures. Those are facts about one
/// part of the answer, they are carried by [`Supported::No`] on
/// [`EnvironmentSymbols`], and they surface on the survey as a part that
/// reports itself unsupported rather than as a part that found nothing.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentError {
    /// No process's environment can be reached on this build at all, and no
    /// partial answer would be honest. The message names what is missing.
    #[error("process environments cannot be read on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// The active process list could not be walked, so there is no list of
    /// processes whose environments could be read.
    #[error("the process list could not be walked, so there are no environments to read: {0}")]
    Processes(#[from] process::ProcessError),

    /// The symbol table could not answer a question the survey depends on.
    ///
    /// Distinct from [`EnvironmentError::Unsupported`]: this says the table is
    /// unusable, not that this build lacks a member. A build that lacks one is
    /// answered, not failed.
    #[error(transparent)]
    Object(#[from] ObjError),
}

impl EnvironmentError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            EnvironmentError::Unsupported { .. } => "unsupported_build",
            EnvironmentError::Processes(err) => err.class(),
            EnvironmentError::Object(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            EnvironmentError::Unsupported { .. } => IncompleteReason::UnresolvedStructure,
            EnvironmentError::Processes(err) => err.incomplete_reason(),
            EnvironmentError::Object(err) => err.incomplete_reason(),
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be read" refusal.
    pub fn unsupported(detail: impl Into<String>) -> EnvironmentError {
        EnvironmentError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Resolve the first of `candidates` that this build's `type_name` actually has.
///
/// The member holding the environment's length is `EnvironmentSize` on Vista
/// and later and absent on Windows XP. Picking by build number means a build
/// nobody has catalogued reads the wrong member; asking the symbol table which
/// one exists means it reads the right one or reports that it read none.
///
/// This module used to carry its own copy, which returned a bare `Option` built
/// from `member_offset(..).is_ok()` and so reported "the symbol table could not
/// answer" as "this build has no such member". Those are opposite claims and the
/// shared helper keeps them apart; there is one definition of it so the two
/// cannot drift.
pub(crate) use seance_memory::binding::first_member;

/// A part of the survey that this build's symbols either describe or do not.
///
/// The point of the type is that [`Supported::No`] carries a *reason*. A
/// desktop survey that could not run and a desktop survey that ran and found
/// only the ordinary `WinSta0\Default` are opposite findings, and a report that
/// renders both as an empty table has published the second when it only had the
/// first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Supported<T> {
    /// The symbols describe it, and this is what was resolved.
    Yes(T),
    /// They do not. The string names exactly what is missing, in terms an
    /// examiner can act on — normally by supplying a fuller symbol table.
    No(String),
}

impl<T> Supported<T> {
    /// What was resolved, when the build supports it.
    pub fn get(&self) -> Option<&T> {
        match self {
            Supported::Yes(value) => Some(value),
            Supported::No(_) => None,
        }
    }

    /// Why this part cannot run, when it cannot.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Supported::Yes(_) => None,
            Supported::No(detail) => Some(detail),
        }
    }

    /// Whether this build supports the part.
    pub fn is_supported(&self) -> bool {
        matches!(self, Supported::Yes(_))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self, render: impl FnOnce(&T) -> serde_json::Value) -> serde_json::Value {
        match self {
            Supported::Yes(value) => {
                serde_json::json!({"supported": true, "symbols": render(value)})
            }
            Supported::No(detail) => serde_json::json!({"supported": false, "detail": detail}),
        }
    }
}

/// The member paths this image's environments, sessions and desktops are read
/// through.
///
/// Resolved once per image and checked once, so a build whose `_PEB` the
/// symbols cannot describe fails here naming the member that is missing, rather
/// than at process three hundred having already emitted variables read at the
/// wrong offsets.
#[derive(Debug, Clone)]
pub struct EnvironmentSymbols {
    /// The process-list layout, which every part of the survey walks over.
    pub process: ProcessSymbols,
    /// Path to the PEB pointer inside `_EPROCESS`. The address it holds is in
    /// the **process's own** space, not the kernel's.
    pub peb: String,
    /// Path to the parameter-block pointer inside `_PEB`.
    pub process_parameters: String,
    /// Path to the environment pointer inside `_RTL_USER_PROCESS_PARAMETERS`.
    pub environment: String,
    /// Path to the member giving the block's length, and what that member
    /// actually measures. `None` on a build that records neither, where the
    /// block is instead read to its double NUL.
    pub environment_size: Option<(String, LengthSource)>,
    /// The session layout, or why sessions cannot be enumerated on this build.
    pub sessions: Supported<SessionSymbols>,
    /// The win32k GUI layout, or why desktops cannot be walked on this build.
    pub gui: Supported<GuiSymbols>,
}

impl EnvironmentSymbols {
    /// Resolve every layout fact this survey needs.
    ///
    /// # Errors
    ///
    /// [`EnvironmentError::Unsupported`] naming the type or member that is
    /// missing, for the four facts without which no environment can be reached
    /// at all: `_EPROCESS.Peb`, `_PEB`, `_PEB.ProcessParameters` and
    /// `_RTL_USER_PROCESS_PARAMETERS.Environment`. A build that cannot describe
    /// *sessions* or *desktops* is not an error here — those become
    /// [`Supported::No`] and the survey reports them as unsupported rather than
    /// as empty.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, EnvironmentError> {
        let process = ProcessSymbols::from_profile(profile)?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        let peb = process.peb.clone().ok_or_else(|| {
            EnvironmentError::unsupported(format!(
                "'{TYPE_EPROCESS}' has no Peb member on this build, so no process's environment \
                 block can be reached"
            ))
        })?;

        if !profile.symbols.has_type(TYPE_PEB) {
            return Err(EnvironmentError::unsupported(format!(
                "the symbol table has no '{TYPE_PEB}', so the block holding a process's \
                 environment cannot be located"
            )));
        }
        let process_parameters = first_member(&reader, TYPE_PEB, &["ProcessParameters"])?
            .ok_or_else(|| {
                EnvironmentError::unsupported(format!(
                    "'{TYPE_PEB}' has no ProcessParameters, so a process's environment cannot be \
                     reached"
                ))
            })?
            .to_string();

        if !profile.symbols.has_type(TYPE_PROCESS_PARAMETERS) {
            return Err(EnvironmentError::unsupported(format!(
                "the symbol table has no '{TYPE_PROCESS_PARAMETERS}', so the pointer to a \
                 process's environment cannot be located"
            )));
        }
        let environment = first_member(&reader, TYPE_PROCESS_PARAMETERS, &["Environment"])?
            .ok_or_else(|| {
                EnvironmentError::unsupported(format!(
                    "'{TYPE_PROCESS_PARAMETERS}' has no Environment, so where a process's \
                     variables live is unknown"
                ))
            })?
            .to_string();

        // `EnvironmentSize` is the block's own length and is exactly right.
        // `Length` is the *parameter block's* length, which Windows XP has and
        // which is only ever an over-estimate; the read still stops at the
        // double NUL, so using it as a bound cannot invent variables.
        let environment_size =
            match first_member(&reader, TYPE_PROCESS_PARAMETERS, &["EnvironmentSize"])? {
                Some(path) => Some((path.to_string(), LengthSource::EnvironmentSize)),
                None => first_member(&reader, TYPE_PROCESS_PARAMETERS, &["Length"])?
                    .map(|path| (path.to_string(), LengthSource::ParametersLength)),
            };

        Ok(Self {
            peb,
            process_parameters,
            environment,
            environment_size,
            sessions: SessionSymbols::from_profile(profile, &process),
            gui: GuiSymbols::from_profile(profile),
            process,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "peb": self.peb,
            "process_parameters": self.process_parameters,
            "environment": self.environment,
            "environment_size": self.environment_size.as_ref().map(|(path, source)| {
                serde_json::json!({"member": path, "measures": source.as_str()})
            }),
            "sessions": self.sessions.to_json(SessionSymbols::to_json),
            "gui": self.gui.to_json(GuiSymbols::to_json),
        })
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps and switches for one survey.
///
/// Every cap here sets a flag that reaches the artifact when it fires. A cap
/// that silently truncated would turn "we stopped counting" into "that is all
/// there was", which is the one mistake this whole tier exists to avoid.
#[derive(Debug, Clone)]
pub struct EnvironmentConfig {
    /// Ceiling on processes whose environment is read.
    pub max_processes: usize,
    /// Ceiling on bytes read from one environment block.
    pub max_environment_bytes: u64,
    /// Ceiling on variables recorded for one process. The *count* stays exact.
    pub max_variables: usize,
    /// Whether to establish which variable names are persistent by reading them
    /// out of the registry. Turning it off makes every variable's
    /// [`EnvVar::persistent`] `None` — unknown, not "not persistent".
    pub classify_persistent: bool,
    /// Ceiling on distinct persistent variable names collected.
    pub max_persistent_names: usize,
    /// Ceiling on sessions reported.
    pub max_sessions: usize,
    /// Ceiling on processes listed under one session.
    pub max_session_processes: usize,
    /// Whether to survey window stations and desktops. Turning it off leaves
    /// [`DesktopSurvey::NotRequested`], which is not the same as an empty one.
    pub survey_desktops: bool,
    /// Ceiling on window stations followed.
    pub max_window_stations: usize,
    /// Ceiling on desktops followed per window station.
    pub max_desktops_per_station: usize,
    /// Ceiling on threads listed per desktop.
    pub max_desktop_threads: usize,
    /// Caps and geometry for the pool sweep that finds window stations.
    ///
    /// Exposed because that sweep runs over a *virtual* address space on
    /// Windows 10 and later, where enumerating the mapped regions of a 64-bit
    /// space is the expensive part; an examiner who knows where the pool is can
    /// bound it. Whatever it is set to, a sweep that stopped early reports
    /// itself incomplete rather than as a machine with no window stations.
    ///
    /// [`PoolScanConfig::type_map`] is filled in by the survey when it is
    /// `None`, because without it the object-manager type of every candidate
    /// goes unverified.
    pub pool: PoolScanConfig,
}

impl Default for EnvironmentConfig {
    fn default() -> Self {
        Self {
            max_processes: MAX_SURVEYED_PROCESSES,
            max_environment_bytes: MAX_ENVIRONMENT_BYTES,
            max_variables: MAX_ENVIRONMENT_VARIABLES,
            classify_persistent: true,
            max_persistent_names: persistent::MAX_PERSISTENT_NAMES,
            max_sessions: sessions::MAX_SESSIONS,
            max_session_processes: sessions::MAX_SESSION_PROCESSES,
            survey_desktops: true,
            max_window_stations: MAX_WINDOW_STATIONS,
            max_desktops_per_station: MAX_DESKTOPS_PER_STATION,
            max_desktop_threads: MAX_DESKTOP_THREADS,
            pool: PoolScanConfig::default(),
        }
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One process's environment, with enough of the process to identify the row.
#[derive(Debug, Clone)]
pub struct ProcessEnvironment {
    /// Kernel address of the `_EPROCESS`.
    pub address: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// The image name, when it was readable.
    pub image_file_name: Option<String>,
    /// The session the process belongs to, as the process list read it.
    pub session_id: Option<u64>,
    /// The environment, or why there is not one.
    pub environment: EnvironmentBlock,
}

impl ProcessEnvironment {
    /// The value of a variable, matched case-insensitively as Windows does.
    ///
    /// `None` both for a process with no such variable and for one whose block
    /// could not be read: a caller that needs to tell those apart must look at
    /// [`ProcessEnvironment::environment`] itself.
    pub fn get(&self, name: &str) -> Option<&str> {
        match &self.environment {
            EnvironmentBlock::Block(record) => record.get(name),
            _ => None,
        }
    }

    /// Whether this row is a positive statement about the process rather than a
    /// gap in the evidence.
    pub fn is_complete(&self) -> bool {
        match &self.environment {
            EnvironmentBlock::Block(record) => record.is_complete(),
            EnvironmentBlock::Unavailable(_) => false,
            // No user address space, no parameter block and no environment
            // pointer are all positive statements about the process.
            _ => true,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "session_id": self.session_id,
            "environment": self.environment.to_json(),
            "complete": self.is_complete(),
        })
    }
}

/// Everything one survey established, and everything it could not.
#[derive(Debug, Clone)]
pub struct EnvironmentSurvey {
    /// One row per process examined, in process-list order.
    pub processes: Vec<ProcessEnvironment>,
    /// How many processes the list held.
    pub processes_listed: usize,
    /// Whether the process cap fired. The survey stopped; the list did not end.
    pub processes_capped: bool,
    /// Everything the process-list walk itself could not do.
    pub process_list_incomplete: Vec<Incomplete>,
    /// Which variable names are persistent, or why that could not be
    /// established.
    pub persistent: PersistentVariables,
    /// The logon sessions, or why they could not be enumerated.
    pub sessions: SessionSurvey,
    /// The window stations and desktops, or why they could not be walked.
    pub desktops: DesktopSurvey,
    /// Everything odd about the survey that did not stop it.
    pub notes: Vec<String>,
}

impl EnvironmentSurvey {
    /// Whether every part of the survey ran to completion.
    ///
    /// The question a report must ask before writing "no process had a proxy
    /// set" or "there were no hidden desktops": a survey that could not read
    /// one process's block, or could not walk desktops at all, says nothing
    /// about what it did not reach.
    pub fn is_complete(&self) -> bool {
        !self.processes_capped
            && self.process_list_incomplete.is_empty()
            && self.processes.iter().all(ProcessEnvironment::is_complete)
            && self.persistent.is_complete()
            && self.sessions.is_complete()
            && self.desktops.is_complete()
    }

    /// Every process whose environment sets a variable that is not persistent.
    ///
    /// These are the variables set with `SetEnvironmentVariable` or inherited
    /// from a parent that set one — the deliberate ones. Empty when the
    /// persistent set could not be established, which is why
    /// [`PersistentVariables::is_complete`] has to be consulted beside it.
    pub fn explicitly_set(&self) -> Vec<(&ProcessEnvironment, Vec<&EnvVar>)> {
        self.processes
            .iter()
            .filter_map(|entry| {
                let EnvironmentBlock::Block(record) = &entry.environment else {
                    return None;
                };
                let explicit: Vec<&EnvVar> = record
                    .variables
                    .iter()
                    .filter(|var| var.persistent == Some(false))
                    .collect();
                if explicit.is_empty() {
                    None
                } else {
                    Some((entry, explicit))
                }
            })
            .collect()
    }

    /// Everything a report must declare about this survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        // The process cap is already declared by the list walk itself, in
        // `process_list_incomplete`; repeating it here would double-count it.
        let mut out = self.process_list_incomplete.clone();
        for entry in &self.processes {
            if let EnvironmentBlock::Unavailable(detail) = &entry.environment {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the process at {:#x} has an environment block that could not be read, so \
                         its variables are unknown rather than absent: {detail}",
                        entry.address
                    ),
                ));
                continue;
            }
            if let EnvironmentBlock::Block(record) = &entry.environment {
                out.extend(record.incomplete(entry.address));
            }
        }
        out.extend(self.persistent.incomplete());
        out.extend(self.sessions.incomplete());
        out.extend(self.desktops.incomplete());
        out
    }

    /// Serializable form for the environment artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "processes": self
                .processes
                .iter()
                .map(ProcessEnvironment::to_json)
                .collect::<Vec<_>>(),
            "process_count": self.processes.len(),
            "processes_listed": self.processes_listed,
            "processes_capped": self.processes_capped,
            "persistent": self.persistent.to_json(),
            "sessions": self.sessions.to_json(),
            "desktops": self.desktops.to_json(),
            "notes": self.notes,
            "complete": self.is_complete(),
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

// ── The survey ──────────────────────────────────────────────────────────────

/// Read every process's environment, group the processes into logon sessions,
/// and walk the window stations and desktops.
///
/// The single entry point for this stage. Everything it needs beyond the
/// profile is in `symbols`, which was resolved and checked once, and `config`,
/// whose every cap is reported when it fires.
///
/// # Errors
///
/// Only for failures that make the whole survey meaningless: a build whose
/// `_PEB` the symbols cannot describe, or an active process list that could not
/// be walked at all. A process whose block was paged out is not an error — it
/// is one [`EnvironmentBlock::Unavailable`] row among the others. A build that
/// cannot describe sessions or desktops is not an error either — those parts
/// report themselves unsupported, naming what is missing.
pub fn survey_environment(
    profile: &WindowsProfile,
    symbols: &EnvironmentSymbols,
    config: &EnvironmentConfig,
) -> Result<EnvironmentSurvey, EnvironmentError> {
    let list = process::list_processes(
        profile,
        &symbols.process,
        &ProcessListConfig {
            max_processes: config.max_processes.max(1),
        },
    )?;

    // One page-table memo across every process: a page-table entry is keyed by
    // physical address and means the same thing in every address space, so a
    // case with four hundred processes keeps one bounded cache rather than four
    // hundred.
    let cache = Arc::new(TableCache::new());
    let mut notes = Vec::new();

    let persistent = if config.classify_persistent {
        PersistentVariables::from_profile(profile, config)
    } else {
        PersistentVariables::not_requested()
    };

    // The cap is the walk's own, so it is read from how the walk stopped rather
    // than inferred from a count: a machine with exactly `max_processes`
    // processes must not be reported as truncated.
    let processes_capped = matches!(list.forward_stop, ListStop::CapReached { .. })
        || matches!(list.backward_stop, Some(ListStop::CapReached { .. }));
    let mut processes: Vec<ProcessEnvironment> = Vec::new();
    for record in list.processes.iter().take(config.max_processes) {
        let mut environment = match record.peb {
            // The process list already established that this process has no
            // user address space. Building one to rediscover that would be a
            // page-table walk per kernel process for an answer already held.
            process::Field::NotApplicable => EnvironmentBlock::NoUserSpace,
            _ => read_environment(profile, symbols, record.address, &cache, config),
        };
        if let EnvironmentBlock::Block(block) = &mut environment {
            for variable in &mut block.variables {
                variable.persistent = persistent.classify(&variable.name);
            }
        }
        processes.push(ProcessEnvironment {
            address: record.address,
            pid: record.pid.known().copied(),
            image_file_name: record.image_file_name.known().cloned(),
            session_id: record.session_id.known().copied(),
            environment,
        });
    }

    let session_survey =
        sessions::survey_sessions(profile, symbols, &list, &processes, config, &mut notes);

    let desktop_survey = if !config.survey_desktops {
        DesktopSurvey::NotRequested
    } else {
        let layers = sessions::session_layers(
            profile,
            &symbols.process,
            &session_survey,
            &cache,
            config,
            &mut notes,
        );
        desktops::survey_desktops(profile, symbols, &layers, config)
    };

    Ok(EnvironmentSurvey {
        processes,
        processes_listed: list.processes.len(),
        processes_capped,
        process_list_incomplete: list.incomplete(),
        persistent,
        sessions: session_survey,
        desktops: desktop_survey,
        notes,
    })
}

/// The address spaces one survey built, keyed by session id.
///
/// Session space is mapped per session, so a `tagDESKTOP` pointer taken from
/// session 1 means nothing in the system process's address space. Every pointer
/// the desktop walk follows is resolved through the entry for the session the
/// window station belongs to, and a session with no entry here is reported as
/// unreachable rather than walked in the wrong space.
pub type SessionLayers = BTreeMap<u64, Arc<dyn MemoryLayer>>;

#[cfg(test)]
#[path = "environment_test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::test_support::{
        gui_isf, image_with_environment, plain_isf, virtual_profile, DESKTOP_A, DESKTOP_B,
        EXPLORER, HIDDEN, IMAGE_SIZE, PARAMS_EXPLORER, PEB_EXPLORER, STATION, SVCHOST, SYSTEM,
    };
    use crate::poolscan::test_support::table;

    /// The last page the fixture maps: everything above it was never acquired.
    ///
    /// Derived from [`IMAGE_SIZE`] rather than written out, because an address
    /// written out to mean "the top of the acquisition" stops meaning that the
    /// moment the fixture image grows — which has already happened once in this
    /// crate, and silently turned "never captured" into "captured as zeros".
    const LAST_MAPPED_PAGE: u64 = IMAGE_SIZE as u64 - 0x1000;

    /// A profile and a resolved layout over the synthetic image.
    fn built(isf: &str) -> (WindowsProfile, EnvironmentSymbols) {
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(isf));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");
        (profile, symbols)
    }

    /// The synthetic image has no registry, so the persistent classification is
    /// turned off wherever it is not the thing under test.
    fn config() -> EnvironmentConfig {
        EnvironmentConfig {
            classify_persistent: false,
            ..EnvironmentConfig::default()
        }
    }

    // ── Refusals ────────────────────────────────────────────────────────────

    /// A build whose `_PEB` has no `ProcessParameters` cannot reach any
    /// environment, and must name the member it wanted rather than report that
    /// every process had no variables.
    #[test]
    fn a_build_without_process_parameters_is_refused_by_name() {
        let isf = plain_isf().replace(
            r#""ProcessParameters": {"offset": 32,"#,
            r#""NotProcessParameters": {"offset": 32,"#,
        );
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let err = EnvironmentSymbols::from_profile(&profile)
            .expect_err("a build with no ProcessParameters must be refused");
        assert!(
            err.to_string().contains("ProcessParameters"),
            "the refusal names the member that is missing: {err}"
        );
        assert_eq!(err.class(), "unsupported_build");
    }

    /// A symbol table with no `_PEB` at all is refused naming the type.
    #[test]
    fn a_build_without_a_peb_type_is_refused_by_name() {
        let isf = plain_isf().replace(r#""_PEB": {"#, r#""_NOT_PEB": {"#);
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let err = EnvironmentSymbols::from_profile(&profile)
            .expect_err("a build with no _PEB must be refused");
        assert!(err.to_string().contains("_PEB"), "{err}");
    }

    /// A build with no `_RTL_USER_PROCESS_PARAMETERS.Environment` is refused
    /// rather than reporting empty environments everywhere.
    #[test]
    fn a_build_without_an_environment_pointer_is_refused_by_name() {
        let isf = plain_isf().replace(
            r#""Environment": {"offset": 128,"#,
            r#""NotEnvironment": {"offset": 128,"#,
        );
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let err = EnvironmentSymbols::from_profile(&profile)
            .expect_err("a build with no Environment member must be refused");
        assert!(err.to_string().contains("Environment"), "{err}");
    }

    /// A build with no `_MM_SESSION_SPACE` must not guess the session id from a
    /// fixed offset, which is what Windows 11 24H2 tempts a reader into.
    #[test]
    fn a_build_without_a_session_space_reports_sessions_unsupported_by_name() {
        let isf = plain_isf().replace(r#""_MM_SESSION_SPACE": {"#, r#""_PSP_SESSION_SPACE": {"#);
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let symbols = EnvironmentSymbols::from_profile(&profile)
            .expect("the environment layout still resolves");
        // The renamed type exists but is still described here, so this build is
        // supported; the refusal case is the one where its members are absent.
        assert!(symbols.sessions.is_supported());

        let stripped = isf.replace(
            r#""SessionId": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}},"#,
            "",
        );
        let profile = virtual_profile(&image, table(&stripped));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");
        let reason = symbols
            .sessions
            .reason()
            .expect("a build with no SessionId cannot enumerate sessions");
        assert!(reason.contains("SessionId"), "{reason}");
        assert!(
            reason.contains("fixed offset"),
            "the refusal says why the offset is not guessed: {reason}"
        );

        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        assert!(matches!(survey.sessions, SessionSurvey::Unsupported { .. }));
        assert!(!survey.sessions.is_complete());
    }

    // ── Environments ────────────────────────────────────────────────────────

    /// The whole stage end to end: the process list, each process's own address
    /// space, and the variables in its block.
    #[test]
    fn the_survey_reads_an_environment_and_names_the_process_it_belongs_to() {
        let (profile, symbols) = built(&plain_isf());
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");

        let explorer = survey
            .processes
            .iter()
            .find(|entry| entry.address == EXPLORER)
            .expect("explorer.exe is on the list");
        assert_eq!(explorer.pid, Some(1400));
        assert_eq!(explorer.image_file_name.as_deref(), Some("explorer.exe"));
        assert_eq!(explorer.get("USERNAME"), Some("sarah"));
        assert_eq!(explorer.get("username"), Some("sarah"));
        assert_eq!(explorer.get("USERDOMAIN"), Some("CORP"));
        assert_eq!(
            explorer.get("COR_PROFILER_PATH"),
            Some("C:\\Users\\sarah\\evil.dll"),
            "the injected-profiler variable is the reason this stage exists"
        );
        assert_eq!(
            explorer.get("=C:"),
            Some("C:\\Users\\sarah"),
            "a per-drive current directory keeps its own name"
        );
        assert!(explorer.is_complete());

        let record = explorer
            .environment
            .record()
            .expect("explorer.exe has a block");
        assert!(record.terminated);
        assert_eq!(record.length_source, LengthSource::EnvironmentSize);
        assert_eq!(record.variables_total, 6);
        assert_eq!(record.malformed_total, 0);
    }

    /// A process with no user address space has no environment to have, and
    /// that is an answer rather than a gap.
    #[test]
    fn a_kernel_process_answers_that_it_has_no_environment_rather_than_failing() {
        let (profile, symbols) = built(&plain_isf());
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let system = survey
            .processes
            .iter()
            .find(|entry| entry.address == SYSTEM)
            .expect("System is on the list");
        assert_eq!(system.environment, EnvironmentBlock::NoUserSpace);
        assert!(system.environment.is_answered());
        assert!(system.is_complete());
    }

    /// A block whose declared length runs past the end of the acquisition must
    /// come back as read short, never as a shorter environment.
    #[test]
    fn a_block_whose_pages_were_not_captured_is_reported_short_not_small() {
        let mut image = image_with_environment();
        // Point explorer.exe's environment at the very top of the mapped range
        // so the block runs off the end of what was acquired.
        image.put_u64(PARAMS_EXPLORER + 128, LAST_MAPPED_PAGE);
        image.put_u64(PARAMS_EXPLORER + 136, 0x4000);
        let profile = virtual_profile(&image, table(&plain_isf()));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");

        let explorer = survey
            .processes
            .iter()
            .find(|entry| entry.address == EXPLORER)
            .expect("explorer.exe is on the list");
        match &explorer.environment {
            EnvironmentBlock::Block(record) => {
                assert!(record.stopped.is_some(), "the short read is recorded");
                assert!(!record.is_complete());
            }
            EnvironmentBlock::Unavailable(_) => {}
            other => panic!("a block that ran off the acquisition must not look whole: {other:?}"),
        }
        assert!(!explorer.is_complete());
        assert!(!survey.is_complete());
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("environment block")));
    }

    /// Windows XP records no `EnvironmentSize`, and the parameter block's own
    /// `Length` stands in as an upper bound. The row has to say which it used.
    #[test]
    fn a_build_without_an_environment_size_falls_back_to_the_parameter_block_length() {
        let isf = plain_isf().replace(
            r#""EnvironmentSize": {"offset": 136,"#,
            r#""NoEnvironmentSize": {"offset": 136,"#,
        );
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");
        assert_eq!(
            symbols.environment_size.as_ref().map(|(_, source)| *source),
            Some(LengthSource::ParametersLength)
        );

        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let explorer = survey
            .processes
            .iter()
            .find(|entry| entry.address == EXPLORER)
            .expect("explorer.exe is on the list");
        let record = explorer.environment.record().expect("a block was read");
        assert_eq!(record.length_source, LengthSource::ParametersLength);
        assert!(
            record.terminated,
            "the decode still stops at the double NUL"
        );
        assert_eq!(record.get("USERNAME"), Some("sarah"));
    }

    /// Turning the persistent classification off must leave every variable's
    /// persistence *unknown*, never "not persistent" — the value that reads as
    /// "this was deliberately set".
    #[test]
    fn declining_to_read_the_registry_leaves_persistence_unknown_not_false() {
        let (profile, symbols) = built(&plain_isf());
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        for entry in &survey.processes {
            if let EnvironmentBlock::Block(record) = &entry.environment {
                assert!(
                    record.variables.iter().all(|var| var.persistent.is_none()),
                    "persistence must be unknown, not false"
                );
            }
        }
        assert!(survey.explicitly_set().is_empty());
        assert!(!survey.persistent.is_complete());
    }

    /// The image carries no hive list, so asking for the classification has to
    /// produce a stated failure rather than an empty persistent set — which
    /// would mark every variable as deliberately set.
    #[test]
    fn a_registry_that_cannot_be_read_leaves_persistence_unavailable_not_empty() {
        let (profile, symbols) = built(&plain_isf());
        let survey = survey_environment(&profile, &symbols, &EnvironmentConfig::default())
            .expect("the survey runs");
        assert!(!survey.persistent.is_complete());
        assert!(survey.persistent.is_empty());
        assert_eq!(survey.persistent.classify("PATH"), None);
        assert!(survey.explicitly_set().is_empty());
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("set persistently")));
    }

    // ── Sessions ────────────────────────────────────────────────────────────

    /// Sessions are how a service is told apart from somebody typing, and the
    /// name comes out of the processes' own environments.
    #[test]
    fn processes_are_grouped_into_sessions_and_the_user_comes_from_the_environment() {
        let (profile, symbols) = built(&plain_isf());
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let listing = survey.sessions.listing().expect("sessions were enumerated");

        assert_eq!(listing.sessions.len(), 2);
        assert!(
            listing.without_session.contains(&SYSTEM),
            "System has no session, and that is not a failure"
        );

        let interactive = listing
            .sessions
            .iter()
            .find(|session| session.id == 1)
            .expect("session 1 exists");
        assert_eq!(interactive.users, vec!["CORP\\sarah"]);
        assert_eq!(interactive.kind, SessionKind::Console);
        assert!(interactive.plausible_id);

        let services = listing
            .sessions
            .iter()
            .find(|session| session.id == 0)
            .expect("session 0 exists");
        assert_eq!(services.users, vec!["NT AUTHORITY\\SYSTEM"]);
        assert_eq!(
            services.kind,
            SessionKind::Other("Services".into()),
            "session 0 is where services live"
        );
        assert!(services
            .members
            .iter()
            .any(|member| member.process == SVCHOST));
    }

    /// A process on the session's own list that the active process list does
    /// not know about has been unlinked, and that is the finding.
    #[test]
    fn a_process_missing_from_the_active_list_is_found_on_its_session_list() {
        let (profile, symbols) = built(&plain_isf());
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let listing = survey.sessions.listing().expect("sessions were enumerated");
        let interactive = listing
            .sessions
            .iter()
            .find(|session| session.id == 1)
            .expect("session 1 exists");

        assert!(interactive.cross_checked);
        let unlinked = interactive.unlinked();
        assert_eq!(unlinked.len(), 1, "{:?}", interactive.members);
        assert_eq!(unlinked[0].process, HIDDEN);
        assert_eq!(unlinked[0].pid, Some(666));
        assert_eq!(unlinked[0].image_file_name.as_deref(), Some("evil.exe"));

        // The process that is on both lists says so, rather than looking like
        // it was found only one way.
        assert!(interactive
            .members
            .iter()
            .any(|member| member.process == EXPLORER && member.source == MemberSource::Both));
        assert!(!survey.processes.iter().any(|entry| entry.address == HIDDEN));
    }

    /// A build with no session process list cannot rule out an unlinked
    /// process, and the survey must say so rather than reporting the sessions
    /// as fully enumerated.
    #[test]
    fn a_build_without_the_session_process_list_says_it_could_not_cross_check() {
        let isf = plain_isf().replace(
            r#""SessionProcessLinks": {"offset": 120,"#,
            r#""NoSessionProcessLinks": {"offset": 120,"#,
        );
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");

        let listing = survey.sessions.listing().expect("sessions were enumerated");
        assert!(!listing.cross_checked);
        assert!(!survey.sessions.is_complete());
        assert!(survey
            .sessions
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("unlinked")));
        // The hidden process is invisible without the cross-check, which is
        // exactly what the incompleteness is warning about.
        let interactive = listing
            .sessions
            .iter()
            .find(|session| session.id == 1)
            .expect("session 1 exists");
        assert!(interactive.unlinked().is_empty());
    }

    // ── Desktops ────────────────────────────────────────────────────────────

    /// The kernel PDB does not describe win32k, so the ordinary case is a
    /// desktop survey that names what it is missing. It must never look like a
    /// survey that ran and found nothing.
    #[test]
    fn a_kernel_only_symbol_table_reports_desktops_unsupported_rather_than_empty() {
        let (profile, symbols) = built(&plain_isf());
        assert!(!symbols.gui.is_supported());
        let reason = symbols
            .gui
            .reason()
            .expect("an unsupported part has a reason");
        assert!(reason.contains(TYPE_WINDOW_STATION), "{reason}");
        assert!(reason.contains(TYPE_DESKTOP), "{reason}");

        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        assert!(matches!(survey.desktops, DesktopSurvey::Unsupported { .. }));
        assert!(
            !survey.desktops.is_complete(),
            "an unsupported desktop survey is not a complete one"
        );
        assert!(
            !survey.is_complete(),
            "a survey that could not look for hidden desktops is not complete"
        );
    }

    /// Supplying win32k symbols makes the walk run: the station is found by its
    /// pool tag, named from its object header, and both its desktops followed.
    #[test]
    fn a_symbol_table_describing_win32k_finds_the_station_and_both_its_desktops() {
        let (profile, symbols) = built(&gui_isf());
        assert!(
            symbols.gui.is_supported(),
            "a table with tagWINDOWSTATION supports the walk: {:?}",
            symbols.gui.reason()
        );
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let listing = survey.desktops.listing().expect("the walk ran");

        assert_eq!(listing.stations.len(), 1, "{:?}", listing.unreadable);
        let station = &listing.stations[0];
        assert_eq!(station.address, STATION);
        assert_eq!(station.session_id, Some(1));
        assert_eq!(station.space, "session");
        assert_eq!(station.name.text(), Some("WinSta0"));

        assert_eq!(station.desktops.len(), 2);
        assert_eq!(station.desktops[0].address, DESKTOP_A);
        assert_eq!(station.desktops[0].name.text(), Some("Default"));
        assert_eq!(station.desktops[1].address, DESKTOP_B);
        assert_eq!(station.desktops[1].name.text(), Some("hidden"));
    }

    /// The finding: a desktop Windows did not create, with a process attached
    /// to it that the active process list does not carry.
    #[test]
    fn a_second_desktop_is_reported_with_the_process_drawing_on_it() {
        let (profile, symbols) = built(&gui_isf());
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");

        let nonstandard = survey.desktops.nonstandard_desktops();
        assert_eq!(nonstandard.len(), 1);
        let (station, desktop) = nonstandard[0];
        assert_eq!(station.name.text(), Some("WinSta0"));
        assert_eq!(desktop.name.text(), Some("hidden"));
        assert_eq!(desktop.standard_name(), Some(false));

        assert_eq!(desktop.threads.len(), 1, "{:?}", desktop.notes);
        assert_eq!(desktop.threads[0].process, Some(HIDDEN));
        assert_eq!(desktop.threads[0].pid, Some(666));
        assert_eq!(
            desktop.threads[0].image_file_name.as_deref(),
            Some("evil.exe")
        );
        assert!(desktop.thread_list_walked);

        // And the ordinary desktop is still attributed to the ordinary process.
        let default = &station.desktops[0];
        assert_eq!(default.standard_name(), Some(true));
        assert_eq!(default.threads[0].process, Some(EXPLORER));
        assert_eq!(default.threads[0].pid, Some(1400));
    }

    /// A build with the GUI types but no thread list leaves each desktop saying
    /// its threads are unknown, not that nobody was attached.
    #[test]
    fn a_build_without_a_desktop_thread_list_says_the_threads_are_unknown() {
        let isf = gui_isf().replace(
            r#""PtiList": {"offset": 16,"#,
            r#""NoPtiList": {"offset": 16,"#,
        );
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let listing = survey.desktops.listing().expect("the walk ran");
        let station = &listing.stations[0];

        // Without this the loop below is vacuous: a walk that returned a
        // station with no desktops at all would satisfy every assertion in it
        // while proving nothing about how a missing thread list is reported.
        // The count itself is pinned at two by
        // `a_symbol_table_describing_win32k_finds_the_station_and_both_its_desktops`,
        // which uses this fixture with `PtiList` left in place.
        assert!(
            !station.desktops.is_empty(),
            "the walk must reach the desktops it is being asked about: {:?}",
            listing.unreadable
        );

        for desktop in &station.desktops {
            assert!(desktop.threads.is_empty());
            assert!(!desktop.thread_list_walked);
            assert!(
                desktop
                    .notes
                    .iter()
                    .any(|note| note.contains("unknown rather than none")),
                "{:?}",
                desktop.notes
            );
        }
        assert!(!survey.desktops.is_complete());
    }

    /// Declining the desktop survey is a third state, and it must not read like
    /// either "unsupported" or "nothing found".
    #[test]
    fn declining_the_desktop_survey_is_recorded_as_such() {
        let (profile, symbols) = built(&gui_isf());
        let config = EnvironmentConfig {
            survey_desktops: false,
            ..config()
        };
        let survey = survey_environment(&profile, &symbols, &config).expect("the survey runs");
        assert_eq!(survey.desktops, DesktopSurvey::NotRequested);
        assert!(!survey.desktops.is_complete());
        assert!(!survey.is_complete());
    }

    // ── Caps and serialization ──────────────────────────────────────────────

    /// A cap that fired must reach the artifact. A truncated list of processes
    /// that claimed to be complete is the failure this whole tier guards.
    #[test]
    fn the_process_cap_is_reported_rather_than_silently_truncating() {
        let (profile, symbols) = built(&plain_isf());
        let config = EnvironmentConfig {
            max_processes: 1,
            ..config()
        };
        let survey = survey_environment(&profile, &symbols, &config).expect("the survey runs");
        assert!(
            survey.processes.len() < 3,
            "the image holds three processes and one was allowed"
        );
        assert!(survey.processes_capped);
        assert!(!survey.is_complete());
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("cap of")));
    }

    /// Every survey is serializable, and the serialization has to carry the
    /// completeness flag rather than leaving a reader to infer it from counts.
    #[test]
    fn the_serialized_survey_states_whether_it_is_complete() {
        let (profile, symbols) = built(&plain_isf());
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let json = survey.to_json();
        assert_eq!(json["complete"], serde_json::json!(false));
        assert!(json["incomplete"].as_array().is_some_and(|a| !a.is_empty()));
        assert!(json["processes"].as_array().is_some());
        assert!(json["sessions"]["supported"] == serde_json::json!(true));
        assert_eq!(json["desktops"]["surveyed"], serde_json::json!(false));
        assert_eq!(
            json["desktops"]["reason"],
            serde_json::json!("unsupported_build")
        );

        // The resolved layout is serializable too, so a report can show which
        // members every number above was read through.
        let layout = symbols.to_json();
        assert_eq!(layout["environment"], serde_json::json!("Environment"));
        assert_eq!(layout["sessions"]["supported"], serde_json::json!(true));
        assert_eq!(layout["gui"]["supported"], serde_json::json!(false));
    }

    /// The `Supported` wrapper is the thing that keeps "could not run" and
    /// "found nothing" apart, so its two states must not collapse.
    #[test]
    fn a_supported_part_and_an_unsupported_one_serialize_differently() {
        let yes: Supported<u8> = Supported::Yes(7);
        let no: Supported<u8> = Supported::No("no symbols for it".into());
        assert!(yes.is_supported());
        assert_eq!(yes.get(), Some(&7));
        assert_eq!(yes.reason(), None);
        assert!(!no.is_supported());
        assert_eq!(no.get(), None);
        assert_eq!(no.reason(), Some("no symbols for it"));
        assert_eq!(
            no.to_json(|value| serde_json::json!(value))["detail"],
            serde_json::json!("no symbols for it")
        );
        assert_eq!(
            yes.to_json(|value| serde_json::json!(value))["symbols"],
            serde_json::json!(7)
        );
    }

    /// A build with no `rpdeskNext` reaches exactly one desktop per station,
    /// and that station's desktop list is therefore a floor.
    ///
    /// The second desktop is the whole finding. A station listed with one
    /// desktop and no statement that the chain was never followed reads as a
    /// station that has one desktop, which is the opposite conclusion.
    #[test]
    fn a_build_without_rpdesknext_cannot_claim_a_stations_desktops_are_all_of_them() {
        let isf = gui_isf().replace(
            r#""rpdeskNext": {"offset": 0,"#,
            r#""NoRpdeskNext": {"offset": 0,"#,
        );
        assert!(
            isf.contains("NoRpdeskNext"),
            "the fixture's rpdeskNext member must have been removed"
        );
        let image = image_with_environment();
        let profile = virtual_profile(&image, table(&isf));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");
        let survey = survey_environment(&profile, &symbols, &config()).expect("the survey runs");
        let listing = survey.desktops.listing().expect("the walk ran");
        let station = &listing.stations[0];

        assert_eq!(
            station.desktops.len(),
            1,
            "without rpdeskNext only the first desktop is reachable"
        );
        assert!(
            station.desktops_capped,
            "a chain that was never followed must not render as a finished list"
        );
        assert!(!survey.desktops.is_complete());
        assert!(
            survey
                .desktops
                .incomplete()
                .iter()
                .any(|entry| entry.detail.contains("floor")),
            "{:?}",
            survey.desktops.incomplete()
        );
    }

    /// The needle that re-declares the environment pointer as a signed integer.
    ///
    /// Some builds' symbol packs declare a pointer-shaped member through a
    /// signed base type, and the fixture has to be able to reproduce that.
    const SIGNED_ENVIRONMENT_FROM: &str = concat!(
        "\"Environment\": {\"offset\": 128, \"type\": {\"kind\": \"pointer\",\n",
        "                       \"subtype\": {\"kind\": \"base\", \"name\": \"unsigned char\"}}},"
    );

    /// What it is replaced with.
    const SIGNED_ENVIRONMENT_TO: &str =
        "\"Environment\": {\"offset\": 128, \"type\": {\"kind\": \"base\", \"name\": \"long long\"}},";

    /// A member that did not read as an address must never be folded to zero.
    ///
    /// Zero in `_RTL_USER_PROCESS_PARAMETERS.Environment` is a positive finding:
    /// this process really was given no environment block. Folding a value that
    /// is not an address into it manufactures that finding out of a member the
    /// symbols declared signed over an ordinary kernel address, and the
    /// resulting row is indistinguishable from a correct one.
    #[test]
    fn an_environment_pointer_that_is_not_an_address_is_unknown_rather_than_absent() {
        let isf = plain_isf().replace(SIGNED_ENVIRONMENT_FROM, SIGNED_ENVIRONMENT_TO);
        assert!(
            isf.contains(SIGNED_ENVIRONMENT_TO),
            "the fixture's Environment member must have been re-declared signed"
        );

        let mut image = image_with_environment();
        // The top bit set: an ordinary address, and a negative number once the
        // member is read at the signedness this build declares.
        image.put_u64(PARAMS_EXPLORER + 128, 0x8000_0000_0000_1000);
        let profile = virtual_profile(&image, table(&isf));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");

        let cache = Arc::new(TableCache::new());
        match read_environment(&profile, &symbols, EXPLORER, &cache, &config()) {
            EnvironmentBlock::Unavailable(detail) => assert!(
                detail.contains("not an address"),
                "the reason must name what went wrong: {detail}"
            ),
            other => panic!(
                "a value that is not an address must not read as a process given no \
                 environment: {other:?}"
            ),
        }
    }

    /// The same rule, one level up: a `_PEB.ProcessParameters` that is not an
    /// address must not render as a process caught during creation.
    #[test]
    fn a_parameter_block_pointer_that_is_not_an_address_is_unknown_rather_than_absent() {
        let isf = plain_isf().replace(
            concat!(
                "\"ProcessParameters\": {\"offset\": 32, \"type\": {\"kind\": \"pointer\",\n",
                "                             \"subtype\": {\"kind\": \"base\", \"name\": \"unsigned char\"}}}"
            ),
            "\"ProcessParameters\": {\"offset\": 32, \"type\": {\"kind\": \"base\", \"name\": \"long long\"}}",
        );
        assert!(
            isf.contains("\"ProcessParameters\": {\"offset\": 32, \"type\": {\"kind\": \"base\""),
            "the fixture's ProcessParameters member must have been re-declared signed"
        );

        let mut image = image_with_environment();
        image.put_u64(PEB_EXPLORER + 32, 0x8000_0000_0000_2000);
        let profile = virtual_profile(&image, table(&isf));
        let symbols = EnvironmentSymbols::from_profile(&profile).expect("the layout resolves");

        let cache = Arc::new(TableCache::new());
        match read_environment(&profile, &symbols, EXPLORER, &cache, &config()) {
            EnvironmentBlock::Unavailable(detail) => assert!(
                detail.contains("not an address"),
                "the reason must name what went wrong: {detail}"
            ),
            other => panic!(
                "a value that is not an address must not read as a process with no parameter \
                 block: {other:?}"
            ),
        }
    }
}
