//! Logon sessions: who was on this machine, and which processes were theirs.
//!
//! `_EPROCESS.Session` points at an `_MM_SESSION_SPACE`, and its `SessionId` is
//! the terminal-services session the process belongs to. From Windows Vista
//! onwards session 0 is reserved for services and drivers; the first
//! interactive logon gets session 1, the next gets 2, and a machine with three
//! people signed in over RDP has sessions 1, 2 and 3 side by side.
//!
//! That single number is what turns a process list into an account of *who did
//! what*. A `cmd.exe` in session 0 was started by a service. The same
//! `cmd.exe` in session 2 was typed by whoever was logged on there. A process
//! list alone cannot tell them apart, because both rows say `cmd.exe`, and the
//! parent process id is frequently a process that has since exited.
//!
//! # Naming the human
//!
//! Nothing in `_MM_SESSION_SPACE` says whose session it is. The name comes from
//! the environment of the processes *inside* it: `USERNAME`, `USERDOMAIN` and
//! `SESSIONNAME`, which the logon process plants in every process it starts.
//! Because those come out of a block that may have been read short, a session
//! records every distinct value it saw rather than the first — two different
//! usernames in one session is either smear or a token that was swapped, and
//! silently keeping whichever came first would hide it.
//!
//! # Two lists, and why both are walked
//!
//! Membership is derived from the active process list: every process whose
//! `Session` points at this space. Where the build declares them,
//! `_MM_SESSION_SPACE.ProcessList` is walked too, threading through
//! `_EPROCESS.SessionProcessLinks`. A process on the session's own list that is
//! **not** on the active process list has been unlinked from the active list —
//! the oldest process-hiding technique there is — and it appears here with
//! [`MemberSource::SessionProcessList`].
//!
//! Where the build does *not* declare that list, the cross-check cannot run,
//! and the survey says so rather than reporting the sessions as fully
//! enumerated. "Every process in this session" and "every process in this
//! session that was still on the active list" are different claims.
//!
//! # Windows 11 24H2
//!
//! That build replaced `_MM_SESSION_SPACE` with `_PSP_SESSION_SPACE`, whose
//! members the kernel PDB does not describe. Upstream Volatility reads the
//! session id from offset 8 anyway, on the grounds that the layout appears
//! unchanged. This module will not: an offset that is not in the symbol table
//! is a guess, and a guessed session id moves a process between "a service" and
//! "somebody typing", which is exactly the distinction the stage exists to
//! draw. The session part reports itself unsupported, naming the type and the
//! member, and the environment and desktop parts still run.

use std::collections::BTreeMap;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_core::time::filetime_to_rfc3339;
use seance_memory::object::{ListSpec, ListStop, ObjError, StructReader};
use seance_memory::translate::TableCache;
use seance_memory::Incomplete;

use crate::environment::{
    first_member, EnvironmentConfig, EnvironmentSymbols, ProcessEnvironment, SessionLayers,
    Supported, TYPE_EPROCESS,
};
use crate::poolscan::image_file_name;
use crate::process::{self, ProcessList, ProcessSymbols};
use crate::profile::WindowsProfile;

/// One candidate lookup, with the two ways there is no answer kept apart.
///
/// `Ok(None)` is this build declaring no such member — a fact about the machine
/// the image came from. `Err` is the symbol table failing to answer, which is
/// damage to the evidence about layout and must not be reported as the first.
fn declared(found: Result<Option<&str>, ObjError>) -> Result<Option<String>, String> {
    found.map(|path| path.map(str::to_string)).map_err(|err| {
        format!(
            "the symbol table could not be read, so this build's session layout is unknown: {err}"
        )
    })
}

/// The session space a process's `Session` member points at.
pub const TYPE_MM_SESSION_SPACE: &str = "_MM_SESSION_SPACE";

/// What Windows 11 24H2 renamed it to. Named here so a refusal can say which
/// type it found and which member of it was missing.
pub const TYPE_PSP_SESSION_SPACE: &str = "_PSP_SESSION_SPACE";

/// The list-link structure the session's process list is threaded through.
pub const TYPE_LIST_ENTRY: &str = "_LIST_ENTRY";

/// The highest session id this survey treats as believable.
///
/// Windows allocates session ids sequentially from zero and a machine does not
/// reach three digits, so a larger value is smear rather than a session. It is
/// recorded on the session rather than used to discard it: a session with an
/// implausible id is still a fact about the bytes that were read.
pub const MAX_PLAUSIBLE_SESSION_ID: u64 = 256;

/// Ceiling on sessions reported.
pub const MAX_SESSIONS: usize = 1_024;

/// Ceiling on processes listed under one session.
pub const MAX_SESSION_PROCESSES: usize = 65_536;

// ── Layout ──────────────────────────────────────────────────────────────────

/// The member paths one image's sessions are read through.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSymbols {
    /// Path to the session-space pointer inside `_EPROCESS`.
    pub session: String,
    /// The session-space type this build declares.
    pub space_type: String,
    /// Path to the session id inside it.
    pub session_id: String,
    /// Path to the session's own process list, when the build declares one.
    pub process_list: Option<String>,
    /// Path to the link that threads an `_EPROCESS` onto that list.
    pub session_links: Option<String>,
}

impl SessionSymbols {
    /// Resolve the session layout, or say exactly what is missing.
    ///
    /// Not a `Result`: a build that cannot describe sessions is a fact about
    /// the build, and the environment and desktop parts of the survey still
    /// run. The [`Supported::No`] string names the type and member an examiner
    /// would need symbols for.
    pub fn from_profile(profile: &WindowsProfile, process: &ProcessSymbols) -> Supported<Self> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        let Some(session) = process.session.clone() else {
            return Supported::No(format!(
                "'{TYPE_EPROCESS}' has no Session member on this build, so no process can be \
                 attributed to a logon session"
            ));
        };

        let space_type = if profile.symbols.has_type(TYPE_MM_SESSION_SPACE) {
            TYPE_MM_SESSION_SPACE
        } else if profile.symbols.has_type(TYPE_PSP_SESSION_SPACE) {
            TYPE_PSP_SESSION_SPACE
        } else {
            return Supported::No(format!(
                "the symbol table has neither '{TYPE_MM_SESSION_SPACE}' nor \
                 '{TYPE_PSP_SESSION_SPACE}', so a process's session id cannot be read; the \
                 session id is not guessed from a fixed offset because a wrong one turns a \
                 service into an interactive logon"
            ));
        };

        let session_id = match declared(first_member(&reader, space_type, &["SessionId"])) {
            Ok(Some(path)) => path,
            Ok(None) => {
                return Supported::No(format!(
                    "'{space_type}' is declared but has no SessionId member, which is what \
                     Windows 11 24H2 kernel symbols look like; the id is not read from a fixed \
                     offset because a wrong one turns a service into an interactive logon"
                ))
            }
            Err(reason) => return Supported::No(reason),
        };

        // The session's own process list is a cross-check rather than the
        // membership itself, so a build without it is still supported — the
        // survey records that the cross-check did not run. Both members or
        // neither: walking the list without the link member's offset would
        // report every entry at a constant distance from its real address, and
        // every one of those addresses would parse as an `_EPROCESS`.
        let list = match declared(first_member(&reader, space_type, &["ProcessList"])) {
            Ok(value) => value,
            Err(reason) => return Supported::No(reason),
        };
        let link = match declared(first_member(
            &reader,
            TYPE_EPROCESS,
            &["SessionProcessLinks"],
        )) {
            Ok(value) => value,
            Err(reason) => return Supported::No(reason),
        };
        let (process_list, session_links) = match (list, link) {
            (Some(list), Some(link)) => (Some(list), Some(link)),
            _ => (None, None),
        };

        Supported::Yes(Self {
            session,
            space_type: space_type.to_string(),
            session_id,
            process_list,
            session_links,
        })
    }

    /// Whether this build can cross-check membership against the session's own
    /// process list.
    pub fn can_cross_check(&self) -> bool {
        self.process_list.is_some() && self.session_links.is_some()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "session": self.session,
            "space_type": self.space_type,
            "session_id": self.session_id,
            "process_list": self.process_list,
            "session_links": self.session_links,
            "can_cross_check": self.can_cross_check(),
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// Which listing a process was found in.
///
/// The distinction is the finding: a process the session still knows about but
/// the active process list does not has been unlinked from that list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberSource {
    /// Both listings agree.
    Both,
    /// Only the active process list, which is ordinary on a build whose
    /// session process list could not be walked.
    ActiveProcessList,
    /// Only the session's own process list. The process is not on the active
    /// process list, which does not happen by itself.
    SessionProcessList,
}

impl MemberSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            MemberSource::Both => "both",
            MemberSource::ActiveProcessList => "active_process_list",
            MemberSource::SessionProcessList => "session_process_list",
        }
    }
}

/// What kind of session this is, as its `SESSIONNAME` says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionKind {
    /// Somebody at the physical keyboard.
    Console,
    /// A remote desktop connection. Carries the station name, which numbers the
    /// connection: `RDP-Tcp#3`.
    Remote(String),
    /// A `SESSIONNAME` this classifier does not recognise, kept verbatim.
    Other(String),
    /// No process in the session carried a readable `SESSIONNAME`. Not the same
    /// as a session with no name: it means nothing said.
    Unknown,
}

impl SessionKind {
    /// Classify a `SESSIONNAME` value.
    pub fn from_session_name(name: &str) -> Self {
        let trimmed = name.trim();
        if trimmed.is_empty() {
            return SessionKind::Unknown;
        }
        if trimmed.eq_ignore_ascii_case("Console") {
            return SessionKind::Console;
        }
        // Compared as bytes rather than by slicing the string: a `SESSIONNAME`
        // comes out of evidence and may begin with a multi-byte character, and
        // `&trimmed[..7]` would panic on one.
        let bytes = trimmed.as_bytes();
        if bytes.len() >= 7 && bytes[..7].eq_ignore_ascii_case(b"RDP-Tcp") {
            return SessionKind::Remote(trimmed.to_string());
        }
        SessionKind::Other(trimmed.to_string())
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionKind::Console => "console",
            SessionKind::Remote(_) => "remote",
            SessionKind::Other(_) => "other",
            SessionKind::Unknown => "unknown",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            SessionKind::Remote(name) | SessionKind::Other(name) => {
                serde_json::json!({"kind": self.as_str(), "session_name": name})
            }
            other => serde_json::json!({"kind": other.as_str()}),
        }
    }
}

/// One process inside a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionMember {
    /// Kernel address of the `_EPROCESS`.
    pub process: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// The image name, when it was readable.
    pub image_file_name: Option<String>,
    /// When the process started, when the process list read it.
    pub started: Option<String>,
    /// `USERDOMAIN\USERNAME` from this process's own environment.
    pub user: Option<String>,
    /// `SESSIONNAME` from this process's own environment.
    pub session_name: Option<String>,
    /// Which listing found it.
    pub source: MemberSource,
}

impl SessionMember {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "started": self.started,
            "user": self.user,
            "session_name": self.session_name,
            "source": self.source.as_str(),
        })
    }
}

/// One logon session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    /// The session id.
    pub id: u64,
    /// Address of the session space the id was read from.
    pub space: u64,
    /// The processes in it.
    pub members: Vec<SessionMember>,
    /// Every distinct `USERDOMAIN\USERNAME` its processes carried.
    ///
    /// More than one is a finding rather than a tie to break: a session whose
    /// processes disagree about whose it is has either been smeared or had a
    /// token swapped into it.
    pub users: Vec<String>,
    /// Every distinct `SESSIONNAME` its processes carried.
    pub session_names: Vec<String>,
    /// What kind of session this is, from the names above.
    pub kind: SessionKind,
    /// Whether the id is inside [`MAX_PLAUSIBLE_SESSION_ID`].
    pub plausible_id: bool,
    /// Whether membership was cross-checked against the session's own process
    /// list. `false` means no claim can be made about processes unlinked from
    /// the active process list.
    pub cross_checked: bool,
    /// Whether the member cap fired.
    pub capped: bool,
    /// Everything odd about the session that did not stop it being reported.
    pub notes: Vec<String>,
}

impl Session {
    /// The processes that only the session's own list knows about.
    ///
    /// A non-empty result is the finding: these are unlinked from the active
    /// process list.
    pub fn unlinked(&self) -> Vec<&SessionMember> {
        self.members
            .iter()
            .filter(|member| member.source == MemberSource::SessionProcessList)
            .collect()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "id": self.id,
            "space": self.space,
            "members": self.members.iter().map(SessionMember::to_json).collect::<Vec<_>>(),
            "member_count": self.members.len(),
            "unlinked_count": self.unlinked().len(),
            "users": self.users,
            "session_names": self.session_names,
            "kind": self.kind.to_json(),
            "plausible_id": self.plausible_id,
            "cross_checked": self.cross_checked,
            "capped": self.capped,
            "notes": self.notes,
        })
    }
}

/// A process whose session could not be established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableSession {
    /// Kernel address of the `_EPROCESS`.
    pub process: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// Why the session could not be read.
    pub detail: String,
}

impl UnreadableSession {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"process": self.process, "pid": self.pid, "detail": self.detail})
    }
}

/// Every session the survey found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionListing {
    /// The sessions, in ascending id order.
    pub sessions: Vec<Session>,
    /// Processes with a null `Session` pointer, which is what the System
    /// process and the kernel's own processes have. Not a failure.
    pub without_session: Vec<u64>,
    /// Processes whose session could not be read.
    pub unreadable: Vec<UnreadableSession>,
    /// Whether the session cap fired.
    pub capped: bool,
    /// Whether membership was cross-checked against the sessions' own process
    /// lists.
    pub cross_checked: bool,
    /// Everything odd that did not stop the listing.
    pub notes: Vec<String>,
}

/// The logon sessions, or why they could not be enumerated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionSurvey {
    /// This build's symbols do not describe the session space, so no process
    /// can be attributed to a session at all. Deliberately not the same value
    /// as a machine with no sessions.
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },
    /// The survey ran.
    Surveyed(SessionListing),
}

impl SessionSurvey {
    /// The listing, when the survey ran.
    pub fn listing(&self) -> Option<&SessionListing> {
        match self {
            SessionSurvey::Surveyed(listing) => Some(listing),
            SessionSurvey::Unsupported { .. } => None,
        }
    }

    /// Whether every session was enumerated and cross-checked.
    ///
    /// An unsupported survey is never complete: a report must not write "this
    /// machine had one logon session" on the strength of a part that could not
    /// run.
    pub fn is_complete(&self) -> bool {
        match self {
            SessionSurvey::Unsupported { .. } => false,
            SessionSurvey::Surveyed(listing) => {
                !listing.capped
                    && listing.unreadable.is_empty()
                    && listing.cross_checked
                    && listing.sessions.iter().all(|session| !session.capped)
            }
        }
    }

    /// Everything a report must declare about this survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let listing = match self {
            SessionSurvey::Unsupported { detail } => {
                return vec![Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "logon sessions could not be enumerated, so no process is shown as \
                         belonging to one: {detail}"
                    ),
                )]
            }
            SessionSurvey::Surveyed(listing) => listing,
        };

        let mut out = Vec::new();
        if listing.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the session survey stopped at its cap of {} session(s)",
                    listing.sessions.len()
                ),
            ));
        }
        if !listing.cross_checked {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "this build does not declare the session's own process list, so a process \
                 unlinked from the active process list would not appear in its session"
                    .to_string(),
            ));
        }
        for entry in &listing.unreadable {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the session of the process at {:#x} could not be read, so it is not \
                     attributed to any session: {}",
                    entry.process, entry.detail
                ),
            ));
        }
        for session in &listing.sessions {
            if session.capped {
                out.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!(
                        "session {} stopped at its cap of {} process(es)",
                        session.id,
                        session.members.len()
                    ),
                ));
            }
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            SessionSurvey::Unsupported { detail } => serde_json::json!({
                "supported": false,
                "detail": detail,
                "complete": false,
            }),
            SessionSurvey::Surveyed(listing) => serde_json::json!({
                "supported": true,
                "sessions": listing.sessions.iter().map(Session::to_json).collect::<Vec<_>>(),
                "session_count": listing.sessions.len(),
                "without_session": listing.without_session,
                "unreadable": listing
                    .unreadable
                    .iter()
                    .map(UnreadableSession::to_json)
                    .collect::<Vec<_>>(),
                "capped": listing.capped,
                "cross_checked": listing.cross_checked,
                "notes": listing.notes,
                "complete": self.is_complete(),
            }),
        }
    }
}

// ── The survey ──────────────────────────────────────────────────────────────

/// One session under construction.
struct Building {
    space: u64,
    members: Vec<SessionMember>,
    seen: Vec<u64>,
    users: Vec<String>,
    session_names: Vec<String>,
    capped: bool,
    notes: Vec<String>,
}

/// Group every process on `list` into the logon session it belongs to.
///
/// `environments` supplies the `USERNAME`, `USERDOMAIN` and `SESSIONNAME` a
/// session is named from, so the environment blocks are read once for the whole
/// stage rather than once per part.
pub fn survey_sessions(
    profile: &WindowsProfile,
    symbols: &EnvironmentSymbols,
    list: &ProcessList,
    environments: &[ProcessEnvironment],
    config: &EnvironmentConfig,
    notes: &mut Vec<String>,
) -> SessionSurvey {
    let session_symbols = match &symbols.sessions {
        Supported::Yes(resolved) => resolved,
        Supported::No(detail) => {
            notes.push(format!("sessions were not enumerated: {detail}"));
            return SessionSurvey::Unsupported {
                detail: detail.clone(),
            };
        }
    };

    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let by_address: BTreeMap<u64, &ProcessEnvironment> = environments
        .iter()
        .map(|entry| (entry.address, entry))
        .collect();

    let mut building: BTreeMap<u64, Building> = BTreeMap::new();
    let mut without_session: Vec<u64> = Vec::new();
    let mut unreadable: Vec<UnreadableSession> = Vec::new();
    let mut capped = false;
    let mut listing_notes: Vec<String> = Vec::new();

    for record in &list.processes {
        let pid = record.pid.known().copied();
        let object = match reader.object(record.address, TYPE_EPROCESS) {
            Ok(object) => object,
            Err(err) => {
                unreadable.push(UnreadableSession {
                    process: record.address,
                    pid,
                    detail: err.to_string(),
                });
                continue;
            }
        };
        let space = match object.int(&session_symbols.session) {
            Ok(value) => value.as_u64().unwrap_or(0),
            Err(err) => {
                unreadable.push(UnreadableSession {
                    process: record.address,
                    pid,
                    detail: format!("'{TYPE_EPROCESS}.{}': {err}", session_symbols.session),
                });
                continue;
            }
        };
        if space == 0 {
            without_session.push(record.address);
            continue;
        }
        let id = match read_session_id(&reader, session_symbols, space) {
            Ok(id) => id,
            Err(detail) => {
                unreadable.push(UnreadableSession {
                    process: record.address,
                    pid,
                    detail,
                });
                continue;
            }
        };

        if !building.contains_key(&id) && building.len() >= config.max_sessions.max(1) {
            capped = true;
            continue;
        }
        let environment = by_address.get(&record.address).copied();
        let entry = building.entry(id).or_insert_with(|| Building {
            space,
            members: Vec::new(),
            seen: Vec::new(),
            users: Vec::new(),
            session_names: Vec::new(),
            capped: false,
            notes: Vec::new(),
        });
        if entry.space != space {
            entry.notes.push(format!(
                "the process at {:#x} reaches session {id} through the space at {space:#x}, where \
                 an earlier process reached it through {:#x}; one of the two pointers is smeared",
                record.address, entry.space
            ));
        }
        if entry.members.len() >= config.max_session_processes.max(1) {
            entry.capped = true;
            continue;
        }

        let user = environment.and_then(compose_user);
        let session_name = environment
            .and_then(|process| process.get("SESSIONNAME"))
            .map(str::to_string);
        record_distinct(&mut entry.users, user.as_deref());
        record_distinct(&mut entry.session_names, session_name.as_deref());
        entry.seen.push(record.address);
        entry.members.push(SessionMember {
            process: record.address,
            pid,
            image_file_name: record.image_file_name.known().cloned(),
            started: record.create_time.filetime().and_then(filetime_to_rfc3339),
            user,
            session_name,
            source: MemberSource::ActiveProcessList,
        });
    }

    let cross_checked = session_symbols.can_cross_check();
    if !cross_checked {
        listing_notes.push(format!(
            "'{}' has no ProcessList, or '{TYPE_EPROCESS}' has no SessionProcessLinks, on this \
             build, so a process unlinked from the active process list would not be found",
            session_symbols.space_type
        ));
    }

    let mut sessions: Vec<Session> = Vec::new();
    for (id, mut entry) in building {
        if cross_checked {
            cross_check(
                &reader,
                &symbols.process,
                session_symbols,
                &mut entry,
                config,
            );
        }
        let kind = entry
            .session_names
            .first()
            .map(|name| SessionKind::from_session_name(name))
            .unwrap_or(SessionKind::Unknown);
        let plausible_id = id < MAX_PLAUSIBLE_SESSION_ID;
        if !plausible_id {
            entry.notes.push(format!(
                "session id {id} is past {MAX_PLAUSIBLE_SESSION_ID}, which no real machine \
                 reaches, so the pointer this id was read through is probably smeared"
            ));
        }
        if entry.users.len() > 1 {
            entry.notes.push(format!(
                "the processes in session {id} name {} different users, so either the image is \
                 smeared or a token was swapped",
                entry.users.len()
            ));
        }
        sessions.push(Session {
            id,
            space: entry.space,
            members: entry.members,
            users: entry.users,
            session_names: entry.session_names,
            kind,
            plausible_id,
            cross_checked,
            capped: entry.capped,
            notes: entry.notes,
        });
    }

    SessionSurvey::Surveyed(SessionListing {
        sessions,
        without_session,
        unreadable,
        capped,
        cross_checked,
        notes: listing_notes,
    })
}

/// Read a session space's id, naming the member when it cannot be read.
fn read_session_id(
    reader: &StructReader,
    symbols: &SessionSymbols,
    space: u64,
) -> Result<u64, String> {
    let object = reader
        .object(space, &symbols.space_type)
        .map_err(|err| format!("the session space at {space:#x} could not be read: {err}"))?;
    let value = object.int(&symbols.session_id).map_err(|err| {
        format!(
            "'{}.{}' at {space:#x} could not be read: {err}",
            symbols.space_type, symbols.session_id
        )
    })?;
    value.as_u64().ok_or_else(|| {
        format!(
            "'{}.{}' at {space:#x} is negative, which is not a session id",
            symbols.space_type, symbols.session_id
        )
    })
}

/// `USERDOMAIN\USERNAME` from one process's environment, when both are there.
fn compose_user(entry: &ProcessEnvironment) -> Option<String> {
    let name = entry.get("USERNAME")?;
    match entry.get("USERDOMAIN") {
        Some(domain) if !domain.is_empty() => Some(format!("{domain}\\{name}")),
        _ => Some(name.to_string()),
    }
}

/// Add a value to a list if it is not already there.
fn record_distinct(into: &mut Vec<String>, value: Option<&str>) {
    let Some(value) = value else { return };
    if value.is_empty() {
        return;
    }
    if !into.iter().any(|held| held == value) {
        into.push(value.to_string());
    }
}

/// Walk the session's own process list and mark, or add, its members.
///
/// A process on both lists is [`MemberSource::Both`]. A process on the session's
/// list alone is [`MemberSource::SessionProcessList`], and that is the finding:
/// it is not on the active process list, which does not happen without help.
fn cross_check(
    reader: &StructReader,
    process_symbols: &ProcessSymbols,
    symbols: &SessionSymbols,
    entry: &mut Building,
    config: &EnvironmentConfig,
) {
    let (Some(list_member), Some(link_member)) = (&symbols.process_list, &symbols.session_links)
    else {
        return;
    };
    let head = match reader
        .object(entry.space, &symbols.space_type)
        .and_then(|object| object.member_address(list_member))
    {
        Ok(head) => head,
        Err(err) => {
            entry.notes.push(format!(
                "'{}.{list_member}' at {:#x} could not be located, so the session's own process \
                 list was not walked: {err}",
                symbols.space_type, entry.space
            ));
            return;
        }
    };

    let spec = ListSpec::new(TYPE_LIST_ENTRY, "Flink")
        .in_container(TYPE_EPROCESS, link_member)
        .with_max_entries(config.max_session_processes.max(1));
    let walk = match reader.walk_list(head, &spec) {
        Ok(walk) => walk,
        Err(err) => {
            entry.notes.push(format!(
                "the session's own process list at {head:#x} could not be walked: {err}"
            ));
            return;
        }
    };
    let (found, stop) = walk.walk_to_end();
    if stop != ListStop::Wrapped {
        entry.notes.push(format!(
            "the session's own process list at {head:#x} did not close, so a process on the far \
             side of the break would not be found: {}",
            stop.as_str()
        ));
    }

    for object in found {
        let address = object.address();
        if let Some(position) = entry.seen.iter().position(|held| *held == address) {
            if let Some(member) = entry.members.get_mut(position) {
                member.source = MemberSource::Both;
            }
            continue;
        }
        if entry.members.len() >= config.max_session_processes.max(1) {
            entry.capped = true;
            return;
        }
        let pid = object
            .int(&process_symbols.unique_process_id)
            .ok()
            .and_then(|value| value.as_u64());
        let name = object
            .bytes(crate::process::MEMBER_IMAGE_FILE_NAME)
            .ok()
            .map(|raw| image_file_name(&raw));
        entry.seen.push(address);
        entry.members.push(SessionMember {
            process: address,
            pid,
            image_file_name: name,
            started: None,
            user: None,
            session_name: None,
            source: MemberSource::SessionProcessList,
        });
        entry.notes.push(format!(
            "the process at {address:#x} is on this session's own process list and not on the \
             active process list, so it has been unlinked from the active list"
        ));
    }
}

// ── Session address spaces ──────────────────────────────────────────────────

/// Build one address space per session.
///
/// Session space — where `tagWINDOWSTATION` and `tagDESKTOP` live — is mapped
/// per session, so a pointer taken from session 1 resolves to nothing, or to
/// something else entirely, in the system process's address space. Each
/// session's space is built from the first of its processes whose directory
/// table base names a page table.
///
/// A session with no entry in the result is one whose space could not be built,
/// and the reason is appended to `notes`. That is different from a session with
/// no desktops, and the desktop survey keeps the two apart.
pub fn session_layers(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    survey: &SessionSurvey,
    cache: &Arc<TableCache>,
    config: &EnvironmentConfig,
    notes: &mut Vec<String>,
) -> SessionLayers {
    let mut out = SessionLayers::new();
    let Some(listing) = survey.listing() else {
        notes.push(
            "no session address space could be built because sessions could not be enumerated on \
             this build"
                .to_string(),
        );
        return out;
    };

    for session in listing.sessions.iter().take(config.max_sessions.max(1)) {
        let mut last: Option<String> = None;
        for member in &session.members {
            match process::process_address_space(profile, symbols, member.process, cache) {
                Ok(layer) => {
                    out.insert(session.id, layer);
                    last = None;
                    break;
                }
                Err(err) => last = Some(err.to_string()),
            }
        }
        if let Some(detail) = last {
            notes.push(format!(
                "no process in session {} has a usable address space, so anything living in that \
                 session's space could not be read: {detail}",
                session.id
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_console_session_name_is_told_apart_from_a_remote_one() {
        assert_eq!(
            SessionKind::from_session_name("Console"),
            SessionKind::Console
        );
        assert_eq!(
            SessionKind::from_session_name("console"),
            SessionKind::Console
        );
        assert_eq!(
            SessionKind::from_session_name("RDP-Tcp#3"),
            SessionKind::Remote("RDP-Tcp#3".into())
        );
        assert_eq!(
            SessionKind::from_session_name("rdp-tcp#12"),
            SessionKind::Remote("rdp-tcp#12".into())
        );
        assert_eq!(SessionKind::from_session_name(""), SessionKind::Unknown);
        assert_eq!(SessionKind::from_session_name("   "), SessionKind::Unknown);
        assert_eq!(
            SessionKind::from_session_name("Services"),
            SessionKind::Other("Services".into())
        );
    }

    /// A short `SESSIONNAME` must not be indexed past its end.
    #[test]
    fn a_session_name_shorter_than_the_rdp_prefix_does_not_panic() {
        assert_eq!(
            SessionKind::from_session_name("RDP"),
            SessionKind::Other("RDP".into())
        );
        assert_eq!(
            SessionKind::from_session_name("R"),
            SessionKind::Other("R".into())
        );
    }

    /// An unsupported session survey is never complete, and it says why. A
    /// report must not write "one logon session" from a part that could not run.
    #[test]
    fn an_unsupported_session_survey_is_incomplete_and_names_what_is_missing() {
        let survey = SessionSurvey::Unsupported {
            detail: "the symbol table has neither '_MM_SESSION_SPACE' nor '_PSP_SESSION_SPACE'"
                .into(),
        };
        assert!(!survey.is_complete());
        assert!(survey.listing().is_none());
        let incomplete = survey.incomplete();
        assert_eq!(incomplete.len(), 1);
        assert!(incomplete[0].detail.contains("_PSP_SESSION_SPACE"));
        assert_eq!(survey.to_json()["supported"], serde_json::json!(false));
    }

    /// A survey that ran but could not cross-check is not complete either: it
    /// cannot rule out a process unlinked from the active list.
    #[test]
    fn a_survey_without_the_session_process_list_cannot_claim_completeness() {
        let survey = SessionSurvey::Surveyed(SessionListing {
            sessions: vec![Session {
                id: 1,
                space: 0x2000,
                members: Vec::new(),
                users: Vec::new(),
                session_names: Vec::new(),
                kind: SessionKind::Unknown,
                plausible_id: true,
                cross_checked: false,
                capped: false,
                notes: Vec::new(),
            }],
            without_session: Vec::new(),
            unreadable: Vec::new(),
            capped: false,
            cross_checked: false,
            notes: Vec::new(),
        });
        assert!(!survey.is_complete());
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("unlinked")));
    }

    /// A process only the session knows about is the finding this cross-check
    /// exists for, and it has to be visible on the session.
    #[test]
    fn a_process_only_the_session_list_holds_is_reported_as_unlinked() {
        let session = Session {
            id: 1,
            space: 0x2000,
            members: vec![
                SessionMember {
                    process: 0x3000,
                    pid: Some(400),
                    image_file_name: Some("explorer.exe".into()),
                    started: None,
                    user: None,
                    session_name: None,
                    source: MemberSource::Both,
                },
                SessionMember {
                    process: 0x4000,
                    pid: Some(666),
                    image_file_name: Some("evil.exe".into()),
                    started: None,
                    user: None,
                    session_name: None,
                    source: MemberSource::SessionProcessList,
                },
            ],
            users: Vec::new(),
            session_names: Vec::new(),
            kind: SessionKind::Unknown,
            plausible_id: true,
            cross_checked: true,
            capped: false,
            notes: Vec::new(),
        };
        let unlinked = session.unlinked();
        assert_eq!(unlinked.len(), 1);
        assert_eq!(unlinked[0].pid, Some(666));
        assert_eq!(session.to_json()["unlinked_count"], serde_json::json!(1));
    }

    /// Distinct values accumulate; repeats and blanks do not.
    #[test]
    fn distinct_values_accumulate_without_repeats_or_blanks() {
        let mut into = Vec::new();
        record_distinct(&mut into, Some("CORP\\sarah"));
        record_distinct(&mut into, Some("CORP\\sarah"));
        record_distinct(&mut into, Some(""));
        record_distinct(&mut into, None);
        record_distinct(&mut into, Some("CORP\\admin"));
        assert_eq!(into, vec!["CORP\\sarah", "CORP\\admin"]);
    }
}
