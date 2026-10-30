//! Window stations and desktops: where a process could draw, and who could see
//! it.
//!
//! A window station (`tagWINDOWSTATION`) owns a clipboard, an atom table and a
//! list of desktops. A desktop (`tagDESKTOP`) owns the windows drawn on it, and
//! a thread is attached to exactly one desktop at a time: it can create windows
//! only there, and it can see windows only there. The interactive station is
//! `WinSta0`, and its desktops are `Default` (what somebody sitting at the
//! machine is looking at), `Winlogon` (the secure desktop, where the
//! Ctrl-Alt-Del screen and UAC prompts live) and `Screen-saver`.
//!
//! Creating a desktop of your own and running there is a complete way to be
//! invisible without hiding anything: `CreateDesktop`, `SetThreadDesktop`, and
//! the process's windows exist, respond and are drawn — on a desktop nobody is
//! switched to. Everything else about the process looks ordinary. The only
//! place the second desktop shows up is here.
//!
//! # Why this usually reports itself unsupported, and why that is right
//!
//! `tagWINDOWSTATION` and `tagDESKTOP` belong to `win32k.sys`, not to the
//! kernel, and they are **not in `ntoskrnl.pdb`**. Upstream Volatility ships
//! hand-written symbol files for them, one per Windows build, and refuses to
//! run on a build it has no file for. This crate resolves every offset from the
//! symbol table it was given, so on an image profiled from the kernel PDB alone
//! the survey returns [`DesktopSurvey::Unsupported`], naming the two types.
//!
//! That is deliberately not the same value as a survey that ran and found only
//! `WinSta0\Default`. Guessing win32k offsets from a build number is how a
//! desktop gets reported at the wrong address, with the wrong name, owned by
//! the wrong process — and a *wrong* answer about a hidden desktop is worse
//! than no answer, because an examiner would act on it.
//!
//! # Session space
//!
//! When the symbols do describe these types, the walk still cannot be done in
//! the system process's address space. `tagWINDOWSTATION` lives in *session*
//! space, which is mapped per session: the same virtual address holds session
//! 1's window station in one session's page tables and something unrelated, or
//! nothing, in another's. Stations are located by their `Wind` pool tag through
//! the shared pool sweep — which reads their bytes wherever the sweep ran — and
//! every pointer out of them is then followed through the address space of the
//! session the station's own `dwSessionId` names.
//!
//! # One place this deliberately differs from upstream
//!
//! Upstream's `tagWINDOWSTATION.desktops()` re-reads `rpdeskList` on every
//! iteration of its loop, so its cycle check fires immediately and it yields
//! exactly one desktop per station — the first. A station with a hidden second
//! desktop is exactly the case that behaviour loses. Here `rpdeskList` gives
//! the first desktop and `rpdeskNext` gives the rest, bounded by
//! [`MAX_DESKTOPS_PER_STATION`] and a visited set.

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{ListSpec, ListStop, ObjError, StructReader};
use seance_memory::{Incomplete, MemoryLayer};

use crate::environment::{
    first_member, EnvironmentConfig, EnvironmentSymbols, SessionLayers, Supported,
};
use crate::handles::name::{generic_name, HandleName, NameSymbols};
use crate::poolscan::{
    image_file_name, pool_scan, render_tag, ObjectTypeMap, PoolConstraint, PoolSymbols, PoolTypes,
    ScanSpace,
};
use crate::process;
use crate::profile::WindowsProfile;

/// One candidate lookup, with the two ways there is no answer kept apart.
///
/// `Ok(None)` is this build declaring no such member — a fact about the machine
/// the image came from, and the caller says what that costs. `Err` is the symbol
/// table failing to answer, which is damage to the evidence about layout and
/// must not be reported as the first.
fn declared(found: Result<Option<&str>, ObjError>) -> Result<Option<String>, String> {
    found.map(|path| path.map(str::to_string)).map_err(|err| {
        format!(
            "the symbol table could not be read, so this build's window-station layout is \
             unknown: {err}"
        )
    })
}

/// The window station structure.
pub const TYPE_WINDOW_STATION: &str = "tagWINDOWSTATION";

/// The desktop structure.
pub const TYPE_DESKTOP: &str = "tagDESKTOP";

/// The window structure. **Never read by this build** — see
/// [`WINDOWS_NOT_ENUMERATED`].
pub const TYPE_WINDOW: &str = "tagWND";

/// The per-thread win32k structure a desktop's thread list is made of.
pub const TYPE_THREAD_INFO: &str = "tagTHREADINFO";

/// The per-process win32k structure a thread reaches its `_EPROCESS` through.
pub const TYPE_PROCESS_INFO: &str = "tagPROCESSINFO";

/// The list-link structure a desktop's thread list is threaded through.
pub const TYPE_LIST_ENTRY: &str = "_LIST_ENTRY";

/// Why no desktop record here lists the windows drawn on it.
///
/// A desktop owns its windows through `tagDESKTOP.pDeskInfo->spwnd` and the
/// `tagWND` chain of siblings and children beneath it — which is how
/// upstream's `windows` plugin answers "which window belonged to which
/// process". `tagWND` is a win32k type like the two above and is not in the
/// kernel PDB either, so this build does not walk it; and it says so on every
/// desktop rather than leaving an absent window list to read as a desktop with
/// nothing drawn on it.
///
/// **Measured against upstream on this project's Windows 11 corpus**
/// (`test_data/win11_bitlocker/memory-unlocked.raw`, build 26200, 2026-09-15),
/// which is what makes the refusal a position rather than an excuse:
///
/// | upstream plugin | rows |
/// |---|---|
/// | `windows.windowstations.WindowStations` | 14 — of which **7** are names no
///   machine has (`諬q` three times, `靔©` twice, and two runs of pointer bytes
///   rendered as CJK), beside the seven real ones (`WinSta0` in sessions 0 and
///   1, `Service-0x0-3e4$`, `-3e5$`, `-3e7$`, `-322f2$`, `msswindowstation`) |
/// | `windows.desktops.Desktops` | **0** |
/// | `windows.windows.Windows` (tagWND) | **0** |
///
/// So on a current Windows build the alternative to this refusal is not an
/// answer: it is an empty table for desktops and windows, and a station list
/// half of which is noise a reader cannot tell from evidence. That measurement
/// is in `seance_memory/tests/KNOWN_ANSWERS.md`.
pub const WINDOWS_NOT_ENUMERATED: &str = concat!(
    "The windows drawn on this desktop were NOT enumerated, and this is not a desktop with no ",
    "windows on it. A desktop's windows hang off `tagDESKTOP.pDeskInfo->spwnd` as a `tagWND` ",
    "chain; `tagWND` belongs to win32k.sys and is not in the kernel PDB, so this build has no ",
    "layout for it and does not guess one from the build number -- a window reported at a wrong ",
    "address, with a wrong title, owned by the wrong process, is worse than no window. Reading ",
    "them would need a symbol table describing tagWND for this exact build."
);

/// The pool tag `win32k` allocates a window station under.
pub const TAG_WINDOW_STATION: [u8; 4] = *b"Wind";

/// The object-manager type name a window station's object header carries.
pub const OBJECT_TYPE_WINDOW_STATION: &str = "WindowStation";

/// Ceiling on window stations followed.
///
/// A machine has one interactive station and a handful of service ones.
/// Reaching this means the `rpwinstaNext` chain is not a chain.
pub const MAX_WINDOW_STATIONS: usize = 64;

/// Ceiling on desktops followed per window station.
pub const MAX_DESKTOPS_PER_STATION: usize = 64;

/// Ceiling on threads listed per desktop.
pub const MAX_DESKTOP_THREADS: usize = 65_536;

/// The desktops Windows creates for itself on the interactive station.
///
/// A desktop whose name is not one of these is not by itself a finding — an
/// application may create one legitimately — but it is the set an examiner
/// wants marked, because a desktop nobody switches to is where a process runs
/// to be unseen.
pub const STANDARD_DESKTOP_NAMES: [&str; 4] = ["Default", "Winlogon", "Disconnect", "Screen-saver"];

/// Whether a desktop name is one Windows creates for itself.
pub fn is_standard_desktop_name(name: &str) -> bool {
    STANDARD_DESKTOP_NAMES
        .iter()
        .any(|known| known.eq_ignore_ascii_case(name))
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// The member paths a window-station walk is read through.
///
/// Every one of these comes from the symbol table. None of them has a fallback
/// constant, because there is no build-independent layout for a win32k
/// structure to fall back to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuiSymbols {
    /// Path to the session id inside `tagWINDOWSTATION`.
    pub session_id: String,
    /// Path to the station's first desktop.
    pub desktop_list: String,
    /// Path to the next station in the session's chain, where the build has one.
    pub next_station: Option<String>,
    /// Path to the next desktop on a station, where the build has one.
    pub next_desktop: Option<String>,
    /// Path from a desktop back to its station, used to check that a desktop
    /// really belongs where it was found.
    pub desktop_station: Option<String>,
    /// Path to the desktop's thread list.
    pub thread_list: Option<String>,
    /// Path to the link that threads a `tagTHREADINFO` onto it.
    pub thread_link: Option<String>,
    /// Path from a `tagTHREADINFO` to its `tagPROCESSINFO`.
    pub thread_process_info: Option<String>,
    /// Path from a `tagPROCESSINFO` to its `_EPROCESS`.
    pub process_info_process: Option<String>,
    /// Declared size of `tagWINDOWSTATION`, used as the smallest believable
    /// allocation for the pool sweep.
    pub station_size: u64,
}

impl GuiSymbols {
    /// Resolve the win32k layout, or say exactly what is missing.
    ///
    /// Not a `Result`: a symbol table without win32k types is the ordinary
    /// case, not an error, and the rest of the survey still runs. The
    /// [`Supported::No`] string names the types an examiner would need symbols
    /// for.
    pub fn from_profile(profile: &WindowsProfile) -> Supported<Self> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        let mut missing: Vec<&str> = Vec::new();
        if !profile.symbols.has_type(TYPE_WINDOW_STATION) {
            missing.push(TYPE_WINDOW_STATION);
        }
        if !profile.symbols.has_type(TYPE_DESKTOP) {
            missing.push(TYPE_DESKTOP);
        }
        if !missing.is_empty() {
            return Supported::No(format!(
                "the symbol table does not describe {}, which belong to win32k.sys and are not in \
                 the kernel PDB, so window stations and desktops cannot be walked; their offsets \
                 are not guessed from the build number because a desktop reported at a wrong \
                 address, with a wrong name and a wrong owning process is worse than no answer",
                missing.join(" or ")
            ));
        }

        let session_id =
            match declared(first_member(&reader, TYPE_WINDOW_STATION, &["dwSessionId"])) {
                Ok(Some(path)) => path,
                Ok(None) => {
                    return Supported::No(format!(
                    "'{TYPE_WINDOW_STATION}' has no dwSessionId, so a station cannot be placed in \
                     the session whose address space its pointers are only meaningful in"
                ))
                }
                Err(reason) => return Supported::No(reason),
            };
        let desktop_list =
            match declared(first_member(&reader, TYPE_WINDOW_STATION, &["rpdeskList"])) {
                Ok(Some(path)) => path,
                Ok(None) => {
                    return Supported::No(format!(
                    "'{TYPE_WINDOW_STATION}' has no rpdeskList, so a station's desktops cannot be \
                     reached"
                ))
                }
                Err(reason) => return Supported::No(reason),
            };

        let station_size = match reader.size_of(TYPE_WINDOW_STATION) {
            Ok(size) => size.bytes(),
            Err(err) => {
                return Supported::No(format!(
                    "'{TYPE_WINDOW_STATION}' has no declared size, so a pool allocation cannot be \
                     checked against it: {err}"
                ))
            }
        };

        // A thread list needs three members to be usable end to end. Any one of
        // them missing leaves the desktops listed without their threads, which
        // is stated on each desktop rather than rendered as a desktop nobody
        // was attached to.
        let thread_list = match declared(first_member(&reader, TYPE_DESKTOP, &["PtiList"])) {
            Ok(value) => value,
            Err(reason) => return Supported::No(reason),
        };
        let thread_link = if profile.symbols.has_type(TYPE_THREAD_INFO) {
            match declared(first_member(&reader, TYPE_THREAD_INFO, &["PtiLink"])) {
                Ok(value) => value,
                Err(reason) => return Supported::No(reason),
            }
        } else {
            None
        };
        let (thread_list, thread_link) = match (thread_list, thread_link) {
            (Some(list), Some(link)) => (Some(list), Some(link)),
            _ => (None, None),
        };
        let thread_process_info = if profile.symbols.has_type(TYPE_THREAD_INFO) {
            match declared(first_member(&reader, TYPE_THREAD_INFO, &["ppi"])) {
                Ok(value) => value,
                Err(reason) => return Supported::No(reason),
            }
        } else {
            None
        };
        let process_info_process = if profile.symbols.has_type(TYPE_PROCESS_INFO) {
            match declared(first_member(&reader, TYPE_PROCESS_INFO, &["Process"])) {
                Ok(value) => value,
                Err(reason) => return Supported::No(reason),
            }
        } else {
            None
        };
        let next_station = match declared(first_member(
            &reader,
            TYPE_WINDOW_STATION,
            &["rpwinstaNext"],
        )) {
            Ok(value) => value,
            Err(reason) => return Supported::No(reason),
        };
        let next_desktop = match declared(first_member(&reader, TYPE_DESKTOP, &["rpdeskNext"])) {
            Ok(value) => value,
            Err(reason) => return Supported::No(reason),
        };
        let desktop_station =
            match declared(first_member(&reader, TYPE_DESKTOP, &["rpwinstaParent"])) {
                Ok(value) => value,
                Err(reason) => return Supported::No(reason),
            };

        Supported::Yes(Self {
            session_id,
            desktop_list,
            next_station,
            next_desktop,
            desktop_station,
            thread_list,
            thread_link,
            thread_process_info,
            process_info_process,
            station_size,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "session_id": self.session_id,
            "desktop_list": self.desktop_list,
            "next_station": self.next_station,
            "next_desktop": self.next_desktop,
            "desktop_station": self.desktop_station,
            "thread_list": self.thread_list,
            "thread_link": self.thread_link,
            "thread_process_info": self.thread_process_info,
            "process_info_process": self.process_info_process,
            "station_size": self.station_size,
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One thread attached to a desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopThread {
    /// Address of the `tagTHREADINFO`.
    pub thread_info: u64,
    /// Address of the owning `_EPROCESS`, when it was reachable.
    pub process: Option<u64>,
    /// The owning process's id.
    pub pid: Option<u64>,
    /// The owning process's image name.
    pub image_file_name: Option<String>,
    /// Why the owning process could not be named, when it could not.
    pub detail: Option<String>,
}

impl DesktopThread {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "thread_info": self.thread_info,
            "process": self.process,
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "detail": self.detail,
        })
    }
}

/// One desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Desktop {
    /// Address of the `tagDESKTOP`, in the session's address space.
    pub address: u64,
    /// The desktop's name, or why it could not be read.
    pub name: HandleName,
    /// The threads attached to it.
    pub threads: Vec<DesktopThread>,
    /// Whether the thread list was walked end to end.
    pub thread_list_walked: bool,
    /// Whether the thread cap fired.
    pub threads_capped: bool,
    /// Everything odd about the desktop that did not stop it being reported.
    pub notes: Vec<String>,
}

impl Desktop {
    /// Whether the name is one Windows creates for itself.
    ///
    /// `None` when the name could not be read, which must not render as
    /// "non-standard": an unnamed desktop is a gap in the evidence, and a
    /// non-standard one is a lead.
    pub fn standard_name(&self) -> Option<bool> {
        self.name.text().map(is_standard_desktop_name)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "name": self.name.to_json(),
            "standard_name": self.standard_name(),
            "threads": self.threads.iter().map(DesktopThread::to_json).collect::<Vec<_>>(),
            "thread_count": self.threads.len(),
            "thread_list_walked": self.thread_list_walked,
            "threads_capped": self.threads_capped,
            // Stated on every desktop, because an absent window list would
            // otherwise read as a desktop with nothing drawn on it.
            "windows_enumerated": false,
            "windows_not_enumerated_reason": WINDOWS_NOT_ENUMERATED,
            "notes": self.notes,
        })
    }
}

/// One window station and its desktops.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowStation {
    /// Address of the `tagWINDOWSTATION`, in whichever space it was read from.
    pub address: u64,
    /// The station's name, or why it could not be read.
    pub name: HandleName,
    /// The session it belongs to, when `dwSessionId` was readable.
    pub session_id: Option<u64>,
    /// Whether that id is inside [`crate::environment::MAX_PLAUSIBLE_SESSION_ID`].
    pub plausible_session: bool,
    /// Which address space this station's pointers were followed through:
    /// `"session"` when the session's own space was available, `"kernel"` when
    /// it was not and the system process's space had to be used instead.
    pub space: &'static str,
    /// The desktops.
    pub desktops: Vec<Desktop>,
    /// Whether the desktop chain stopped before it ended: the cap fired, the
    /// build declares no `rpdeskNext` to follow, or a link could not be read.
    ///
    /// All three mean the same thing to a report — [`WindowStation::desktops`]
    /// is a floor and not a total — and a hidden desktop is precisely what
    /// would be sitting past the break, so none of them may render as a
    /// finished list.
    pub desktops_capped: bool,
    /// Everything odd about the station that did not stop it being reported.
    pub notes: Vec<String>,
}

impl WindowStation {
    /// The desktops whose name is not one Windows creates for itself.
    ///
    /// The lead this stage exists to produce: a process attached to one of
    /// these is drawing where nobody is looking.
    pub fn nonstandard_desktops(&self) -> Vec<&Desktop> {
        self.desktops
            .iter()
            .filter(|desktop| desktop.standard_name() == Some(false))
            .collect()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "name": self.name.to_json(),
            "session_id": self.session_id,
            "plausible_session": self.plausible_session,
            "space": self.space,
            "desktops": self.desktops.iter().map(Desktop::to_json).collect::<Vec<_>>(),
            "desktop_count": self.desktops.len(),
            "nonstandard_desktop_count": self.nonstandard_desktops().len(),
            "desktops_capped": self.desktops_capped,
            "notes": self.notes,
        })
    }
}

/// A window station that was found and could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnreadableStation {
    /// Where the allocation was.
    pub address: u64,
    /// Why it could not be read.
    pub detail: String,
}

impl UnreadableStation {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({"address": self.address, "detail": self.detail})
    }
}

/// Everything the desktop walk found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopListing {
    /// The stations, in the order the sweep found them.
    pub stations: Vec<WindowStation>,
    /// Stations that could not be read.
    pub unreadable: Vec<UnreadableStation>,
    /// How many allocations carried the tag.
    pub candidates: usize,
    /// Which address space the sweep ran in.
    pub space: &'static str,
    /// Whether the sweep covered every mapped byte and returned every object.
    pub scan_complete: bool,
    /// Whether the station cap fired.
    pub capped: bool,
    /// Everything odd that did not stop the walk.
    pub notes: Vec<String>,
}

/// The window stations and desktops, or why they could not be walked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DesktopSurvey {
    /// The caller asked for no desktop survey.
    ///
    /// Distinct from a survey that ran and found nothing: nobody looked.
    NotRequested,
    /// This build's symbols do not describe the win32k structures, so no claim
    /// about desktops can be made at all.
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },
    /// The walk ran.
    Surveyed(DesktopListing),
}

impl DesktopSurvey {
    /// The listing, when the walk ran.
    pub fn listing(&self) -> Option<&DesktopListing> {
        match self {
            DesktopSurvey::Surveyed(listing) => Some(listing),
            _ => None,
        }
    }

    /// Whether every station and desktop was enumerated.
    ///
    /// Never true for [`DesktopSurvey::NotRequested`] or
    /// [`DesktopSurvey::Unsupported`]: a report must not write "there were no
    /// hidden desktops" on the strength of a walk that did not happen.
    pub fn is_complete(&self) -> bool {
        match self {
            DesktopSurvey::NotRequested | DesktopSurvey::Unsupported { .. } => false,
            DesktopSurvey::Surveyed(listing) => {
                listing.scan_complete
                    && !listing.capped
                    && listing.unreadable.is_empty()
                    && listing.stations.iter().all(|station| {
                        !station.desktops_capped
                            && station.desktops.iter().all(|desktop| {
                                desktop.thread_list_walked && !desktop.threads_capped
                            })
                    })
            }
        }
    }

    /// Every non-standard desktop across every station.
    pub fn nonstandard_desktops(&self) -> Vec<(&WindowStation, &Desktop)> {
        let Some(listing) = self.listing() else {
            return Vec::new();
        };
        listing
            .stations
            .iter()
            .flat_map(|station| {
                station
                    .nonstandard_desktops()
                    .into_iter()
                    .map(move |desktop| (station, desktop))
            })
            .collect()
    }

    /// Everything a report must declare about this survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let listing = match self {
            DesktopSurvey::NotRequested => {
                return vec![Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    "window stations and desktops were not surveyed, so nothing here rules out a \
                     process running on a desktop nobody was switched to"
                        .to_string(),
                )]
            }
            DesktopSurvey::Unsupported { detail } => {
                return vec![Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "window stations and desktops could not be walked, so nothing here rules \
                         out a process running on a desktop nobody was switched to: {detail}"
                    ),
                )]
            }
            DesktopSurvey::Surveyed(listing) => listing,
        };

        let mut out = Vec::new();
        if !listing.scan_complete {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the sweep of the {} address space for window stations did not cover every \
                     mapped byte, so a station in the part it missed is not listed",
                    listing.space
                ),
            ));
        }
        if listing.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the walk stopped at its cap of {} window station(s)",
                    listing.stations.len()
                ),
            ));
        }
        for entry in &listing.unreadable {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "the window station at {:#x} could not be read, so its desktops are unknown \
                     rather than absent: {}",
                    entry.address, entry.detail
                ),
            ));
        }
        for station in &listing.stations {
            if station.desktops_capped {
                out.push(Incomplete::new(
                    IncompleteReason::CapReached,
                    format!(
                        "the desktop chain of the window station at {:#x} was not followed to its \
                         end, so the {} desktop(s) listed are a floor rather than all of them",
                        station.address,
                        station.desktops.len()
                    ),
                ));
            }
            for desktop in &station.desktops {
                if !desktop.thread_list_walked {
                    out.push(Incomplete::new(
                        IncompleteReason::UnresolvedStructure,
                        format!(
                            "the threads attached to the desktop at {:#x} could not be listed, so \
                             which processes were drawing there is unknown rather than none",
                            desktop.address
                        ),
                    ));
                }
                if desktop.threads_capped {
                    out.push(Incomplete::new(
                        IncompleteReason::CapReached,
                        format!(
                            "the desktop at {:#x} stopped at its cap of {} thread(s)",
                            desktop.address,
                            desktop.threads.len()
                        ),
                    ));
                }
            }
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            DesktopSurvey::NotRequested => {
                serde_json::json!({"surveyed": false, "reason": "not_requested", "complete": false})
            }
            DesktopSurvey::Unsupported { detail } => serde_json::json!({
                "surveyed": false,
                "reason": "unsupported_build",
                "detail": detail,
                "windows_enumerated": false,
                "windows_not_enumerated_reason": WINDOWS_NOT_ENUMERATED,
                "complete": false,
            }),
            DesktopSurvey::Surveyed(listing) => serde_json::json!({
                "surveyed": true,
                "stations": listing
                    .stations
                    .iter()
                    .map(WindowStation::to_json)
                    .collect::<Vec<_>>(),
                "station_count": listing.stations.len(),
                "nonstandard_desktop_count": self.nonstandard_desktops().len(),
                "unreadable": listing
                    .unreadable
                    .iter()
                    .map(UnreadableStation::to_json)
                    .collect::<Vec<_>>(),
                "candidates": listing.candidates,
                "space": listing.space,
                "scan_complete": listing.scan_complete,
                "capped": listing.capped,
                "notes": listing.notes,
                // The survey's own boundary, stated where the reader is
                // already looking at what it did find.
                "windows_enumerated": false,
                "windows_not_enumerated_reason": WINDOWS_NOT_ENUMERATED,
                "complete": self.is_complete(),
            }),
        }
    }
}

// ── The walk ────────────────────────────────────────────────────────────────

/// Everything one desktop walk reads through, gathered so each step can be a
/// method rather than a function with nine parameters.
struct Walk<'a> {
    profile: &'a WindowsProfile,
    symbols: &'a EnvironmentSymbols,
    gui: &'a GuiSymbols,
    /// A reader whose bytes come from the space the pool sweep ran in.
    scanned: &'a StructReader,
    /// A reader over the kernel address space, for `_EPROCESS` structures,
    /// which are kernel-space whatever session reached them.
    kernel: &'a StructReader,
    /// How objects are named, when this build's object headers can be described.
    names: Option<&'a NameSymbols>,
    /// One address space per session.
    layers: &'a SessionLayers,
    config: &'a EnvironmentConfig,
    /// Which space the sweep ran in, which decides whether a swept object's
    /// header is at an address the kernel's name table can be indexed from.
    space: ScanSpace,
}

impl Walk<'_> {
    /// A reader over the address space of a named session, or over the kernel
    /// space when that session has none.
    ///
    /// The second value is what [`WindowStation::space`] records, because a
    /// station walked through the wrong space may resolve its pointers to
    /// unrelated bytes and an examiner has to be able to see which rows are in
    /// that position.
    fn session_reader(&self, session_id: Option<u64>) -> (StructReader, &'static str) {
        match session_id.and_then(|id| self.layers.get(&id)) {
            Some(layer) => (
                StructReader::new(Arc::clone(layer), Arc::clone(&self.profile.symbols)),
                "session",
            ),
            None => (
                StructReader::new(
                    Arc::clone(&self.profile.kernel_space),
                    Arc::clone(&self.profile.symbols),
                ),
                "kernel",
            ),
        }
    }

    /// Follow one swept station and the `rpwinstaNext` chain hanging off it.
    ///
    /// The first station's bytes are wherever the sweep found them. Every
    /// station after it was reached by a session-space pointer, so its bytes are
    /// read through the previous station's session space — which is why the
    /// reader is carried from one link of the chain to the next rather than
    /// rebuilt from the kernel space each time.
    fn station_chain(
        &self,
        first: u64,
        first_header: Option<u64>,
        seen: &mut HashSet<u64>,
        listing: &mut DesktopListing,
    ) {
        let mut address = first;
        let mut header = first_header;
        let mut from_sweep = true;
        let mut carried: Option<StructReader> = None;

        loop {
            if !seen.insert(address) {
                return;
            }
            if listing.stations.len() >= self.config.max_window_stations.max(1) {
                listing.capped = true;
                return;
            }

            // Owned rather than borrowed: cloning a reader is three `Arc`
            // bumps, and it keeps the reader for the next link of the chain
            // assignable at the bottom of this one.
            let bytes: StructReader = carried.clone().unwrap_or_else(|| self.scanned.clone());
            let object = match bytes.object(address, TYPE_WINDOW_STATION) {
                Ok(object) => object,
                Err(err) => {
                    listing.unreadable.push(UnreadableStation {
                        address,
                        detail: err.to_string(),
                    });
                    return;
                }
            };
            let session_id = match object.int(&self.gui.session_id) {
                Ok(value) => value.as_u64(),
                Err(err) => {
                    listing.unreadable.push(UnreadableStation {
                        address,
                        detail: format!("'{TYPE_WINDOW_STATION}.{}': {err}", self.gui.session_id),
                    });
                    return;
                }
            };

            let (session, space_label) = self.session_reader(session_id);
            let name = if from_sweep && self.space == ScanSpace::Physical {
                // The name is reached through a table the kernel holds at a
                // virtual address, and a physical sweep gives a physical
                // offset. Refusing beats indexing that table from the wrong
                // number, which yields a name.
                HandleName::Unavailable(
                    "the sweep ran in physical memory, so this station's object header is at a \
                     physical offset and the kernel's own name table cannot be indexed from it"
                        .to_string(),
                )
            } else {
                self.object_name(&session, header, address)
            };

            let mut station = WindowStation {
                address,
                name,
                session_id,
                plausible_session: session_id
                    .is_some_and(|id| id < crate::environment::MAX_PLAUSIBLE_SESSION_ID),
                space: space_label,
                desktops: Vec::new(),
                desktops_capped: false,
                notes: Vec::new(),
            };
            match session_id {
                None => station.notes.push(format!(
                    "'{TYPE_WINDOW_STATION}.{}' is negative, which is not a session id",
                    self.gui.session_id
                )),
                Some(id) if !station.plausible_session => station.notes.push(format!(
                    "this station names session {id}, which is past \
                     {} and so is smear rather than a session",
                    crate::environment::MAX_PLAUSIBLE_SESSION_ID
                )),
                Some(_) => {}
            }
            if space_label == "kernel" {
                station.notes.push(
                    "no address space was available for this station's session, so its pointers \
                     were followed through the system process's space and may resolve to \
                     unrelated bytes"
                        .to_string(),
                );
            }

            let first_desktop = match object.pointer(&self.gui.desktop_list) {
                Ok(first) => Some(first),
                Err(err) => {
                    station.notes.push(format!(
                        "'{TYPE_WINDOW_STATION}.{}' could not be read, so this station's desktops \
                         are unknown rather than absent: {err}",
                        self.gui.desktop_list
                    ));
                    None
                }
            };
            if let Some(first_desktop) = first_desktop {
                self.desktops(&session, first_desktop, &mut station);
            }

            // A link that could not be read is not the end of the chain, and
            // collapsing the two would end the walk with nothing said. The
            // stations after the break are still reachable through the sweep,
            // which is the primary enumeration, so this is a note rather than a
            // completeness flag — but it must be a note and not silence.
            let next = match self.gui.next_station.as_ref() {
                Some(path) => match object.pointer(path) {
                    Ok(next) => Some(next),
                    Err(err) => {
                        station.notes.push(format!(
                            "'{TYPE_WINDOW_STATION}.{path}' could not be read, so the chain was \
                             not followed past this station and any station after it appears only \
                             if the sweep found its allocation: {err}"
                        ));
                        None
                    }
                },
                None => {
                    station.notes.push(format!(
                        "'{TYPE_WINDOW_STATION}' has no rpwinstaNext on this build, so the \
                         station chain could not be followed and the stations listed are the ones \
                         the sweep found"
                    ));
                    None
                }
            };
            listing.stations.push(station);

            match next {
                None | Some(0) => return,
                Some(next) => {
                    address = next;
                    header = None;
                    from_sweep = false;
                    carried = Some(session);
                }
            }
        }
    }

    /// Walk one station's desktops, following `rpdeskList` and then
    /// `rpdeskNext`.
    ///
    /// Upstream re-reads `rpdeskList` on every iteration and so yields exactly
    /// one desktop per station. A station's *second* desktop is the whole
    /// finding, so the chain is followed properly here, bounded by
    /// [`MAX_DESKTOPS_PER_STATION`] and a visited set.
    fn desktops(&self, session: &StructReader, first: u64, station: &mut WindowStation) {
        let mut address = first;
        let mut visited: HashSet<u64> = HashSet::new();

        while address != 0 {
            if !visited.insert(address) {
                station.notes.push(format!(
                    "the desktop chain returns to {address:#x}, so it does not terminate and was \
                     not followed further"
                ));
                return;
            }
            if station.desktops.len() >= self.config.max_desktops_per_station.max(1) {
                station.desktops_capped = true;
                return;
            }

            let mut desktop = Desktop {
                address,
                name: self.object_name(session, None, address),
                threads: Vec::new(),
                thread_list_walked: false,
                threads_capped: false,
                notes: Vec::new(),
            };

            // A desktop that names a different parent was reached through a
            // pointer that is not what it claimed to be, and saying so beats
            // attributing its threads to this station.
            if let Some(path) = &self.gui.desktop_station {
                match session
                    .object(address, TYPE_DESKTOP)
                    .and_then(|object| object.pointer(path))
                {
                    Ok(parent) if parent != station.address => desktop.notes.push(format!(
                        "this desktop names the station at {parent:#x} as its parent, not the \
                         station at {:#x} it was reached from",
                        station.address
                    )),
                    Ok(_) => {}
                    Err(err) => desktop.notes.push(format!(
                        "'{TYPE_DESKTOP}.{path}' could not be read, so this desktop's own account \
                         of which station it belongs to is unknown: {err}"
                    )),
                }
            }

            self.desktop_threads(session, &mut desktop);

            let next = match &self.gui.next_desktop {
                // A read failure here is *not* the end of the chain. Treating it
                // as one ends the walk silently, and the desktop that would have
                // come next — the second desktop on a station, which is the
                // whole finding — never appears and nothing says it was missed.
                Some(path) => match session
                    .object(address, TYPE_DESKTOP)
                    .and_then(|object| object.pointer(path))
                {
                    Ok(next) => next,
                    Err(err) => {
                        desktop.notes.push(format!(
                            "'{TYPE_DESKTOP}.{path}' at {address:#x} could not be read, so any \
                             desktop after this one on the station is unknown rather than absent: \
                             {err}"
                        ));
                        station.desktops_capped = true;
                        0
                    }
                },
                None => {
                    desktop.notes.push(format!(
                        "'{TYPE_DESKTOP}' has no rpdeskNext on this build, so only this station's \
                         first desktop could be reached and a second one would not be listed"
                    ));
                    station.desktops_capped = true;
                    0
                }
            };
            station.desktops.push(desktop);
            address = next;
        }
    }

    /// List the threads attached to one desktop and the processes owning them.
    fn desktop_threads(&self, session: &StructReader, desktop: &mut Desktop) {
        let (Some(list_member), Some(link_member)) = (&self.gui.thread_list, &self.gui.thread_link)
        else {
            desktop.notes.push(format!(
                "'{TYPE_DESKTOP}.PtiList' or '{TYPE_THREAD_INFO}.PtiLink' is not described by this \
                 build's symbols, so which threads were attached here is unknown rather than none"
            ));
            return;
        };

        let head = match session
            .object(desktop.address, TYPE_DESKTOP)
            .and_then(|object| object.member_address(list_member))
        {
            Ok(head) => head,
            Err(err) => {
                desktop.notes.push(format!(
                    "'{TYPE_DESKTOP}.{list_member}' could not be located, so which threads were \
                     attached here is unknown rather than none: {err}"
                ));
                return;
            }
        };

        let spec = ListSpec::new(TYPE_LIST_ENTRY, "Flink")
            .in_container(TYPE_THREAD_INFO, link_member)
            .with_max_entries(self.config.max_desktop_threads.max(1));
        let walk = match session.walk_list(head, &spec) {
            Ok(walk) => walk,
            Err(err) => {
                desktop.notes.push(format!(
                    "the thread list at {head:#x} could not be walked: {err}"
                ));
                return;
            }
        };
        let (found, stop) = walk.walk_to_end();
        desktop.thread_list_walked = stop == ListStop::Wrapped;
        if !desktop.thread_list_walked {
            desktop.notes.push(format!(
                "the thread list at {head:#x} did not close, so a thread on the far side of the \
                 break is not listed: {}",
                stop.as_str()
            ));
        }

        for object in found {
            if desktop.threads.len() >= self.config.max_desktop_threads.max(1) {
                desktop.threads_capped = true;
                return;
            }
            desktop
                .threads
                .push(self.owning_process(session, object.address()));
        }
    }

    /// Follow one `tagTHREADINFO` to the process that owns it.
    ///
    /// Every step is optional on some build, and a step that cannot be taken
    /// leaves [`DesktopThread::detail`] saying which — a thread whose owner is
    /// unknown must not render like a thread owned by nothing.
    fn owning_process(&self, session: &StructReader, thread_info: u64) -> DesktopThread {
        let mut out = DesktopThread {
            thread_info,
            process: None,
            pid: None,
            image_file_name: None,
            detail: None,
        };

        let (Some(ppi), Some(process_member)) = (
            &self.gui.thread_process_info,
            &self.gui.process_info_process,
        ) else {
            out.detail = Some(format!(
                "'{TYPE_THREAD_INFO}.ppi' or '{TYPE_PROCESS_INFO}.Process' is not described by \
                 this build's symbols, so the process this thread belongs to cannot be named"
            ));
            return out;
        };

        let info = match session
            .object(thread_info, TYPE_THREAD_INFO)
            .and_then(|object| object.pointer(ppi))
        {
            Ok(0) => {
                out.detail = Some(format!("'{TYPE_THREAD_INFO}.{ppi}' is null"));
                return out;
            }
            Ok(info) => info,
            Err(err) => {
                out.detail = Some(format!("'{TYPE_THREAD_INFO}.{ppi}': {err}"));
                return out;
            }
        };
        let process = match session
            .object(info, TYPE_PROCESS_INFO)
            .and_then(|object| object.pointer(process_member))
        {
            Ok(0) => {
                out.detail = Some(format!("'{TYPE_PROCESS_INFO}.{process_member}' is null"));
                return out;
            }
            Ok(process) => process,
            Err(err) => {
                out.detail = Some(format!("'{TYPE_PROCESS_INFO}.{process_member}': {err}"));
                return out;
            }
        };
        out.process = Some(process);

        // An `_EPROCESS` is kernel-space whatever session reached it.
        match self
            .kernel
            .object(process, crate::environment::TYPE_EPROCESS)
        {
            Ok(object) => {
                out.pid = object
                    .int(&self.symbols.process.unique_process_id)
                    .ok()
                    .and_then(|value| value.as_u64());
                out.image_file_name = object
                    .bytes(process::MEMBER_IMAGE_FILE_NAME)
                    .ok()
                    .map(|raw| image_file_name(&raw));
                if out.pid.is_none() && out.image_file_name.is_none() {
                    out.detail = Some(format!(
                        "neither the id nor the image name of the process at {process:#x} could \
                         be read, so this thread's owner is unknown"
                    ));
                }
            }
            Err(err) => {
                out.detail = Some(format!(
                    "the process at {process:#x} could not be read: {err}"
                ));
            }
        }
        out
    }

    /// The name an object's `_OBJECT_HEADER_NAME_INFO` carries.
    ///
    /// `header` is the object header's address when it is already known — the
    /// pool sweep reports one — and `None` when it has to be derived by
    /// stepping back from the object by the symbol-declared distance from an
    /// `_OBJECT_HEADER` to its body.
    ///
    /// The reader must be one whose space maps both the object and the kernel,
    /// because the name is reached through an index into a table the kernel
    /// holds. A session address space maps both; the kernel space alone does
    /// not map session space.
    fn object_name(&self, reader: &StructReader, header: Option<u64>, address: u64) -> HandleName {
        let Some(names) = self.names else {
            return HandleName::Unavailable(
                "this build's object headers cannot be described, so no object can be named"
                    .to_string(),
            );
        };
        let header = match header {
            Some(header) => header,
            None => match address.checked_sub(names.body_offset) {
                Some(header) => header,
                None => {
                    return HandleName::Unavailable(format!(
                        "the object header of {address:#x} would lie below the bottom of the \
                         address space"
                    ))
                }
            },
        };
        generic_name(reader, names, header)
    }
}

/// Find every window station and walk its desktops.
///
/// `layers` maps a session id to that session's address space, as built by
/// [`crate::environment::sessions::session_layers`]. A station whose session
/// has no entry there is still reported, with its pointers followed through the
/// kernel space and [`WindowStation::space`] saying so: a station found in the
/// wrong space, and flagged, is better evidence than a station silently dropped.
///
/// Never returns an error. Every way of not producing a listing is a
/// [`DesktopSurvey`] variant, so a caller cannot render "this build has no
/// win32k symbols" as "this machine had no hidden desktops".
pub fn survey_desktops(
    profile: &WindowsProfile,
    symbols: &EnvironmentSymbols,
    layers: &SessionLayers,
    config: &EnvironmentConfig,
) -> DesktopSurvey {
    let gui = match &symbols.gui {
        Supported::Yes(gui) => gui,
        Supported::No(detail) => {
            return DesktopSurvey::Unsupported {
                detail: detail.clone(),
            }
        }
    };

    let pool = match PoolSymbols::from_profile(profile) {
        Ok(pool) => pool,
        Err(err) => {
            return DesktopSurvey::Unsupported {
                detail: format!(
                    "the pool layout could not be established, so allocations tagged {} cannot be \
                     found: {err}",
                    render_tag(&TAG_WINDOW_STATION)
                ),
            }
        }
    };

    let constraint = PoolConstraint::new(TAG_WINDOW_STATION, TYPE_WINDOW_STATION)
        .executive(OBJECT_TYPE_WINDOW_STATION)
        .page_type(PoolTypes::any())
        // From the symbol table, never written down: the smallest believable
        // allocation is the structure's own declared size.
        .min_size(gui.station_size);

    // The object-manager type test is what rejects the several plausible-looking
    // object-header positions inside one allocation. Without it every one of
    // them becomes a "window station", so a survey that could not build the map
    // says so rather than publishing them.
    let mut pool_config = config.pool.clone();
    let mut notes: Vec<String> = Vec::new();
    if pool_config.type_map.is_none() {
        match ObjectTypeMap::from_profile(profile) {
            Ok(map) => pool_config.type_map = Some(Arc::new(map)),
            Err(err) => notes.push(format!(
                "the object-manager type table could not be read, so no candidate's type was \
                 verified against {OBJECT_TYPE_WINDOW_STATION}: {err}"
            )),
        }
    }

    let outcome = match pool_scan(
        profile,
        &pool,
        std::slice::from_ref(&constraint),
        &pool_config,
    ) {
        Ok(outcome) => outcome,
        Err(err) => {
            return DesktopSurvey::Unsupported {
                detail: format!("the sweep for window stations could not run: {err}"),
            }
        }
    };

    // The station's own bytes come from whichever space the sweep ran in; every
    // pointer inside it is a session-space virtual address, resolved separately
    // below. Getting these two the wrong way round does not fail — it reads
    // unrelated bytes, and they parse.
    let swept: Arc<dyn MemoryLayer> = match pool.space {
        ScanSpace::Physical => Arc::clone(&profile.physical),
        ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
    };
    let scanned = StructReader::with_native(
        swept,
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    let names = match NameSymbols::from_profile(profile) {
        Ok(names) => Some(names),
        Err(err) => {
            notes.push(format!(
                "object names cannot be resolved on this build, so no window station or desktop \
                 is named: {err}"
            ));
            None
        }
    };

    let mut listing = DesktopListing {
        stations: Vec::new(),
        unreadable: Vec::new(),
        candidates: outcome.objects.len(),
        space: pool.space.as_str(),
        scan_complete: outcome.is_complete(),
        capped: false,
        notes,
    };

    let walk = Walk {
        profile,
        symbols,
        gui,
        scanned: &scanned,
        kernel: &kernel,
        names: names.as_ref(),
        layers,
        config,
        space: pool.space,
    };

    let mut seen: HashSet<u64> = HashSet::new();
    for object in outcome.of_type(TYPE_WINDOW_STATION) {
        if listing.stations.len() >= config.max_window_stations.max(1) {
            listing.capped = true;
            break;
        }
        walk.station_chain(
            object.address,
            object.object_header,
            &mut seen,
            &mut listing,
        );
    }

    DesktopSurvey::Surveyed(listing)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ordinary case on a kernel-only symbol table, and the one that must
    /// never render as "no hidden desktops".
    #[test]
    fn an_unsupported_survey_is_incomplete_and_names_both_win32k_types() {
        let survey = DesktopSurvey::Unsupported {
            detail: "the symbol table does not describe tagWINDOWSTATION or tagDESKTOP".into(),
        };
        assert!(!survey.is_complete());
        assert!(survey.listing().is_none());
        assert!(survey.nonstandard_desktops().is_empty());
        let incomplete = survey.incomplete();
        assert_eq!(incomplete.len(), 1);
        assert!(incomplete[0].detail.contains("tagWINDOWSTATION"));
        assert_eq!(survey.to_json()["surveyed"], serde_json::json!(false));
        assert_eq!(survey.to_json()["complete"], serde_json::json!(false));
    }

    /// **The windows on a desktop are not enumerated, and every record says
    /// so.** A desktop with an absent window list would otherwise read as a
    /// desktop with nothing drawn on it, which is the one reading this stage
    /// exists to prevent — a process drawing on a desktop nobody is switched
    /// to is exactly what it is for.
    ///
    /// The refusal is a position rather than an excuse because it was
    /// measured: on this project's Windows 11 corpus (build 26200), upstream's
    /// `windows.windows.Windows` returns **no rows at all**, its
    /// `windows.desktops.Desktops` returns none either, and its
    /// `windows.windowstations.WindowStations` returns fourteen of which seven
    /// are names no machine has. See `WINDOWS_NOT_ENUMERATED` and
    /// `seance_memory/tests/KNOWN_ANSWERS.md`.
    #[test]
    fn no_record_lets_an_unenumerated_window_list_read_as_a_desktop_with_no_windows() {
        // On the survey, where a reader is looking at what it did find.
        let surveyed = DesktopSurvey::Surveyed(DesktopListing {
            stations: Vec::new(),
            unreadable: Vec::new(),
            candidates: 0,
            space: "session",
            scan_complete: true,
            capped: false,
            notes: Vec::new(),
        });
        let json = surveyed.to_json();
        assert_eq!(json["windows_enumerated"], serde_json::json!(false));
        let reason = json["windows_not_enumerated_reason"]
            .as_str()
            .expect("a reason");
        assert!(reason.contains("NOT enumerated"), "{reason}");
        assert!(
            reason.contains("not a desktop with no windows on it"),
            "{reason}"
        );
        assert!(reason.contains("tagWND"), "{reason}");
        assert!(reason.contains("does not guess"), "{reason}");

        // And on the unsupported arm, which is the ordinary case.
        let unsupported = DesktopSurvey::Unsupported {
            detail: "no win32k types".into(),
        };
        assert_eq!(
            unsupported.to_json()["windows_enumerated"],
            serde_json::json!(false)
        );
        assert!(unsupported.to_json()["windows_not_enumerated_reason"]
            .as_str()
            .is_some_and(|r| r.contains("tagWND")));

        // And on each desktop, which is the row an examiner reads.
        let desktop = Desktop {
            address: 0xffff_8000_0000_0000,
            name: HandleName::Name("Default".into()),
            threads: Vec::new(),
            thread_list_walked: true,
            threads_capped: false,
            notes: Vec::new(),
        };
        let json = desktop.to_json();
        assert_eq!(json["windows_enumerated"], serde_json::json!(false));
        assert!(json["windows_not_enumerated_reason"]
            .as_str()
            .is_some_and(|r| r.contains("tagWND")));
        // The thread list IS walked, and that stays a separate statement: the
        // threads attached to a desktop are read, the windows on it are not.
        assert_eq!(json["thread_list_walked"], serde_json::json!(true));
    }

    /// Declining to survey is a third thing, and it must not read like either
    /// of the other two.
    #[test]
    fn a_survey_nobody_asked_for_is_told_apart_from_one_that_could_not_run() {
        let skipped = DesktopSurvey::NotRequested;
        assert!(!skipped.is_complete());
        assert_eq!(
            skipped.to_json()["reason"],
            serde_json::json!("not_requested")
        );
        let unsupported = DesktopSurvey::Unsupported {
            detail: "no win32k symbols".into(),
        };
        assert_eq!(
            unsupported.to_json()["reason"],
            serde_json::json!("unsupported_build")
        );
    }

    /// The standard desktop names are matched without regard to case, and
    /// nothing else is standard.
    #[test]
    fn only_the_desktops_windows_creates_are_standard() {
        assert!(is_standard_desktop_name("Default"));
        assert!(is_standard_desktop_name("default"));
        assert!(is_standard_desktop_name("Winlogon"));
        assert!(is_standard_desktop_name("Screen-saver"));
        assert!(!is_standard_desktop_name("hidden"));
        assert!(!is_standard_desktop_name(""));
    }

    /// A desktop whose name could not be read is unknown, not non-standard: the
    /// lead this stage produces must not be manufactured out of a failed read.
    #[test]
    fn a_desktop_with_an_unreadable_name_is_not_reported_as_nonstandard() {
        let unreadable = Desktop {
            address: 0x1000,
            name: HandleName::Unavailable("paged out".into()),
            threads: Vec::new(),
            thread_list_walked: true,
            threads_capped: false,
            notes: Vec::new(),
        };
        assert_eq!(unreadable.standard_name(), None);

        let hidden = Desktop {
            address: 0x2000,
            name: HandleName::Name("hidden".into()),
            threads: Vec::new(),
            thread_list_walked: true,
            threads_capped: false,
            notes: Vec::new(),
        };
        assert_eq!(hidden.standard_name(), Some(false));

        let station = WindowStation {
            address: 0x3000,
            name: HandleName::Name("WinSta0".into()),
            session_id: Some(1),
            plausible_session: true,
            space: "session",
            desktops: vec![unreadable, hidden],
            desktops_capped: false,
            notes: Vec::new(),
        };
        assert_eq!(station.nonstandard_desktops().len(), 1);
        assert_eq!(
            station.nonstandard_desktops()[0].name.text(),
            Some("hidden")
        );
    }

    /// A desktop whose threads could not be listed leaves the survey
    /// incomplete: "no threads" and "we could not look" are opposite findings.
    #[test]
    fn a_desktop_whose_thread_list_did_not_walk_leaves_the_survey_incomplete() {
        let survey = DesktopSurvey::Surveyed(DesktopListing {
            stations: vec![WindowStation {
                address: 0x3000,
                name: HandleName::Name("WinSta0".into()),
                session_id: Some(1),
                plausible_session: true,
                space: "session",
                desktops: vec![Desktop {
                    address: 0x4000,
                    name: HandleName::Name("Default".into()),
                    threads: Vec::new(),
                    thread_list_walked: false,
                    threads_capped: false,
                    notes: Vec::new(),
                }],
                desktops_capped: false,
                notes: Vec::new(),
            }],
            unreadable: Vec::new(),
            candidates: 1,
            space: "kernel_virtual",
            scan_complete: true,
            capped: false,
            notes: Vec::new(),
        });
        assert!(!survey.is_complete());
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("unknown rather than none")));
    }

    /// A fully walked survey with only the standard desktop is complete, and it
    /// reports no leads — which is a claim it is now entitled to make.
    #[test]
    fn a_fully_walked_survey_with_only_standard_desktops_is_complete() {
        let survey = DesktopSurvey::Surveyed(DesktopListing {
            stations: vec![WindowStation {
                address: 0x3000,
                name: HandleName::Name("WinSta0".into()),
                session_id: Some(1),
                plausible_session: true,
                space: "session",
                desktops: vec![Desktop {
                    address: 0x4000,
                    name: HandleName::Name("Default".into()),
                    threads: Vec::new(),
                    thread_list_walked: true,
                    threads_capped: false,
                    notes: Vec::new(),
                }],
                desktops_capped: false,
                notes: Vec::new(),
            }],
            unreadable: Vec::new(),
            candidates: 1,
            space: "kernel_virtual",
            scan_complete: true,
            capped: false,
            notes: Vec::new(),
        });
        assert!(survey.is_complete());
        assert!(survey.incomplete().is_empty());
        assert!(survey.nonstandard_desktops().is_empty());
    }

    /// A sweep that did not cover every mapped byte cannot support "these are
    /// all the window stations".
    #[test]
    fn an_incomplete_sweep_leaves_the_survey_incomplete() {
        let survey = DesktopSurvey::Surveyed(DesktopListing {
            stations: Vec::new(),
            unreadable: Vec::new(),
            candidates: 0,
            space: "physical",
            scan_complete: false,
            capped: false,
            notes: Vec::new(),
        });
        assert!(!survey.is_complete());
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("did not cover every mapped byte")));
    }
}
