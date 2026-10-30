//! The process list: `pslist`, `pstree` and `cmdline`.
//!
//! Everything else in a memory case hangs off this. A network connection is
//! attributed to a process, an injected page is found in a process's VAD tree,
//! a handle is held by a process, a registry hive from Windows 10 17063 onward
//! is mapped through a process. Get the list wrong and every finding after it
//! is attached to the wrong name.
//!
//! # The list, and the one arithmetic mistake that ruins it
//!
//! The kernel threads every live process onto one doubly-linked list whose head
//! is the exported `PsActiveProcessHead` and whose links are the
//! `_EPROCESS.ActiveProcessLinks` member. That member is **not at offset 0** —
//! it is at 136 on the 32-bit XP build and at 0x448 on Windows 11 — so every
//! `Flink` points into the *middle* of the next `_EPROCESS`, and the structure
//! begins that many bytes earlier. This is `CONTAINING_RECORD`, and it is done
//! here by [`seance_memory::object::ListSpec::in_container`] with the offset
//! taken from the symbol table.
//!
//! Subtracting the wrong number, or subtracting nothing, does not fail. Every
//! field then reads from a plausible place inside the previous structure: a PID
//! that is a small even number, a name that is printable ASCII, a thread count
//! in single figures. The output looks like a process list. That is why the
//! offset is never written down here and why
//! [`ProcessList::links_offset`] is published on the result, so an examiner can
//! check the number the answer was built on.
//!
//! # Times
//!
//! `CreateTime` and `ExitTime` are Windows FILETIMEs — 100 ns ticks since
//! 1601-01-01 — converted by [`seance_core::time`] and by nothing else. A
//! **zero** FILETIME is an *absent* time, not the first instant of 1601: every
//! running process has a zero `ExitTime`, and rendering that as a date would put
//! four hundred wrong timestamps in a report. [`ProcessTime`] keeps "did not
//! happen", "could not be read" and "this build has no such field" apart,
//! because all three would otherwise render as an empty cell.
//!
//! # The tree
//!
//! `pstree` is the parent/child hierarchy implied by
//! `InheritedFromUniqueProcessId`. Three things actually occur in evidence and
//! all three are handled rather than assumed away:
//!
//! * **The parent exited.** Its `_EPROCESS` is off the list, so the PPID names
//!   nobody. The child is reported at the root and annotated
//!   [`ParentLink::Orphaned`] — never dropped, because a process whose parent
//!   has gone is exactly the shape a launcher leaves behind.
//! * **A PPID cycle.** A smeared or tampered list can make two processes name
//!   each other. A recursive renderer hangs; [`build_tree`] breaks the closing
//!   edge, marks it [`ParentLink::Cycle`] and reports the process at the root.
//! * **PID reuse.** Windows reissues PIDs. Matching on PID alone attaches a
//!   child to a *later* process that happens to carry the same number, which is
//!   how a tool draws `cmd.exe` under a process that started after it. A parent
//!   is only accepted when its create time precedes the child's, and when that
//!   cannot be established the link says so instead of pretending.
//!
//! # Command lines
//!
//! The command line is not in the kernel structure. It is in the **process's
//! own** user address space: `_EPROCESS.Peb` →
//! `_PEB.ProcessParameters` → `_RTL_USER_PROCESS_PARAMETERS.CommandLine`. So it
//! is read through a [`seance_memory::translate::VirtualLayer`] built on that
//! process's `_KPROCESS.DirectoryTableBase`, not through the kernel space.
//! Reading it through the kernel space returns whatever the kernel has mapped at
//! that user address, which on a modern build is nothing and on an older one is
//! another process's memory.
//!
//! A PEB that is paged out yields [`CommandLine::Unavailable`]. It must never
//! yield an empty string: "this process was started with no arguments" and "the
//! page holding its arguments was not captured" are opposite findings. The
//! System process and Registry have **no** PEB at all, which is
//! [`CommandLine::NoUserSpace`] and is not a failure.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_core::time::{filetime_to_rfc3339, filetime_to_unix_secs};
use seance_memory::object::{ListSpec, ListStop, Obj, ObjError, StructReader};
use seance_memory::translate::{
    PagingMode, PagingSpec, PteSemantics, TableCache, TranslateError, TranslationPath,
    TranslationPolicy, VirtualLayer,
};
use seance_memory::{Incomplete, MemoryLayer};
use seance_symbols::SymbolError;

use crate::poolscan::{image_file_name, MAX_UNICODE_STRING_BYTES};
use crate::profile::WindowsProfile;
use crate::registry::key::decode_utf16le;

// ── Names this module knows ─────────────────────────────────────────────────

/// The kernel symbol the active process list hangs off.
pub const SYMBOL_PS_ACTIVE_PROCESS_HEAD: &str = "PsActiveProcessHead";

/// The process structure.
pub const TYPE_EPROCESS: &str = "_EPROCESS";

/// The list-link structure the process list is threaded through.
pub const TYPE_LIST_ENTRY: &str = "_LIST_ENTRY";

/// The member of `_EPROCESS` that holds the active-process link.
pub const MEMBER_ACTIVE_PROCESS_LINKS: &str = "ActiveProcessLinks";

/// The member of `_EPROCESS` that holds the image name.
pub const MEMBER_IMAGE_FILE_NAME: &str = "ImageFileName";

/// The handle table a process's `ObjectTable` points at.
pub const TYPE_HANDLE_TABLE: &str = "_HANDLE_TABLE";

/// The session space a process's `Session` points at.
pub const TYPE_MM_SESSION_SPACE: &str = "_MM_SESSION_SPACE";

/// The process environment block, in the process's own address space.
pub const TYPE_PEB: &str = "_PEB";

/// The parameter block the PEB points at, in the process's own address space.
pub const TYPE_PROCESS_PARAMETERS: &str = "_RTL_USER_PROCESS_PARAMETERS";

/// Ceiling on the processes one walk will report.
///
/// A busy Windows machine runs a few hundred processes and the largest images
/// in circulation hold about a thousand. Reaching this means the link chain is
/// wrong, not that the machine was busy, and it is reported as a cap rather
/// than as the end of the list.
pub const MAX_PROCESSES: usize = 65_536;

/// Ceiling on the declared width of `ImageFileName`.
///
/// The real member is 15 or 16 bytes. The count comes out of a symbol pack,
/// which is untrusted input the moment it arrives from outside the lab, and a
/// pack declaring a megabyte-wide name would otherwise cost one allocation of
/// that size per process.
pub const MAX_IMAGE_NAME_BYTES: u64 = 256;

/// Ceiling on the bytes of a command line that will be read.
///
/// `Length` is a `USHORT` read out of the image, so this is the largest a
/// `_UNICODE_STRING` can legitimately declare. A longer declaration is refused
/// rather than truncated: the structure is not a string.
pub const MAX_COMMAND_LINE_BYTES: u64 = MAX_UNICODE_STRING_BYTES;

// ── Addresses on the wire ───────────────────────────────────────────────────

/// Write an address into a JSON object as both a number and an exact string.
///
/// `serde_json` encodes `u64` as an IEEE double, and every x64 kernel address
/// is above 2^53. The numeric form is therefore rounded — by up to about a
/// kilobyte at `0xffff_8000_0000_0000` — so an `_EPROCESS` address quoted in a
/// report from it points at memory the process never occupied. The number stays
/// because every existing consumer reads it; `<key>_hex` is the form that
/// survives the wire intact, and the frontend prefers it wherever it is
/// present.
///
/// Both keys are written by this one call, so an emitter cannot write the
/// rounded number and forget the exact one. That is the point of the helper:
/// the pair is the unit, and there is no way to spell half of it.
pub(crate) fn put_address(
    object: &mut serde_json::Map<String, serde_json::Value>,
    key: &str,
    address: u64,
) {
    object.insert(key.to_string(), serde_json::json!(address));
    object.insert(
        format!("{key}_hex"),
        serde_json::json!(format!("{address:#x}")),
    );
}

/// A JSON object with the address pairs `fill` writes added to it.
///
/// The shape every `to_json` in this file uses: the ordinary fields in a
/// literal, then every address through [`put_address`].
///
/// # Panics
///
/// Never in practice — the caller passes an object literal. A non-object would
/// be a programming error at the call site and is reported as one rather than
/// silently dropping the addresses.
pub(crate) fn with_addresses(
    mut value: serde_json::Value,
    fill: impl FnOnce(&mut serde_json::Map<String, serde_json::Value>),
) -> serde_json::Value {
    fill(
        value
            .as_object_mut()
            .expect("with_addresses is given an object literal"),
    );
    value
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a process list before it can produce an answer worth
/// reading.
///
/// Note what is *not* here: a process whose PID or name could not be read. That
/// is a fact about one structure, and it lands on the record as
/// [`Field::Unavailable`] where an examiner can count it — the process's
/// existence at that address is evidence even when its contents were not
/// captured.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// This build's process list cannot be walked with what is available, and
    /// no partial answer would be honest. The message names what is missing.
    #[error("the process list cannot be walked on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// Address arithmetic that would have wrapped the 64-bit address space.
    #[error("{0}")]
    Overflow(String),

    /// A typed read failed for a reason that invalidates the whole walk rather
    /// than one process.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the walk depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// A process's own address space could not be built from its directory
    /// table base.
    #[error(transparent)]
    Translate(#[from] TranslateError),
}

impl ProcessError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            ProcessError::Unsupported { .. } => "unsupported_build",
            ProcessError::Overflow(_) => "overflow",
            ProcessError::Object(err) => err.class(),
            ProcessError::Symbols(_) => "symbols",
            ProcessError::Translate(_) => "translate",
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            ProcessError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be walked" refusal.
    pub fn unsupported(detail: impl Into<String>) -> ProcessError {
        ProcessError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── One field of one process ────────────────────────────────────────────────

/// One attribute of a process, with the ways it can be missing kept apart.
///
/// Defined once, in [`seance_memory::binding::Field`], and re-exported here so
/// that every consumer of this crate keeps naming it `process::Field`. It used
/// to be declared in this file, which meant the Linux and macOS tiers would
/// each have grown their own; two definitions of a completeness type is how
/// they drift, and a drifted `kind` string blanks a column in
/// `frontend/src/pages/memory/normalize.ts` rather than failing a build.
///
/// A session id that is [`Field::NotApplicable`] belongs to a process that has
/// no session — the System process — one that is [`Field::NotDeclared`] belongs
/// to a build whose symbols publish no `_MM_SESSION_SPACE.SessionId` (Windows 11
/// 24H2+, where the session pointer's target is a type no ISF declares), and one
/// that is [`Field::Unavailable`] belongs to a process whose session space was
/// not captured. The first two are facts about the machine and the build, the
/// third is a fact about the acquisition, and only the third costs the process
/// list its completeness (MEM-023). A build whose `_EPROCESS` has no `Session`
/// member at all still reports [`Field::NotApplicable`]; see `read_session_id`.
pub use seance_memory::binding::Field;

// ── Times ───────────────────────────────────────────────────────────────────

/// A Windows FILETIME field, with "absent" kept apart from "unreadable".
///
/// The distinction is the whole point. A zero `ExitTime` means the process was
/// still running when the image was taken; converting it would date every
/// running process to 1601-01-01, and a reader who sees that column populated
/// will reasonably conclude the process had exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProcessTime {
    /// The field held zero: the event it records did not happen. Every running
    /// process has this as its exit time.
    NotRecorded,
    /// A time.
    At {
        /// The raw FILETIME, so an examiner can check the conversion.
        filetime: u64,
        /// Whole seconds since the Unix epoch.
        unix_seconds: i64,
        /// The same instant in RFC 3339, UTC.
        rfc3339: String,
    },
    /// The field held a value that is not a time: negative, or before the Unix
    /// epoch. Kept rather than dropped, because a nonsensical timestamp is
    /// evidence of smear or of a structure read at the wrong offset.
    Implausible {
        /// The raw value, exactly as stored.
        raw: i128,
    },
    /// The field could not be read. The string says why.
    Unavailable(String),
    /// This build's `_EPROCESS` has no such member.
    NotApplicable,
}

impl ProcessTime {
    /// The raw FILETIME, when there is a time.
    pub fn filetime(&self) -> Option<u64> {
        match self {
            ProcessTime::At { filetime, .. } => Some(*filetime),
            _ => None,
        }
    }

    /// Whether a time was read.
    pub fn is_known(&self) -> bool {
        matches!(self, ProcessTime::At { .. })
    }

    /// Stable identifier for artifact metadata.
    pub fn kind(&self) -> &'static str {
        match self {
            ProcessTime::NotRecorded => "not_recorded",
            ProcessTime::At { .. } => "at",
            ProcessTime::Implausible { .. } => "implausible",
            ProcessTime::Unavailable(_) => "unavailable",
            ProcessTime::NotApplicable => "not_applicable",
        }
    }

    /// Serializable form for artifact metadata.
    ///
    /// `filetime_hex` is beside `filetime` for the same reason every address in
    /// this file carries one. A Windows FILETIME for any date after 1629 is
    /// above 2^53, so the JSON number is rounded — by hundreds of 100 ns ticks
    /// — and [`ProcessTime::At::filetime`] exists precisely so an examiner can
    /// recompute `rfc3339` from it by hand. A raw value that cannot be
    /// recomputed from does not do the job it is there for.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            ProcessTime::At {
                filetime,
                unix_seconds,
                rfc3339,
            } => serde_json::json!({
                "kind": "at",
                "filetime": filetime,
                "filetime_hex": format!("{filetime:#x}"),
                "unix_seconds": unix_seconds,
                "rfc3339": rfc3339,
            }),
            ProcessTime::Implausible { raw } => {
                serde_json::json!({"kind": "implausible", "raw": raw.to_string()})
            }
            ProcessTime::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
            other => serde_json::json!({"kind": other.kind()}),
        }
    }
}

/// Turn a raw FILETIME field into a [`ProcessTime`].
///
/// Zero is [`ProcessTime::NotRecorded`] before anything else, because
/// [`seance_core::time`] and this module must agree that zero is an absence and
/// not the year 1601.
fn classify_filetime(raw: i128) -> ProcessTime {
    if raw == 0 {
        return ProcessTime::NotRecorded;
    }
    let Ok(filetime) = u64::try_from(raw) else {
        return ProcessTime::Implausible { raw };
    };
    match (
        filetime_to_unix_secs(filetime),
        filetime_to_rfc3339(filetime),
    ) {
        (Some(unix_seconds), Some(rfc3339)) => ProcessTime::At {
            filetime,
            unix_seconds,
            rfc3339,
        },
        // Non-zero but below the Unix epoch, which no process creation ever is.
        _ => ProcessTime::Implausible { raw },
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Resolve the first of `candidates` this build's `type_name` actually has.
///
/// The member holding a process's WOW64 block is `Wow64Process` on Windows 7
/// and `WoW64Process` on Windows 10; the create time is `CreateTime.QuadPart`
/// where `_LARGE_INTEGER` is modelled and `CreateTime` where it is not.
/// Choosing by build number means a build nobody catalogued reads the wrong
/// member. Asking the symbol table which one exists means it reads the right
/// one or reports that it read none.
fn resolve_member(reader: &StructReader, type_name: &str, candidates: &[&str]) -> Option<String> {
    candidates
        .iter()
        .find(|path| reader.member_offset(type_name, path).is_ok())
        .map(|path| (*path).to_string())
}

/// The member paths and offsets this build's process list is read through.
///
/// Resolved once per image and checked once, so a build whose `_EPROCESS` the
/// symbols cannot describe fails here naming the member that is missing, rather
/// than at process three hundred having already emitted records read at the
/// wrong offsets.
#[derive(Debug, Clone)]
pub struct ProcessSymbols {
    /// Byte offset of `ActiveProcessLinks` inside `_EPROCESS`.
    ///
    /// Published because every address in the result was computed by
    /// subtracting it. An examiner checking one row by hand needs this number,
    /// and a wrong one produces a list that looks entirely plausible.
    pub links_offset: u64,
    /// Declared width of `ImageFileName`, in bytes.
    pub image_name_len: u64,
    /// Path to the process id.
    pub unique_process_id: String,
    /// Path to the parent's process id, where the build records one.
    pub inherited_from: Option<String>,
    /// Path to the live thread count.
    pub active_threads: Option<String>,
    /// Path to the handle-table pointer.
    pub object_table: Option<String>,
    /// Path to the session-space pointer.
    pub session: Option<String>,
    /// Path to the WOW64 block pointer, which is non-null exactly for a 32-bit
    /// process on a 64-bit kernel.
    pub wow64: Option<String>,
    /// Path to the creation FILETIME.
    pub create_time: Option<String>,
    /// Path to the exit FILETIME.
    pub exit_time: Option<String>,
    /// Path to the PEB pointer, which addresses the process's *own* space.
    pub peb: Option<String>,
    /// Path to the directory table base.
    pub directory_table_base: String,
    /// Whether the directory table base is declared as an array, as it is on
    /// 32-bit builds where it is `ULONG[2]`.
    pub dtb_is_array: bool,
    /// Whether this build's symbols describe `_HANDLE_TABLE`.
    pub has_handle_table: bool,
    /// Whether this build's symbols describe `_MM_SESSION_SPACE`.
    pub has_session_space: bool,
}

impl ProcessSymbols {
    /// Resolve every layout fact a process list of this image needs.
    ///
    /// # Errors
    ///
    /// [`ProcessError::Unsupported`] naming the type or member that is missing,
    /// for the three facts without which a process list is meaningless: the
    /// list link, the process id and the image name. Everything else is
    /// optional, and an absent optional member becomes [`Field::NotApplicable`]
    /// on every record rather than a zero.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, ProcessError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        if !profile.symbols.has_type(TYPE_EPROCESS) {
            return Err(ProcessError::unsupported(format!(
                "the symbol table has no '{TYPE_EPROCESS}', so there is no process structure to \
                 read"
            )));
        }
        if !profile.symbols.has_type(TYPE_LIST_ENTRY) {
            return Err(ProcessError::unsupported(format!(
                "the symbol table has no '{TYPE_LIST_ENTRY}', so the process list's links cannot \
                 be followed"
            )));
        }

        // The load-bearing number. Taken from the table, never written down:
        // it is 136 on XP and 0x448 on Windows 11, and a wrong one reads every
        // field of every process out of the previous structure.
        let links_offset = reader
            .member_offset(TYPE_EPROCESS, MEMBER_ACTIVE_PROCESS_LINKS)
            .map_err(|err| {
                ProcessError::unsupported(format!(
                    "'{TYPE_EPROCESS}.{MEMBER_ACTIVE_PROCESS_LINKS}' could not be located, so the \
                     structure a list link belongs to cannot be recovered: {err}"
                ))
            })?
            .bytes();

        let unique_process_id = resolve_member(&reader, TYPE_EPROCESS, &["UniqueProcessId"])
            .ok_or_else(|| {
                ProcessError::unsupported(format!(
                    "'{TYPE_EPROCESS}' has no UniqueProcessId, so a process cannot be identified"
                ))
            })?;

        // Reading the declared width from the table costs no memory access:
        // the probe object is never read from. A build declaring an
        // implausibly wide name is refused rather than allocated for.
        let probe = reader.object(0, TYPE_EPROCESS)?;
        let image_name_len = probe
            .array_len_capped(MEMBER_IMAGE_FILE_NAME, MAX_IMAGE_NAME_BYTES)
            .map_err(|err| {
                ProcessError::unsupported(format!(
                    "'{TYPE_EPROCESS}.{MEMBER_IMAGE_FILE_NAME}' is not a character array this \
                     build can be read through: {err}"
                ))
            })?;

        let directory_table_base = resolve_member(
            &reader,
            TYPE_EPROCESS,
            &["Pcb.DirectoryTableBase", "DirectoryTableBase"],
        )
        .ok_or_else(|| {
            ProcessError::unsupported(format!(
                "'{TYPE_EPROCESS}' has no DirectoryTableBase, so no process's own address space \
                 can be built"
            ))
        })?;
        let dtb_is_array = probe.array_len(&directory_table_base).is_ok();

        Ok(Self {
            links_offset,
            image_name_len,
            unique_process_id,
            inherited_from: resolve_member(
                &reader,
                TYPE_EPROCESS,
                &["InheritedFromUniqueProcessId"],
            ),
            active_threads: resolve_member(&reader, TYPE_EPROCESS, &["ActiveThreads"]),
            object_table: resolve_member(&reader, TYPE_EPROCESS, &["ObjectTable"]),
            session: resolve_member(&reader, TYPE_EPROCESS, &["Session"]),
            // Both spellings occur, and neither is a typo: the member was
            // renamed between builds.
            wow64: resolve_member(&reader, TYPE_EPROCESS, &["WoW64Process", "Wow64Process"]),
            create_time: resolve_member(
                &reader,
                TYPE_EPROCESS,
                &["CreateTime.QuadPart", "CreateTime"],
            ),
            exit_time: resolve_member(&reader, TYPE_EPROCESS, &["ExitTime.QuadPart", "ExitTime"]),
            peb: resolve_member(&reader, TYPE_EPROCESS, &["Peb"]),
            directory_table_base,
            dtb_is_array,
            has_handle_table: profile.symbols.has_type(TYPE_HANDLE_TABLE),
            has_session_space: profile.symbols.has_type(TYPE_MM_SESSION_SPACE),
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "links_offset": self.links_offset,
            "image_name_len": self.image_name_len,
            "unique_process_id": self.unique_process_id,
            "inherited_from": self.inherited_from,
            "active_threads": self.active_threads,
            "object_table": self.object_table,
            "session": self.session,
            "wow64": self.wow64,
            "create_time": self.create_time,
            "exit_time": self.exit_time,
            "peb": self.peb,
            "directory_table_base": self.directory_table_base,
            "dtb_is_array": self.dtb_is_array,
            "has_handle_table": self.has_handle_table,
            "has_session_space": self.has_session_space,
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// Which way round the list a process was reached.
///
/// Recorded per process because it is provenance. A process found only by
/// walking backwards was on the far side of something unreadable, and an
/// examiner is entitled to know which rows are in that position.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WalkDirection {
    /// Reached by following `Flink` from `PsActiveProcessHead`.
    Forward,
    /// Reached by following `Blink`, after the forward walk stopped early.
    Backward,
}

impl WalkDirection {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            WalkDirection::Forward => "forward",
            WalkDirection::Backward => "backward",
        }
    }

    /// The `_LIST_ENTRY` member this direction follows.
    fn member(self) -> &'static str {
        match self {
            WalkDirection::Forward => "Flink",
            WalkDirection::Backward => "Blink",
        }
    }
}

/// One process, as the active process list describes it.
#[derive(Debug, Clone)]
pub struct ProcessRecord {
    /// Address of the `_EPROCESS` in the kernel address space.
    ///
    /// The handle everything downstream takes: the VAD walk, the handle table,
    /// the process's own address space. It is a fact even when every field
    /// below it is [`Field::Unavailable`], because the list linked to it.
    pub address: u64,
    /// Which way round the list this process was reached.
    pub direction: WalkDirection,
    /// `UniqueProcessId`.
    pub pid: Field<u64>,
    /// `InheritedFromUniqueProcessId` — the PID of whatever created this
    /// process, which may since have exited and may since have been reissued.
    pub ppid: Field<u64>,
    /// `ImageFileName`, truncated at its first NUL.
    pub image_file_name: Field<String>,
    /// Whether every byte of the name before its first NUL was valid UTF-8.
    ///
    /// The member is an OEM code page in principle. A false here means bytes
    /// were replaced to render it, and the raw name differed.
    pub image_name_well_formed: bool,
    /// `ActiveThreads`: live threads at capture.
    pub threads: Field<u64>,
    /// `ObjectTable.HandleCount`.
    pub handles: Field<u64>,
    /// The terminal-services session, from `Session.SessionId`.
    /// [`Field::NotApplicable`] for a process with no session, which is what
    /// the System process has.
    pub session_id: Field<u64>,
    /// Whether this is a 32-bit process on a 64-bit kernel.
    pub wow64: Field<bool>,
    /// When the process started.
    pub create_time: ProcessTime,
    /// When it exited. [`ProcessTime::NotRecorded`] for a process that was
    /// still running.
    pub exit_time: ProcessTime,
    /// The `_PEB` address, in the **process's own** address space.
    /// [`Field::NotApplicable`] for a process with no user address space.
    pub peb: Field<u64>,
    /// Everything odd about the record that did not disqualify it.
    pub notes: Vec<String>,
}

impl ProcessRecord {
    /// Whether the process had exited by the time the image was taken.
    ///
    /// `None` when the exit time could not be read, which is not the same as
    /// "still running" and must not render as it.
    pub fn has_exited(&self) -> Option<bool> {
        match &self.exit_time {
            ProcessTime::NotRecorded => Some(false),
            ProcessTime::At { .. } => Some(true),
            _ => None,
        }
    }

    /// The names of the fields that exist and could not be read.
    ///
    /// The list a report must declare beside the row. An empty vector means
    /// every column on this row is either a value or a stated absence.
    pub fn unreadable_fields(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        if self.pid.is_unavailable() {
            out.push("pid");
        }
        if self.ppid.is_unavailable() {
            out.push("ppid");
        }
        if self.image_file_name.is_unavailable() {
            out.push("image_file_name");
        }
        if self.threads.is_unavailable() {
            out.push("threads");
        }
        if self.handles.is_unavailable() {
            out.push("handles");
        }
        if self.session_id.is_unavailable() {
            out.push("session_id");
        }
        if self.wow64.is_unavailable() {
            out.push("wow64");
        }
        if matches!(self.create_time, ProcessTime::Unavailable(_)) {
            out.push("create_time");
        }
        if matches!(self.exit_time, ProcessTime::Unavailable(_)) {
            out.push("exit_time");
        }
        if self.peb.is_unavailable() {
            out.push("peb");
        }
        out
    }

    /// The fields this build declares no layout for, each with the member it
    /// lacks, as `(field, member)`.
    ///
    /// The counterpart of [`Self::unreadable_fields`]: these are facts about
    /// the kernel build, not about the acquisition. Nothing was missed in the
    /// bytes; the question could not be put. A session id on Windows 11 24H2+,
    /// whose `_EPROCESS.Session` points at a structure no ISF describes, lands
    /// here.
    pub fn undeclared_fields(&self) -> Vec<(&'static str, &'static str)> {
        let fields: [(&'static str, Option<&'static str>); 8] = [
            ("pid", self.pid.undeclared_member()),
            ("ppid", self.ppid.undeclared_member()),
            ("image_file_name", self.image_file_name.undeclared_member()),
            ("threads", self.threads.undeclared_member()),
            ("handles", self.handles.undeclared_member()),
            ("session_id", self.session_id.undeclared_member()),
            ("wow64", self.wow64.undeclared_member()),
            ("peb", self.peb.undeclared_member()),
        ];
        fields
            .into_iter()
            .filter_map(|(field, member)| member.map(|member| (field, member)))
            .collect()
    }

    /// Serializable form for artifact metadata.
    ///
    /// `address` is the `_EPROCESS` pointer and `peb` is a user-space pointer;
    /// both go out through [`put_address`] and [`Field::to_json_address`], so
    /// each carries the exact hex beside the rounded number. Everything else
    /// here is a count or an identifier that fits in a double.
    pub fn to_json(&self) -> serde_json::Value {
        with_addresses(
            serde_json::json!({
                "direction": self.direction.as_str(),
                "pid": self.pid.to_json(),
                "ppid": self.ppid.to_json(),
                "image_file_name": self.image_file_name.to_json(),
                "image_name_well_formed": self.image_name_well_formed,
                "threads": self.threads.to_json(),
                "handles": self.handles.to_json(),
                "session_id": self.session_id.to_json(),
                "wow64": self.wow64.to_json(),
                "create_time": self.create_time.to_json(),
                "exit_time": self.exit_time.to_json(),
                "peb": self.peb.to_json_address(),
                "has_exited": self.has_exited(),
                "unreadable_fields": self.unreadable_fields(),
                "notes": self.notes,
            }),
            |object| put_address(object, "address", self.address),
        )
    }
}

/// Caps for one process-list walk.
#[derive(Debug, Clone)]
pub struct ProcessListConfig {
    /// Ceiling on processes reported.
    pub max_processes: usize,
}

impl Default for ProcessListConfig {
    fn default() -> Self {
        Self {
            max_processes: MAX_PROCESSES,
        }
    }
}

/// Every process on the active list, and everything the walk could not do.
#[derive(Debug, Clone)]
pub struct ProcessList {
    /// Address of `PsActiveProcessHead` in the kernel address space.
    pub head: u64,
    /// The offset subtracted from every list link to recover its `_EPROCESS`.
    ///
    /// Published so the arithmetic every address in this list rests on can be
    /// checked rather than trusted.
    pub links_offset: u64,
    /// The processes, in the order the list gave them.
    pub processes: Vec<ProcessRecord>,
    /// Why the forward walk ended. Only [`ListStop::Wrapped`] means the list
    /// was enumerated end to end.
    pub forward_stop: ListStop,
    /// Why the backward walk ended, when the forward one stopped early enough
    /// to make one worth doing.
    pub backward_stop: Option<ListStop>,
}

impl ProcessList {
    /// Whether the list was walked end to end and every field of every row was
    /// either read or explicitly absent.
    ///
    /// The question a report must ask before writing "this machine was running
    /// these processes": a walk that stopped early says nothing about what it
    /// did not reach, and a short process list looks exactly like a quiet
    /// machine.
    ///
    /// A field that is [`Field::NotDeclared`] is an explicit absence and does
    /// not make the list incomplete: the build publishes no layout for it, no
    /// process was missed and no bytes went unread. It is disclosed, with a
    /// count, by [`Self::undescribed_fields`] instead (owner decision
    /// 2026-09-26 on MEM-023).
    pub fn is_complete(&self) -> bool {
        self.forward_stop.is_complete()
            && self.backward_stop.is_none()
            && self
                .processes
                .iter()
                .all(|process| process.unreadable_fields().is_empty())
    }

    /// Every process carrying a PID.
    ///
    /// A vector rather than an option: PIDs are reissued, and an image taken
    /// moments after a process exited can hold two structures with the same
    /// one. A caller that assumed uniqueness would silently pick whichever came
    /// first.
    pub fn by_pid(&self, pid: u64) -> Vec<&ProcessRecord> {
        self.processes
            .iter()
            .filter(|process| process.pid.known() == Some(&pid))
            .collect()
    }

    /// The process at a kernel address, if it is on this list.
    pub fn at(&self, address: u64) -> Option<&ProcessRecord> {
        self.processes
            .iter()
            .find(|process| process.address == address)
    }

    /// Everything a report must declare about this list.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(incomplete) = self.forward_stop.incomplete() {
            out.push(Incomplete::new(
                incomplete.reason,
                format!(
                    "walking the active process list forward from {:#x}: {}",
                    self.head, incomplete.detail
                ),
            ));
        }
        if let Some(stop) = &self.backward_stop {
            if let Some(incomplete) = stop.incomplete() {
                out.push(Incomplete::new(
                    incomplete.reason,
                    format!(
                        "walking the active process list backward from {:#x}: {}",
                        self.head, incomplete.detail
                    ),
                ));
            }
        }
        for process in &self.processes {
            let unreadable = process.unreadable_fields();
            if !unreadable.is_empty() {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the process at {:#x} has field(s) that exist and could not be read: {}",
                        process.address,
                        unreadable.join(", ")
                    ),
                ));
            }
        }
        out
    }

    /// Every field some row could not have because this build declares no
    /// layout for it, as `(field, member, processes)`, in first-seen order.
    ///
    /// Published beside `incomplete` rather than inside it. An undescribed
    /// field misses no process and no bytes, so it does not make the list a
    /// floor (see [`ProcessInventory`]); but a column that is blank on every
    /// row of a build is still something a report must say, and say with a
    /// count.
    pub fn undescribed_fields(&self) -> Vec<(&'static str, &'static str, usize)> {
        let mut out: Vec<(&'static str, &'static str, usize)> = Vec::new();
        for process in &self.processes {
            for (field, member) in process.undeclared_fields() {
                match out.iter_mut().find(|(seen_field, seen_member, _)| {
                    *seen_field == field && *seen_member == member
                }) {
                    Some(entry) => entry.2 += 1,
                    None => out.push((field, member, 1)),
                }
            }
        }
        out
    }

    /// Serializable form for the process-list artifact.
    pub fn to_json(&self) -> serde_json::Value {
        with_addresses(
            serde_json::json!({
                "undescribed": self
                    .undescribed_fields()
                    .iter()
                    .map(|(field, member, processes)| serde_json::json!({
                        "field": field,
                        "member": member,
                        "processes": processes,
                        "meaning": "This build's symbols declare no such member, so the field could \
                                    not be asked for on these processes. Nothing was missed in the \
                                    bytes, and it does not make the process list a floor.",
                    }))
                    .collect::<Vec<_>>(),
                "links_offset": self.links_offset,
                "count": self.processes.len(),
                "complete": self.is_complete(),
                "forward_stop": self.forward_stop.as_str(),
                "backward_stop": self.backward_stop.as_ref().map(ListStop::as_str),
                "processes": self
                    .processes
                    .iter()
                    .map(ProcessRecord::to_json)
                    .collect::<Vec<_>>(),
                "incomplete": self
                    .incomplete()
                    .iter()
                    .map(Incomplete::to_json)
                    .collect::<Vec<_>>(),
            }),
            |object| put_address(object, "head", self.head),
        )
    }

    /// The completeness stamp every stage that walks this list must carry.
    ///
    /// See [`ProcessInventory`] for why a stage cannot judge its own
    /// completeness without it.
    pub fn inventory(&self) -> ProcessInventory {
        ProcessInventory {
            head: self.head,
            listed: self.processes.len(),
            complete: self.is_complete(),
            incomplete: self.incomplete(),
        }
    }
}

// ── Inventory completeness ──────────────────────────────────────────────────

/// How complete the process inventory a downstream stage rested on was.
///
/// Every per-process stage — VAD trees, handle tables, loaded modules, system
/// calls, image tampering — is handed one [`ProcessList`] and walks it. Each of
/// those stages can measure only what *it* failed to do: a VAD tree that would
/// not walk, a handle table that ran short. None of them can see that the list
/// itself stopped ten processes early, because a short list looks exactly like
/// a quiet machine.
///
/// That is the whole reason this type exists. Without it a tampering scan that
/// examined every process it was given reports `content_complete: true` over a
/// list that never reached the process doing the tampering, and an examiner
/// reads "no tampering signals on this machine" from a stage that never saw it.
/// With it, the stage's completeness is the *conjunction* of its own work and
/// the inventory it walked, and the reasons the inventory fell short travel on
/// the same artifact.
///
/// # What an examiner learns
///
/// `listed` is how many processes the stage was given, `complete` says whether
/// that was all of them, and `incomplete` names each reason it was not — a link
/// that would not follow, a cap that fired, a field that could not be read. A
/// wrong answer here looks like a per-process stage claiming a total when it
/// only ever had a floor.
///
/// # What does not make it a floor
///
/// A field this build declares no layout for — the session id on Windows 11
/// 24H2+, whose `_EPROCESS.Session` points at a type no ISF describes — is not
/// a reason. It misses no process and no bytes, and this type answers whether
/// every process on the active list was reached. Counting it made the inventory
/// a floor on every modern capture, and a completeness flag that is false on
/// every capture stops being read (MEM-023, owner decision 2026-09-26, option
/// A). The process-list artifact discloses it under `undescribed` instead.
#[derive(Debug, Clone)]
pub struct ProcessInventory {
    /// Address of `PsActiveProcessHead` the list was walked from.
    pub head: u64,
    /// How many processes the stage was handed.
    pub listed: usize,
    /// Whether that was every process on the active list.
    pub complete: bool,
    /// Why it was not, when it was not. Empty when `complete`.
    pub incomplete: Vec<Incomplete>,
}

impl ProcessInventory {
    /// Whether the inventory is a total rather than a floor.
    pub fn is_complete(&self) -> bool {
        self.complete && self.incomplete.is_empty()
    }

    /// Serializable form, for embedding in a stage's artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let complete = self.is_complete();
        let meaning = if complete {
            "The process list this stage walked was enumerated end to end, so the set of \
             processes examined here is every process on the active list."
        } else {
            "The process list this stage walked stopped short, so the processes examined here \
             are a floor. Nothing here is a statement about a process the list never reached."
        };
        with_addresses(
            serde_json::json!({
                "listed": self.listed,
                "complete": complete,
                "count_is_floor": !complete,
                "incomplete": self
                    .incomplete
                    .iter()
                    .map(Incomplete::to_json)
                    .collect::<Vec<_>>(),
                "meaning": meaning,
            }),
            |object| put_address(object, "head", self.head),
        )
    }

    /// Stamp a stage's artifact metadata with the inventory it rests on.
    ///
    /// Inserts `process_inventory`, and — the part that matters — forces
    /// `content_complete` to false when the inventory is a floor. A stage that
    /// examined every process it was handed is still incomplete when the list
    /// it was handed was short, and a record claiming completeness there is how
    /// a report ends up asserting an absence nobody tested for.
    ///
    /// Does nothing to a value that is not a JSON object, because there is
    /// nothing to stamp; every stage's `to_json` produces an object.
    pub fn stamp(&self, value: &mut serde_json::Value) {
        let Some(object) = value.as_object_mut() else {
            return;
        };
        object.insert("process_inventory".into(), self.to_json());
        if !self.is_complete() {
            object.insert("content_complete".into(), serde_json::json!(false));
            object.insert("content_incomplete".into(), serde_json::json!(true));
            object.insert(
                "process_inventory_incomplete".into(),
                serde_json::json!(true),
            );
        }
    }
}

// ── The walk ────────────────────────────────────────────────────────────────

/// Walk `PsActiveProcessHead` and report every process on the active list.
///
/// The list is walked forward first. If the forward walk stops early — an
/// `_EPROCESS` whose page was not captured breaks the chain at that entry — the
/// list is walked **backward** as well, because it is doubly linked and the
/// processes past the break are still reachable from the other end. Anything
/// already seen is skipped, which is what makes the two walks meet in the
/// middle rather than report the same process twice.
///
/// # Errors
///
/// Only for failures that make the walk impossible to start: no
/// `PsActiveProcessHead` in the symbol table, a kernel base plus symbol address
/// that does not fit in 64 bits, or an `_EPROCESS` the symbols cannot describe.
/// A failure *during* the walk is not an error — the processes found before it
/// are evidence, and it is recorded in [`ProcessList::incomplete`] beside them.
pub fn list_processes(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    config: &ProcessListConfig,
) -> Result<ProcessList, ProcessError> {
    let rva = profile
        .symbols
        .symbol_address(SYMBOL_PS_ACTIVE_PROCESS_HEAD)
        .map_err(|_| {
            ProcessError::unsupported(format!(
                "the symbol table has no '{SYMBOL_PS_ACTIVE_PROCESS_HEAD}', so the active process \
                 list has no head to walk from"
            ))
        })?;
    let head = profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
        ProcessError::Overflow(format!(
            "the kernel base {:#x} plus '{SYMBOL_PS_ACTIVE_PROCESS_HEAD}' at {rva:#x} does not \
             fit in 64 bits",
            profile.kernel_base.value
        ))
    })?;
    list_processes_from(profile, symbols, head, config)
}

/// Walk an active process list whose head address is already known.
///
/// Separated so an examiner who recovered `PsActiveProcessHead` by other means
/// — a second symbol table, a `KdDebuggerDataBlock` — uses the same walk and
/// gets the same guarantees.
pub fn list_processes_from(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    head: u64,
    config: &ProcessListConfig,
) -> Result<ProcessList, ProcessError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    let mut processes: Vec<ProcessRecord> = Vec::new();
    let mut seen: HashSet<u64> = HashSet::new();

    let forward_stop = walk_direction(
        &reader,
        symbols,
        config,
        head,
        WalkDirection::Forward,
        &mut seen,
        &mut processes,
    )?;

    // A cap is a bound the caller set, not a chain that could not be followed;
    // walking backward after one would re-walk the same list from the other end
    // and defeat the bound. Every other early stop means the forward chain
    // broke, and the processes past the break are still reachable.
    let capped = matches!(forward_stop, ListStop::CapReached { .. });
    let backward_stop = if forward_stop.is_complete() || capped {
        None
    } else {
        Some(walk_direction(
            &reader,
            symbols,
            config,
            head,
            WalkDirection::Backward,
            &mut seen,
            &mut processes,
        )?)
    };

    Ok(ProcessList {
        head,
        links_offset: symbols.links_offset,
        processes,
        forward_stop,
        backward_stop,
    })
}

/// One pass over the list in one direction.
fn walk_direction(
    reader: &StructReader,
    symbols: &ProcessSymbols,
    config: &ProcessListConfig,
    head: u64,
    direction: WalkDirection,
    seen: &mut HashSet<u64>,
    processes: &mut Vec<ProcessRecord>,
) -> Result<ListStop, ProcessError> {
    // `in_container` is what turns a link address into the structure it is
    // embedded in, and it checks against the symbol table that the named member
    // really is the link — pointing it at a different member would subtract a
    // wrong constant from every entry and yield a list of structures that all
    // parse.
    let spec = ListSpec::new(TYPE_LIST_ENTRY, direction.member())
        .in_container(TYPE_EPROCESS, MEMBER_ACTIVE_PROCESS_LINKS)
        .with_max_entries(config.max_processes);
    let walk = reader.walk_list(head, &spec)?;
    let (entries, stop) = walk.walk_to_end();

    for entry in entries {
        let address = entry.address();
        if !seen.insert(address) {
            continue;
        }
        processes.push(read_process(reader, symbols, &entry, direction));
    }
    Ok(stop)
}

/// Read one `_EPROCESS` into a record.
///
/// Never fails. Every field that cannot be read becomes [`Field::Unavailable`]
/// carrying the reason, because the process's presence on the list is evidence
/// independently of whether its page was captured, and dropping the row would
/// silently shorten the process list.
fn read_process(
    reader: &StructReader,
    symbols: &ProcessSymbols,
    entry: &Obj,
    direction: WalkDirection,
) -> ProcessRecord {
    let mut notes = Vec::new();
    let address = entry.address();

    let pid = read_unsigned(entry, Some(symbols.unique_process_id.as_str()));
    // NT hands out process ids in multiples of four. One that is not is either
    // a structure read at the wrong offset or a smeared page, and it is worth a
    // line beside the row rather than a silent acceptance.
    if let Some(&value) = pid.known() {
        if value % 4 != 0 {
            notes.push(format!(
                "the process id {value} is not a multiple of four, and every id NT hands out is"
            ));
        }
    }

    let (image_file_name, image_name_well_formed) = read_image_name(entry);
    let create_time = read_time(entry, symbols.create_time.as_deref());
    let exit_time = read_time(entry, symbols.exit_time.as_deref());

    if let (ProcessTime::At { filetime: born, .. }, ProcessTime::At { filetime: died, .. }) =
        (&create_time, &exit_time)
    {
        if died < born {
            notes.push(format!(
                "the exit time {died} precedes the create time {born}, so one of the two was not \
                 read from this process"
            ));
        }
    }

    ProcessRecord {
        address,
        direction,
        pid,
        ppid: read_unsigned(entry, symbols.inherited_from.as_deref()),
        image_file_name,
        image_name_well_formed,
        threads: read_unsigned(entry, symbols.active_threads.as_deref()),
        handles: read_handle_count(reader, symbols, entry),
        session_id: read_session_id(reader, symbols, entry),
        wow64: read_wow64(entry, symbols.wow64.as_deref()),
        create_time,
        exit_time,
        peb: read_peb(entry, symbols.peb.as_deref()),
        notes,
    }
}

/// Read an integer or pointer member into a [`Field`].
///
/// `int` rather than `unsigned` because `UniqueProcessId` is declared as a
/// `void*` on every real build and as an integer on some synthetic ones, and
/// both read identically through the symbol table's declared width. A member
/// the build does not have is [`Field::NotApplicable`], never zero.
fn read_unsigned(object: &Obj, path: Option<&str>) -> Field<u64> {
    let Some(path) = path else {
        return Field::NotApplicable;
    };
    match object.int(path) {
        Ok(value) => match value.as_u64() {
            Some(value) => Field::Known(value),
            None => Field::Unavailable(format!(
                "'{}.{path}' is negative, which is not a count or an identifier",
                object.type_name()
            )),
        },
        Err(err) => Field::Unavailable(err.to_string()),
    }
}

/// Read `ImageFileName`, stopping at the first NUL and never past the array.
///
/// The member is a fixed 15- or 16-byte array, NUL-padded but **not guaranteed
/// to be NUL-terminated**: a name that exactly fills it has no terminator, so a
/// reader that scanned for one would run off the end of the member and into
/// whatever field follows. The bytes come back at the width the symbol table
/// declares, and the name is everything before the first NUL if there is one
/// and the whole array if there is not.
fn read_image_name(object: &Obj) -> (Field<String>, bool) {
    match object.bytes(MEMBER_IMAGE_FILE_NAME) {
        Ok(raw) => {
            let end = raw.iter().position(|&byte| byte == 0).unwrap_or(raw.len());
            // The member is an OEM code page, so a byte above 0x7F is not
            // necessarily UTF-8. Rendering it lossily is right; hiding that it
            // was rendered lossily is not.
            let well_formed = std::str::from_utf8(&raw[..end]).is_ok();
            (Field::Known(image_file_name(&raw)), well_formed)
        }
        Err(err) => (Field::Unavailable(err.to_string()), true),
    }
}

/// Read a FILETIME member into a [`ProcessTime`].
fn read_time(object: &Obj, path: Option<&str>) -> ProcessTime {
    let Some(path) = path else {
        return ProcessTime::NotApplicable;
    };
    match object.int(path) {
        // `QuadPart` is declared signed, so the raw value is widened losslessly
        // and classified rather than cast: a negative FILETIME is not a date
        // eighteen thousand years hence, it is a field that is not a time.
        Ok(value) => classify_filetime(value.as_i128()),
        Err(err) => ProcessTime::Unavailable(err.to_string()),
    }
}

/// Read `ObjectTable.HandleCount`, following the pointer into the kernel space.
///
/// The count is not in the `_EPROCESS`; the `_EPROCESS` points at a
/// `_HANDLE_TABLE` that holds it. A build whose symbols do not describe that
/// structure, or whose handle table declares no count, yields
/// [`Field::NotApplicable`] rather than zero — a process with no handles at all
/// does not exist, so a zero in that column is always wrong.
fn read_handle_count(reader: &StructReader, symbols: &ProcessSymbols, object: &Obj) -> Field<u64> {
    let Some(path) = symbols.object_table.as_deref() else {
        return Field::NotApplicable;
    };
    if !symbols.has_handle_table {
        return Field::NotApplicable;
    }
    let table_address = match object.int(path) {
        Ok(value) => match value.as_u64() {
            Some(value) => value,
            None => {
                return Field::Unavailable(format!(
                    "'{}.{path}' is negative, which is not an address",
                    object.type_name()
                ))
            }
        },
        Err(err) => return Field::Unavailable(err.to_string()),
    };
    if table_address == 0 {
        // A process whose object table has been torn down: it has exited.
        return Field::NotApplicable;
    }
    let table = match reader.object(table_address, TYPE_HANDLE_TABLE) {
        Ok(table) => table,
        Err(err) => return Field::Unavailable(err.to_string()),
    };
    if !table.has_member("HandleCount") {
        return Field::NotApplicable;
    }
    read_unsigned(&table, Some("HandleCount"))
}

/// The member a session id is read from, named when a build does not declare it.
const SESSION_ID_MEMBER: &str = "_MM_SESSION_SPACE.SessionId";

/// Read the terminal-services session id through `_MM_SESSION_SPACE`.
///
/// A null `Session` is [`Field::NotApplicable`]: the System process and the
/// other kernel-only processes belong to no session, and reporting session 0
/// for them would put them in the console session alongside the interactive
/// user's processes.
///
/// Where upstream falls back to reading an unsigned long at a **hardcoded**
/// offset of 8 when the session type is missing from the symbols — as it is on
/// Windows 11 24H2, where `_EPROCESS.Session` points at a `_PSP_SESSION_SPACE`
/// no ISF declares — this declines. A number read at an offset nobody can check
/// against the build is not evidence.
///
/// That refusal is [`Field::NotDeclared`] naming `_MM_SESSION_SPACE.SessionId`,
/// not [`Field::Unavailable`] (MEM-023): the pointer read fine and nothing in
/// the image was missed; it is the build that publishes no layout for the
/// target. Counting it as a failed read made every process on every 24H2+
/// capture "exist and could not be read", and the process inventory — and so
/// every per-process stage — a floor on every modern capture. A session pointer
/// that is negative, or whose target will not read, is still `Unavailable`:
/// those are facts about the acquisition.
fn read_session_id(reader: &StructReader, symbols: &ProcessSymbols, object: &Obj) -> Field<u64> {
    let Some(path) = symbols.session.as_deref() else {
        return Field::NotApplicable;
    };
    let session = match object.int(path) {
        Ok(value) => match value.as_u64() {
            Some(value) => value,
            None => {
                return Field::Unavailable(format!(
                    "'{}.{path}' is negative, which is not an address",
                    object.type_name()
                ))
            }
        },
        Err(err) => return Field::Unavailable(err.to_string()),
    };
    if session == 0 {
        return Field::NotApplicable;
    }
    if !symbols.has_session_space {
        // The build publishes no layout for the session space; reading at an
        // assumed offset is what upstream does and what this declines to do.
        return Field::NotDeclared {
            member: SESSION_ID_MEMBER,
        };
    }
    let space = match reader.object(session, TYPE_MM_SESSION_SPACE) {
        Ok(space) => space,
        Err(err) => return Field::Unavailable(err.to_string()),
    };
    if !space.has_member("SessionId") {
        return Field::NotDeclared {
            member: SESSION_ID_MEMBER,
        };
    }
    read_unsigned(&space, Some("SessionId"))
}

/// Whether the process is a 32-bit process running on a 64-bit kernel.
///
/// The member holds a pointer to the WOW64 block, so any non-null value means
/// yes. A build with no such member is [`Field::NotApplicable`] rather than
/// `false`: a 32-bit kernel cannot host a WOW64 process at all, and stating
/// that as a measured `false` claims a check that was never made.
fn read_wow64(object: &Obj, path: Option<&str>) -> Field<bool> {
    let Some(path) = path else {
        return Field::NotApplicable;
    };
    match object.int(path) {
        Ok(value) => Field::Known(value.as_i128() != 0),
        Err(err) => Field::Unavailable(err.to_string()),
    }
}

/// The `_PEB` address, which is an address in the **process's own** space.
///
/// Zero is [`Field::NotApplicable`] and is the ordinary state of the System
/// process, of Registry and of Memory Compression: they have no user address
/// space, so there is no PEB to have. It is not a failure and must not be
/// reported as one.
fn read_peb(object: &Obj, path: Option<&str>) -> Field<u64> {
    let Some(path) = path else {
        // The build's `_EPROCESS` has no `Peb` at all. That is a fact about the
        // build, not about this process, and a consumer that reads it as "this
        // process has no user address space" will skip every process on the
        // image while still rendering a scan that found nothing.
        return Field::NotDeclared { member: "Peb" };
    };
    match object.int(path) {
        Ok(value) => match value.as_u64() {
            Some(0) => Field::NotApplicable,
            Some(value) => Field::Known(value),
            None => Field::Unavailable(format!(
                "'{}.{path}' is negative, which is not an address",
                object.type_name()
            )),
        },
        Err(err) => Field::Unavailable(err.to_string()),
    }
}

// ── The tree ────────────────────────────────────────────────────────────────

/// How confident the tree is that a process's parent is the one it drew.
///
/// Rendered beside every edge. A tree that draws every edge the same way is
/// asserting a hierarchy it cannot support: PIDs are reissued, so an edge
/// derived from a PID match alone is a guess, and an examiner testifying to
/// "this process launched that one" needs to know which kind of edge they are
/// looking at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParentLink {
    /// Exactly one process on the list carries the parent PID, and its create
    /// time precedes this process's. The strongest statement the list supports.
    Confirmed,
    /// Exactly one process carries the parent PID, but the two create times
    /// could not be compared, so PID reuse cannot be ruled out.
    Unverified {
        /// Which of the two times was missing.
        detail: String,
    },
    /// More than one process carries the parent PID. If one of them was created
    /// before this process, it was chosen; otherwise no edge was drawn.
    Ambiguous {
        /// Kernel addresses of every process carrying the parent PID.
        candidates: Vec<u64>,
        /// What was and was not established.
        detail: String,
    },
    /// No process on the list carries the parent PID, or the only one that does
    /// was created afterwards. The parent has exited; this process is reported
    /// at the root.
    Orphaned {
        /// The parent PID as the process records it.
        ppid: u64,
        /// Why no edge was drawn.
        detail: String,
    },
    /// Following parent links from here comes back to this process. The edge
    /// that closed the loop was broken and the process is reported at the root.
    Cycle {
        /// What the loop was.
        detail: String,
    },
    /// The parent PID could not be read, so no edge could be considered.
    Unknown,
}

impl ParentLink {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ParentLink::Confirmed => "confirmed",
            ParentLink::Unverified { .. } => "unverified",
            ParentLink::Ambiguous { .. } => "ambiguous",
            ParentLink::Orphaned { .. } => "orphaned",
            ParentLink::Cycle { .. } => "cycle",
            ParentLink::Unknown => "unknown",
        }
    }

    /// Whether the edge rests on more than a PID match.
    pub fn is_confirmed(&self) -> bool {
        matches!(self, ParentLink::Confirmed)
    }

    /// Serializable form for artifact metadata.
    ///
    /// `candidates` are `_EPROCESS` addresses, so they carry `candidates_hex`
    /// beside them: these are the rows an examiner opens by hand to decide
    /// which of several processes carrying one id was really the parent, and a
    /// rounded pointer opens the wrong one.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            ParentLink::Unverified { detail } | ParentLink::Cycle { detail } => {
                serde_json::json!({"kind": self.as_str(), "detail": detail})
            }
            ParentLink::Ambiguous { candidates, detail } => serde_json::json!({
                "kind": "ambiguous",
                "candidates": candidates,
                "candidates_hex": candidates
                    .iter()
                    .map(|address| format!("{address:#x}"))
                    .collect::<Vec<_>>(),
                "detail": detail,
            }),
            ParentLink::Orphaned { ppid, detail } => serde_json::json!({
                "kind": "orphaned",
                "ppid": ppid,
                "detail": detail,
            }),
            other => serde_json::json!({"kind": other.as_str()}),
        }
    }
}

/// One process's place in the hierarchy.
///
/// The index of a node in [`ProcessTree::nodes`] is the index of its process in
/// [`ProcessList::processes`], so the two are read together and nothing needs
/// matching back up by PID.
#[derive(Debug, Clone)]
pub struct TreeNode {
    /// Kernel address of the `_EPROCESS`, repeated here so a node renders
    /// without reaching back into the list.
    pub address: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// The parent process id, as this process records it.
    pub ppid: Option<u64>,
    /// Index of the parent node, when an edge was drawn.
    pub parent: Option<usize>,
    /// Indices of the children, ordered by PID then address so two runs over
    /// the same image render identically.
    pub children: Vec<usize>,
    /// Distance from the root this node hangs under. Roots are zero.
    pub depth: u32,
    /// What the edge to the parent rests on.
    pub link: ParentLink,
}

impl TreeNode {
    /// Serializable form for artifact metadata.
    ///
    /// `address` is the `_EPROCESS` pointer and carries its exact hex; `pid`,
    /// `ppid`, `parent` and `children` are identifiers and node indices, which
    /// are small and are not addresses.
    pub fn to_json(&self) -> serde_json::Value {
        with_addresses(
            serde_json::json!({
                "pid": self.pid,
                "ppid": self.ppid,
                "parent": self.parent,
                "children": self.children,
                "depth": self.depth,
                "link": self.link.to_json(),
            }),
            |object| put_address(object, "address", self.address),
        )
    }
}

/// The parent/child hierarchy of a process list.
///
/// Every process on the list appears exactly once, whatever its PPID says.
/// A process whose parent exited, whose PPID is part of a loop, or whose PPID
/// could not be read is a root; none of them is dropped, because a process
/// missing from a tree is indistinguishable from a process that was not running.
#[derive(Debug, Clone)]
pub struct ProcessTree {
    /// One node per process, indexed as the list is.
    pub nodes: Vec<TreeNode>,
    /// Indices of the nodes with no parent edge, ordered by PID then address.
    pub roots: Vec<usize>,
    /// Whether the list this tree was derived from was itself complete.
    ///
    /// Carried on the tree rather than left with the caller because a tree is
    /// only ever as good as the list under it: a hierarchy drawn from a walk
    /// that stopped early is missing whole branches, and nothing in the tree
    /// itself shows that. Set by [`build_tree`] from
    /// [`ProcessList::is_complete`].
    pub list_complete: bool,
}

impl ProcessTree {
    /// The nodes in the order a tree is drawn: each node immediately before its
    /// descendants, with the depth to indent it by.
    ///
    /// Every node appears exactly once. A node that the descent from the roots
    /// somehow failed to reach is appended at depth zero rather than lost —
    /// this cannot happen once cycles are broken, and the guarantee is written
    /// down rather than assumed because losing a process is the one outcome a
    /// tree renderer must not have.
    pub fn render_order(&self) -> Vec<(u32, usize)> {
        let mut out = Vec::with_capacity(self.nodes.len());
        let mut emitted = vec![false; self.nodes.len()];
        // An explicit stack: a recursive descent over parent links taken from
        // an image overflows the host's stack on a deep or crafted chain, and a
        // crash is not a finding.
        let mut stack: Vec<usize> = self.roots.iter().rev().copied().collect();

        while let Some(index) = stack.pop() {
            let Some(node) = self.nodes.get(index) else {
                continue;
            };
            if emitted[index] {
                continue;
            }
            emitted[index] = true;
            out.push((node.depth, index));
            for &child in node.children.iter().rev() {
                if !emitted.get(child).copied().unwrap_or(true) {
                    stack.push(child);
                }
            }
        }

        for (index, done) in emitted.iter().enumerate() {
            if !done {
                out.push((0, index));
            }
        }
        out
    }

    /// Nodes whose parent was not on the list.
    pub fn orphans(&self) -> Vec<usize> {
        self.nodes
            .iter()
            .enumerate()
            .filter(|(_, node)| matches!(node.link, ParentLink::Orphaned { .. }))
            .map(|(index, _)| index)
            .collect()
    }

    /// Whether every edge in the tree rests on more than a process-id match.
    ///
    /// False when any process sits in a broken cycle, shares its parent's id
    /// with another process, or has a parent that could only be matched by id
    /// because a create time was missing.
    ///
    /// An orphan does not make this false: "the parent is not on this list" is
    /// a definite statement about the list, not an unresolved one. Orphans are
    /// reported by [`ProcessTree::orphans`], and a process whose parent id could
    /// not be read at all is already in
    /// [`ProcessRecord::unreadable_fields`].
    pub fn every_edge_is_confirmed(&self) -> bool {
        !self.nodes.iter().any(|node| {
            matches!(
                node.link,
                ParentLink::Unverified { .. }
                    | ParentLink::Ambiguous { .. }
                    | ParentLink::Cycle { .. }
            )
        })
    }

    /// Whether this tree can be quoted as the machine's process hierarchy.
    ///
    /// Both halves matter and neither implies the other. The list can be walked
    /// end to end and still yield edges that rest on a process-id match alone,
    /// and every edge can be confirmed on a list that stopped at the third
    /// entry. A report that stamps the tree complete from the list walk alone
    /// says "these processes launched those" about a hierarchy whose edges are
    /// reuse-ambiguous or cyclic.
    ///
    /// # What a wrong answer looks like
    ///
    /// A tree rendered without qualification in which `explorer.exe` appears
    /// under a PID-matched parent that is really an unrelated process that
    /// inherited the id after the real parent exited.
    pub fn is_complete(&self) -> bool {
        self.list_complete && self.incomplete().is_empty()
    }

    /// Everything a report must declare about this tree.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        for node in &self.nodes {
            match &node.link {
                ParentLink::Cycle { detail } => out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!("the process at {:#x}: {detail}", node.address),
                )),
                ParentLink::Ambiguous { detail, .. } => out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!("the process at {:#x}: {detail}", node.address),
                )),
                ParentLink::Unverified { detail } => out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!("the process at {:#x}: {detail}", node.address),
                )),
                _ => {}
            }
        }
        out
    }

    /// Serializable form for the process-tree artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "nodes": self.nodes.iter().map(TreeNode::to_json).collect::<Vec<_>>(),
            "roots": self.roots,
            "render_order": self
                .render_order()
                .iter()
                .map(|(depth, index)| serde_json::json!({"depth": depth, "node": index}))
                .collect::<Vec<_>>(),
            "every_edge_is_confirmed": self.every_edge_is_confirmed(),
            "list_complete": self.list_complete,
            "complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// The create time of a process, when one was read.
fn create_filetime(process: &ProcessRecord) -> Option<u64> {
    process.create_time.filetime()
}

/// Build the parent/child hierarchy of a process list.
///
/// Never fails and never loses a process. See [`ParentLink`] for what each edge
/// rests on, and [`ProcessTree::render_order`] for drawing it.
///
/// The list's own completeness travels onto the tree, so a caller stamping an
/// artifact asks [`ProcessTree::is_complete`] rather than reaching back to the
/// list — which would report a tree of ambiguous edges as complete whenever the
/// walk that produced it happened to finish.
pub fn build_tree(list: &ProcessList) -> ProcessTree {
    let count = list.processes.len();
    let mut by_pid: HashMap<u64, Vec<usize>> = HashMap::new();
    for (index, process) in list.processes.iter().enumerate() {
        if let Some(&pid) = process.pid.known() {
            by_pid.entry(pid).or_default().push(index);
        }
    }

    let mut parent: Vec<Option<usize>> = vec![None; count];
    let mut link: Vec<ParentLink> = vec![ParentLink::Unknown; count];

    for index in 0..count {
        let (chosen, decided) = choose_parent(list, &by_pid, index);
        parent[index] = chosen;
        link[index] = decided;
    }

    break_cycles(&mut parent, &mut link, list);

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); count];
    let mut roots: Vec<usize> = Vec::new();
    for (index, slot) in parent.iter().enumerate().take(count) {
        match *slot {
            Some(owner) => children[owner].push(index),
            None => roots.push(index),
        }
    }

    // Deterministic ordering: two runs over the same image must render the same
    // tree, and the list's own order depends on which direction each entry was
    // reached from.
    let key = |index: &usize| {
        let process = &list.processes[*index];
        (process.pid.known().copied(), process.address)
    };
    roots.sort_by_key(key);
    for bucket in &mut children {
        bucket.sort_by_key(key);
    }

    let depth = compute_depths(&roots, &children, count);

    let nodes = (0..count)
        .map(|index| TreeNode {
            address: list.processes[index].address,
            pid: list.processes[index].pid.known().copied(),
            ppid: list.processes[index].ppid.known().copied(),
            parent: parent[index],
            children: children[index].clone(),
            depth: depth[index],
            link: link[index].clone(),
        })
        .collect();

    ProcessTree {
        nodes,
        roots,
        list_complete: list.is_complete(),
    }
}

/// Pick the parent of one process, and say what the choice rests on.
///
/// The PID-reuse rule: a parent must have been created **before** its child.
/// Windows reissues PIDs within seconds on a busy machine, so a PID match alone
/// routinely names a process that started after the one it would be the parent
/// of. Where the times settle it, they are used; where they do not, the edge is
/// either declared unverified or not drawn at all.
fn choose_parent(
    list: &ProcessList,
    by_pid: &HashMap<u64, Vec<usize>>,
    index: usize,
) -> (Option<usize>, ParentLink) {
    let child = &list.processes[index];
    let Some(&ppid) = child.ppid.known() else {
        return (None, ParentLink::Unknown);
    };

    let mut candidates: Vec<usize> = by_pid
        .get(&ppid)
        .map(|found| {
            found
                .iter()
                .copied()
                .filter(|&other| other != index)
                .collect()
        })
        .unwrap_or_default();
    candidates.sort_by_key(|&other| list.processes[other].address);

    if candidates.is_empty() {
        return (
            None,
            ParentLink::Orphaned {
                ppid,
                detail: format!(
                    "no process on the list carries the parent id {ppid}, so the parent had \
                     already exited"
                ),
            },
        );
    }

    let child_time = create_filetime(child);
    // Only a candidate created no later than the child can be its parent.
    let plausible: Vec<(usize, u64)> = match child_time {
        Some(born) => candidates
            .iter()
            .filter_map(|&other| {
                create_filetime(&list.processes[other])
                    .filter(|&parent_born| parent_born <= born)
                    .map(|parent_born| (other, parent_born))
            })
            .collect(),
        None => Vec::new(),
    };

    let addresses: Vec<u64> = candidates
        .iter()
        .map(|&other| list.processes[other].address)
        .collect();

    if candidates.len() == 1 {
        let only = candidates[0];
        let parent_time = create_filetime(&list.processes[only]);
        return match (child_time, parent_time) {
            (Some(_), Some(_)) if !plausible.is_empty() => (Some(only), ParentLink::Confirmed),
            (Some(born), Some(parent_born)) => (
                None,
                ParentLink::Orphaned {
                    ppid,
                    detail: format!(
                        "the only process carrying id {ppid} was created at {parent_born}, after \
                         this one at {born}, so it is not the parent and the id has been reused"
                    ),
                },
            ),
            _ => (
                Some(only),
                ParentLink::Unverified {
                    detail: format!(
                        "one process carries id {ppid}, but the create times could not be \
                         compared, so process-id reuse cannot be ruled out"
                    ),
                },
            ),
        };
    }

    // Several processes carry the parent id, which is process-id reuse by
    // definition. The latest one created before the child is the best available
    // answer; there is no better one on the list alone.
    match plausible
        .iter()
        .max_by_key(|&&(other, born)| (born, std::cmp::Reverse(list.processes[other].address)))
    {
        Some(&(chosen, born)) => (
            Some(chosen),
            ParentLink::Ambiguous {
                candidates: addresses,
                detail: format!(
                    "{} processes carry id {ppid}; the one created at {born} was chosen as the \
                     latest that precedes this process",
                    candidates.len()
                ),
            },
        ),
        None => (
            None,
            ParentLink::Ambiguous {
                candidates: addresses,
                detail: format!(
                    "{} processes carry id {ppid} and none of them could be shown to precede this \
                     process, so no parent edge was drawn",
                    candidates.len()
                ),
            },
        ),
    }
}

/// Break every parent cycle, marking the edge that closed it.
///
/// A smeared list, or one a rootkit edited, can make two processes name each
/// other as parent. Left alone that is an infinite descent in any renderer.
/// This is the standard three-colour walk: each node is entered once, so the
/// whole pass is linear in the number of processes and cannot itself loop.
fn break_cycles(parent: &mut [Option<usize>], link: &mut [ParentLink], list: &ProcessList) {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Mark {
        Unseen,
        OnPath,
        Settled,
    }

    let count = parent.len();
    let mut mark = vec![Mark::Unseen; count];

    for start in 0..count {
        if mark[start] != Mark::Unseen {
            continue;
        }
        let mut path: Vec<usize> = Vec::new();
        let mut cursor = start;
        loop {
            match mark[cursor] {
                Mark::OnPath => {
                    // `cursor` is already on the path being walked, so the edge
                    // from the node we just came through closes a loop.
                    if let Some(&last) = path.last() {
                        parent[last] = None;
                        link[last] = ParentLink::Cycle {
                            detail: format!(
                                "following parent ids from here returns to the process at {:#x}, \
                                 so the chain does not terminate and this edge was not drawn",
                                list.processes[cursor].address
                            ),
                        };
                    }
                    break;
                }
                Mark::Settled => break,
                Mark::Unseen => {
                    mark[cursor] = Mark::OnPath;
                    path.push(cursor);
                    match parent[cursor] {
                        Some(next) => cursor = next,
                        None => break,
                    }
                }
            }
        }
        for &node in &path {
            mark[node] = Mark::Settled;
        }
    }
}

/// Depth of every node, by descent from the roots.
///
/// Iterative and visit-guarded. The parent links are acyclic by the time this
/// runs, and the guard is kept anyway because a depth computation that can loop
/// is worse than one that reports a wrong number.
fn compute_depths(roots: &[usize], children: &[Vec<usize>], count: usize) -> Vec<u32> {
    let mut depth = vec![0u32; count];
    let mut seen = vec![false; count];
    let mut stack: Vec<(usize, u32)> = roots.iter().map(|&root| (root, 0)).collect();

    while let Some((index, level)) = stack.pop() {
        if index >= count || seen[index] {
            continue;
        }
        seen[index] = true;
        depth[index] = level;
        let next = level.saturating_add(1);
        for &child in &children[index] {
            if !seen.get(child).copied().unwrap_or(true) {
                stack.push((child, next));
            }
        }
    }
    depth
}

// ── Provenance of a process's own address space ─────────────────────────────

/// Where the page-table walk found the entry that resolved one page.
///
/// # What an examiner learns
///
/// Whether bytes quoted from that page are **shared**. A page resolved through
/// a section object's prototype PTE belongs to that section — a mapped file or
/// a shared memory region — and can be mapped into other processes at the same
/// time. "This process held these bytes" is then a statement about a shared
/// mapping, not about memory private to the process, and a report that merges
/// the two claims more than the evidence carries.
///
/// # What a wrong answer would look like
///
/// Reading [`PageBacking::PageTables`] as "private to this process". It is not,
/// and this walk cannot establish that it is: once a shared page is resident,
/// the hardware page-table entry points straight at the frame and the prototype
/// PTE is never consulted, so the ordinary path is exactly what a resident
/// shared page looks like. Only [`PageBacking::SharedSection`] is a positive
/// finding. The other two variants say the question was not answered, and
/// nothing here may be read as evidence that a page is private.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PageBacking {
    /// A prototype PTE resolved the page. It is section-backed, and therefore
    /// shared rather than private to this process.
    SharedSection {
        /// Kernel virtual address of the prototype PTE that resolved it.
        proto_va: u64,
        /// Physical address that prototype PTE was read from.
        proto_pa: u64,
    },
    /// The hardware page tables resolved it outright. **Not** evidence that the
    /// page is private; see this type's own note.
    PageTables,
    /// The address did not translate, so nothing can be said about its backing.
    /// The string says why.
    NotEstablished(String),
}

impl PageBacking {
    /// What the walk says about `va` in `layer`.
    ///
    /// The one place [`seance_memory::translate::Translation::via`] is read.
    /// The walk is repeated rather than remembered because a read goes through
    /// [`seance_memory::MemoryLayer`], which returns bytes and not the path the
    /// bytes were found by; the table cache makes the second walk a memo
    /// lookup.
    pub fn of(layer: &VirtualLayer, va: u64) -> PageBacking {
        match layer.translate(va) {
            Ok(translation) => match translation.via {
                TranslationPath::PrototypePte { proto_va, proto_pa } => {
                    PageBacking::SharedSection { proto_va, proto_pa }
                }
                TranslationPath::PageTables => PageBacking::PageTables,
            },
            Err(err) => PageBacking::NotEstablished(err.to_string()),
        }
    }

    /// Whether the page is established as shared.
    ///
    /// False covers both "the hardware tables resolved it" and "it did not
    /// translate", neither of which is evidence of privacy.
    pub fn is_shared(&self) -> bool {
        matches!(self, PageBacking::SharedSection { .. })
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            PageBacking::SharedSection { .. } => "shared_section",
            PageBacking::PageTables => "page_tables",
            PageBacking::NotEstablished(_) => "not_established",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            PageBacking::SharedSection { proto_va, proto_pa } => with_addresses(
                serde_json::json!({
                    "kind": self.as_str(),
                    "shared": true,
                    "meaning": "A prototype PTE resolved this page, so it belongs to a section \
                                object — a mapped file or shared memory — and may be mapped into \
                                other processes as well. Bytes read from it are not private to \
                                this process.",
                }),
                |object| {
                    put_address(object, "proto_va", *proto_va);
                    put_address(object, "proto_pa", *proto_pa);
                },
            ),
            PageBacking::PageTables => serde_json::json!({
                "kind": self.as_str(),
                "shared": false,
                "meaning": "The hardware page tables resolved this page. That does NOT establish \
                            that it is private to this process: a resident shared page has a \
                            valid hardware entry and never consults its prototype PTE.",
            }),
            PageBacking::NotEstablished(detail) => serde_json::json!({
                "kind": self.as_str(),
                "shared": serde_json::Value::Null,
                "detail": detail,
                "meaning": "The address did not translate, so nothing is known about how this \
                            page is backed.",
            }),
        }
    }
}

/// One page a record was read out of, and what resolved it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageProvenance {
    /// What the page held, in the examiner's terms.
    pub what: &'static str,
    /// The virtual address examined, in the process's own address space.
    pub va: u64,
    /// What resolved it.
    pub backing: PageBacking,
}

impl PageProvenance {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        with_addresses(
            serde_json::json!({
                "what": self.what,
                "backing": self.backing.to_json(),
            }),
            |object| put_address(object, "va", self.va),
        )
    }
}

/// What a process's own address space reported while a record was read from it.
///
/// Two facts no read returns on its own, and both are provenance an examiner is
/// entitled to see beside the record they qualify.
///
/// # The suppression count
///
/// [`TranslationPolicy::suppress_uniform_tables`] — on by default — makes the
/// walker treat a page-sized table whose entries are all identical and present
/// as absent, because Windows maps unused address ranges that way and following
/// them turns minutes into hours. Every refusal is visible on the read that hit
/// it, as a suppressed-table hole no consumer can confuse with an absent page.
/// The running **total**, though, lives only on the layer, and the layer does
/// not outlive the stage that built it. This is where it reaches the record, so
/// that an examiner asking *could this tool have hidden a page from me* gets a
/// number rather than silence.
///
/// `None` is **not** zero. Zero means the heuristic never fired while this
/// record was read. `None` means no address space of this process was built
/// here, so the question was never put — and the two must never render alike.
///
/// # The page paths
///
/// [`PageProvenance`] names the pages the record's own evidence came out of and
/// what resolved each one. See [`PageBacking`] for what may and may not be
/// concluded from it; in particular an empty `pages` list, or a list of
/// [`PageBacking::PageTables`], is not a finding that anything was private.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SpaceProvenance {
    /// Translations refused under the uniform-table heuristic, or `None` when
    /// no address space was built and the counter could not be reached.
    pub uniform_tables_suppressed: Option<u64>,
    /// The pages this record's evidence was read out of.
    pub pages: Vec<PageProvenance>,
}

impl SpaceProvenance {
    /// The provenance of a record no address space was built for.
    ///
    /// Both facts absent rather than zero and empty, because nothing was asked.
    pub fn not_built() -> SpaceProvenance {
        SpaceProvenance::default()
    }

    /// Whether any page examined is established as shared.
    pub fn any_page_shared(&self) -> bool {
        self.pages.iter().any(|page| page.backing.is_shared())
    }

    /// Whether the uniform-table heuristic refused anything.
    ///
    /// `None` when no address space was built, so the question was never put.
    pub fn suppression_occurred(&self) -> Option<bool> {
        self.uniform_tables_suppressed.map(|count| count > 0)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let suppression_meaning = match self.uniform_tables_suppressed {
            None => {
                "No address space of this process was built here, so it is not known whether the \
                 uniform-table heuristic refused anything. This is an absent answer, not a count \
                 of zero."
            }
            Some(0) => {
                "The uniform-table heuristic refused nothing while this record was read: it hid \
                 no page from this result."
            }
            Some(_) => {
                "Translations the uniform-table heuristic refused while this record was read. It \
                 counts refusals, not distinct tables — many addresses behind one suppressed \
                 table are many here — and each refusal is also visible as a suppressed-table \
                 hole on the read that hit it."
            }
        };
        serde_json::json!({
            "uniform_tables_suppressed": self.uniform_tables_suppressed,
            "uniform_tables_suppression_occurred": self.suppression_occurred(),
            "uniform_tables_suppressed_meaning": suppression_meaning,
            "pages": self.pages.iter().map(PageProvenance::to_json).collect::<Vec<_>>(),
            "any_page_shared": self.any_page_shared(),
            "shared_meaning": "A page resolved through a section object's prototype PTE is \
                               shared, so bytes read from it are not private to this process. A \
                               page resolved by the hardware page tables is NOT thereby private: \
                               a resident shared page never consults its prototype.",
        })
    }
}

// ── The process's own address space ─────────────────────────────────────────

/// The paging mode the kernel address space was built with.
///
/// Read from the layer's own published metadata rather than inferred from the
/// architecture, because 32-bit Windows runs both PAE and non-PAE paging and
/// the two disagree about the width of every page-table entry. A layer that
/// does not publish one is refused: choosing a mode would build an address
/// space whose every translation is wrong and whose every read still returns
/// bytes.
fn paging_mode_of(profile: &WindowsProfile) -> Result<PagingMode, ProcessError> {
    let note = profile
        .kernel_space
        .layer_meta()
        .note("paging_mode")
        .and_then(|value| value.as_str().map(str::to_string))
        .ok_or_else(|| {
            ProcessError::unsupported(
                "the kernel address space does not publish the paging mode it was built with, so \
                 a process's own address space cannot be built without guessing between PAE and \
                 non-PAE paging",
            )
        })?;
    match note.as_str() {
        "intel32" => Ok(PagingMode::Intel32),
        "intel_pae" => Ok(PagingMode::IntelPae),
        "intel32e" => Ok(PagingMode::Intel32e),
        other => Err(ProcessError::unsupported(format!(
            "the kernel address space was built with paging mode {other:?}, which this tier \
             cannot reproduce for a process"
        ))),
    }
}

/// Read a process's directory table base out of its `_KPROCESS`.
///
/// Two shapes, both real: 64-bit builds declare it as one `ULONGLONG`, and
/// 32-bit builds declare it as `ULONG[2]`, where the second element is the
/// hyperspace mapping and only the first is the base. Reading the array as a
/// scalar yields a value the low half of which is right and the whole of which
/// is not an address at all.
///
/// # Why not `UserDirectoryTableBase`
///
/// Builds from Windows 10 1803 onwards carry a second field,
/// `_KPROCESS.UserDirectoryTableBase`, added for KVA Shadow — the Meltdown
/// mitigation that gives each process a second set of page tables. It is
/// tempting to read that one for user memory on the strength of its name, and
/// it would be wrong twice over.
///
/// `DirectoryTableBase` is the table loaded into `CR3` in **kernel** mode, and
/// it maps the whole address space: kernel *and* user. It has to, because
/// kernel code dereferences user buffers directly. `UserDirectoryTableBase` is
/// the *shadow* table loaded in user mode, which maps user space plus only the
/// handful of kernel trampoline pages the transition needs — so it is strictly
/// less, never more. Reading a user address through `DirectoryTableBase`
/// therefore succeeds on a KVA Shadow build exactly as it does without one, and
/// nothing here is short of a page because of Meltdown mitigation.
///
/// The shadow field is also not always an address: Windows stores `1` in it to
/// mean the process is not shadowed, which is not page-aligned and names no
/// page table. Preferring it would build spaces rooted at physical zero for
/// every such process, and lose kernel mappings for the rest.
fn directory_table_base(
    object: &Obj,
    symbols: &ProcessSymbols,
    mask: u64,
) -> Result<u64, ProcessError> {
    let path = symbols.directory_table_base.as_str();
    let raw = if symbols.dtb_is_array {
        object.element_int(path, 0)?
    } else {
        object.int(path)?
    };
    let value = raw.as_u64().ok_or_else(|| {
        SymbolError::malformed(format!(
            "'{}.{path}' is negative, which is not a directory table base",
            object.type_name()
        ))
    })?;
    Ok(value & mask)
}

/// Build one process's own virtual address space.
///
/// `process` is the address of an `_EPROCESS` in the **kernel** space. The
/// layer this returns addresses that process's *user* memory, which is where
/// its PEB, its command line and its loaded module list all live.
///
/// `cache` should be the same [`TableCache`] for every process over one image:
/// page-table entries are keyed by physical address and mean the same thing in
/// every address space, so sharing one memo keeps a case with four hundred
/// processes to one bounded cache rather than four hundred.
///
/// # Errors
///
/// [`ProcessError::Unsupported`] when the kernel space does not publish its
/// paging mode, or when the process's directory table base names no page table
/// — a base of zero, or one whose page frame is zero, which is what an exited
/// process leaves behind. Refusing is the point: a space rooted at physical
/// zero reads whatever lies at the bottom of the image and produces confident
/// nonsense.
pub fn process_address_space(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    process: u64,
    cache: &Arc<TableCache>,
) -> Result<Arc<dyn MemoryLayer>, ProcessError> {
    let layer: Arc<dyn MemoryLayer> = process_virtual_space(profile, symbols, process, cache)?;
    Ok(layer)
}

/// The same space, with its concrete type kept.
///
/// [`process_address_space`] erases the layer to `dyn MemoryLayer`, which is
/// everything a reader needs to fetch bytes. The concrete layer is what carries
/// [`VirtualLayer::uniform_tables_suppressed`] and
/// [`VirtualLayer::translate`], and a caller that means to state the provenance
/// of what it read — how many translations the uniform-table heuristic refused,
/// and whether a page came through a section object's prototype PTE — has to
/// hold on to it. See [`SpaceProvenance`].
///
/// # Errors
///
/// Exactly those of [`process_address_space`], which is a thin wrapper over
/// this.
pub fn process_virtual_space(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    process: u64,
    cache: &Arc<TableCache>,
) -> Result<Arc<VirtualLayer>, ProcessError> {
    let mode = paging_mode_of(profile)?;
    // State which `MMPTE_SOFTWARE.PageFileLow` layout this build uses, so a
    // swapped-out page names the right pagefile. `is_win8_or_later` returns
    // `Option<bool>` precisely so "the build was never established" cannot be
    // mistaken for "not Windows 8"; when it is `None` the spec is left unset
    // and declines to name a pagefile at all.
    let spec = match profile.build.is_win8_or_later() {
        Some(win8) => PagingSpec::new(mode, PteSemantics::Windows).with_win8_pagefile_layout(win8),
        None => PagingSpec::new(mode, PteSemantics::Windows),
    };
    let bits = spec.bits_per_register();
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits).saturating_sub(1)
    };

    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let object = reader.object(process, TYPE_EPROCESS)?;
    let dtb = directory_table_base(&object, symbols, mask)?;
    // The low twelve bits of a directory table base are flags and a process
    // context id, never part of the frame. A base whose frame is zero is not a
    // page table, however many low bits are set.
    if dtb & !0xFFF == 0 {
        return Err(ProcessError::unsupported(format!(
            "the process at {process:#x} has directory table base {dtb:#x}, which names no page \
             table, so it has no address space to read"
        )));
    }

    let layer = VirtualLayer::with_cache(
        Arc::clone(&profile.physical),
        dtb,
        spec,
        TranslationPolicy::default(),
        Arc::clone(cache),
    )?
    // Most swapped pages are a process's, not the kernel's, so this is where
    // an attached pagefile earns its keep. Empty unless the examiner named one.
    .with_swap(profile.pagefiles.clone());
    Ok(Arc::new(layer))
}

/// What one process's address space reported, naming the pages that mattered.
///
/// `pages` is `(what the page held, its virtual address in this space)`. Each
/// is translated so the record can say whether the bytes quoted from it are
/// shared; the table cache makes that a memo lookup rather than a second walk.
///
/// The counter is read **before** those translations and the field order below
/// is what does it. The number is meant to be the refusals the record's own
/// reads provoked; counting the probes made to describe them would inflate it
/// with work the examiner never asked for.
fn space_provenance(layer: &VirtualLayer, pages: &[(&'static str, u64)]) -> SpaceProvenance {
    SpaceProvenance {
        uniform_tables_suppressed: Some(layer.uniform_tables_suppressed()),
        pages: pages
            .iter()
            .map(|&(what, va)| PageProvenance {
                what,
                va,
                backing: PageBacking::of(layer, va),
            })
            .collect(),
    }
}

// ── Command lines ───────────────────────────────────────────────────────────

/// A process's command line, with every way of not having one kept apart.
///
/// Five outcomes rather than "a string or nothing", because the differences
/// carry findings. `svchost.exe` with no arguments and `svchost.exe` whose
/// arguments were never captured look identical if both render as an empty
/// cell, and the arguments are the whole point of examining `svchost.exe`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandLine {
    /// The process has no user address space, so there is no PEB and no command
    /// line to have. The ordinary state of System, Registry and Memory
    /// Compression. Not a failure.
    NoUserSpace,
    /// The PEB was readable and its `ProcessParameters` pointer is null, which
    /// is what a process caught during creation looks like.
    NoParameters,
    /// The `CommandLine` string is present and zero bytes long: the process
    /// really was started with an empty command line.
    Empty,
    /// The command line.
    Line {
        /// The text, decoded from UTF-16LE.
        text: String,
        /// Whether every code unit decoded cleanly. `false` means unpaired
        /// surrogates were replaced to render it, so the text on screen is not
        /// byte-for-byte what the process held — which is itself a finding, and
        /// is flagged rather than hidden.
        well_formed: bool,
    },
    /// The command line exists and could not be read: the PEB or the parameter
    /// block was paged out, the process's page tables could not be walked, or
    /// the declared length was not a length. Never an empty string.
    Unavailable(String),
}

impl CommandLine {
    /// The text, when there is one.
    pub fn text(&self) -> Option<&str> {
        match self {
            CommandLine::Line { text, .. } => Some(text),
            _ => None,
        }
    }

    /// Whether the answer is a positive statement about the process rather than
    /// a gap in the evidence.
    pub fn is_answered(&self) -> bool {
        !matches!(self, CommandLine::Unavailable(_))
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            CommandLine::NoUserSpace => "no_user_space",
            CommandLine::NoParameters => "no_parameters",
            CommandLine::Empty => "empty",
            CommandLine::Line { .. } => "line",
            CommandLine::Unavailable(_) => "unavailable",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            CommandLine::Line { text, well_formed } => serde_json::json!({
                "kind": "line",
                "text": text,
                "well_formed": well_formed,
            }),
            CommandLine::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
            other => serde_json::json!({"kind": other.as_str()}),
        }
    }
}

/// One process's command line, with enough of the process to identify the row.
#[derive(Debug, Clone)]
pub struct CommandLineRecord {
    /// Kernel address of the `_EPROCESS`.
    pub address: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// The image name, when it was readable.
    pub image_file_name: Option<String>,
    /// The command line, or why there is not one.
    pub command_line: CommandLine,
    /// What the process's own address space reported while this record was
    /// read: how many translations the uniform-table heuristic refused, and
    /// whether the pages the text came out of are shared.
    ///
    /// [`SpaceProvenance::not_built`] for a process no address space was built
    /// for — a kernel process with no PEB, or one whose directory table base
    /// names no page table. That is an absent answer, not a clean one.
    pub space: SpaceProvenance,
}

impl CommandLineRecord {
    /// Serializable form for the command-line artifact.
    ///
    /// `address` is the `_EPROCESS` pointer and carries its exact hex beside
    /// the number, for the reason [`put_address`] gives.
    pub fn to_json(&self) -> serde_json::Value {
        with_addresses(
            serde_json::json!({
                "pid": self.pid,
                "image_file_name": self.image_file_name,
                "command_line": self.command_line.to_json(),
                "space": self.space.to_json(),
            }),
            |object| put_address(object, "address", self.address),
        )
    }
}

/// Read a `_UNICODE_STRING` member, with the four things a naive reader gets
/// wrong.
///
/// * **`Length` counts bytes, not characters.** Halving it reads half the
///   string and can split a surrogate pair.
/// * **The length is capped before anything is allocated.** It came out of the
///   image, and a corrupt `USHORT` must not become an allocation per process.
/// * **`MaximumLength` must not be below `Length`.** A string claiming more
///   text than its buffer holds is not a string, and reading it anyway reads
///   whatever follows the buffer.
/// * **No NUL termination is assumed.** Kernel `_UNICODE_STRING`s frequently
///   are not terminated; exactly `Length` bytes are read.
///
/// `Ok(None)` is a genuinely zero-length string, which is a different fact from
/// an unreadable one.
///
/// The buffer's address travels back with the text so a caller can say which
/// page the quoted bytes actually came out of — see [`SpaceProvenance`]. It is
/// returned rather than re-derived because re-reading `Buffer` after the fact
/// would read whatever is at that offset *now*, which on a smeared image is not
/// necessarily what the text was read through.
fn read_unicode_string(
    object: &Obj,
    path: &str,
    cap: u64,
) -> Result<Option<(String, bool, u64)>, ObjError> {
    let length = object
        .int(&format!("{path}.Length"))?
        .as_u64()
        .ok_or_else(|| {
            SymbolError::malformed(format!(
                "'{}.{path}.Length' is negative, which is not a length",
                object.type_name()
            ))
        })?;
    if length == 0 {
        return Ok(None);
    }
    if length % 2 != 0 {
        return Err(SymbolError::malformed(format!(
            "'{}.{path}' declares {length} byte(s) of UTF-16 text, which is not a whole number of \
             code units",
            object.type_name()
        ))
        .into());
    }
    if length > cap {
        return Err(ObjError::Cap {
            what: "the declared byte length of a _UNICODE_STRING",
            cap,
        });
    }
    if let Ok(maximum) = object.int(&format!("{path}.MaximumLength")) {
        if let Some(maximum) = maximum.as_u64() {
            if maximum < length {
                return Err(SymbolError::malformed(format!(
                    "'{}.{path}' declares {length} byte(s) of text in a buffer of {maximum}",
                    object.type_name()
                ))
                .into());
            }
        }
    }
    let buffer = object.int(&format!("{path}.Buffer"))?.as_u64().unwrap_or(0);
    if buffer == 0 {
        return Err(SymbolError::malformed(format!(
            "'{}.{path}' declares {length} byte(s) of text and a null buffer",
            object.type_name()
        ))
        .into());
    }
    let bytes = object.reader().read_bytes(buffer, length)?;
    let (text, well_formed) = decode_utf16le(&bytes);
    Ok(Some((text, well_formed, buffer)))
}

/// Read the command line out of a PEB, in a reader over the **process's own**
/// address space.
///
/// Separated from [`read_command_line`] so the decoding is testable without a
/// page-table walk, and so a caller that already holds a process address space
/// — one dumping several things out of the same process — does not build a
/// second one.
///
/// `peb` is an address in that reader's space. Passing a reader over the kernel
/// space instead is the mistake this signature exists to make visible: the
/// answer would be whatever the kernel maps at a user address.
pub fn read_command_line_in(reader: &StructReader, peb: u64) -> CommandLine {
    read_command_line_pages(reader, peb).0
}

/// The command line, and the addresses in this space its evidence came from.
///
/// The pages are named as they are reached, so a caller holding the concrete
/// [`VirtualLayer`] can say how each one was resolved — see [`PageBacking`].
/// A page that was never reached is not in the list, which is why an empty list
/// is a statement that nothing was examined rather than that nothing was
/// shared.
fn read_command_line_pages(
    reader: &StructReader,
    peb: u64,
) -> (CommandLine, Vec<(&'static str, u64)>) {
    if peb == 0 {
        return (CommandLine::NoUserSpace, Vec::new());
    }
    let mut pages: Vec<(&'static str, u64)> = vec![("the process environment block", peb)];
    let block = match reader.object(peb, TYPE_PEB) {
        Ok(block) => block,
        Err(err) => return (CommandLine::Unavailable(err.to_string()), pages),
    };
    let parameters = match block.int("ProcessParameters") {
        Ok(value) => value.as_u64().unwrap_or(0),
        Err(err) => return (CommandLine::Unavailable(err.to_string()), pages),
    };
    if parameters == 0 {
        return (CommandLine::NoParameters, pages);
    }
    pages.push(("the process parameter block", parameters));
    let block = match reader.object(parameters, TYPE_PROCESS_PARAMETERS) {
        Ok(block) => block,
        Err(err) => return (CommandLine::Unavailable(err.to_string()), pages),
    };
    match read_unicode_string(&block, "CommandLine", MAX_COMMAND_LINE_BYTES) {
        Ok(Some((text, well_formed, buffer))) => {
            pages.push(("the command line text", buffer));
            (CommandLine::Line { text, well_formed }, pages)
        }
        Ok(None) => (CommandLine::Empty, pages),
        Err(err) => (CommandLine::Unavailable(err.to_string()), pages),
    }
}

/// Read one process's command line, building its address space to do it.
///
/// `process` is the address of an `_EPROCESS` in the kernel space. Never fails:
/// every way of not getting an answer is one of the [`CommandLine`] variants,
/// so a caller cannot accidentally render a failure as an empty command line.
pub fn read_command_line(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    process: u64,
    cache: &Arc<TableCache>,
) -> CommandLine {
    read_command_line_with_provenance(profile, symbols, process, cache).0
}

/// The command line, and what the process's own address space reported while it
/// was read.
///
/// The provenance is produced here rather than left to the caller because the
/// [`VirtualLayer`] it comes off is built here and dropped here: its
/// suppression counter and its translation paths cannot be recovered afterwards
/// from the bytes alone. See [`SpaceProvenance`] for what each half means, and
/// in particular for why [`SpaceProvenance::not_built`] is not a count of zero.
pub fn read_command_line_with_provenance(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    process: u64,
    cache: &Arc<TableCache>,
) -> (CommandLine, SpaceProvenance) {
    let unresolved = |line: CommandLine| (line, SpaceProvenance::not_built());

    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let object = match kernel.object(process, TYPE_EPROCESS) {
        Ok(object) => object,
        Err(err) => return unresolved(CommandLine::Unavailable(err.to_string())),
    };
    let Some(path) = symbols.peb.as_deref() else {
        return unresolved(CommandLine::Unavailable(format!(
            "this build's '{TYPE_EPROCESS}' has no Peb member, so no process's command line can \
             be reached"
        )));
    };
    let peb = match object.int(path) {
        Ok(value) => value.as_u64().unwrap_or(0),
        Err(err) => return unresolved(CommandLine::Unavailable(err.to_string())),
    };
    if peb == 0 {
        return unresolved(CommandLine::NoUserSpace);
    }

    let space = match process_virtual_space(profile, symbols, process, cache) {
        Ok(space) => space,
        Err(err) => return unresolved(CommandLine::Unavailable(err.to_string())),
    };
    // Method syntax, not `Arc::clone(&space)`: the latter takes its type
    // parameter from the annotation and would demand `&Arc<dyn MemoryLayer>`.
    // `space` stays owned here because `space_provenance` reads it after the walk.
    let bytes: Arc<dyn MemoryLayer> = space.clone();
    let reader = StructReader::new(bytes, Arc::clone(&profile.symbols));
    let (line, pages) = read_command_line_pages(&reader, peb);
    // Read after the walk, not before: the counter is a running total on the
    // layer, and the refusals that matter are the ones this read provoked.
    (line, space_provenance(&space, &pages))
}

/// Every process's command line, and what could not be established.
///
/// The result of the `command_lines` stage. A vector of records would not do:
/// "this machine ran no process with arguments" and "no process's arguments
/// could be read" produce the same rows and opposite conclusions, so the
/// listing carries its own verdict.
#[derive(Debug, Clone)]
pub struct CommandLineListing {
    /// One record per process on the list, in the list's order. A process whose
    /// command line could not be read is still here, carrying the reason.
    pub records: Vec<CommandLineRecord>,
}

/// Ceiling on command lines named individually in
/// [`CommandLineListing::incomplete`].
///
/// A capped image can hold tens of thousands of processes; the count stays
/// exact and only the naming is bounded.
pub const MAX_RECORDED_UNAVAILABLE: usize = 128;

impl CommandLineListing {
    /// How many processes gave a positive answer — a line, an empty line, no
    /// parameters, or no user address space at all.
    pub fn answered(&self) -> usize {
        self.records
            .iter()
            .filter(|record| record.command_line.is_answered())
            .count()
    }

    /// How many processes' command lines exist and could not be read.
    pub fn unavailable(&self) -> usize {
        self.records.len() - self.answered()
    }

    /// Whether every process on the list gave a positive answer.
    ///
    /// The question a report must ask before writing "these are the commands
    /// this machine ran": a listing with unreadable rows is a floor, and a
    /// missing command line reads exactly like a program started with none.
    pub fn is_complete(&self) -> bool {
        self.unavailable() == 0
    }

    /// Everything a report must declare about this listing.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let unreadable: Vec<&CommandLineRecord> = self
            .records
            .iter()
            .filter(|record| !record.command_line.is_answered())
            .collect();
        let mut out: Vec<Incomplete> = unreadable
            .iter()
            .take(MAX_RECORDED_UNAVAILABLE)
            .map(|record| {
                Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the command line of the process at {:#x} exists and could not be read, \
                         so it is unknown rather than absent",
                        record.address
                    ),
                )
            })
            .collect();
        let further = unreadable.len().saturating_sub(MAX_RECORDED_UNAVAILABLE);
        if further > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{further} further process(es) have a command line that could not be read and \
                     are not listed individually"
                ),
            ));
        }
        out
    }

    /// Serializable form for the command-line artifact.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "command_lines": self
                .records
                .iter()
                .map(CommandLineRecord::to_json)
                .collect::<Vec<_>>(),
            "count": self.records.len(),
            "answered": self.answered(),
            "unavailable": self.unavailable(),
            "complete": self.is_complete(),
            "incomplete": self
                .incomplete()
                .iter()
                .map(Incomplete::to_json)
                .collect::<Vec<_>>(),
        })
    }
}

/// Read the command line of every process on a list.
///
/// One [`TableCache`] is shared across every process, because a page-table
/// entry means the same thing in every address space over the same physical
/// memory.
pub fn read_command_lines(
    profile: &WindowsProfile,
    symbols: &ProcessSymbols,
    list: &ProcessList,
) -> CommandLineListing {
    let cache = Arc::new(TableCache::new());
    CommandLineListing {
        records: list
            .processes
            .iter()
            .map(|process| {
                let (command_line, space) = match process.peb {
                    // The record already established that this process has no
                    // user address space; building one to rediscover that would
                    // be a page-table walk per kernel process for no answer, and
                    // the provenance says plainly that none was built.
                    Field::NotApplicable => {
                        (CommandLine::NoUserSpace, SpaceProvenance::not_built())
                    }
                    _ => {
                        read_command_line_with_provenance(profile, symbols, process.address, &cache)
                    }
                };
                CommandLineRecord {
                    address: process.address,
                    pid: process.pid.known().copied(),
                    image_file_name: process.image_file_name.known().cloned(),
                    command_line,
                    space,
                }
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image, IMAGE_SIZE};
    use seance_memory::Architecture;

    /// A structure straddling the end of the acquisition: its first sixteen
    /// bytes were captured and everything past them was not.
    ///
    /// Derived from [`IMAGE_SIZE`] rather than written out. It was written out
    /// once, as `0x1_FFF0`, and when the fixture image grew from 128 KiB to 192
    /// KiB that address moved *inside* the acquisition — so every test using it
    /// to mean "these bytes were never captured" silently became a test that
    /// the fixture reads back zeros, which is the opposite finding.
    const NOT_CAPTURED: u64 = IMAGE_SIZE as u64 - 0x10;

    // Where the synthetic 64-bit fixture puts things.
    const HEAD: u64 = 0x1000;
    const SYSTEM: u64 = 0x2000;
    const SMSS: u64 = 0x3000;
    const CSRSS: u64 = 0x4000;
    const HANDLE_TABLE_AT: u64 = 0x9000;
    const SESSION_AT: u64 = 0x9100;
    const PEB_AT: u64 = 0xA000;
    const PARAMS_AT: u64 = 0xA100;
    const CMDLINE_AT: u64 = 0xA200;

    /// Two real FILETIMEs, ordered, so a parent can precede its child.
    const EARLY: u64 = 129_067_776_000_000_000; // 2010-01-01T00:00:00Z
    const LATE: u64 = 129_067_776_010_000_000; // one second later

    /// Offsets the synthetic 64-bit ISF declares.
    mod off {
        pub(super) const DTB: u64 = 0;
        pub(super) const CREATE_TIME: u64 = 32;
        pub(super) const EXIT_TIME: u64 = 40;
        pub(super) const PID: u64 = 48;
        pub(super) const LINKS: u64 = 56;
        pub(super) const LINKS_BLINK: u64 = 64;
        pub(super) const PPID: u64 = 72;
        pub(super) const OBJECT_TABLE: u64 = 80;
        pub(super) const SESSION: u64 = 88;
        pub(super) const PEB: u64 = 96;
        pub(super) const WOW64: u64 = 104;
        pub(super) const THREADS: u64 = 112;
        pub(super) const NAME: u64 = 120;
        pub(super) const NAME_LEN: usize = 15;
    }

    /// Offsets the synthetic 32-bit ISF declares, mirroring the real XP build
    /// where `ActiveProcessLinks` sits 136 bytes into the structure.
    mod off32 {
        pub(super) const CREATE_TIME: u64 = 112;
        pub(super) const PID: u64 = 132;
        pub(super) const LINKS: u64 = 136;
        pub(super) const LINKS_BLINK: u64 = 140;
        pub(super) const PPID: u64 = 148;
        pub(super) const NAME: u64 = 352;
        pub(super) const THREADS: u64 = 392;
    }

    /// A synthetic 64-bit Windows ISF whose `ActiveProcessLinks` is deliberately
    /// well inside `_EPROCESS`, because a link at offset zero would let broken
    /// container arithmetic pass.
    fn windows64_process_isf() -> String {
        r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "1A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": {
    "pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long long": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_LIST_ENTRY": {"size": 16, "kind": "struct", "fields": {
      "Flink": {"offset": 0, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
      "Blink": {"offset": 8, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
    }},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_KPROCESS": {"size": 32, "kind": "struct", "fields": {
      "DirectoryTableBase": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_HANDLE_TABLE": {"size": 16, "kind": "struct", "fields": {
      "HandleCount": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_MM_SESSION_SPACE": {"size": 16, "kind": "struct", "fields": {
      "SessionId": {"offset": 8, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_RTL_USER_PROCESS_PARAMETERS": {"size": 128, "kind": "struct", "fields": {
      "CommandLine": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "ImagePathName": {"offset": 16, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_PEB": {"size": 64, "kind": "struct", "fields": {
      "ProcessParameters": {"offset": 32, "type": {"kind": "pointer",
                            "subtype": {"kind": "struct",
                                        "name": "_RTL_USER_PROCESS_PARAMETERS"}}}
    }},
    "_EPROCESS": {"size": 256, "kind": "struct", "fields": {
      "Pcb": {"offset": 0, "type": {"kind": "struct", "name": "_KPROCESS"}},
      "CreateTime": {"offset": 32, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ExitTime": {"offset": 40, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "UniqueProcessId": {"offset": 48, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned long long"}}},
      "ActiveProcessLinks": {"offset": 56, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InheritedFromUniqueProcessId": {"offset": 72, "type": {"kind": "pointer",
                                       "subtype": {"kind": "base", "name": "unsigned long long"}}},
      "ObjectTable": {"offset": 80, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_HANDLE_TABLE"}}},
      "Session": {"offset": 88, "type": {"kind": "pointer",
                  "subtype": {"kind": "base", "name": "unsigned long long"}}},
      "Peb": {"offset": 96, "type": {"kind": "pointer",
              "subtype": {"kind": "struct", "name": "_PEB"}}},
      "WoW64Process": {"offset": 104, "type": {"kind": "pointer",
                       "subtype": {"kind": "base", "name": "unsigned long long"}}},
      "ActiveThreads": {"offset": 112, "type": {"kind": "base", "name": "unsigned long"}},
      "ImageFileName": {"offset": 120, "type": {"kind": "array", "count": 15,
                        "subtype": {"kind": "base", "name": "unsigned char"}}}
    }}
  },
  "enums": {},
  "symbols": {
    "PsActiveProcessHead": {"address": 4096}
  }
}"#
        .to_string()
    }

    /// A synthetic 32-bit Windows XP ISF: four-byte pointers, an
    /// `ActiveProcessLinks` at 136, a `DirectoryTableBase` declared as an array,
    /// and no `WoW64Process`, `ObjectTable` or `Session` at all.
    fn windows32_process_isf() -> String {
        r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "2A1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 332}}
  },
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long long": {"size": 8, "signed": true, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned short": {"size": 2, "signed": false, "kind": "int", "endian": "little"},
    "unsigned char": {"size": 1, "signed": false, "kind": "int", "endian": "little"}
  },
  "user_types": {
    "_LIST_ENTRY": {"size": 8, "kind": "struct", "fields": {
      "Flink": {"offset": 0, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
      "Blink": {"offset": 4, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
    }},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_KPROCESS": {"size": 108, "kind": "struct", "fields": {
      "DirectoryTableBase": {"offset": 24, "type": {"kind": "array", "count": 2,
                             "subtype": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_UNICODE_STRING": {"size": 8, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 4, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_RTL_USER_PROCESS_PARAMETERS": {"size": 64, "kind": "struct", "fields": {
      "CommandLine": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_PEB": {"size": 32, "kind": "struct", "fields": {
      "ProcessParameters": {"offset": 16, "type": {"kind": "pointer",
                            "subtype": {"kind": "struct",
                                        "name": "_RTL_USER_PROCESS_PARAMETERS"}}}
    }},
    "_EPROCESS": {"size": 608, "kind": "struct", "fields": {
      "Pcb": {"offset": 0, "type": {"kind": "struct", "name": "_KPROCESS"}},
      "CreateTime": {"offset": 112, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "ExitTime": {"offset": 120, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "UniqueProcessId": {"offset": 132, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned long"}}},
      "ActiveProcessLinks": {"offset": 136, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InheritedFromUniqueProcessId": {"offset": 148, "type": {"kind": "pointer",
                                       "subtype": {"kind": "base", "name": "unsigned long"}}},
      "ImageFileName": {"offset": 352, "type": {"kind": "array", "count": 16,
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Peb": {"offset": 384, "type": {"kind": "pointer",
              "subtype": {"kind": "struct", "name": "_PEB"}}},
      "ActiveThreads": {"offset": 392, "type": {"kind": "base", "name": "unsigned long"}}
    }}
  },
  "enums": {},
  "symbols": {
    "PsActiveProcessHead": {"address": 4096}
  }
}"#
        .to_string()
    }

    fn profile64(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&windows64_process_isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    fn profile32(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&windows32_process_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        )
    }

    /// One 64-bit process, with its links left for the caller to thread.
    #[allow(clippy::too_many_arguments)]
    fn put_process(
        image: &mut Image,
        at: u64,
        pid: u64,
        ppid: u64,
        name: &[u8],
        threads: u32,
        create: u64,
        exit: u64,
    ) {
        image.put_u64(at + off::DTB, 0x1B000);
        image.put_u64(at + off::CREATE_TIME, create);
        image.put_u64(at + off::EXIT_TIME, exit);
        image.put_u64(at + off::PID, pid);
        image.put_u64(at + off::PPID, ppid);
        image.put_u32(at + off::THREADS, threads);
        // The array is written whole, so a shorter name leaves the NUL padding
        // a real kernel writes and a longer one is refused by the fixture
        // rather than silently spilling into the next member.
        let mut raw = [0u8; off::NAME_LEN];
        let take = name.len().min(off::NAME_LEN);
        raw[..take].copy_from_slice(&name[..take]);
        image.write(at + off::NAME, &raw);
    }

    /// Thread `entries` into a circular list whose head is `HEAD`.
    fn thread_list(image: &mut Image, entries: &[u64]) {
        let links: Vec<u64> = entries.iter().map(|at| at + off::LINKS).collect();
        let Some(&first) = links.first() else {
            return;
        };
        let Some(&last) = links.last() else {
            return;
        };
        image.put_u64(HEAD, first);
        image.put_u64(HEAD + 8, last);
        for (index, &link) in links.iter().enumerate() {
            let next = links.get(index + 1).copied().unwrap_or(HEAD);
            let previous = if index == 0 { HEAD } else { links[index - 1] };
            image.put_u64(link, next);
            image.put_u64(link + 8, previous);
        }
    }

    /// The three-process image every list test starts from: System, then smss,
    /// then csrss, each created after the last.
    fn three_process_image() -> Image {
        let mut image = Image::new();
        put_process(&mut image, SYSTEM, 4, 0, b"System", 61, EARLY, 0);
        put_process(&mut image, SMSS, 448, 4, b"smss.exe", 3, EARLY + 1, 0);
        put_process(&mut image, CSRSS, 504, 448, b"csrss.exe", 12, LATE, 0);
        thread_list(&mut image, &[SYSTEM, SMSS, CSRSS]);
        image
    }

    fn walk(profile: &WindowsProfile) -> (ProcessSymbols, ProcessList) {
        let symbols = ProcessSymbols::from_profile(profile).expect("a describable build");
        let list = list_processes(profile, &symbols, &ProcessListConfig::default())
            .expect("a runnable walk");
        (symbols, list)
    }

    fn names(list: &ProcessList) -> Vec<String> {
        list.processes
            .iter()
            .map(|process| {
                process
                    .image_file_name
                    .known()
                    .cloned()
                    .unwrap_or_else(|| "<unreadable>".to_string())
            })
            .collect()
    }

    // ── The list ────────────────────────────────────────────────────────────

    #[test]
    fn the_active_process_list_walks_from_the_kernel_symbol_and_reports_every_process() {
        let (_, list) = walk(&profile64(three_process_image()));
        assert_eq!(list.head, HEAD);
        assert_eq!(names(&list), vec!["System", "smss.exe", "csrss.exe"]);
        assert_eq!(
            list.processes
                .iter()
                .map(|process| process.pid.known().copied())
                .collect::<Vec<_>>(),
            vec![Some(4), Some(448), Some(504)]
        );
        assert_eq!(
            list.processes
                .iter()
                .map(|process| process.threads.known().copied())
                .collect::<Vec<_>>(),
            vec![Some(61), Some(3), Some(12)]
        );
        assert_eq!(list.forward_stop, ListStop::Wrapped);
        assert!(list.backward_stop.is_none());
        assert!(list.is_complete());
        assert!(list.incomplete().is_empty());
    }

    #[test]
    fn a_list_link_in_the_middle_of_the_structure_resolves_to_the_object_base() {
        // The one arithmetic mistake that produces a completely plausible wrong
        // answer. The raw link really does point 56 bytes into the structure;
        // the record must be the structure, not the link.
        let (symbols, list) = walk(&profile64(three_process_image()));
        assert_eq!(symbols.links_offset, off::LINKS);
        assert_eq!(list.links_offset, off::LINKS);
        assert_eq!(
            list.processes
                .iter()
                .map(|process| process.address)
                .collect::<Vec<_>>(),
            vec![SYSTEM, SMSS, CSRSS]
        );

        let profile = profile64(three_process_image());
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        assert_eq!(
            reader
                .read_pointer_at(HEAD)
                .expect("the head's forward link"),
            SYSTEM + off::LINKS,
            "the link points into the middle of the structure, not at its start"
        );
    }

    #[test]
    fn a_thirty_two_bit_build_walks_four_byte_links_at_the_offset_its_own_table_declares() {
        // Read at the host's eight bytes the head's link would be nonsense, and
        // subtracting the 64-bit build's offset would put every process 80
        // bytes from where it is — where the bytes still parse.
        let mut image = Image::new();
        image.put_u32(HEAD, (SYSTEM + off32::LINKS) as u32);
        image.put_u32(HEAD + 4, (SMSS + off32::LINKS) as u32);
        for (at, next, previous, pid, ppid, name) in [
            (SYSTEM, SMSS, HEAD, 4u32, 0u32, &b"System"[..]),
            (SMSS, 0, SYSTEM, 448, 4, &b"smss.exe"[..]),
        ] {
            let next = if next == 0 { HEAD } else { next + off32::LINKS };
            let previous = if previous == HEAD {
                HEAD
            } else {
                previous + off32::LINKS
            };
            image.put_u32(at + off32::LINKS, next as u32);
            image.put_u32(at + off32::LINKS_BLINK, previous as u32);
            image.put_u32(at + off32::PID, pid);
            image.put_u32(at + off32::PPID, ppid);
            image.put_u64(at + off32::CREATE_TIME, EARLY);
            image.put_u32(at + off32::THREADS, 7);
            let mut raw = [0u8; 16];
            raw[..name.len()].copy_from_slice(name);
            image.write(at + off32::NAME, &raw);
        }

        let profile = profile32(image);
        let symbols = ProcessSymbols::from_profile(&profile).expect("a describable build");
        assert_eq!(
            symbols.links_offset, 136,
            "the XP build puts the link 136 bytes into the structure"
        );
        assert!(symbols.dtb_is_array, "32-bit builds declare it as ULONG[2]");

        let list = list_processes(&profile, &symbols, &ProcessListConfig::default())
            .expect("a runnable walk");
        assert_eq!(names(&list), vec!["System", "smss.exe"]);
        assert_eq!(list.forward_stop, ListStop::Wrapped);
    }

    #[test]
    fn the_walk_stops_at_its_cap_and_never_calls_that_the_end_of_the_list() {
        let profile = profile64(three_process_image());
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        let list = list_processes(&profile, &symbols, &ProcessListConfig { max_processes: 2 })
            .expect("a runnable walk");
        assert_eq!(
            list.processes.len(),
            2,
            "the list has three; two were allowed"
        );
        assert_eq!(list.forward_stop, ListStop::CapReached { cap: 2 });
        assert!(!list.is_complete());
        let declared = list.incomplete();
        assert!(declared
            .iter()
            .any(|entry| entry.reason == IncompleteReason::CapReached));
    }

    #[test]
    fn the_backward_walk_recovers_the_processes_past_an_unreadable_link() {
        // The second process sits at the very top of the image, so its own link
        // is off the end of the acquisition and the forward chain stops there.
        // The third is still reachable from the other end, and losing it would
        // shorten the process list in a way nothing in the output would show.
        let broken = NOT_CAPTURED;
        let mut image = Image::new();
        put_process(&mut image, SYSTEM, 4, 0, b"System", 61, EARLY, 0);
        put_process(&mut image, CSRSS, 504, 4, b"csrss.exe", 12, LATE, 0);
        // head -> System -> (broken) -> csrss -> head, in both directions.
        image.put_u64(HEAD, SYSTEM + off::LINKS);
        image.put_u64(HEAD + 8, CSRSS + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS, broken + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS_BLINK, HEAD);
        image.put_u64(CSRSS + off::LINKS, HEAD);
        image.put_u64(CSRSS + off::LINKS_BLINK, broken + off::LINKS);

        let (_, list) = walk(&profile64(image));
        let addresses: Vec<u64> = list.processes.iter().map(|p| p.address).collect();
        assert_eq!(
            addresses,
            vec![SYSTEM, broken, CSRSS],
            "the entry whose bytes are missing is still a fact, and the one past it is recovered"
        );
        assert!(!list.forward_stop.is_complete());
        assert!(list.backward_stop.is_some());
        assert_eq!(list.processes[1].direction, WalkDirection::Forward);
        assert_eq!(list.processes[2].direction, WalkDirection::Backward);

        // The unreadable one is a row of stated gaps, not a row of zeros.
        assert!(list.processes[1].pid.is_unavailable());
        assert!(!list.processes[1].unreadable_fields().is_empty());
        assert!(!list.is_complete());
        assert!(list
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("could not be read")));
    }

    #[test]
    fn a_process_reached_from_both_ends_is_reported_once() {
        // The two walks must meet in the middle rather than double the list.
        let broken = NOT_CAPTURED;
        let mut image = Image::new();
        put_process(&mut image, SYSTEM, 4, 0, b"System", 61, EARLY, 0);
        image.put_u64(HEAD, SYSTEM + off::LINKS);
        image.put_u64(HEAD + 8, SYSTEM + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS, broken + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS_BLINK, HEAD);

        let (_, list) = walk(&profile64(image));
        let system = list
            .processes
            .iter()
            .filter(|process| process.address == SYSTEM)
            .count();
        assert_eq!(system, 1, "one structure, one row");
    }

    // ── Fields ──────────────────────────────────────────────────────────────

    #[test]
    fn an_image_name_stops_at_its_first_nul_and_is_never_read_past_the_array() {
        // Two shapes that both occur: a short name with NUL padding and stale
        // bytes behind it, and a name that exactly fills the member with no
        // terminator at all.
        let mut image = three_process_image();
        let mut padded = [0u8; off::NAME_LEN];
        padded[..4].copy_from_slice(b"cmd\0");
        padded[4..8].copy_from_slice(b"JUNK");
        image.write(SYSTEM + off::NAME, &padded);
        // Fifteen characters, filling the array, with the next member's bytes
        // immediately after it.
        image.write(SMSS + off::NAME, b"aaaaaaaaaaaaaaa");
        image.write(SMSS + off::NAME + off::NAME_LEN as u64, b"OVERRUN");

        let (_, list) = walk(&profile64(image));
        assert_eq!(
            list.processes[0].image_file_name,
            Field::Known("cmd".into())
        );
        assert_eq!(
            list.processes[1].image_file_name,
            Field::Known("aaaaaaaaaaaaaaa".into()),
            "the member is fifteen bytes wide and the name stops there"
        );
        assert!(list.processes[0].image_name_well_formed);
    }

    #[test]
    fn a_name_that_is_not_valid_utf8_is_rendered_lossily_and_flagged() {
        let mut image = three_process_image();
        let mut raw = [0u8; off::NAME_LEN];
        raw[..3].copy_from_slice(&[b'a', 0xFF, b'b']);
        image.write(SYSTEM + off::NAME, &raw);
        let (_, list) = walk(&profile64(image));
        assert!(
            !list.processes[0].image_name_well_formed,
            "the bytes on the machine were not the characters on the screen"
        );
        assert!(list.processes[0].image_file_name.is_known());
    }

    #[test]
    fn a_zero_filetime_is_an_absent_time_and_not_the_first_instant_of_1601() {
        // Every running process has a zero exit time. Converting it would date
        // four hundred running processes to 1601 and read as "all exited".
        let (_, list) = walk(&profile64(three_process_image()));
        let system = &list.processes[0];
        assert_eq!(system.exit_time, ProcessTime::NotRecorded);
        assert_eq!(system.has_exited(), Some(false));
        assert!(matches!(system.create_time, ProcessTime::At { .. }));
        match &system.create_time {
            ProcessTime::At {
                filetime,
                unix_seconds,
                rfc3339,
            } => {
                assert_eq!(*filetime, EARLY);
                assert_eq!(*unix_seconds, 1_262_304_000);
                assert!(rfc3339.starts_with("2010-01-01T00:00:00"), "{rfc3339}");
            }
            other => panic!("expected a time, got {other:?}"),
        }
        assert_eq!(system.exit_time.to_json()["kind"], "not_recorded");
    }

    #[test]
    fn an_exit_time_that_is_set_marks_the_process_as_having_exited() {
        let mut image = three_process_image();
        image.put_u64(SMSS + off::EXIT_TIME, LATE);
        let (_, list) = walk(&profile64(image));
        assert_eq!(list.processes[1].has_exited(), Some(true));
        assert_eq!(list.processes[1].exit_time.filetime(), Some(LATE));
    }

    #[test]
    fn a_filetime_that_is_not_a_time_is_reported_as_implausible_rather_than_converted() {
        // A negative QuadPart, which is what a structure read at the wrong
        // offset produces. Converting it would put a date in the record.
        let mut image = three_process_image();
        image.put_u64(SYSTEM + off::CREATE_TIME, u64::MAX);
        let (_, list) = walk(&profile64(image));
        assert!(matches!(
            list.processes[0].create_time,
            ProcessTime::Implausible { .. }
        ));
        assert_eq!(list.processes[0].create_time.filetime(), None);
        assert!(!list.processes[0].create_time.is_known());
    }

    #[test]
    fn an_unreadable_time_is_not_the_same_as_an_absent_one() {
        // Both render as an empty cell if they are collapsed, and one of them
        // means the process was running while the other means nothing at all.
        let unreadable = ProcessTime::Unavailable("the page was not acquired".into());
        assert_ne!(unreadable, ProcessTime::NotRecorded);
        assert_eq!(unreadable.to_json()["kind"], "unavailable");
        assert_eq!(
            ProcessTime::NotApplicable.to_json()["kind"],
            "not_applicable"
        );
        assert_eq!(classify_filetime(0), ProcessTime::NotRecorded);
        assert!(matches!(
            classify_filetime(-1),
            ProcessTime::Implausible { .. }
        ));
    }

    #[test]
    fn the_handle_count_the_session_and_the_wow64_flag_come_from_the_structures_they_live_in() {
        let mut image = three_process_image();
        image.put_u64(SMSS + off::OBJECT_TABLE, HANDLE_TABLE_AT);
        image.put_u32(HANDLE_TABLE_AT, 74);
        image.put_u64(SMSS + off::SESSION, SESSION_AT);
        image.put_u32(SESSION_AT + 8, 1);
        image.put_u64(SMSS + off::WOW64, 0xDEAD_0000);

        let (_, list) = walk(&profile64(image));
        let smss = &list.processes[1];
        assert_eq!(smss.handles, Field::Known(74));
        assert_eq!(smss.session_id, Field::Known(1));
        assert_eq!(smss.wow64, Field::Known(true));

        // The System process has neither an object table nor a session, and
        // both are stated absences rather than zeros.
        let system = &list.processes[0];
        assert_eq!(system.handles, Field::NotApplicable);
        assert_eq!(system.session_id, Field::NotApplicable);
        assert_eq!(system.wow64, Field::Known(false));
        assert!(system.unreadable_fields().is_empty());
    }

    #[test]
    fn a_build_without_wow64_or_a_session_reports_them_absent_rather_than_false_or_zero() {
        // The XP fixture has no WoW64Process, no ObjectTable and no Session. A
        // measured `false` would claim a check that the build cannot support.
        let mut image = Image::new();
        image.put_u32(HEAD, (SYSTEM + off32::LINKS) as u32);
        image.put_u32(HEAD + 4, (SYSTEM + off32::LINKS) as u32);
        image.put_u32(SYSTEM + off32::LINKS, HEAD as u32);
        image.put_u32(SYSTEM + off32::LINKS_BLINK, HEAD as u32);
        image.put_u32(SYSTEM + off32::PID, 4);
        image.write(SYSTEM + off32::NAME, b"System\0");

        let profile = profile32(image);
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        assert_eq!(symbols.wow64, None);
        assert_eq!(symbols.object_table, None);
        assert!(!symbols.has_handle_table);

        let list = list_processes(&profile, &symbols, &ProcessListConfig::default()).unwrap();
        let system = &list.processes[0];
        assert_eq!(system.wow64, Field::NotApplicable);
        assert_eq!(system.handles, Field::NotApplicable);
        assert_eq!(system.session_id, Field::NotApplicable);
        assert!(system.unreadable_fields().is_empty());
    }

    /// The assertions MEM-023 turns on: an undescribed session layout is a
    /// fact about the build, disclosed with a count, and not a failed read.
    fn assert_session_is_undescribed_not_unreadable(list: &ProcessList) {
        let smss = &list.processes[1];
        assert_eq!(
            smss.session_id,
            Field::NotDeclared {
                member: "_MM_SESSION_SPACE.SessionId"
            },
            "a session this build cannot describe is not declared, not unreadable"
        );
        assert_eq!(smss.session_id.known(), None, "and it is not session zero");
        assert!(
            smss.unreadable_fields().is_empty(),
            "{:?}",
            smss.unreadable_fields()
        );
        for incomplete in list.incomplete() {
            assert_ne!(
                incomplete.reason,
                IncompleteReason::ShortRead,
                "{}",
                incomplete.detail
            );
            assert!(
                !incomplete.detail.contains("session_id"),
                "{}",
                incomplete.detail
            );
        }
        let json = list.to_json();
        let undescribed = json["undescribed"].as_array().expect("an undescribed list");
        let session = undescribed
            .iter()
            .find(|entry| entry["field"] == "session_id")
            .unwrap_or_else(|| panic!("session_id is disclosed as undescribed: {undescribed:?}"));
        assert_eq!(session["member"], "_MM_SESSION_SPACE.SessionId");
        assert_eq!(session["processes"], 1);
        assert_eq!(
            json["processes"][1]["session_id"]["kind"], "not_declared",
            "the wire shape the frontend decodes"
        );
    }

    fn smss_with_a_session(isf: &str) -> ProcessList {
        let mut image = three_process_image();
        image.put_u64(SMSS + off::SESSION, SESSION_AT);
        image.put_u32(SESSION_AT + 8, 1);
        let mut profile = profile64(image);
        profile.symbols = table(isf);
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        list_processes(&profile, &symbols, &ProcessListConfig::default()).unwrap()
    }

    #[test]
    fn a_session_this_build_cannot_describe_is_not_declared_and_not_session_zero() {
        // Windows 11 24H2 renamed `_MM_SESSION_SPACE`, and upstream falls back
        // to a hardcoded offset. Reporting session 0 would put a service in the
        // interactive user's session; reporting "could not be read" would say
        // evidence went unseen when the pointer read fine (MEM-023).
        let isf = windows64_process_isf().replace("_MM_SESSION_SPACE", "_PSP_SESSION_SPACE");
        let symbols = {
            let mut profile = profile64(three_process_image());
            profile.symbols = table(&isf);
            ProcessSymbols::from_profile(&profile).unwrap()
        };
        assert!(!symbols.has_session_space);
        assert_session_is_undescribed_not_unreadable(&smss_with_a_session(&isf));
    }

    #[test]
    fn a_session_space_without_a_session_id_member_is_not_declared() {
        let isf = windows64_process_isf().replace("\"SessionId\"", "\"NotTheSessionId\"");
        assert_session_is_undescribed_not_unreadable(&smss_with_a_session(&isf));
    }

    #[test]
    fn a_session_pointer_that_will_not_read_is_still_unavailable() {
        // The layout is described; the bytes it points at were not captured.
        // That is the acquisition's gap and stays a short read.
        let mut image = three_process_image();
        image.put_u64(SMSS + off::SESSION, NOT_CAPTURED + 0x1000);
        let list = walk(&profile64(image)).1;
        let smss = &list.processes[1];
        assert!(smss.session_id.is_unavailable(), "{:?}", smss.session_id);
        assert_eq!(smss.unreadable_fields(), vec!["session_id"]);
        assert!(list
            .incomplete()
            .iter()
            .any(|i| i.reason == IncompleteReason::ShortRead && i.detail.contains("session_id")));
        assert!(!list.is_complete());
        assert!(list.to_json()["undescribed"].as_array().unwrap().is_empty());
    }

    #[test]
    fn an_undescribed_field_does_not_make_the_inventory_a_floor() {
        // Owner decision 2026-09-26 (MEM-023, option A): the inventory says
        // whether every process on the active list was reached. A column this
        // build declares no layout for misses no process and no bytes.
        let isf = windows64_process_isf().replace("_MM_SESSION_SPACE", "_PSP_SESSION_SPACE");
        let list = smss_with_a_session(&isf);
        assert!(list.is_complete());
        let inventory = list.inventory();
        assert!(inventory.is_complete(), "{:?}", inventory.incomplete);
        let mut record = serde_json::json!({"content_complete": true});
        inventory.stamp(&mut record);
        assert_eq!(record["content_complete"], true);
        assert!(record.get("process_inventory_incomplete").is_none());
    }

    // ── Fail closed ─────────────────────────────────────────────────────────

    #[test]
    fn a_build_whose_eprocess_has_no_active_process_links_fails_closed_naming_the_member() {
        let isf = windows64_process_isf().replace("\"ActiveProcessLinks\"", "\"NotTheLinks\"");
        let mut profile = profile64(Image::new());
        profile.symbols = table(&isf);
        let err = ProcessSymbols::from_profile(&profile)
            .expect_err("without the link member there is no list to walk");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("ActiveProcessLinks"), "{err}");
    }

    #[test]
    fn a_build_whose_eprocess_has_no_process_id_fails_closed_rather_than_numbering_rows() {
        let isf = windows64_process_isf().replace("\"UniqueProcessId\"", "\"NotThePid\"");
        let mut profile = profile64(Image::new());
        profile.symbols = table(&isf);
        let err = ProcessSymbols::from_profile(&profile)
            .expect_err("a process that cannot be identified is not a process list");
        assert!(err.to_string().contains("UniqueProcessId"), "{err}");
    }

    #[test]
    fn an_image_without_the_process_list_symbol_says_so_rather_than_reporting_no_processes() {
        // An empty list and "there is no head to walk from" must not render the
        // same: one says the machine was idle and the other says nothing at all.
        let isf = windows64_process_isf().replace("PsActiveProcessHead", "SomethingElse");
        let mut profile = profile64(three_process_image());
        profile.symbols = table(&isf);
        let symbols = ProcessSymbols::from_profile(&profile).expect("the structures still resolve");
        let err = list_processes(&profile, &symbols, &ProcessListConfig::default())
            .expect_err("there is no head");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("PsActiveProcessHead"), "{err}");
    }

    #[test]
    fn a_kernel_base_that_would_wrap_the_address_space_is_refused() {
        let mut profile = profile64(Image::new());
        profile.kernel_base.value = u64::MAX;
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        let err = list_processes(&profile, &symbols, &ProcessListConfig::default())
            .expect_err("an address that wraps is a wrong address");
        assert_eq!(err.class(), "overflow");
    }

    // ── The tree ────────────────────────────────────────────────────────────

    /// The tree's rendering as `(depth, pid)`, which is what a reader sees.
    fn rendered(tree: &ProcessTree) -> Vec<(u32, Option<u64>)> {
        tree.render_order()
            .iter()
            .map(|&(depth, index)| (depth, tree.nodes[index].pid))
            .collect()
    }

    #[test]
    fn the_tree_hangs_each_process_under_the_parent_that_preceded_it() {
        let (_, list) = walk(&profile64(three_process_image()));
        let tree = build_tree(&list);

        assert_eq!(tree.roots.len(), 1, "only System has no parent on the list");
        assert_eq!(
            rendered(&tree),
            vec![(0, Some(4)), (1, Some(448)), (2, Some(504))]
        );
        assert_eq!(tree.nodes[1].link, ParentLink::Confirmed);
        assert_eq!(tree.nodes[2].link, ParentLink::Confirmed);
        assert_eq!(tree.nodes[1].parent, Some(0));
        assert_eq!(tree.nodes[0].children, vec![1_usize]);
    }

    #[test]
    fn a_process_whose_parent_is_not_on_the_list_is_a_root_and_is_annotated_as_orphaned() {
        // The ordinary case as well as the interesting one: PID 4's parent is
        // the idle process, which is never on this list, and a launcher that
        // has exited leaves exactly the same shape behind.
        let (_, list) = walk(&profile64(three_process_image()));
        let tree = build_tree(&list);
        match &tree.nodes[0].link {
            ParentLink::Orphaned { ppid, detail } => {
                assert_eq!(*ppid, 0);
                assert!(detail.contains("already exited"), "{detail}");
            }
            other => panic!("expected an orphan, got {other:?}"),
        }
        assert_eq!(tree.orphans(), vec![0_usize]);
        assert!(tree.roots.contains(&0));
    }

    #[test]
    fn an_orphan_deeper_in_the_list_still_surfaces_at_the_root_rather_than_vanishing() {
        let mut image = three_process_image();
        // csrss now claims a parent nothing on the list carries.
        image.put_u64(CSRSS + off::PPID, 9999);
        let (_, list) = walk(&profile64(image));
        let tree = build_tree(&list);

        assert_eq!(
            rendered(&tree),
            vec![(0, Some(4)), (1, Some(448)), (0, Some(504))],
            "the orphan is drawn at the root, and no process is lost"
        );
        assert!(matches!(
            tree.nodes[2].link,
            ParentLink::Orphaned { ppid: 9999, .. }
        ));
        assert_eq!(tree.orphans().len(), 2, "PID 4 and the new orphan");
    }

    #[test]
    fn a_parent_id_cycle_terminates_and_every_process_still_appears_exactly_once() {
        // Two processes naming each other. A recursive renderer descends
        // forever; this breaks the edge that closes the loop and says so.
        let mut image = three_process_image();
        image.put_u64(SMSS + off::PPID, 504);
        image.put_u64(CSRSS + off::PPID, 448);
        // Equal create times, so neither one can be ruled out by age and the
        // loop really does close.
        image.put_u64(SMSS + off::CREATE_TIME, EARLY);
        image.put_u64(CSRSS + off::CREATE_TIME, EARLY);
        let (_, list) = walk(&profile64(image));
        let tree = build_tree(&list);

        let order = rendered(&tree);
        assert_eq!(order.len(), 3, "three processes in, three processes out");
        let mut pids: Vec<Option<u64>> = order.iter().map(|&(_, pid)| pid).collect();
        pids.sort();
        assert_eq!(pids, vec![Some(4), Some(448), Some(504)]);

        let cycles = tree
            .nodes
            .iter()
            .filter(|node| matches!(node.link, ParentLink::Cycle { .. }))
            .count();
        assert_eq!(cycles, 1, "exactly one edge is broken to open the loop");
        assert!(!tree.every_edge_is_confirmed());
        assert!(tree
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("does not terminate")));
    }

    #[test]
    fn a_process_that_names_itself_as_its_own_parent_is_a_root_rather_than_its_own_child() {
        let mut image = three_process_image();
        image.put_u64(SMSS + off::PPID, 448);
        let (_, list) = walk(&profile64(image));
        let tree = build_tree(&list);
        assert_eq!(tree.nodes[1].parent, None);
        assert!(tree.roots.contains(&1));
        assert_eq!(rendered(&tree).len(), 3);
    }

    #[test]
    fn a_candidate_parent_created_after_its_supposed_child_is_process_id_reuse_not_a_parent() {
        // Windows reissues process ids within seconds. Matching on the id alone
        // draws a child under a process that started after it, which is a
        // hierarchy that never existed.
        let mut image = three_process_image();
        // smss now claims parent 504, and csrss (504) was created later.
        image.put_u64(SMSS + off::PPID, 504);
        let (_, list) = walk(&profile64(image));
        let tree = build_tree(&list);

        assert_eq!(tree.nodes[1].parent, None, "no edge to a later process");
        match &tree.nodes[1].link {
            ParentLink::Orphaned { ppid, detail } => {
                assert_eq!(*ppid, 504);
                assert!(detail.contains("reused"), "{detail}");
            }
            other => panic!("expected the reuse refusal, got {other:?}"),
        }
    }

    #[test]
    fn two_processes_sharing_a_parent_id_make_the_edge_ambiguous_and_say_which_was_chosen() {
        // An image taken moments after a process exited holds two structures
        // with the same id. The edge is drawn to the one that precedes the
        // child, and the fact that it was a choice is not hidden.
        let mut image = Image::new();
        put_process(&mut image, SYSTEM, 4, 0, b"older.exe", 1, EARLY, 0);
        put_process(&mut image, SMSS, 4, 0, b"newer.exe", 1, LATE, 0);
        put_process(&mut image, CSRSS, 900, 4, b"child.exe", 1, LATE, 0);
        thread_list(&mut image, &[SYSTEM, SMSS, CSRSS]);

        let (_, list) = walk(&profile64(image));
        assert_eq!(list.by_pid(4).len(), 2, "the id really is carried twice");
        let tree = build_tree(&list);
        match &tree.nodes[2].link {
            ParentLink::Ambiguous { candidates, detail } => {
                assert_eq!(candidates, &vec![SYSTEM, SMSS]);
                assert!(detail.contains("chosen"), "{detail}");
            }
            other => panic!("expected an ambiguous edge, got {other:?}"),
        }
        assert_eq!(
            tree.nodes[2].parent,
            Some(1),
            "the latest parent that still precedes the child"
        );
        assert!(!tree.every_edge_is_confirmed());
    }

    #[test]
    fn an_edge_that_cannot_be_checked_against_a_create_time_says_so_rather_than_claiming_it() {
        let mut image = three_process_image();
        image.put_u64(SMSS + off::CREATE_TIME, 0);
        let (_, list) = walk(&profile64(image));
        let tree = build_tree(&list);
        match &tree.nodes[1].link {
            ParentLink::Unverified { detail } => {
                assert!(detail.contains("reuse"), "{detail}")
            }
            other => panic!("expected an unverified edge, got {other:?}"),
        }
        assert_eq!(tree.nodes[1].parent, Some(0), "the edge is still drawn");
        assert!(!tree.every_edge_is_confirmed());
    }

    #[test]
    fn a_process_whose_parent_id_could_not_be_read_is_a_root_with_no_edge_considered() {
        let broken = NOT_CAPTURED;
        let mut image = Image::new();
        put_process(&mut image, SYSTEM, 4, 0, b"System", 61, EARLY, 0);
        image.put_u64(HEAD, SYSTEM + off::LINKS);
        image.put_u64(HEAD + 8, broken + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS, broken + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS_BLINK, HEAD);

        let (_, list) = walk(&profile64(image));
        let tree = build_tree(&list);
        let unreadable = tree
            .nodes
            .iter()
            .find(|node| node.address == broken)
            .expect("the unreadable entry is still a node");
        assert_eq!(unreadable.link, ParentLink::Unknown);
        assert_eq!(unreadable.parent, None);
        assert_eq!(rendered(&tree).len(), list.processes.len());
    }

    #[test]
    fn a_tree_of_ambiguous_edges_is_not_complete_even_when_the_list_walk_finished() {
        // The failure this guards: stamping the tree artifact complete from the
        // list walk alone. The list here is walked end to end, so anything that
        // asks the list gets `true` — and the hierarchy it produced rests on a
        // process-id match that two structures answer to.
        let mut image = Image::new();
        put_process(&mut image, SYSTEM, 4, 0, b"older.exe", 1, EARLY, 0);
        put_process(&mut image, SMSS, 4, 0, b"newer.exe", 1, LATE, 0);
        put_process(&mut image, CSRSS, 900, 4, b"child.exe", 1, LATE, 0);
        thread_list(&mut image, &[SYSTEM, SMSS, CSRSS]);

        let (_, list) = walk(&profile64(image));
        assert!(list.is_complete(), "the walk itself reached every entry");

        let tree = build_tree(&list);
        assert!(
            tree.list_complete,
            "the tree records the list's own verdict"
        );
        assert!(
            !tree.is_complete(),
            "an ambiguous parent edge is not a hierarchy a report may quote"
        );

        let json = tree.to_json();
        assert_eq!(json["complete"], serde_json::json!(false));
        assert_eq!(json["list_complete"], serde_json::json!(true));
    }

    #[test]
    fn a_tree_of_confirmed_edges_over_a_short_list_walk_is_not_complete_either() {
        // The other direction, and the reason both halves are asked: every edge
        // here is confirmed, and the list they were drawn from stopped at an
        // entry whose page was never captured. The branches past the break are
        // missing and nothing in the tree itself shows it.
        let broken = NOT_CAPTURED;
        let mut image = Image::new();
        put_process(&mut image, SYSTEM, 4, 0, b"System", 61, EARLY, 0);
        image.put_u64(HEAD, SYSTEM + off::LINKS);
        image.put_u64(HEAD + 8, broken + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS, broken + off::LINKS);
        image.put_u64(SYSTEM + off::LINKS_BLINK, HEAD);

        let (_, list) = walk(&profile64(image));
        assert!(!list.is_complete(), "the walk did not reach every entry");

        let tree = build_tree(&list);
        assert!(!tree.list_complete);
        assert!(!tree.is_complete());
    }

    // ── Command lines ───────────────────────────────────────────────────────

    /// A reader standing in for a process's own address space.
    ///
    /// The decoding is what these tests are about; building the real space is
    /// a page-table walk covered by its own test below. The signature of
    /// [`read_command_line_in`] is what keeps the two apart in production.
    fn process_reader(profile: &WindowsProfile) -> StructReader {
        StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        )
    }

    /// A PEB pointing at a parameter block holding `text`.
    fn put_peb(image: &mut Image, text: &str) {
        image.put_u64(PEB_AT + 32, PARAMS_AT);
        let bytes = (text.encode_utf16().count() * 2) as u16;
        image.put_u16(PARAMS_AT, bytes);
        image.put_u16(PARAMS_AT + 2, bytes);
        image.put_u64(PARAMS_AT + 8, CMDLINE_AT);
        image.put_utf16(CMDLINE_AT, text);
    }

    #[test]
    fn a_command_line_is_read_through_the_peb_and_its_parameter_block() {
        let text = "\\SystemRoot\\System32\\smss.exe -x";
        let mut image = three_process_image();
        put_peb(&mut image, text);
        let profile = profile64(image);
        assert_eq!(
            read_command_line_in(&process_reader(&profile), PEB_AT),
            CommandLine::Line {
                text: text.to_string(),
                well_formed: true,
            }
        );
    }

    #[test]
    fn the_declared_length_is_bytes_not_characters() {
        // Treating `Length` as a character count reads twice as far and runs
        // into whatever follows the buffer; halving it reads half the string
        // and can split a surrogate pair.
        let text = "abcd";
        let mut image = three_process_image();
        put_peb(&mut image, text);
        // Bytes past the string, which a reader using the wrong unit reaches.
        image.put_utf16(CMDLINE_AT + 8, "XXXX");
        let profile = profile64(image);
        let line = read_command_line_in(&process_reader(&profile), PEB_AT);
        assert_eq!(line.text(), Some("abcd"));
    }

    #[test]
    fn a_paged_out_peb_is_unavailable_and_never_an_empty_command_line() {
        // The finding this protects: "started with no arguments" and "the page
        // holding the arguments was not captured" are opposite conclusions.
        let profile = profile64(three_process_image());
        let line = read_command_line_in(&process_reader(&profile), NOT_CAPTURED);
        assert!(
            matches!(line, CommandLine::Unavailable(_)),
            "got {line:?} instead of a stated gap"
        );
        assert!(!line.is_answered());
        assert_eq!(line.text(), None);
        assert_ne!(line, CommandLine::Empty);
        assert_eq!(line.to_json()["kind"], "unavailable");
    }

    #[test]
    fn a_process_with_no_peb_has_no_command_line_and_that_is_not_a_failure() {
        // The System process and Registry have no user address space at all.
        let profile = profile64(three_process_image());
        let line = read_command_line_in(&process_reader(&profile), 0);
        assert_eq!(line, CommandLine::NoUserSpace);
        assert!(line.is_answered());
    }

    #[test]
    fn a_peb_whose_parameter_block_is_null_is_distinguishable_from_one_that_is_unreadable() {
        let profile = profile64(three_process_image());
        let line = read_command_line_in(&process_reader(&profile), PEB_AT);
        assert_eq!(line, CommandLine::NoParameters);
        assert!(line.is_answered());
    }

    #[test]
    fn a_command_line_of_zero_length_is_empty_rather_than_unavailable() {
        let mut image = three_process_image();
        image.put_u64(PEB_AT + 32, PARAMS_AT);
        image.put_u16(PARAMS_AT, 0);
        let profile = profile64(image);
        assert_eq!(
            read_command_line_in(&process_reader(&profile), PEB_AT),
            CommandLine::Empty
        );
    }

    #[test]
    fn an_unpaired_surrogate_is_decoded_lossily_and_flagged_rather_than_dropped() {
        let mut image = three_process_image();
        image.put_u64(PEB_AT + 32, PARAMS_AT);
        image.put_u16(PARAMS_AT, 4);
        image.put_u16(PARAMS_AT + 2, 4);
        image.put_u64(PARAMS_AT + 8, CMDLINE_AT);
        // A lone high surrogate followed by 'A'.
        image.put_u16(CMDLINE_AT, 0xD800);
        image.put_u16(CMDLINE_AT + 2, 0x0041);

        let profile = profile64(image);
        match read_command_line_in(&process_reader(&profile), PEB_AT) {
            CommandLine::Line { text, well_formed } => {
                assert!(!well_formed, "the damage must reach the reader");
                assert!(text.contains('A'), "the readable part is not discarded");
                assert!(text.contains(char::REPLACEMENT_CHARACTER));
            }
            other => panic!("expected a lossily decoded line, got {other:?}"),
        }
    }

    #[test]
    fn a_declared_length_above_the_cap_is_refused_before_anything_is_allocated() {
        // The length came out of the image. A corrupt USHORT must not become
        // an allocation, and it must not become a shortened read either: the
        // first n bytes of a structure that is not a string are not a prefix
        // of the command line.
        let mut image = three_process_image();
        image.put_u16(PARAMS_AT, 4096);
        image.put_u16(PARAMS_AT + 2, 4096);
        image.put_u64(PARAMS_AT + 8, CMDLINE_AT);
        let profile = profile64(image);
        let reader = process_reader(&profile);
        let params = reader.object(PARAMS_AT, TYPE_PROCESS_PARAMETERS).unwrap();

        let err = read_unicode_string(&params, "CommandLine", 64)
            .expect_err("a length taken from the image must be bounded");
        assert_eq!(err.class(), "cap");
        assert_eq!(err.incomplete_reason(), IncompleteReason::CapReached);
        // The production cap is the most a _UNICODE_STRING can declare.
        assert_eq!(MAX_COMMAND_LINE_BYTES, 65_534);
    }

    #[test]
    fn a_string_claiming_more_text_than_its_buffer_holds_is_refused() {
        let mut image = three_process_image();
        image.put_u64(PEB_AT + 32, PARAMS_AT);
        image.put_u16(PARAMS_AT, 64);
        image.put_u16(PARAMS_AT + 2, 8);
        image.put_u64(PARAMS_AT + 8, CMDLINE_AT);
        let profile = profile64(image);
        match read_command_line_in(&process_reader(&profile), PEB_AT) {
            CommandLine::Unavailable(detail) => {
                assert!(detail.contains("buffer of 8"), "{detail}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_odd_declared_length_is_not_a_whole_number_of_utf16_units_and_is_refused() {
        let mut image = three_process_image();
        image.put_u64(PEB_AT + 32, PARAMS_AT);
        image.put_u16(PARAMS_AT, 7);
        image.put_u16(PARAMS_AT + 2, 8);
        image.put_u64(PARAMS_AT + 8, CMDLINE_AT);
        let profile = profile64(image);
        match read_command_line_in(&process_reader(&profile), PEB_AT) {
            CommandLine::Unavailable(detail) => {
                assert!(detail.contains("code units"), "{detail}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn a_declared_length_with_a_null_buffer_is_refused_rather_than_read_from_zero() {
        let mut image = three_process_image();
        image.put_u64(PEB_AT + 32, PARAMS_AT);
        image.put_u16(PARAMS_AT, 8);
        image.put_u16(PARAMS_AT + 2, 8);
        image.put_u64(PARAMS_AT + 8, 0);
        let profile = profile64(image);
        match read_command_line_in(&process_reader(&profile), PEB_AT) {
            CommandLine::Unavailable(detail) => {
                assert!(detail.contains("null buffer"), "{detail}")
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    // ── The process's own address space ─────────────────────────────────────

    #[test]
    fn a_process_address_space_is_refused_when_the_kernel_space_names_no_paging_mode() {
        // Choosing between PAE and non-PAE would build a space whose every
        // translation is wrong and whose every read still returns bytes.
        let profile = profile64(three_process_image());
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        let cache = Arc::new(TableCache::new());
        let err = process_address_space(&profile, &symbols, SMSS, &cache)
            .expect_err("the fixture's kernel space publishes no paging mode");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("paging mode"), "{err}");
    }

    #[test]
    fn a_command_line_that_needs_an_address_space_that_cannot_be_built_is_unavailable() {
        // The whole point of the enum: a failure to build the space must not
        // arrive at the report as an empty command line.
        let mut image = three_process_image();
        image.put_u64(SMSS + off::PEB, PEB_AT);
        put_peb(&mut image, "smss.exe");
        let profile = profile64(image);
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        let cache = Arc::new(TableCache::new());
        let line = read_command_line(&profile, &symbols, SMSS, &cache);
        assert!(matches!(line, CommandLine::Unavailable(_)), "{line:?}");
        assert!(!line.is_answered());
    }

    #[test]
    fn a_kernel_process_needs_no_address_space_to_answer_that_it_has_no_command_line() {
        let mut image = three_process_image();
        image.put_u64(SMSS + off::PEB, PEB_AT);
        let profile = profile64(image);
        let (symbols, list) = walk(&profile);
        let listing = read_command_lines(&profile, &symbols, &list);
        let lines = &listing.records;

        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].pid, Some(4));
        assert_eq!(
            lines[0].command_line,
            CommandLine::NoUserSpace,
            "System has no PEB, and that is an answer rather than a gap"
        );
        assert_eq!(lines[0].image_file_name.as_deref(), Some("System"));
        assert!(matches!(lines[1].command_line, CommandLine::Unavailable(_)));
        assert_eq!(lines[0].to_json()["command_line"]["kind"], "no_user_space");

        // The listing's own verdict. System and csrss have no user address
        // space, which is an answer; smss has one that could not be built, which
        // is a gap. A report quoting these rows as "the commands this machine
        // ran" would be quoting a floor, and the listing says so.
        assert!(!listing.is_complete());
        assert_eq!(listing.answered(), 2);
        assert_eq!(listing.unavailable(), 1);
        assert_eq!(listing.incomplete().len(), 1);
        let json = listing.to_json();
        assert_eq!(json["count"], 3);
        assert_eq!(json["unavailable"], 1);
        assert_eq!(json["complete"], false);

        // And the provenance of a process no address space was built for is an
        // absent answer, not a clean one: `null` says the question was never
        // put, where `0` would say the suppression heuristic never fired.
        assert_eq!(lines[0].space, SpaceProvenance::not_built());
        assert!(json["command_lines"][0]["space"]["uniform_tables_suppressed"].is_null());
        assert_eq!(
            json["command_lines"][0]["space"]["any_page_shared"],
            serde_json::json!(false)
        );
    }

    #[test]
    fn a_directory_table_base_with_no_page_frame_names_no_page_table() {
        let mut image = three_process_image();
        image.put_u64(SMSS + off::DTB, 0x0FF);
        let profile = profile64(image);
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        // The paging mode is refused first on this fixture, so the base check
        // is exercised through the reader directly.
        let reader = process_reader(&profile);
        let object = reader.object(SMSS, TYPE_EPROCESS).unwrap();
        let dtb = directory_table_base(&object, &symbols, u64::MAX).unwrap();
        assert_eq!(dtb, 0x0FF);
        assert_eq!(dtb & !0xFFF, 0, "no page frame, so no page table");
    }

    #[test]
    fn a_thirty_two_bit_directory_table_base_is_read_from_the_first_array_element() {
        // 32-bit builds declare it as ULONG[2]; the second element is the
        // hyperspace mapping, and reading the pair as one value is not an
        // address at all.
        let mut image = Image::new();
        image.put_u32(SYSTEM + 24, 0x0033_9000);
        image.put_u32(SYSTEM + 28, 0xFFFF_FFFF);
        image.put_u32(HEAD, (SYSTEM + off32::LINKS) as u32);
        image.put_u32(HEAD + 4, (SYSTEM + off32::LINKS) as u32);
        image.put_u32(SYSTEM + off32::LINKS, HEAD as u32);
        image.put_u32(SYSTEM + off32::LINKS_BLINK, HEAD as u32);

        let profile = profile32(image);
        let symbols = ProcessSymbols::from_profile(&profile).unwrap();
        let reader = process_reader(&profile);
        let object = reader.object(SYSTEM, TYPE_EPROCESS).unwrap();
        assert_eq!(
            directory_table_base(&object, &symbols, 0xFFFF_FFFF).unwrap(),
            0x0033_9000
        );
    }

    // ── The artifact view ───────────────────────────────────────────────────

    #[test]
    fn the_json_view_carries_the_offset_the_whole_list_rests_on() {
        let (symbols, list) = walk(&profile64(three_process_image()));
        let json = list.to_json();
        assert_eq!(json["links_offset"], off::LINKS);
        assert_eq!(json["count"], 3);
        assert_eq!(json["complete"], true);
        assert_eq!(json["forward_stop"], "wrapped");
        assert_eq!(json["processes"][0]["pid"]["value"], 4);
        assert_eq!(json["processes"][0]["exit_time"]["kind"], "not_recorded");
        assert_eq!(symbols.to_json()["links_offset"], off::LINKS);

        let tree = build_tree(&list).to_json();
        assert_eq!(tree["every_edge_is_confirmed"], true);
        assert_eq!(tree["nodes"][1]["link"]["kind"], "confirmed");
        assert_eq!(tree["nodes"][0]["link"]["kind"], "orphaned");
    }

    // ── Addresses on the wire ───────────────────────────────────────────────

    /// Largest integer a JSON number carries exactly.
    ///
    /// `serde_json` encodes `u64` as an IEEE double, so anything from here up
    /// arrives at a consumer rounded — by 2 at 2^53 and by 2048 at
    /// `0xffff_8000_0000_0000`.
    const EXACT_JSON_INTEGER: u64 = 1u64 << 53;

    /// A real x64 `_EPROCESS` address: above 2^53, so the JSON number for it is
    /// not the number that was read.
    const KERNEL_EPROCESS: u64 = 0xFFFF_F800_0A1B_2C30;

    /// A user-space PEB, as a WOW64-free x64 process has.
    const USER_PEB: u64 = 0x0000_7FF6_1234_5000;

    /// A FILETIME as an image actually holds one: 1.3e17 ticks, and not a round
    /// number of anything, so it needs more than a double's 53 bits of mantissa.
    const REAL_FILETIME: u64 = 132_800_123_456_789_017;

    /// Every place in `value` where a number too large for a JSON double was
    /// emitted with no exact `_hex` sibling beside it.
    ///
    /// The structural guard the whole `_hex` convention rests on. It does not
    /// hold a list of the fields that happen to be addresses today — such a
    /// list is exactly what drifts — it walks whatever a producer actually
    /// emitted and reports any number that cannot survive the wire and has
    /// nothing beside it that can.
    fn rounded_without_exact_form(value: &serde_json::Value, path: &str) -> Vec<String> {
        let mut out = Vec::new();
        match value {
            serde_json::Value::Object(map) => {
                for (key, child) in map {
                    let here = format!("{path}.{key}");
                    let exact = map.contains_key(&format!("{key}_hex"));
                    let unrepresentable = match child {
                        serde_json::Value::Number(_) => child
                            .as_u64()
                            .is_some_and(|number| number >= EXACT_JSON_INTEGER),
                        // A list of addresses is one field and takes one
                        // sibling, so it is checked against the parent key.
                        serde_json::Value::Array(items) => items.iter().any(|item| {
                            item.as_u64()
                                .is_some_and(|number| number >= EXACT_JSON_INTEGER)
                        }),
                        _ => false,
                    };
                    if unrepresentable && !exact {
                        out.push(here.clone());
                    }
                    out.extend(rounded_without_exact_form(child, &here));
                }
            }
            serde_json::Value::Array(items) => {
                for (index, child) in items.iter().enumerate() {
                    out.extend(rounded_without_exact_form(
                        child,
                        &format!("{path}[{index}]"),
                    ));
                }
            }
            _ => {}
        }
        out
    }

    /// One process with the addresses and times a real x64 image holds.
    fn a_real_x64_process(address: u64, pid: u64, ppid: u64, born: u64) -> ProcessRecord {
        ProcessRecord {
            address,
            direction: WalkDirection::Forward,
            pid: Field::Known(pid),
            ppid: Field::Known(ppid),
            image_file_name: Field::Known("svchost.exe".to_string()),
            image_name_well_formed: true,
            threads: Field::Known(9),
            handles: Field::Known(214),
            session_id: Field::Known(1),
            wow64: Field::Known(false),
            create_time: classify_filetime(i128::from(born)),
            exit_time: ProcessTime::NotRecorded,
            peb: Field::Known(USER_PEB),
            notes: Vec::new(),
        }
    }

    #[test]
    fn a_process_row_carries_the_exact_form_of_every_pointer_it_reports() {
        // Against the unfixed producer this fails on the first assertion:
        // `to_json` wrote `address` as a JSON number and nothing else. The
        // number is exact in the JSON text, but every consumer that parses it
        // as a double — which is what `JSON.parse` does, and the memory lens is
        // a browser — gets 0xfffff8000a1b2c30 rounded to the nearest 2048, an
        // address inside a different structure. The number stays for the
        // consumers that read it; the string is what a report may quote.
        let record = a_real_x64_process(KERNEL_EPROCESS, 1234, 712, REAL_FILETIME);
        let json = record.to_json();

        assert_eq!(json["address_hex"], format!("{KERNEL_EPROCESS:#x}"));
        assert_eq!(json["peb"]["value_hex"], format!("{USER_PEB:#x}"));
        assert_eq!(json["peb"]["kind"], "known");
        assert_eq!(
            json["create_time"]["filetime_hex"],
            format!("{REAL_FILETIME:#x}"),
            "the raw FILETIME is published so the conversion can be checked by hand, which a \
             rounded one cannot be"
        );

        // The number really is unusable on its own once parsed as a double,
        // which is the whole reason the sibling exists.
        assert_ne!(
            KERNEL_EPROCESS as f64 as u64, KERNEL_EPROCESS,
            "if this pointer fitted in a double there would be nothing to fix"
        );
        assert_ne!(
            REAL_FILETIME as f64 as u64, REAL_FILETIME,
            "nor does a FILETIME, which is why the raw value needs an exact form too"
        );

        assert_eq!(
            rounded_without_exact_form(&json, "process"),
            Vec::<String>::new()
        );
    }

    #[test]
    fn no_producer_in_this_file_emits_a_pointer_that_cannot_survive_the_wire() {
        // The class guard. Every artifact view this module writes is walked,
        // and any number above 2^53 with no exact sibling is named. A field
        // added later that happens to be an address gets caught here rather
        // than in a report.
        //
        // Two processes carry parent id 712 so the third's parent edge is
        // ambiguous, which is the only branch that emits a list of candidate
        // addresses.
        let list = ProcessList {
            head: KERNEL_EPROCESS - 0x1000,
            links_offset: 0x448,
            processes: vec![
                a_real_x64_process(KERNEL_EPROCESS, 712, 4, REAL_FILETIME),
                a_real_x64_process(KERNEL_EPROCESS + 0x4000, 712, 4, REAL_FILETIME + 10),
                a_real_x64_process(KERNEL_EPROCESS + 0x8000, 1234, 712, REAL_FILETIME + 20),
            ],
            forward_stop: ListStop::Wrapped,
            backward_stop: None,
        };
        let tree = build_tree(&list);
        // The ambiguous edge really is exercised, so the candidate list below
        // is a tested path and not a hoped-for one.
        assert!(
            tree.nodes
                .iter()
                .any(|node| matches!(node.link, ParentLink::Ambiguous { .. })),
            "the fixture must produce the branch that emits candidate addresses"
        );

        let listing = CommandLineListing {
            records: vec![CommandLineRecord {
                address: KERNEL_EPROCESS,
                pid: Some(1234),
                image_file_name: Some("svchost.exe".to_string()),
                command_line: CommandLine::Line {
                    text: "svchost.exe -k netsvcs".to_string(),
                    well_formed: true,
                },
                space: SpaceProvenance {
                    uniform_tables_suppressed: Some(3),
                    pages: vec![PageProvenance {
                        what: "the command line text",
                        va: USER_PEB,
                        backing: PageBacking::SharedSection {
                            proto_va: KERNEL_EPROCESS + 0x40,
                            proto_pa: 0x1_2345_6000,
                        },
                    }],
                },
            }],
        };

        for (name, value) in [
            ("process_list", list.to_json()),
            ("process_tree", tree.to_json()),
            ("process_inventory", list.inventory().to_json()),
            ("command_lines", listing.to_json()),
            ("process_record", list.processes[0].to_json()),
        ] {
            assert_eq!(
                rounded_without_exact_form(&value, name),
                Vec::<String>::new(),
                "{name} emits a pointer a consumer can only read rounded"
            );
        }
    }

    // ── Provenance of the process's own address space ───────────────────────

    #[test]
    fn a_page_the_hardware_tables_resolved_is_not_reported_as_private() {
        // The distinction that makes `via` worth carrying, and the one a naive
        // reading gets backwards. A resident shared page has a valid hardware
        // entry and never consults its prototype PTE, so "the page tables
        // resolved it" is not evidence of anything about sharing — only the
        // prototype path is a positive finding.
        let tables = PageBacking::PageTables;
        assert!(!tables.is_shared());
        let json = tables.to_json();
        assert_eq!(json["shared"], serde_json::json!(false));
        assert!(
            json["meaning"]
                .as_str()
                .expect("a meaning is stated")
                .contains("does NOT establish"),
            "{json}"
        );

        let shared = PageBacking::SharedSection {
            proto_va: KERNEL_EPROCESS,
            proto_pa: 0x1_2345_6000,
        };
        assert!(shared.is_shared());
        assert_eq!(shared.to_json()["shared"], serde_json::json!(true));
        assert_eq!(
            shared.to_json()["proto_va_hex"],
            format!("{KERNEL_EPROCESS:#x}")
        );

        // A page that did not translate says nothing either way, and must not
        // collapse into the page-table answer.
        let unknown = PageBacking::NotEstablished("the page was not captured".to_string());
        assert!(!unknown.is_shared());
        assert!(unknown.to_json()["shared"].is_null());
    }

    #[test]
    fn a_suppression_count_that_was_never_taken_is_absent_rather_than_zero() {
        // The failure this exists to stop: an examiner asking "could this tool
        // have hidden a page from me" reading a `0` that means "nobody looked".
        let absent = SpaceProvenance::not_built();
        assert_eq!(absent.uniform_tables_suppressed, None);
        assert_eq!(absent.suppression_occurred(), None);
        let json = absent.to_json();
        assert!(json["uniform_tables_suppressed"].is_null());
        assert!(
            json["uniform_tables_suppressed_meaning"]
                .as_str()
                .expect("a meaning is stated")
                .contains("not a count of zero"),
            "{json}"
        );

        let clean = SpaceProvenance {
            uniform_tables_suppressed: Some(0),
            pages: Vec::new(),
        };
        assert_eq!(clean.suppression_occurred(), Some(false));
        assert_eq!(
            clean.to_json()["uniform_tables_suppressed"],
            serde_json::json!(0)
        );
        assert_ne!(
            clean.to_json()["uniform_tables_suppressed_meaning"],
            json["uniform_tables_suppressed_meaning"],
            "a measured zero and an absent answer must not read alike"
        );

        let fired = SpaceProvenance {
            uniform_tables_suppressed: Some(1483),
            pages: Vec::new(),
        };
        assert_eq!(fired.suppression_occurred(), Some(true));
        assert!(
            fired.to_json()["uniform_tables_suppressed_meaning"]
                .as_str()
                .expect("a meaning is stated")
                .contains("not distinct tables"),
            "the number is refusals, and saying otherwise overstates it"
        );
    }

    // ── Inventory completeness ──────────────────────────────────────────────

    #[test]
    fn a_list_walked_end_to_end_yields_an_inventory_that_is_a_total() {
        let (_symbols, list) = walk(&profile64(three_process_image()));
        let inventory = list.inventory();
        assert!(inventory.is_complete());
        assert_eq!(inventory.listed, 3);
        assert_eq!(inventory.head, list.head);
        let json = inventory.to_json();
        assert_eq!(json["complete"], true);
        assert_eq!(json["count_is_floor"], false);
        assert_eq!(json["incomplete"], serde_json::json!([]));
    }

    #[test]
    fn a_list_that_stopped_early_yields_an_inventory_that_says_so_and_why() {
        let (_symbols, mut list) = walk(&profile64(three_process_image()));
        list.forward_stop = ListStop::CapReached { cap: 3 };
        let inventory = list.inventory();
        assert!(!inventory.is_complete());
        assert!(
            inventory
                .incomplete
                .iter()
                .any(|entry| entry.detail.contains("active process list")),
            "the inventory must name why the list fell short: {:?}",
            inventory.incomplete
        );
        let json = inventory.to_json();
        assert_eq!(json["count_is_floor"], true);
        assert!(json["meaning"].as_str().unwrap().contains("floor"));
    }

    #[test]
    fn stamping_a_stage_over_a_short_inventory_clears_its_completeness_claim() {
        // The failure path this type exists for: a stage that examined
        // everything it was handed, over a list that stopped. Without the
        // stamp the record below says `content_complete: true` and an examiner
        // reads its counts as totals.
        let (_symbols, mut list) = walk(&profile64(three_process_image()));
        list.forward_stop = ListStop::CapReached { cap: 3 };

        let mut record = serde_json::json!({"content_complete": true, "findings": []});
        list.inventory().stamp(&mut record);
        assert_eq!(record["content_complete"], false);
        assert_eq!(record["content_incomplete"], true);
        assert_eq!(record["process_inventory_incomplete"], true);
        assert_eq!(record["process_inventory"]["listed"], 3);
    }

    #[test]
    fn stamping_a_stage_over_a_whole_inventory_leaves_its_completeness_alone() {
        let (_symbols, list) = walk(&profile64(three_process_image()));
        let mut record = serde_json::json!({"content_complete": true});
        list.inventory().stamp(&mut record);
        assert_eq!(record["content_complete"], true);
        assert!(record.get("content_incomplete").is_none());
        assert_eq!(record["process_inventory"]["complete"], true);
    }
}
