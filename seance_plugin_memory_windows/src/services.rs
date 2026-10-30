//! Windows services: the records `services.exe` keeps, reached two ways.
//!
//! A Windows service is not a kernel object. There is no `_SERVICE` in the
//! executive's type table, no pool tag to sweep for, nothing on a kernel list.
//! The Service Control Manager is an ordinary user-mode process —
//! `services.exe` — and every service on the machine is a `_SERVICE_RECORD`
//! structure on that one process's heap. So this whole stage happens inside one
//! process's address space, and a caller that hands it the *kernel* space
//! instead gets a scan of the wrong memory that finds nothing and looks exactly
//! like a machine with no services. That is why the target of every function
//! here is a [`ProcessSpace`], which can only be built from a process's own
//! directory table base.
//!
//! # What an examiner learns
//!
//! For every service: its short name, its display name, its type (kernel
//! driver, filesystem driver, own-process, shared-process), whether it is
//! running, how it is set to start, the binary or driver behind it, and — for a
//! running process service — the PID it is running as. Together with the
//! registry side of the same fact (`ImagePath`, `Parameters\ServiceDll`), that
//! is what identifies a service installed for persistence: a service whose
//! registry `ImagePath` and whose live binary path disagree, or a running
//! service with no registry key at all.
//!
//! # What a wrong answer looks like
//!
//! The `_SERVICE_RECORD` layout is **not** in any PDB. Microsoft ships no
//! symbols for `services.exe`'s private structures. **Provenance (MEM-056,
//! open):** the sixteen catalogue entries below are named after, and on every
//! offset this module reads equal to, upstream Volatility 3's VSL-licensed
//! `symbols/windows/services/services-*.json` packs (a field-by-field check on
//! 2026-09-26 found no differing offset; the only difference is that this
//! module does not read the record's own `Tag` from Vista on). They were not
//! derived here, and under the clean-room rule of 2026-09-26 (ROADMAP,
//! "Clean-room") the catalogue does not comply until each entry is re-derived
//! from a permitted source or refused. The layout moved at Vista, at Windows 8,
//! at Windows 10 1703, 1709, 1809, 1903, 2004 and again at 25398. Decode a
//! Windows 10 record at Vista offsets and it still *parses*: the order is a
//! plausible small number, some pointer lands on some UTF-16 text, and a
//! confident table of nonsense comes out. Nothing about the result says it is
//! wrong.
//!
//! Two consequences run through this module:
//!
//! 1. **A build whose layout is not catalogued is refused.** Not decoded with
//!    the nearest layout, not decoded with defaults. [`ServiceSymbols`] resolves
//!    every offset up front, from the symbol table when the table happens to
//!    describe these types and from the documented per-release catalogue
//!    otherwise, and names the build it cannot describe. An empty result and
//!    "this build's service records cannot be located" never render the same.
//! 2. **The layout source travels with the answer.** [`ServiceLayoutSource`]
//!    says whether the offsets came from a symbol table or from the catalogue,
//!    and [`ServiceLayout::name`] names which catalogue entry. A report that
//!    cannot say which layout produced a row cannot defend the row.
//!
//! # Two enumerations, and the difference between them
//!
//! * **Scanning** ([`scan_services_in`]) sweeps every committed range of
//!   `services.exe` for the record tag — `sErv` before Vista, and from Vista the
//!   `serH` tag of the `_SERVICE_HEADER` that sits in front of each record —
//!   and decodes whatever it finds. It does not care whether anything still
//!   points at the record.
//! * **List walking** ([`list_services_in`]) finds the list head inside the
//!   `services.exe` image itself, by its `Sc27` tag, and follows the record
//!   chain from there. It reaches only records the Service Control Manager
//!   still links.
//!
//! * **The difference** ([`diff_services`]) is the finding. A record that
//!   scanning finds and list walking does not has been unlinked from the SCM's
//!   own chain, which is how a service hides itself from `sc query` and from
//!   every live-response tool. [`ServiceDiff::comparable`] gates the claim: if
//!   the *list* walk was itself incomplete, absence from it is not evidence of
//!   unlinking, and this module says so rather than reporting every service as
//!   hidden.
//!
//! # Service SIDs are computed, never read
//!
//! [`service_sid`] derives `S-1-5-80-…` from the service name by the published
//! rule — SHA-1 of the uppercased name in UTF-16LE, split into five 32-bit
//! little-endian sub-authorities. Nothing is read out of the image to produce
//! it. Every [`ServiceSid`] carries the exact string that was hashed so the
//! derivation can be re-run by hand.

// `scan_dtb_candidates` and its siblings take a *slice* of regions so a caller can
// sweep several disjoint windows. Handing them one is ordinary use, not the
// `vec![a..b]`-meant-`a..b` mistake this lint is looking for.
#![allow(clippy::single_range_in_vec_init)]

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{ObjError, StructReader};
use seance_memory::scan::{scan_range, MultiStringScanner, ScanConfig, ScanError};
use seance_memory::{Architecture, Incomplete};
use seance_symbols::SymbolError;

use crate::modules::{ModuleSymbols, ModuleWalkConfig, ModulesError, ProcessSpace};
use crate::process::{list_processes, Field, ProcessError, ProcessListConfig, ProcessSymbols};
use crate::profile::WindowsProfile;
use crate::registry::key::{decode_utf16le, CellReader, KeyNode, RegistryData, ValueData};
use crate::registry::{hivelist, HiveSpace, RegistryError};
use crate::vad::{list_vads, VadError, VadSymbols, VadWalkConfig};

// ── Names and tags this stage knows ─────────────────────────────────────────

/// The Service Control Manager's image name, as `_EPROCESS.ImageFileName`
/// holds it.
pub const SERVICES_IMAGE_NAME: &str = "services.exe";

/// The tag in front of a `_SERVICE_RECORD` before Windows Vista.
///
/// On XP and Server 2003 the record carries its own tag member, and the scan
/// steps back from a hit by [`ServiceRecordLayout::tag`] to reach the record.
pub const TAG_SERVICE_RECORD: &[u8; 4] = b"sErv";

/// The tag of the `_SERVICE_HEADER` that precedes a record from Windows Vista.
///
/// From Vista the record itself is no longer tagged in a way a sweep can use;
/// each record is reached through a small header whose first four bytes are
/// this, and the header points at the record.
pub const TAG_SERVICE_HEADER: &[u8; 4] = b"serH";

/// The tag of the service list head inside the `services.exe` image.
///
/// A `_SERVICE_HEADER` like any other, but resident in the image's own data
/// rather than on the heap, which is what makes it findable without sweeping
/// the whole process.
pub const TAG_SERVICE_LIST_HEAD: &[u8; 4] = b"Sc27";

/// Alignment a `_SERVICE_HEADER` must sit on.
///
/// The heap's own granularity on both 32- and 64-bit Windows. A `serH` sequence
/// at an address that is not a multiple of this is text or data that happens to
/// read as the tag, not the head of an allocation, and following it decodes
/// whatever bytes lie at the record offsets.
pub const SERVICE_HEADER_ALIGNMENT: u64 = 8;

/// Ceiling on bytes read for one of a record's four strings.
///
/// Matches the 512 bytes upstream reads: 256 UTF-16 code units, which is longer
/// than any real service name, display name or image path.
pub const MAX_SERVICE_STRING_BYTES: u64 = 512;

/// Bytes read per step while following a NUL-terminated wide string.
///
/// Small enough that a string ending just inside an acquired page is still
/// recovered when the next page was not captured.
pub const WIDE_STRING_STEP: u64 = 64;

/// Ceiling on services one enumeration will report.
///
/// A machine with more services than this does not exist; reaching it means the
/// chain or the sweep is following something that is not a service list, and it
/// is reported as a cap rather than as the end of the enumeration.
pub const MAX_SERVICES: usize = 65_536;

/// Ceiling on records one `PrevEntry` chain will follow.
pub const MAX_CHAIN_LENGTH: usize = 65_536;

/// Ceiling on individually recorded skips. The *count* stays exact.
pub const MAX_RECORDED_SKIPS: usize = 256;

/// Ceiling on committed ranges of `services.exe` one sweep will cover.
pub const MAX_SERVICE_SECTIONS: usize = 65_536;

/// How many 32-bit sub-authorities a service SID carries after `S-1-5-80`.
pub const SERVICE_SID_SUBAUTHORITIES: usize = 5;

/// The fixed prefix of every service SID.
pub const SERVICE_SID_PREFIX: &str = "S-1-5-80";

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a service enumeration before it can produce an answer
/// worth reading.
///
/// Note what is *not* here: a record the sweep declined to decode. That is a
/// fact about four hundred bytes of one heap, and it lands in
/// [`ServiceListing::skipped`] where an examiner can count it.
#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    /// This build's service records cannot be located or decoded with what is
    /// available, and no partial answer would be honest. The message names what
    /// is missing.
    #[error("services cannot be enumerated on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// A typed read failed for a reason that invalidates the whole enumeration
    /// rather than one record.
    ///
    /// Carries the underlying [`ObjError`] intact, so the exact unread range and
    /// the exact offset both reach the examiner.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The process list could not be walked, so `services.exe` could not be
    /// found.
    #[error(transparent)]
    Process(#[from] ProcessError),

    /// The Service Control Manager's own address space could not be built.
    #[error(transparent)]
    Modules(#[from] ModulesError),

    /// The committed ranges of `services.exe` could not be established, so
    /// there is nowhere defensible to sweep.
    #[error(transparent)]
    Vad(#[from] VadError),

    /// The sweep itself could not be run.
    #[error(transparent)]
    Scan(#[from] ScanError),

    /// The registry side — `ImagePath`, `ServiceDll`, the service name list —
    /// could not be reached.
    #[error(transparent)]
    Registry(#[from] RegistryError),
}

impl ServiceError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            ServiceError::Unsupported { .. } => "unsupported_build",
            ServiceError::Object(err) => err.class(),
            ServiceError::Process(err) => err.class(),
            ServiceError::Modules(_) => "modules",
            ServiceError::Vad(err) => err.class(),
            ServiceError::Scan(_) => "scan",
            ServiceError::Registry(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            ServiceError::Object(err) => err.incomplete_reason(),
            ServiceError::Vad(err) => err.incomplete_reason(),
            ServiceError::Registry(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be enumerated" refusal.
    pub fn unsupported(detail: impl Into<String>) -> ServiceError {
        ServiceError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Which shape of service record a build uses.
///
/// The boundary is Windows Vista, and it decides three things at once: which
/// tag the sweep looks for, whether records are reached through a
/// `_SERVICE_HEADER`, and whether a record links to the one before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordGeneration {
    /// XP and Server 2003. Each record carries its own `sErv` tag, there is no
    /// header, and records are found one at a time by the sweep.
    PreVista,
    /// Vista and later. Records are reached through a `serH`-tagged
    /// `_SERVICE_HEADER`, and each record points back at the previous one.
    VistaOrLater,
}

impl RecordGeneration {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordGeneration::PreVista => "pre_vista",
            RecordGeneration::VistaOrLater => "vista_or_later",
        }
    }

    /// The four bytes a sweep for service records looks for on this generation.
    pub fn scan_tag(self) -> &'static [u8; 4] {
        match self {
            RecordGeneration::PreVista => TAG_SERVICE_RECORD,
            RecordGeneration::VistaOrLater => TAG_SERVICE_HEADER,
        }
    }
}

/// Where a set of service-record offsets came from.
///
/// Carried on every result. A row decoded from a catalogued layout and a row
/// decoded from offsets the image's own symbol table declared rest on different
/// evidence, and a report that renders them identically has hidden the
/// difference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceLayoutSource {
    /// The symbol table supplied with this image declared `_SERVICE_RECORD`
    /// itself, and every offset was resolved from it.
    ///
    /// Kernel PDBs do not describe `services.exe`'s private structures, so this
    /// only happens when an examiner supplied a symbol table that does.
    SymbolTable,
    /// The offsets came from the per-release catalogue in this module, selected
    /// by the build number and pointer width.
    Catalogue,
}

impl ServiceLayoutSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceLayoutSource::SymbolTable => "symbol_table",
            ServiceLayoutSource::Catalogue => "catalogue",
        }
    }
}

/// Offsets inside the `_SERVICE_HEADER` that precedes a record from Vista.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceHeaderLayout {
    /// Offset of the four-byte tag. Zero on every catalogued build; kept a
    /// field rather than assumed so a symbol-table-resolved header is read the
    /// same way.
    pub tag: u64,
    /// Offset of the pointer to the `_SERVICE_RECORD`.
    pub service_record: u64,
}

/// Offsets inside the `_SERVICE_PROCESS` a running process service points at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceProcessLayout {
    /// Offset of the pointer to the NUL-terminated wide binary path.
    pub binary_path: u64,
    /// Offset of the owning process id.
    pub process_id: u64,
}

/// Offsets inside a `_SERVICE_RECORD`.
///
/// `service_process` and `driver_name` name the same member on every build up
/// to Windows 10 25398, where they finally separated: a process service reads
/// the first and a driver service the second, and a build that put them at one
/// offset simply has both fields equal. Reading the wrong one of the two on
/// 25398 produces a path from the neighbouring member, which is a plausible
/// string in the wrong column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceRecordLayout {
    /// Offset of the record's own four-byte tag.
    ///
    /// `Some` only before Vista, where the sweep steps back from a `sErv` hit
    /// by exactly this to reach the record. From Vista the record's tag is not
    /// what the sweep finds — the header's is — and this is `None` rather than
    /// an offset nothing reads.
    pub tag: Option<u64>,
    /// Offset of the pointer to the previous record in the chain.
    ///
    /// `Some` from Vista, `None` before it. This is what list walking follows,
    /// and its absence is why there is no list walking on XP.
    pub prev_entry: Option<u64>,
    /// Offset of the pointer to the NUL-terminated wide service name.
    pub service_name: u64,
    /// Offset of the pointer to the NUL-terminated wide display name.
    pub display_name: u64,
    /// Offset of the 32-bit load order.
    pub order: u64,
    /// Offset of the 32-bit service type word.
    pub service_type: u64,
    /// Offset of the 32-bit current state.
    pub state: u64,
    /// Offset of the 32-bit start type.
    pub start: u64,
    /// Offset of the pointer to the `_SERVICE_PROCESS`, for a process service.
    pub service_process: u64,
    /// Offset of the pointer to the driver name, for a driver service.
    pub driver_name: u64,
}

/// One release's service structure layout, whole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceLayout {
    /// Which release this describes, in the form the upstream catalogue names
    /// it. Reported so a row can be traced to the layout that produced it.
    pub name: &'static str,
    /// Which shape of record this release uses.
    pub generation: RecordGeneration,
    /// Pointer width, in bytes, of the `services.exe` these offsets describe.
    pub pointer_size: u64,
    /// The header that precedes a record from Vista.
    pub header: ServiceHeaderLayout,
    /// The record itself.
    pub record: ServiceRecordLayout,
    /// The process block a running process service points at.
    pub process: ServiceProcessLayout,
}

impl ServiceLayout {
    /// Refuse a layout whose parts contradict each other.
    ///
    /// Three ways a layout can be internally wrong, each of which would decode
    /// something rather than fail:
    ///
    /// * a pre-Vista layout with no record tag offset — the sweep would have
    ///   nothing to step back by and would decode a record starting at the tag;
    /// * a pre-Vista layout that claims a `PrevEntry` — list walking would
    ///   follow a member that release does not have;
    /// * a Vista-or-later layout with no `PrevEntry` — every chain would be one
    ///   record long, and a full list would render as a machine with one
    ///   service.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unsupported`] naming the contradiction.
    pub fn validate(&self) -> Result<(), ServiceError> {
        match self.generation {
            RecordGeneration::PreVista => {
                if self.record.tag.is_none() {
                    return Err(ServiceError::unsupported(format!(
                        "the '{}' layout is a pre-Vista one but names no offset for the record's \
                         own tag, so a swept hit could not be turned into a record address",
                        self.name
                    )));
                }
                if self.record.prev_entry.is_some() {
                    return Err(ServiceError::unsupported(format!(
                        "the '{}' layout is a pre-Vista one but names a PrevEntry, which that \
                         release's records do not have",
                        self.name
                    )));
                }
            }
            RecordGeneration::VistaOrLater => {
                if self.record.prev_entry.is_none() {
                    return Err(ServiceError::unsupported(format!(
                        "the '{}' layout is a Vista-or-later one but names no PrevEntry, so a \
                         record chain could not be followed past its first entry",
                        self.name
                    )));
                }
            }
        }
        if self.pointer_size != 4 && self.pointer_size != 8 {
            return Err(ServiceError::unsupported(format!(
                "the '{}' layout declares a pointer width of {} bytes, which is neither 32- nor \
                 64-bit",
                self.name, self.pointer_size
            )));
        }
        Ok(())
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "name": self.name,
            "generation": self.generation.as_str(),
            "pointer_size": self.pointer_size,
            "header": {
                "tag": self.header.tag,
                "service_record": self.header.service_record,
            },
            "record": {
                "tag": self.record.tag,
                "prev_entry": self.record.prev_entry,
                "service_name": self.record.service_name,
                "display_name": self.record.display_name,
                "order": self.record.order,
                "type": self.record.service_type,
                "state": self.record.state,
                "start": self.record.start,
                "service_process": self.record.service_process,
                "driver_name": self.record.driver_name,
            },
            "process": {
                "binary_path": self.process.binary_path,
                "process_id": self.process.process_id,
            },
        })
    }
}

// ── The catalogue ───────────────────────────────────────────────────────────

/// Windows XP, 32-bit.
pub const XP_X86: ServiceLayout = ServiceLayout {
    name: "services-xp-x86",
    generation: RecordGeneration::PreVista,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 12,
    },
    record: ServiceRecordLayout {
        tag: Some(24),
        prev_entry: None,
        service_name: 8,
        display_name: 12,
        order: 16,
        service_type: 40,
        state: 44,
        start: 68,
        service_process: 36,
        driver_name: 36,
    },
    process: ServiceProcessLayout {
        binary_path: 8,
        process_id: 12,
    },
};

/// Windows XP x64 and Server 2003, 64-bit.
pub const XP_2003_X64: ServiceLayout = ServiceLayout {
    name: "services-xp-2003-x64",
    generation: RecordGeneration::PreVista,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: Some(32),
        prev_entry: None,
        service_name: 8,
        display_name: 16,
        order: 24,
        service_type: 56,
        state: 60,
        start: 84,
        service_process: 48,
        driver_name: 48,
    },
    process: ServiceProcessLayout {
        binary_path: 16,
        process_id: 24,
    },
};

/// Windows Vista and 7, 32-bit.
pub const VISTA_X86: ServiceLayout = ServiceLayout {
    name: "services-vista-x86",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 12,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(0),
        service_name: 4,
        display_name: 8,
        order: 12,
        service_type: 32,
        state: 36,
        start: 60,
        service_process: 28,
        driver_name: 28,
    },
    process: ServiceProcessLayout {
        binary_path: 8,
        process_id: 12,
    },
};

/// Windows Vista and 7, 64-bit.
pub const VISTA_X64: ServiceLayout = ServiceLayout {
    name: "services-vista-x64",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(0),
        service_name: 8,
        display_name: 16,
        order: 24,
        service_type: 48,
        state: 52,
        start: 76,
        service_process: 40,
        driver_name: 40,
    },
    process: ServiceProcessLayout {
        binary_path: 16,
        process_id: 24,
    },
};

/// Windows 8, 8.1 and Windows 10 up to 1607, 32-bit.
pub const WIN8_X86: ServiceLayout = ServiceLayout {
    name: "services-win8-x86",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 12,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(4),
        service_name: 8,
        display_name: 12,
        order: 16,
        service_type: 40,
        state: 44,
        start: 68,
        service_process: 36,
        driver_name: 36,
    },
    process: ServiceProcessLayout {
        binary_path: 12,
        process_id: 16,
    },
};

/// Windows 8, 8.1 and Windows 10 up to 1607, 64-bit.
pub const WIN8_X64: ServiceLayout = ServiceLayout {
    name: "services-win8-x64",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(8),
        service_name: 16,
        display_name: 24,
        order: 32,
        service_type: 64,
        state: 68,
        start: 92,
        service_process: 56,
        driver_name: 56,
    },
    process: ServiceProcessLayout {
        binary_path: 24,
        process_id: 32,
    },
};

/// Windows 10 1703, 32-bit.
pub const WIN10_15063_X86: ServiceLayout = ServiceLayout {
    name: "services-win10-15063-x86",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 12,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(12),
        service_name: 44,
        display_name: 48,
        order: 20,
        service_type: 52,
        state: 56,
        start: 24,
        service_process: 156,
        driver_name: 156,
    },
    process: ServiceProcessLayout {
        binary_path: 12,
        process_id: 16,
    },
};

/// Windows 10 1703, 64-bit.
pub const WIN10_15063_X64: ServiceLayout = ServiceLayout {
    name: "services-win10-15063-x64",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(16),
        service_name: 56,
        display_name: 64,
        order: 32,
        service_type: 72,
        state: 76,
        start: 36,
        service_process: 232,
        driver_name: 232,
    },
    process: ServiceProcessLayout {
        binary_path: 24,
        process_id: 32,
    },
};

/// Windows 10 1709 and 1803, 32-bit.
pub const WIN10_16299_X86: ServiceLayout = ServiceLayout {
    name: "services-win10-16299-x86",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 12,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(12),
        service_name: 44,
        display_name: 48,
        order: 20,
        service_type: 52,
        state: 56,
        start: 24,
        service_process: 156,
        driver_name: 156,
    },
    process: ServiceProcessLayout {
        binary_path: 12,
        process_id: 20,
    },
};

/// Windows 10 1709 through 1809, 64-bit.
///
/// The record did not move at 1809 on 64-bit — only the 32-bit one did — so
/// this covers 17763 as well.
pub const WIN10_16299_X64: ServiceLayout = ServiceLayout {
    name: "services-win10-16299-x64",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(16),
        service_name: 56,
        display_name: 64,
        order: 32,
        service_type: 72,
        state: 76,
        start: 36,
        service_process: 232,
        driver_name: 232,
    },
    process: ServiceProcessLayout {
        binary_path: 24,
        process_id: 40,
    },
};

/// Windows 10 1809, 32-bit.
pub const WIN10_17763_X86: ServiceLayout = ServiceLayout {
    name: "services-win10-17763-x86",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 12,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(12),
        service_name: 44,
        display_name: 48,
        order: 20,
        service_type: 52,
        state: 56,
        start: 24,
        service_process: 160,
        driver_name: 160,
    },
    process: ServiceProcessLayout {
        binary_path: 12,
        process_id: 20,
    },
};

/// Windows 10 1903 and 1909, 32-bit.
pub const WIN10_18362_X86: ServiceLayout = ServiceLayout {
    name: "services-win10-18362-x86",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 12,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(12),
        service_name: 44,
        display_name: 48,
        order: 20,
        service_type: 52,
        state: 56,
        start: 24,
        service_process: 164,
        driver_name: 164,
    },
    process: ServiceProcessLayout {
        binary_path: 12,
        process_id: 20,
    },
};

/// Windows 10 1903 and 1909, 64-bit.
pub const WIN10_18362_X64: ServiceLayout = ServiceLayout {
    name: "services-win10-18362-x64",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(16),
        service_name: 56,
        display_name: 64,
        order: 32,
        service_type: 72,
        state: 76,
        start: 36,
        service_process: 240,
        driver_name: 240,
    },
    process: ServiceProcessLayout {
        binary_path: 24,
        process_id: 40,
    },
};

/// Windows 10 2004 and later, 32-bit.
///
/// The last 32-bit client release; nothing after it shipped an x86 kernel, so
/// this is the top of the 32-bit catalogue.
pub const WIN10_19041_X86: ServiceLayout = ServiceLayout {
    name: "services-win10-19041-x86",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 4,
    header: ServiceHeaderLayout {
        tag: 0,
        // Not 12: the header grew at 2004 on 32-bit, and reading the record
        // pointer four bytes early lands on the tail of the tag.
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(12),
        service_name: 44,
        display_name: 48,
        order: 20,
        service_type: 52,
        state: 56,
        start: 24,
        service_process: 192,
        driver_name: 192,
    },
    process: ServiceProcessLayout {
        binary_path: 12,
        process_id: 20,
    },
};

/// Windows 10 2004 through Windows 11 22H2, 64-bit.
///
/// Windows 11 21H2 (build 22000) and 22H2 (22621) use this: the record did not
/// move between 19041 and 25398.
pub const WIN10_19041_X64: ServiceLayout = ServiceLayout {
    name: "services-win10-19041-x64",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(16),
        service_name: 56,
        display_name: 64,
        order: 32,
        service_type: 72,
        state: 76,
        start: 36,
        service_process: 296,
        driver_name: 296,
    },
    process: ServiceProcessLayout {
        binary_path: 24,
        process_id: 40,
    },
};

/// Windows Server 2022 23H2 and Windows 11 24H2 onwards, 64-bit.
///
/// The release where the process pointer and the driver name finally stopped
/// sharing an offset, and where the type and state words moved eight bytes on.
pub const WIN10_25398_X64: ServiceLayout = ServiceLayout {
    name: "services-win10-25398-x64",
    generation: RecordGeneration::VistaOrLater,
    pointer_size: 8,
    header: ServiceHeaderLayout {
        tag: 0,
        service_record: 16,
    },
    record: ServiceRecordLayout {
        tag: None,
        prev_entry: Some(16),
        service_name: 56,
        display_name: 64,
        order: 32,
        service_type: 80,
        state: 84,
        start: 36,
        service_process: 336,
        driver_name: 296,
    },
    process: ServiceProcessLayout {
        binary_path: 24,
        process_id: 40,
    },
};

/// Every catalogued layout, for callers that want to enumerate or check them.
pub const CATALOGUE: [ServiceLayout; 16] = [
    XP_X86,
    XP_2003_X64,
    VISTA_X86,
    VISTA_X64,
    WIN8_X86,
    WIN8_X64,
    WIN10_15063_X86,
    WIN10_15063_X64,
    WIN10_16299_X86,
    WIN10_16299_X64,
    WIN10_17763_X86,
    WIN10_18362_X86,
    WIN10_18362_X64,
    WIN10_19041_X86,
    WIN10_19041_X64,
    WIN10_25398_X64,
];

/// The catalogued layout a Windows release uses, if there is one.
///
/// Selection is by build number, because that is the fact that decides the
/// layout: the structure moved at 15063, 16299, 17763 (32-bit only), 18362,
/// 19041 and 25398, and a release between two of those uses the earlier one.
///
/// Two deliberate differences from upstream, both of which upstream gets wrong
/// by omission rather than on purpose:
///
/// * **32-bit Windows 8 and 8.1 get the Windows 8 layout.** Upstream's
///   selection table marks its `services-win8-x86` entry as a 64-bit one, so it
///   never matches and 32-bit Windows 8 falls through to the Vista layout — a
///   different shape, whose offsets decode a record that parses and is wrong.
/// * **32-bit Server 2003 is refused.** Its `services.exe` is a different
///   binary from XP's, and no layout was ever reverse engineered for it.
///   Returning `None` is the whole point: decoding it at XP offsets would
///   produce a table nothing in it marks as untrustworthy.
///
/// `None` means the release is not catalogued, and the caller must refuse.
pub fn select_layout(is_64bit: bool, major: u32, minor: u32, build: u32) -> Option<ServiceLayout> {
    // Windows 2000 (5.0) and everything before it: never catalogued.
    if major < 5 {
        return None;
    }
    if major == 5 {
        return match (is_64bit, minor) {
            // XP x64 and Server 2003 x64 share one layout, as the upstream
            // file's own name records.
            (true, 1..=2) => Some(XP_2003_X64),
            (false, 1) => Some(XP_X86),
            // 5.0 is Windows 2000; 5.2 on 32-bit is Server 2003, which has no
            // catalogued layout of its own.
            _ => None,
        };
    }
    if is_64bit {
        return Some(match build {
            25398.. => WIN10_25398_X64,
            19041..=25397 => WIN10_19041_X64,
            18362..=19040 => WIN10_18362_X64,
            16299..=18361 => WIN10_16299_X64,
            15063..=16298 => WIN10_15063_X64,
            9200..=15062 => WIN8_X64,
            6000..=9199 => VISTA_X64,
            // 6.x below 6000 is not a shipped build number.
            _ => return None,
        });
    }
    Some(match build {
        19041.. => WIN10_19041_X86,
        18362..=19040 => WIN10_18362_X86,
        17763..=18361 => WIN10_17763_X86,
        16299..=17762 => WIN10_16299_X86,
        15063..=16298 => WIN10_15063_X86,
        9200..=15062 => WIN8_X86,
        6000..=9199 => VISTA_X86,
        _ => return None,
    })
}

// ── Resolved layout for one image ───────────────────────────────────────────

/// The service record structure, for symbol tables that happen to declare it.
pub const TYPE_SERVICE_RECORD: &str = "_SERVICE_RECORD";

/// The header that precedes a record from Vista.
pub const TYPE_SERVICE_HEADER: &str = "_SERVICE_HEADER";

/// The process block a running process service points at.
pub const TYPE_SERVICE_PROCESS: &str = "_SERVICE_PROCESS";

/// Every layout fact a service enumeration of one image needs, resolved once.
///
/// Resolved up front and checked once, so a build whose records cannot be
/// described fails here naming the build rather than at record three hundred
/// having already emitted a table of names read at the wrong offsets.
#[derive(Debug, Clone)]
pub struct ServiceSymbols {
    /// The offsets themselves.
    pub layout: ServiceLayout,
    /// Where they came from.
    pub source: ServiceLayoutSource,
    /// Which shape of record this build uses.
    pub generation: RecordGeneration,
    /// Pointer width, in bytes, of `services.exe` on this image.
    pub pointer_size: u64,
    /// The build the layout was selected for, for the record.
    pub build: u32,
}

impl ServiceSymbols {
    /// Resolve every offset a service enumeration of this image needs.
    ///
    /// The symbol table is asked first: if it declares `_SERVICE_RECORD` — which
    /// a kernel PDB never does, but a symbol table an examiner supplied might —
    /// every offset comes from it, and a member it does not declare is an error
    /// naming that member. Otherwise the per-release catalogue is selected by
    /// build number and pointer width.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Unsupported`] when:
    ///
    /// * the build number was never established, so no layout can be chosen —
    ///   this is why [`crate::profile::KernelBuild::build`] is an `Option` and
    ///   why a stage that needs it must refuse rather than guess;
    /// * the architecture is ARM64, for which no service layout has been
    ///   reverse engineered — the pointer width matches the 64-bit layouts but
    ///   nothing establishes that `services.exe` on ARM64 lays its private
    ///   structures out the same way, and "probably the same" is not evidence;
    /// * the release has no catalogued layout, naming the build;
    /// * the symbol table declares `_SERVICE_RECORD` but not every member the
    ///   decode reads, naming the missing member.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, ServiceError> {
        let build = profile.build.build.ok_or_else(|| {
            ServiceError::unsupported(
                "the kernel build number was never established, and the _SERVICE_RECORD layout \
                 moved between releases, so no layout can be chosen for this image",
            )
        })?;

        let is_64bit =
            match profile.architecture {
                Architecture::X64 => true,
                Architecture::X86 => false,
                Architecture::Arm64 => return Err(ServiceError::unsupported(
                    "this image is ARM64, and no _SERVICE_RECORD layout has been established for \
                     ARM64 Windows; the 64-bit layouts are not known to apply, so services are \
                     not enumerated rather than decoded at offsets that may not be theirs",
                )),
            };

        if profile.symbols.has_type(TYPE_SERVICE_RECORD) {
            return Self::from_symbol_table(profile, build, is_64bit);
        }

        let layout = select_layout(is_64bit, profile.build.major, profile.build.minor, build)
            .ok_or_else(|| {
                ServiceError::unsupported(format!(
                    "no _SERVICE_RECORD layout is catalogued for {}-bit Windows {}.{} build {build}, \
                     and the structure moved between releases, so its records are not decoded",
                    if is_64bit { 64 } else { 32 },
                    profile.build.major,
                    profile.build.minor,
                ))
            })?;
        layout.validate()?;
        Ok(Self {
            generation: layout.generation,
            pointer_size: layout.pointer_size,
            layout,
            source: ServiceLayoutSource::Catalogue,
            build,
        })
    }

    /// Resolve the layout from a symbol table that declares these types.
    fn from_symbol_table(
        profile: &WindowsProfile,
        build: u32,
        is_64bit: bool,
    ) -> Result<Self, ServiceError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let required = |type_name: &str, member: &str| -> Result<u64, ServiceError> {
            reader
                .member_offset(type_name, member)
                .map(|o| o.bytes())
                .map_err(|_| {
                    ServiceError::unsupported(format!(
                    "the symbol table declares '{type_name}' but not its '{member}', so a service \
                     record cannot be decoded from it"
                ))
                })
        };
        let optional = |type_name: &str, member: &str| {
            reader
                .member_offset(type_name, member)
                .ok()
                .map(|o| o.bytes())
        };

        for type_name in [TYPE_SERVICE_HEADER, TYPE_SERVICE_PROCESS] {
            if !profile.symbols.has_type(type_name) {
                return Err(ServiceError::unsupported(format!(
                    "the symbol table declares '{TYPE_SERVICE_RECORD}' but no '{type_name}', so \
                     the records it describes cannot be reached or read in full"
                )));
            }
        }

        // The generation follows the release, not the symbol table: it decides
        // which tag the sweep looks for, and a table that happens to declare
        // both shapes must not silently pick one.
        let generation = if profile.build.major >= 6 {
            RecordGeneration::VistaOrLater
        } else {
            RecordGeneration::PreVista
        };

        let service_process = required(TYPE_SERVICE_RECORD, "ServiceProcess")?;
        let layout = ServiceLayout {
            name: "symbol-table",
            generation,
            pointer_size: if is_64bit { 8 } else { 4 },
            header: ServiceHeaderLayout {
                tag: required(TYPE_SERVICE_HEADER, "Tag")?,
                service_record: required(TYPE_SERVICE_HEADER, "ServiceRecord")?,
            },
            record: ServiceRecordLayout {
                tag: optional(TYPE_SERVICE_RECORD, "Tag"),
                prev_entry: optional(TYPE_SERVICE_RECORD, "PrevEntry"),
                service_name: required(TYPE_SERVICE_RECORD, "ServiceName")?,
                display_name: required(TYPE_SERVICE_RECORD, "DisplayName")?,
                order: required(TYPE_SERVICE_RECORD, "Order")?,
                service_type: required(TYPE_SERVICE_RECORD, "Type")?,
                state: required(TYPE_SERVICE_RECORD, "State")?,
                start: required(TYPE_SERVICE_RECORD, "Start")?,
                service_process,
                // Every release up to 25398 put these at one offset; a table
                // that omits the driver name is describing one of those.
                driver_name: optional(TYPE_SERVICE_RECORD, "DriverName").unwrap_or(service_process),
            },
            process: ServiceProcessLayout {
                binary_path: required(TYPE_SERVICE_PROCESS, "BinaryPath")?,
                process_id: required(TYPE_SERVICE_PROCESS, "ProcessId")?,
            },
        };
        layout.validate()?;
        Ok(Self {
            generation: layout.generation,
            pointer_size: layout.pointer_size,
            layout,
            source: ServiceLayoutSource::SymbolTable,
            build,
        })
    }

    /// Whether this build's records can be reached by list walking.
    ///
    /// List walking follows `PrevEntry` from a head found inside the
    /// `services.exe` image. A release whose records have no such member — XP
    /// and Server 2003 — cannot be list walked at all, and saying so is not the
    /// same as walking a list and finding nothing.
    pub fn supports_list_walk(&self) -> bool {
        self.layout.record.prev_entry.is_some()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "source": self.source.as_str(),
            "generation": self.generation.as_str(),
            "pointer_size": self.pointer_size,
            "build": self.build,
            "supports_list_walk": self.supports_list_walk(),
            "layout": self.layout.to_json(),
        })
    }
}

// ── What a record says ──────────────────────────────────────────────────────

/// The state a service is in, as the Service Control Manager records it.
///
/// The numbering is the published `SERVICE_STATUS.dwCurrentState` and has never
/// changed. A word that is none of these is *not* a state, and a record holding
/// one is not a service record — which is exactly what makes this a validity
/// check rather than a rendering detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// `SERVICE_STOPPED`.
    Stopped,
    /// `SERVICE_START_PENDING`.
    StartPending,
    /// `SERVICE_STOP_PENDING`.
    StopPending,
    /// `SERVICE_RUNNING`.
    Running,
    /// `SERVICE_CONTINUE_PENDING`.
    ContinuePending,
    /// `SERVICE_PAUSE_PENDING`.
    PausePending,
    /// `SERVICE_PAUSED`.
    Paused,
}

impl ServiceState {
    /// The state a raw word names, or `None` when it names none.
    pub fn from_raw(raw: i64) -> Option<ServiceState> {
        Some(match raw {
            1 => ServiceState::Stopped,
            2 => ServiceState::StartPending,
            3 => ServiceState::StopPending,
            4 => ServiceState::Running,
            5 => ServiceState::ContinuePending,
            6 => ServiceState::PausePending,
            7 => ServiceState::Paused,
            _ => return None,
        })
    }

    /// The constant's name, as an examiner and the oracle both read it.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceState::Stopped => "SERVICE_STOPPED",
            ServiceState::StartPending => "SERVICE_START_PENDING",
            ServiceState::StopPending => "SERVICE_STOP_PENDING",
            ServiceState::Running => "SERVICE_RUNNING",
            ServiceState::ContinuePending => "SERVICE_CONTINUE_PENDING",
            ServiceState::PausePending => "SERVICE_PAUSE_PENDING",
            ServiceState::Paused => "SERVICE_PAUSED",
        }
    }
}

/// How a service is configured to start.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceStart {
    /// `SERVICE_BOOT_START`: loaded by the boot loader.
    BootStart,
    /// `SERVICE_SYSTEM_START`: started during kernel initialisation.
    SystemStart,
    /// `SERVICE_AUTO_START`: started by the SCM at boot.
    AutoStart,
    /// `SERVICE_DEMAND_START`: started on request.
    DemandStart,
    /// `SERVICE_DISABLED`: cannot be started.
    Disabled,
}

impl ServiceStart {
    /// The start type a raw word names, or `None` when it names none.
    pub fn from_raw(raw: i64) -> Option<ServiceStart> {
        Some(match raw {
            0 => ServiceStart::BootStart,
            1 => ServiceStart::SystemStart,
            2 => ServiceStart::AutoStart,
            3 => ServiceStart::DemandStart,
            4 => ServiceStart::Disabled,
            _ => return None,
        })
    }

    /// The constant's name.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceStart::BootStart => "SERVICE_BOOT_START",
            ServiceStart::SystemStart => "SERVICE_SYSTEM_START",
            ServiceStart::AutoStart => "SERVICE_AUTO_START",
            ServiceStart::DemandStart => "SERVICE_DEMAND_START",
            ServiceStart::Disabled => "SERVICE_DISABLED",
        }
    }
}

/// Highest load order a real service record carries.
///
/// The Service Control Manager numbers services as it loads them; a word above
/// this at the order's offset means the bytes are not a service record. It is
/// the cheapest of the three validity checks and rejects most false hits.
pub const MAX_SERVICE_ORDER: u64 = 0xFFFF;

/// The published service type bits and the names an examiner reads.
///
/// Win32 API constants, fixed by `winnt.h` and unchanged since NT. Spelled as
/// the Windows headers spell them, `SERVICE_ADAPTOR` included.
pub const SERVICE_TYPE_FLAGS: [(&str, u32); 7] = [
    ("SERVICE_KERNEL_DRIVER", 0x0000_0001),
    ("SERVICE_FILE_SYSTEM_DRIVER", 0x0000_0002),
    ("SERVICE_ADAPTOR", 0x0000_0004),
    ("SERVICE_RECOGNIZER_DRIVER", 0x0000_0008),
    ("SERVICE_WIN32_OWN_PROCESS", 0x0000_0010),
    ("SERVICE_WIN32_SHARE_PROCESS", 0x0000_0020),
    ("SERVICE_INTERACTIVE_PROCESS", 0x0000_0100),
];

/// The type bits that make a service a *process* rather than a driver.
///
/// `SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS |
/// SERVICE_INTERACTIVE_PROCESS`. Which side of this a service falls on decides
/// which member holds its binary: a process service reaches its path through a
/// `_SERVICE_PROCESS`, and a driver service holds a driver name directly. Read
/// the wrong one and the binary column shows a pointer's worth of unrelated
/// text.
pub const SERVICE_TYPE_PROCESS_MASK: u32 = 0x0000_0010 | 0x0000_0020 | 0x0000_0100;

/// The type names a service type word sets, joined with `|`.
///
/// `None` when the word sets no bit any published service type defines. That is
/// not "no type": a real record always names at least one, so a word that names
/// none is evidence the bytes are not a type word, and rendering it as an empty
/// cell would read exactly like a successful parse.
pub fn service_type_names(service_type: u32) -> Option<String> {
    let names: Vec<&str> = SERVICE_TYPE_FLAGS
        .iter()
        .filter(|(_, bit)| service_type & bit != 0)
        .map(|(name, _)| *name)
        .collect();
    if names.is_empty() {
        None
    } else {
        Some(names.join("|"))
    }
}

/// Whether a service type word describes a service that runs in a process.
pub fn is_process_service(service_type: u32) -> bool {
    service_type & SERVICE_TYPE_PROCESS_MASK != 0
}

// ── Reading raw bytes at catalogued offsets ─────────────────────────────────

/// A NUL-terminated wide string as it was found, with what is known about how
/// it ended.
///
/// The two flags are separate because they support different conclusions. Text
/// that ran to the read cap without a terminator may be longer than what is
/// shown; text with a replacement character in it is shown exactly as long as
/// it is, but is not byte-for-byte what the process held.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WideText {
    /// The decoded text, up to but not including the terminator.
    pub text: String,
    /// Whether a NUL terminator was actually reached.
    ///
    /// `false` means the read hit its cap or an unacquired page first, so the
    /// string may continue past what is shown.
    pub terminated: bool,
    /// Whether every code unit decoded cleanly.
    pub well_formed: bool,
}

impl WideText {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "text": self.text,
            "terminated": self.terminated,
            "well_formed": self.well_formed,
        })
    }
}

/// Read a NUL-terminated UTF-16LE string, one small step at a time.
///
/// Stepping rather than reading the whole cap at once is deliberate: a service
/// name that ends twenty bytes into a page whose *next* page was never acquired
/// is fully recoverable, and a single 512-byte read spanning both would fail
/// outright and report the name as unreadable.
///
/// # Errors
///
/// [`ObjError`] only when the *first* step could not be read, which means
/// nothing of the string was acquired. A later step failing ends the string with
/// [`WideText::terminated`] false, because the bytes already read are evidence.
pub fn read_wide_string(
    reader: &StructReader,
    address: u64,
    max_bytes: u64,
) -> Result<WideText, ObjError> {
    let mut bytes: Vec<u8> = Vec::new();
    let mut terminated = false;
    let mut offset: u64 = 0;

    while offset < max_bytes {
        let want = WIDE_STRING_STEP.min(max_bytes.saturating_sub(offset));
        let at = address.checked_add(offset).ok_or_else(|| {
            SymbolError::malformed(format!(
                "a wide string at {address:#x} runs past the end of the 64-bit address space"
            ))
        })?;
        let step = match reader.read_bytes(at, want) {
            Ok(step) => step,
            Err(err) if offset == 0 => return Err(err),
            // Something was read before the gap: keep it, and say it did not end.
            Err(_) => break,
        };
        // Whole code units only: a trailing odd byte cannot be half a unit.
        let usable = step.len() - (step.len() % 2);
        let mut end = usable;
        for index in (0..usable).step_by(2) {
            if step[index] == 0 && step[index + 1] == 0 {
                end = index;
                terminated = true;
                break;
            }
        }
        bytes.extend_from_slice(&step[..end]);
        // Stop on the terminator, on an odd tail that cannot be half a code
        // unit, and on a step that came back short — in each case there is no
        // defensible next byte to continue from.
        if terminated || usable != step.len() || (step.len() as u64) < want {
            break;
        }
        offset = offset.saturating_add(want);
    }

    let (text, well_formed) = decode_utf16le(&bytes);
    Ok(WideText {
        text,
        terminated,
        well_formed,
    })
}

/// Add a structure offset to a base address, refusing to wrap.
fn at(base: u64, offset: u64) -> Result<u64, ObjError> {
    base.checked_add(offset).ok_or_else(|| {
        SymbolError::malformed(format!(
            "the member {offset:#x} bytes into the structure at {base:#x} lies past the end of \
             the 64-bit address space"
        ))
        .into()
    })
}

/// Read a little-endian 32-bit word.
fn read_u32(reader: &StructReader, address: u64) -> Result<u32, ObjError> {
    let bytes = reader.read_bytes(address, 4)?;
    let word: [u8; 4] = bytes
        .get(..4)
        .and_then(|slice| <[u8; 4]>::try_from(slice).ok())
        .ok_or_else(|| {
            SymbolError::malformed(format!(
                "fewer than four bytes were acquired at {address:#x}"
            ))
        })?;
    Ok(u32::from_le_bytes(word))
}

/// Read a pointer of this build's width, little-endian.
///
/// The width comes from the resolved layout rather than from the kernel symbol
/// table's pointer type: what matters is how `services.exe` laid its structures
/// out, which is what the layout describes.
fn read_pointer(reader: &StructReader, address: u64, pointer_size: u64) -> Result<u64, ObjError> {
    // Refused rather than clamped: a width that is neither means the layout was
    // never resolved, and reading four or eight bytes anyway would produce an
    // address that looks like one.
    if pointer_size != 4 && pointer_size != 8 {
        return Err(SymbolError::malformed(format!(
            "a pointer width of {pointer_size} byte(s) is neither 32- nor 64-bit, so the value at \
             {address:#x} cannot be read as a pointer"
        ))
        .into());
    }
    let width = pointer_size as usize;
    let bytes = reader.read_bytes(address, pointer_size)?;
    let slice = bytes.get(..width).ok_or_else(|| {
        SymbolError::malformed(format!(
            "fewer than {width} bytes were acquired for the pointer at {address:#x}"
        ))
    })?;
    let mut value = 0u64;
    for (index, byte) in slice.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    Ok(value)
}

// ── Results ─────────────────────────────────────────────────────────────────

/// How a record was reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceMethod {
    /// Found by sweeping the committed memory of `services.exe` for the record
    /// or header tag. Reaches records nothing points at any more.
    Scanned,
    /// Reached by following the record chain from the list head inside the
    /// `services.exe` image. Reaches only records the Service Control Manager
    /// still links.
    Listed,
}

impl ServiceMethod {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceMethod::Scanned => "scanned",
            ServiceMethod::Listed => "listed",
        }
    }
}

/// One service, as its record holds it.
#[derive(Debug, Clone)]
pub struct ServiceRecord {
    /// Where the `_SERVICE_RECORD` is, in the address space of `services.exe`.
    pub address: u64,
    /// The `_SERVICE_HEADER` it was reached through, when it was reached
    /// through one. `None` before Vista, which has no headers.
    pub header: Option<u64>,
    /// How it was reached.
    pub method: ServiceMethod,
    /// The Service Control Manager's load order for it.
    pub order: u64,
    /// The raw service type word, before any bit is named.
    pub service_type: u32,
    /// The type as an examiner reads it. `None` means the word set no known
    /// bit — never "no type".
    pub type_names: Option<String>,
    /// The state the service was in.
    pub state: ServiceState,
    /// How the service is configured to start.
    pub start: ServiceStart,
    /// The service's short name — the one a SID is derived from and the one the
    /// registry keys it under.
    pub name: Field<String>,
    /// The service's display name.
    pub display_name: Field<String>,
    /// The binary behind the service: the image path of a running process
    /// service, or the driver name of a driver service.
    ///
    /// [`Field::NotApplicable`] for a service that is not running, which is what
    /// upstream reports too: the record only carries a live binary while there
    /// is one.
    pub binary: Field<String>,
    /// The PID the service is running as.
    ///
    /// [`Field::NotApplicable`] for anything that is not a *running process*
    /// service: a driver has no PID, and a stopped service is not running as
    /// anything. Never zero, which is a PID.
    pub pid: Field<u64>,
    /// `ImagePath` from the service's own registry key, when the registry side
    /// was supplied.
    ///
    /// Worth its own column because it is the configured binary rather than the
    /// live one, and the two disagreeing is a finding.
    pub registry_binary: Field<String>,
    /// `Parameters\ServiceDll` from the registry, when it was supplied. The DLL
    /// a shared-process service actually runs, which the live binary path —
    /// `svchost.exe -k …` — does not name.
    pub registry_dll: Field<String>,
    /// Everything odd about the record that did not disqualify it.
    pub notes: Vec<String>,
}

impl ServiceRecord {
    /// The service's name, when it was readable.
    pub fn name_text(&self) -> Option<&str> {
        self.name.known().map(String::as_str)
    }

    /// Whether the service was running when the image was taken.
    pub fn is_running(&self) -> bool {
        self.state == ServiceState::Running
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "header": self.header,
            "method": self.method.as_str(),
            "order": self.order,
            "type": self.service_type,
            "type_names": self.type_names,
            "state": self.state.as_str(),
            "start": self.start.as_str(),
            "name": self.name.to_json(),
            "display_name": self.display_name.to_json(),
            "binary": self.binary.to_json(),
            "pid": self.pid.to_json(),
            "registry_binary": self.registry_binary.to_json(),
            "registry_dll": self.registry_dll.to_json(),
            "notes": self.notes,
        })
    }
}

/// A candidate the enumeration declined to report, and why.
#[derive(Debug, Clone)]
pub struct SkippedService {
    /// Where the candidate was: a tag hit, a header, or a record address.
    pub address: u64,
    /// Why it was not reported, in the examiner's terms.
    pub reason: String,
}

/// Why an enumeration ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStop {
    /// Every hit was followed and every chain ran out.
    Exhausted,
    /// A cap fired. The enumeration stopped; the services did not end.
    CapReached {
        /// Which cap fired, in the examiner's terms.
        what: &'static str,
        /// The value it fired at.
        cap: usize,
    },
}

impl ServiceStop {
    /// Whether the enumeration ran to the end.
    pub fn is_complete(&self) -> bool {
        matches!(self, ServiceStop::Exhausted)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceStop::Exhausted => "exhausted",
            ServiceStop::CapReached { .. } => "cap_reached",
        }
    }
}

/// One enumeration of one `services.exe`, and everything it could not do.
#[derive(Debug, Clone)]
pub struct ServiceListing {
    /// The `_EPROCESS` of the `services.exe` this came from, in kernel space.
    pub process: u64,
    /// That process's PID, when it was readable.
    pub pid: Option<u64>,
    /// Which enumeration produced it.
    pub method: ServiceMethod,
    /// Which layout the records were decoded with, for the record.
    pub layout: &'static str,
    /// The services, in the order they were reached.
    pub services: Vec<ServiceRecord>,
    /// Candidates declined, capped by [`ServiceScanConfig::max_recorded_skips`].
    pub skipped: Vec<SkippedService>,
    /// How many were declined in total. Exact even when the list above was
    /// capped.
    pub skipped_total: usize,
    /// How many tag hits the sweep produced.
    pub hits: usize,
    /// How many committed ranges were swept.
    pub sections: usize,
    /// Distinct bytes of `services.exe` actually examined.
    pub bytes_scanned: u64,
    /// Bytes inside the swept ranges that could not be read.
    pub unread_bytes: u64,
    /// How many of [`Self::unread_bytes`] were never mapped.
    ///
    /// A VAD can describe a large reserved region that was never committed, and
    /// sweeping it reaches address space that never held a page. Those bytes
    /// are not evidence that was missed — nothing could have been there — but
    /// they dwarf the bytes that were mapped and genuinely unreadable, which
    /// are the ones an examiner needs to see.
    pub unmapped_bytes: u64,
    /// Whether every requested byte of every range was examined.
    ///
    /// False when any range held bytes that were not examined — including
    /// address space that was never mapped, which is the ordinary state of a
    /// reserved region. Kept deliberately strict: an examiner reading
    /// "complete" should be reading a claim about the whole requested range,
    /// and [`Self::unmapped_bytes`] is there to explain a shortfall that was
    /// never evidence.
    pub scan_complete: bool,
    /// Whether a sweep stopped at a cap rather than running out of range.
    ///
    /// Separate from [`Self::scan_complete`], which a purely unmapped shortfall
    /// also clears. This one means the sweep gave up while there was still
    /// mapped memory ahead of it, which is the case where a record really could
    /// have been missed.
    pub scan_truncated: bool,
    /// Whether the ranges handed to this enumeration were every range the
    /// process had.
    ///
    /// Separate from [`ServiceListing::scan_complete`], which says whether the
    /// ranges that *were* supplied were read in full. A VAD tree that stopped
    /// early yields a shorter list of ranges, every byte of which reads
    /// perfectly, and a listing that only reported `scan_complete` would call
    /// that a complete account of the machine's services.
    pub ranges_complete: bool,
    /// Whether the process list this `services.exe` was found on walked to
    /// completion.
    ///
    /// A machine can run more than one Service Control Manager — a container
    /// host runs one per silo — so a truncated process list can hide an entire
    /// second listing. Every byte of this one can then read perfectly while the
    /// machine's services are still under-reported, and a listing that reported
    /// only its own sweep would call that "these services and no others".
    pub process_list_complete: bool,
    /// Why the enumeration ended.
    pub stop: ServiceStop,
    /// Everything about the enumeration as a whole worth stating.
    pub notes: Vec<String>,
}

impl ServiceListing {
    /// Whether this is a complete account of the services this enumeration can
    /// see.
    ///
    /// The question a report must ask before writing "this machine had these
    /// services and no others", and the question [`diff_services`] asks before
    /// calling anything unlinked. An enumeration that stopped early is not a
    /// short list; it is a wrong one until the report says otherwise.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete()
            && self.skipped_total == 0
            && self.scan_complete
            && self.ranges_complete
            && self.process_list_complete
            && self.unread_bytes == 0
    }

    /// The services whose name was readable, keyed by address.
    fn by_address(&self) -> HashSet<u64> {
        self.services
            .iter()
            .map(|service| service.address)
            .collect()
    }

    /// Everything a report must declare about this enumeration.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let ServiceStop::CapReached { what, cap } = self.stop {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the {} enumeration of the services.exe at {:#x} stopped at its cap of {cap} \
                     {what}; the services did not end there",
                    self.method.as_str(),
                    self.process
                ),
            ));
        }
        if self.skipped_total > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} candidate service record(s) in the services.exe at {:#x} could not be \
                     decoded, so any service among them is not listed",
                    self.skipped_total, self.process
                ),
            ));
        }
        // Only the mapped-but-unreadable part is a gap in the examination. The
        // rest of `unread_bytes` is address space a VAD described and no page
        // ever backed — a large reserved allocation reads as terabytes here,
        // and reporting that as "not examined" both overstates the gap by
        // orders of magnitude and hides the real one behind it. A service
        // record cannot live in memory that was never committed.
        let unreadable = self.unread_bytes.saturating_sub(self.unmapped_bytes);
        if unreadable > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{unreadable} mapped byte(s) of the services.exe at {:#x} could not be read, \
                     so a service record among them would not have been found",
                    self.process
                ),
            ));
        }
        if self.scan_truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "a sweep of the services.exe at {:#x} stopped at a cap with mapped memory \
                     still ahead of it, so a service record beyond that point was not looked for",
                    self.process
                ),
            ));
        }
        // Shortfall that is neither: the swept ranges included address space no
        // page ever backed. `scan_complete` stays false, because the claim it
        // makes is about the whole requested range — but an examiner must not
        // read that as evidence possibly missed, because nothing can be stored
        // in memory that was never committed. Said plainly rather than left as
        // a bare `complete: false` with no entry explaining it.
        if !self.scan_complete && unreadable == 0 && !self.scan_truncated {
            out.push(Incomplete::new(
                IncompleteReason::Unmapped,
                format!(
                    "{} byte(s) of the ranges swept for the services.exe at {:#x} were never \
                     mapped, so they were not examined and could not have held a service record; \
                     every mapped byte was read",
                    self.unmapped_bytes, self.process
                ),
            ));
        }
        if !self.ranges_complete {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the memory ranges of the services.exe at {:#x} could not all be established, \
                     so this enumeration was not offered every byte the process had and a service \
                     record outside what it was offered would not have been found",
                    self.process
                ),
            ));
        }
        if !self.process_list_complete {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the active process list did not walk to completion, so another services.exe may \
                 exist that was never enumerated and this is not a complete account of the \
                 machine's services"
                    .to_string(),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "pid": self.pid,
            "method": self.method.as_str(),
            "layout": self.layout,
            "count": self.services.len(),
            "services": self.services.iter().map(ServiceRecord::to_json).collect::<Vec<_>>(),
            "hits": self.hits,
            "sections": self.sections,
            "bytes_scanned": self.bytes_scanned,
            "unread_bytes": self.unread_bytes,
            "unmapped_bytes": self.unmapped_bytes,
            "scan_complete": self.scan_complete,
            "ranges_complete": self.ranges_complete,
            "process_list_complete": self.process_list_complete,
            "skipped_total": self.skipped_total,
            "skipped": self
                .skipped
                .iter()
                .map(|skip| serde_json::json!({
                    "address": skip.address,
                    "reason": skip.reason,
                }))
                .collect::<Vec<_>>(),
            "stop": self.stop.as_str(),
            "complete": self.is_complete(),
            "notes": self.notes,
        })
    }
}

/// Caps and optional enrichment for one enumeration.
#[derive(Debug, Clone)]
pub struct ServiceScanConfig {
    /// Ceiling on services reported.
    pub max_services: usize,
    /// Ceiling on records one `PrevEntry` chain will follow.
    pub max_chain: usize,
    /// Ceiling on individually recorded skips.
    pub max_recorded_skips: usize,
    /// Ceiling on committed ranges swept.
    pub max_sections: usize,
    /// Ceiling on bytes read for one of a record's strings.
    pub max_string_bytes: u64,
    /// Chunking geometry for the sweep itself.
    pub scan: ScanConfig,
    /// The registry side of the same services, when it was built. `None` leaves
    /// [`ServiceRecord::registry_binary`] and [`ServiceRecord::registry_dll`]
    /// [`Field::Unavailable`] rather than empty, because "this service has no
    /// registry key" and "we did not look" are different findings.
    pub registry: Option<Arc<ServiceRegistryMap>>,
}

impl Default for ServiceScanConfig {
    fn default() -> Self {
        Self {
            max_services: MAX_SERVICES,
            max_chain: MAX_CHAIN_LENGTH,
            max_recorded_skips: MAX_RECORDED_SKIPS,
            max_sections: MAX_SERVICE_SECTIONS,
            max_string_bytes: MAX_SERVICE_STRING_BYTES,
            scan: ScanConfig::default(),
            registry: None,
        }
    }
}

// ── Finding the Service Control Manager ─────────────────────────────────────

/// One `services.exe`, its address space, and where its records can be.
///
/// Built once per process and used by both enumerations, because deriving the
/// committed ranges is the expensive part and scanning them twice would double
/// the cost of `svcdiff` for nothing.
#[derive(Clone)]
pub struct ServiceTarget {
    /// The `_EPROCESS`, in kernel space.
    pub process: u64,
    /// The PID, when it was readable.
    pub pid: Option<u64>,
    /// The process's own address space. A named type because handing these
    /// functions the kernel space instead does not fail — it sweeps the wrong
    /// memory and reports nothing, which reads as a machine with no services.
    pub space: ProcessSpace,
    /// Every committed range of the process, merged, ascending. Where a swept
    /// enumeration looks.
    pub sections: Vec<Range<u64>>,
    /// The range(s) the `services.exe` image itself is mapped at. Where a list
    /// walk looks for the list head.
    pub image_sections: Vec<Range<u64>>,
    /// Whether these ranges are every range the process had.
    ///
    /// `false` when the VAD tree they came from did not walk end to end, or
    /// when merging them hit its cap. A sweep of an incomplete set of ranges
    /// can miss a record entirely, so a listing built from one must not claim
    /// to be a complete account of the machine's services — which is exactly
    /// what would turn a page that was never acquired into a service that was
    /// never there.
    pub ranges_complete: bool,
    /// Whether the active process list this target was found on walked to
    /// completion.
    ///
    /// `false` means another `services.exe` may exist past the point the walk
    /// stopped, so no listing built from this target is a complete account of
    /// the machine's services however perfectly it sweeps.
    pub process_list_complete: bool,
    /// Everything about building this target worth stating.
    pub notes: Vec<String>,
}

impl std::fmt::Debug for ServiceTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceTarget")
            .field("process", &format_args!("{:#x}", self.process))
            .field("pid", &self.pid)
            .field("sections", &self.sections.len())
            .field("image_sections", &self.image_sections.len())
            .finish_non_exhaustive()
    }
}

impl ServiceTarget {
    /// A target a caller has already assembled, for a fixture or for an
    /// examiner who derived the ranges another way.
    ///
    /// [`ServiceTarget::ranges_complete`] and
    /// [`ServiceTarget::process_list_complete`] both start `true`: a caller
    /// that supplies ranges is asserting they are the process's ranges, and a
    /// caller that names the process directly is asserting it found every one.
    /// Clear either before enumerating if that is not so.
    pub fn new(
        process: u64,
        pid: Option<u64>,
        space: ProcessSpace,
        sections: Vec<Range<u64>>,
        image_sections: Vec<Range<u64>>,
    ) -> Self {
        Self {
            process,
            pid,
            space,
            sections,
            image_sections,
            ranges_complete: true,
            process_list_complete: true,
            notes: Vec::new(),
        }
    }
}

/// Merge ranges into an ascending, disjoint, non-adjacent set.
///
/// Adjacency matters rather than being tidiness: the sweep suppresses its chunk
/// overlap at the end of a range, so two ranges that touch would silently lose
/// a tag lying across the join.
///
/// Returns the merged ranges and how many were dropped because `cap` was
/// reached. The count is returned rather than swallowed: a dropped range is a
/// stretch of the process nothing swept, and a sweep that silently covered less
/// than it was asked to still reports every record it found as though it had
/// covered everything.
fn merge_ranges(mut ranges: Vec<Range<u64>>, cap: usize) -> (Vec<Range<u64>>, usize) {
    ranges.retain(|range| range.start < range.end);
    ranges.sort_by_key(|range| (range.start, range.end));
    let mut merged: Vec<Range<u64>> = Vec::new();
    let mut dropped = 0usize;
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => {
                if range.end > last.end {
                    last.end = range.end;
                }
            }
            _ => {
                if merged.len() >= cap {
                    dropped = dropped.saturating_add(1);
                    continue;
                }
                merged.push(range);
            }
        }
    }
    (merged, dropped)
}

/// Why an image yielded no `services.exe` worth enumerating.
///
/// A separate function because it is the branch that decides between "this
/// machine ran no services" and "nobody could look", and the two must not be
/// allowed to converge on an empty result. `candidates` is how many processes on
/// the list were named `services.exe`, `failures` is why each of them could not
/// be used, and `process_list_complete` says whether the list itself was walked
/// end to end.
fn no_targets_refusal(
    candidates: usize,
    failures: &[String],
    process_list_complete: bool,
) -> ServiceError {
    if candidates == 0 {
        return ServiceError::unsupported(format!(
            "no process named {SERVICES_IMAGE_NAME} is on the process list{}, so there is no \
             Service Control Manager to enumerate; an empty service list would read as a machine \
             running no services rather than as a machine whose services were never looked for",
            if process_list_complete {
                ""
            } else {
                ", and the process list itself did not walk to completion"
            }
        ));
    }
    ServiceError::unsupported(format!(
        "{candidates} process(es) named {SERVICES_IMAGE_NAME} were found and none of their \
         address spaces could be built, so no service record can be reached: {}",
        failures.join("; ")
    ))
}

/// Every `services.exe` in the image, with its address space and its ranges.
///
/// A `Vec` rather than one target because a machine with two processes named
/// `services.exe` is itself a finding, and silently picking one would hide it.
/// The ordinary answer has exactly one element.
///
/// # Errors
///
/// [`ServiceError`] when the process list itself cannot be walked or the VAD
/// layout cannot be described, and [`ServiceError::Unsupported`] when no target
/// could be built at all — because no process on the list is named
/// `services.exe`, or because every one that is had an address space that could
/// not be built.
///
/// Never `Ok` with an empty vector. An empty list of targets becomes an empty
/// list of services, which renders as a machine that was running none; every
/// Windows machine runs a Service Control Manager, so not finding one is a
/// failure to look and is reported as one. A `services.exe` that could not be
/// built while another could is not an error — the reason travels on the
/// targets that were built.
pub fn find_service_targets(
    profile: &WindowsProfile,
    config: &ServiceScanConfig,
) -> Result<Vec<ServiceTarget>, ServiceError> {
    let process_symbols = ProcessSymbols::from_profile(profile)?;
    let module_symbols = ModuleSymbols::from_profile(profile)?;
    let vad_symbols = VadSymbols::from_profile(profile)?;
    let list = list_processes(profile, &process_symbols, &ProcessListConfig::default())?;
    let module_config = ModuleWalkConfig::default();
    let vad_config = VadWalkConfig::default();

    let mut targets = Vec::new();
    let mut candidates = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for record in &list.processes {
        let matches = record
            .image_file_name
            .known()
            .is_some_and(|name| name.eq_ignore_ascii_case(SERVICES_IMAGE_NAME));
        if !matches {
            continue;
        }
        candidates += 1;
        let mut notes = Vec::new();
        let space =
            match ProcessSpace::build(profile, &module_symbols, record.address, &module_config) {
                Ok(space) => space,
                Err(err) => {
                    // Not an error for the run while another services.exe may
                    // still be readable, but never silent: the reason is carried
                    // onto every target that was built, and if none was, it is
                    // what the refusal below says.
                    tracing::debug!(
                        process = record.address,
                        "the services.exe address space could not be built: {err}"
                    );
                    failures.push(format!(
                        "the address space of the services.exe at {:#x} could not be built: {err}",
                        record.address
                    ));
                    continue;
                }
            };

        let tree = list_vads(profile, &vad_symbols, record.address, &vad_config)?;
        let mut ranges_complete = tree.is_complete();
        if !tree.is_complete() {
            notes.push(format!(
                "{} of this services.exe's memory ranges could not be followed, so a service \
                 record inside one of them would not have been swept",
                tree.skipped_total
            ));
        }
        let mut sections = Vec::new();
        let mut image_sections = Vec::new();
        for vad in &tree.vads {
            let Some(end) = vad.end.checked_add(1) else {
                notes.push(format!(
                    "the range at {:#x} ends at the top of the address space and is not swept",
                    vad.start
                ));
                ranges_complete = false;
                continue;
            };
            sections.push(vad.start..end);
            if vad
                .file
                .name()
                .is_some_and(|name| name.to_lowercase().ends_with("\\services.exe"))
            {
                image_sections.push(vad.start..end);
            }
        }
        if image_sections.is_empty() {
            notes.push(
                "no mapped range of this process names services.exe, so the service list head \
                 cannot be located and only a swept enumeration is possible"
                    .to_string(),
            );
        }

        let (sections, dropped) = merge_ranges(sections, config.max_sections);
        let (image_sections, image_dropped) = merge_ranges(image_sections, config.max_sections);
        if dropped > 0 || image_dropped > 0 {
            notes.push(format!(
                "{} of this services.exe's memory ranges were dropped at the cap of {} range(s), \
                 so they were not swept",
                dropped.saturating_add(image_dropped),
                config.max_sections
            ));
            ranges_complete = false;
        }

        targets.push(ServiceTarget {
            process: record.address,
            pid: record.pid.known().copied(),
            space,
            sections,
            image_sections,
            ranges_complete,
            process_list_complete: list.is_complete(),
            notes,
        });
    }

    if targets.is_empty() {
        return Err(no_targets_refusal(
            candidates,
            &failures,
            list.is_complete(),
        ));
    }
    // A Service Control Manager nobody could read bounds what every listing
    // below can claim, so it travels with each of them rather than only in a
    // log line.
    if !failures.is_empty() {
        for target in &mut targets {
            for failure in &failures {
                target.notes.push(failure.clone());
            }
        }
    }
    if !list.is_complete() {
        for target in &mut targets {
            target.notes.push(
                "the process list did not walk to completion, so another services.exe may exist \
                 that this enumeration never reached"
                    .to_string(),
            );
        }
    }
    Ok(targets)
}

// ── The enumeration ─────────────────────────────────────────────────────────

/// Shared state for one enumeration, so the sweep and the chain walk agree
/// about what has already been reported and what has already been declined.
struct Enumerator<'a> {
    reader: StructReader,
    symbols: &'a ServiceSymbols,
    config: &'a ServiceScanConfig,
    listing: ServiceListing,
    /// Record addresses already reported. Both the sweep and the chain walk
    /// consult it: a chain that reaches a record another chain already reported
    /// has, by construction, reached every record before it too, so it stops.
    seen: HashSet<u64>,
}

impl<'a> Enumerator<'a> {
    fn new(
        profile: &WindowsProfile,
        symbols: &'a ServiceSymbols,
        target: &ServiceTarget,
        config: &'a ServiceScanConfig,
        method: ServiceMethod,
    ) -> Self {
        Self {
            reader: StructReader::new(
                Arc::clone(target.space.layer()),
                Arc::clone(&profile.symbols),
            ),
            symbols,
            config,
            listing: ServiceListing {
                process: target.process,
                pid: target.pid,
                method,
                layout: symbols.layout.name,
                services: Vec::new(),
                skipped: Vec::new(),
                skipped_total: 0,
                hits: 0,
                sections: 0,
                bytes_scanned: 0,
                unread_bytes: 0,
                unmapped_bytes: 0,
                scan_complete: true,
                scan_truncated: false,
                ranges_complete: target.ranges_complete,
                process_list_complete: target.process_list_complete,
                stop: ServiceStop::Exhausted,
                notes: target.notes.clone(),
            },
            seen: HashSet::new(),
        }
    }

    /// Record a candidate the enumeration declined, keeping the list bounded
    /// without losing the count.
    fn skip(&mut self, address: u64, reason: impl Into<String>) {
        self.listing.skipped_total += 1;
        if self.listing.skipped.len() < self.config.max_recorded_skips {
            self.listing.skipped.push(SkippedService {
                address,
                reason: reason.into(),
            });
        }
    }

    /// Whether the service cap has fired, marking the listing if so.
    fn capped(&mut self) -> bool {
        if self.listing.services.len() >= self.config.max_services {
            self.listing.stop = ServiceStop::CapReached {
                what: "service(s)",
                cap: self.config.max_services,
            };
            return true;
        }
        false
    }

    /// Decode one record and add it, or record why it was declined.
    ///
    /// Returns `false` when the enumeration must stop, which is only ever the
    /// service cap.
    fn take(&mut self, address: u64, header: Option<u64>) -> bool {
        if self.capped() {
            return false;
        }
        if !self.seen.insert(address) {
            return true;
        }
        let decoded = decode_record(
            &self.reader,
            self.symbols,
            self.config,
            address,
            header,
            self.listing.method,
        );
        match decoded {
            Ok(record) => self.listing.services.push(record),
            Err(reason) => self.skip(address, reason),
        }
        true
    }

    /// Follow a `PrevEntry` chain from the record a header points at.
    ///
    /// Returns `false` when the enumeration must stop.
    fn follow_chain(&mut self, header: u64) -> bool {
        let Some(prev_offset) = self.symbols.layout.record.prev_entry else {
            self.skip(
                header,
                "this build's records have no PrevEntry, so a header's chain cannot be followed",
            );
            return true;
        };
        // Hoisted out of the `match` scrutinee so the shared borrow of `self`
        // that reading the pointer takes has ended before an arm records a
        // skip, which needs a mutable one.
        let pointer_size = self.symbols.pointer_size;
        let head_pointer = at(header, self.symbols.layout.header.service_record)
            .and_then(|address| read_pointer(&self.reader, address, pointer_size));
        let record_at = match head_pointer {
            Ok(record) => record,
            Err(err) => {
                self.skip(
                    header,
                    format!("this header's record pointer could not be read: {err}"),
                );
                return true;
            }
        };
        if record_at == 0 {
            self.skip(header, "this header points at no record");
            return true;
        }

        let mut current = record_at;
        let mut steps = 0usize;
        // Chain-local, so a record reached by two different headers is still
        // recognised as the point at which this chain has caught up.
        let mut walked: HashSet<u64> = HashSet::new();
        loop {
            if steps >= self.config.max_chain {
                self.listing.stop = ServiceStop::CapReached {
                    what: "record(s) in one chain",
                    cap: self.config.max_chain,
                };
                return false;
            }
            if !walked.insert(current) {
                self.skip(
                    current,
                    "this record is already on the chain that reached it, so the chain does not \
                     terminate",
                );
                return true;
            }
            // Everything before an already-reported record has already been
            // reported with it, so this chain has nothing left to add.
            if self.seen.contains(&current) {
                return true;
            }
            if !self.take(current, Some(header)) {
                return false;
            }
            // A record that failed to decode is not one to keep walking from:
            // its PrevEntry would be read out of bytes that are not a record.
            if self
                .listing
                .services
                .last()
                .is_none_or(|record| record.address != current)
            {
                return true;
            }
            let previous = at(current, prev_offset)
                .and_then(|address| read_pointer(&self.reader, address, pointer_size));
            let next = match previous {
                Ok(next) => next,
                Err(err) => {
                    self.skip(
                        current,
                        format!(
                            "this record's PrevEntry could not be read, so the chain stops here \
                             rather than continuing: {err}"
                        ),
                    );
                    return true;
                }
            };
            if next == 0 {
                return true;
            }
            current = next;
            steps += 1;
        }
    }

    /// What a tag hit means, which differs by generation and by enumeration.
    ///
    /// An explicit mode rather than a callback because the decision is a
    /// property of the build, and having it in one `match` beside the reasons a
    /// hit is declined keeps the two from drifting apart.
    fn handle_hit(&mut self, mode: HitMode, hit: u64) -> bool {
        match mode {
            HitMode::RecordBehindTag { tag_offset } => {
                // The record starts in front of its own tag; a hit too close to
                // the bottom of the address space cannot have one behind it.
                let Some(record) = hit.checked_sub(tag_offset) else {
                    self.skip(
                        hit,
                        format!(
                            "a record {tag_offset} byte(s) in front of this tag would lie below \
                             the bottom of the address space"
                        ),
                    );
                    return true;
                };
                self.take(record, None)
            }
            HitMode::Header => {
                // The tag is a *member* of the header, not necessarily its
                // first: every catalogued layout puts it at zero, but a symbol
                // table an examiner supplied can name another offset, and
                // taking the tag's address for the header's would read the
                // record pointer from that many bytes past the member it names.
                let tag_offset = self.symbols.layout.header.tag;
                let Some(header) = hit.checked_sub(tag_offset) else {
                    self.skip(
                        hit,
                        format!(
                            "a header {tag_offset} byte(s) in front of this tag would lie below \
                             the bottom of the address space"
                        ),
                    );
                    return true;
                };
                if !header.is_multiple_of(SERVICE_HEADER_ALIGNMENT) {
                    self.skip(
                        hit,
                        format!(
                            "this tag is not on a {SERVICE_HEADER_ALIGNMENT}-byte boundary, so it \
                             is not the start of a heap allocation and the bytes behind it are \
                             not a service header"
                        ),
                    );
                    return true;
                }
                self.follow_chain(header)
            }
        }
    }

    /// Sweep `sections` for `needle`, handing each hit to [`Self::handle_hit`].
    fn sweep(
        &mut self,
        target: &ServiceTarget,
        sections: &[Range<u64>],
        needle: &[u8; 4],
        mode: HitMode,
    ) -> Result<(), ServiceError> {
        let scanner = MultiStringScanner::new("windows-service-tag", [needle.as_slice()])?;
        for section in sections {
            self.listing.sections += 1;
            let outcome = scan_range(
                target.space.layer().as_ref(),
                &scanner,
                section.clone(),
                &self.config.scan,
            )?;
            self.listing.bytes_scanned = self
                .listing
                .bytes_scanned
                .saturating_add(outcome.bytes_scanned);
            self.listing.unread_bytes = self
                .listing
                .unread_bytes
                .saturating_add(outcome.unread_bytes);
            self.listing.unmapped_bytes = self
                .listing
                .unmapped_bytes
                .saturating_add(outcome.unmapped_bytes);
            if !outcome.is_complete() {
                self.listing.scan_complete = false;
            }
            if outcome.truncated {
                self.listing.scan_truncated = true;
            }
            self.listing.hits = self.listing.hits.saturating_add(outcome.hits.len());
            for hit in &outcome.hits {
                if !self.handle_hit(mode, hit.address) {
                    return Ok(());
                }
            }
        }
        Ok(())
    }
}

/// What the sweep should do with a tag hit.
#[derive(Debug, Clone, Copy)]
enum HitMode {
    /// The hit is a record's own tag, and the record starts `tag_offset` bytes
    /// in front of it. Pre-Vista only.
    RecordBehindTag {
        /// Where the tag sits inside the record.
        tag_offset: u64,
    },
    /// The hit is the start of a `_SERVICE_HEADER`, whose record begins a
    /// chain.
    Header,
}

/// Sweep one `services.exe` for service records — `svcscan`.
///
/// Every committed range of the process is swept for the tag this build's
/// records carry, and each hit is decoded. Records nothing points at any more
/// are found by construction: the sweep asks the memory, not the Service
/// Control Manager.
///
/// # Errors
///
/// [`ServiceError`] only for failures that make the whole enumeration
/// meaningless: a sweep configuration that cannot produce a correct walk, or a
/// layer that cannot enumerate its own mapped regions. A record that could not
/// be decoded is not an error — it is counted in [`ServiceListing::skipped`].
pub fn scan_services_in(
    profile: &WindowsProfile,
    symbols: &ServiceSymbols,
    target: &ServiceTarget,
    config: &ServiceScanConfig,
) -> Result<ServiceListing, ServiceError> {
    let mode = match symbols.generation {
        RecordGeneration::PreVista => {
            // `ServiceLayout::validate` proved this is present for a pre-Vista
            // layout, so the refusal here is belt and braces rather than a
            // reachable path — and it is a refusal, not a default of zero,
            // which would decode every record starting at its own tag.
            let tag_offset = symbols.layout.record.tag.ok_or_else(|| {
                ServiceError::unsupported(format!(
                    "the '{}' layout names no offset for a record's own tag, so a swept hit \
                     cannot be turned into a record address",
                    symbols.layout.name
                ))
            })?;
            HitMode::RecordBehindTag { tag_offset }
        }
        RecordGeneration::VistaOrLater => HitMode::Header,
    };

    let mut enumerator = Enumerator::new(profile, symbols, target, config, ServiceMethod::Scanned);
    let sections = target.sections.clone();
    enumerator.sweep(target, &sections, symbols.generation.scan_tag(), mode)?;
    Ok(enumerator.listing)
}

/// Walk the Service Control Manager's own service chain — `svclist`.
///
/// The list head is a `_SERVICE_HEADER` tagged [`TAG_SERVICE_LIST_HEAD`], living
/// in the `services.exe` image rather than on the heap. Following the chain from
/// it reaches exactly the records the SCM still links — which is the point:
/// what it *cannot* reach is what [`diff_services`] reports.
///
/// # Errors
///
/// [`ServiceError::Unsupported`] when this build's records have no `PrevEntry`,
/// so there is no chain to walk — XP and Server 2003 — or when no mapped range
/// of the process names `services.exe`, so the head cannot be looked for. Both
/// are refusals, not empty lists: an empty list here would make every scanned
/// service look unlinked.
pub fn list_services_in(
    profile: &WindowsProfile,
    symbols: &ServiceSymbols,
    target: &ServiceTarget,
    config: &ServiceScanConfig,
) -> Result<ServiceListing, ServiceError> {
    if !symbols.supports_list_walk() {
        return Err(ServiceError::unsupported(format!(
            "the '{}' service record has no PrevEntry, so there is no chain to walk; services on \
             this build can only be found by sweeping",
            symbols.layout.name
        )));
    }
    if target.image_sections.is_empty() {
        return Err(ServiceError::unsupported(format!(
            "no mapped range of the services.exe at {:#x} names services.exe, so the service list \
             head cannot be located",
            target.process
        )));
    }

    let mut enumerator = Enumerator::new(profile, symbols, target, config, ServiceMethod::Listed);
    if symbols.pointer_size != 8 || symbols.build < 15063 {
        enumerator.listing.notes.push(format!(
            "the {:?} list head tag is only established for 64-bit Windows 10 build 15063 and \
             later; this image is {}-bit build {}, so a head that is not found here is not \
             evidence that the chain is empty",
            String::from_utf8_lossy(TAG_SERVICE_LIST_HEAD),
            symbols.pointer_size * 8,
            symbols.build,
        ));
    }
    let sections = target.image_sections.clone();
    enumerator.sweep(target, &sections, TAG_SERVICE_LIST_HEAD, HitMode::Header)?;
    if enumerator.listing.hits == 0 {
        enumerator.listing.notes.push(
            "the service list head was not found in the services.exe image, so this walk had \
             nowhere to start; that is not the same as a Service Control Manager linking no \
             services"
                .to_string(),
        );
    }
    Ok(enumerator.listing)
}

// ── Decoding one record ─────────────────────────────────────────────────────

/// Read one `_SERVICE_RECORD`.
///
/// `Err` carries the reason the bytes are not a service record, which the caller
/// records as a skip. The three checks that decide it are the same three
/// upstream applies, and each rejects a different class of false hit: an order
/// above [`MAX_SERVICE_ORDER`], a state word that names no state, and a start
/// word that names no start type.
fn decode_record(
    reader: &StructReader,
    symbols: &ServiceSymbols,
    config: &ServiceScanConfig,
    address: u64,
    header: Option<u64>,
    method: ServiceMethod,
) -> Result<ServiceRecord, String> {
    let layout = &symbols.layout.record;
    let word = |offset: u64, what: &str| -> Result<u32, String> {
        at(address, offset)
            .and_then(|address| read_u32(reader, address))
            .map_err(|err| format!("this record's {what} could not be read: {err}"))
    };

    let order = u64::from(word(layout.order, "order")?);
    if order > MAX_SERVICE_ORDER {
        return Err(format!(
            "the load order at this offset is {order}, which is above the {MAX_SERVICE_ORDER} a \
             service record can carry, so these bytes are not a service record"
        ));
    }
    let raw_state = i64::from(word(layout.state, "state")? as i32);
    let state = ServiceState::from_raw(raw_state).ok_or_else(|| {
        format!(
            "the state word at this offset is {raw_state}, which names no service state, so these \
             bytes are not a service record"
        )
    })?;
    let raw_start = i64::from(word(layout.start, "start type")? as i32);
    let start = ServiceStart::from_raw(raw_start).ok_or_else(|| {
        format!(
            "the start word at this offset is {raw_start}, which names no service start type, so \
             these bytes are not a service record"
        )
    })?;

    let service_type = word(layout.service_type, "type")?;
    let type_names = service_type_names(service_type);
    let mut notes = Vec::new();
    if type_names.is_none() {
        notes.push(format!(
            "the type word {service_type:#010x} sets no bit any published service type defines, \
             so this record names no type an examiner can rely on"
        ));
    }

    let name = string_at_pointer(
        reader,
        symbols,
        config,
        address,
        layout.service_name,
        "service name",
        &mut notes,
    );
    let display_name = string_at_pointer(
        reader,
        symbols,
        config,
        address,
        layout.display_name,
        "display name",
        &mut notes,
    );

    // The record only carries a live binary and a live PID while the service is
    // running; for anything else there is genuinely nothing there, which is not
    // the same as a value that could not be read.
    let running = state == ServiceState::Running;
    let process_service = is_process_service(service_type);
    let (binary, pid) = if !running {
        (Field::NotApplicable, Field::NotApplicable)
    } else if process_service {
        match at(address, layout.service_process)
            .and_then(|address| read_pointer(reader, address, symbols.pointer_size))
        {
            Ok(0) => (
                Field::Unavailable(
                    "this running process service points at no _SERVICE_PROCESS, so neither its \
                     binary nor its PID is recorded"
                        .to_string(),
                ),
                Field::Unavailable(
                    "this running process service points at no _SERVICE_PROCESS".to_string(),
                ),
            ),
            Ok(service_process) => {
                let binary = string_at_pointer(
                    reader,
                    symbols,
                    config,
                    service_process,
                    symbols.layout.process.binary_path,
                    "binary path",
                    &mut notes,
                );
                let pid = match at(service_process, symbols.layout.process.process_id)
                    .and_then(|address| read_u32(reader, address))
                {
                    Ok(pid) => Field::Known(u64::from(pid)),
                    Err(err) => Field::Unavailable(format!(
                        "this service's owning PID could not be read: {err}"
                    )),
                };
                (binary, pid)
            }
            Err(err) => {
                let detail =
                    format!("this service's _SERVICE_PROCESS pointer could not be read: {err}");
                (
                    Field::Unavailable(detail.clone()),
                    Field::Unavailable(detail),
                )
            }
        }
    } else {
        // A driver has no process, so no PID exists to be missing.
        let binary = string_at_pointer(
            reader,
            symbols,
            config,
            address,
            layout.driver_name,
            "driver name",
            &mut notes,
        );
        (binary, Field::NotApplicable)
    };

    let (registry_binary, registry_dll) = match (config.registry.as_deref(), name.known()) {
        (Some(map), Some(service_name)) => match map.get(service_name) {
            Some(info) => (info.image_path.clone(), info.service_dll.clone()),
            None => {
                let detail = format!(
                    "no registry key named {service_name:?} was found under {}, so this service \
                     has no configured binary on record",
                    map.key_path
                );
                (
                    Field::Unavailable(detail.clone()),
                    Field::Unavailable(detail),
                )
            }
        },
        (Some(_), None) => {
            let detail =
                "this service's name could not be read, so its registry key cannot be found"
                    .to_string();
            (
                Field::Unavailable(detail.clone()),
                Field::Unavailable(detail),
            )
        }
        (None, _) => {
            let detail =
                "the registry side of the services was not supplied, so nothing is known about \
                 this service's configured binary"
                    .to_string();
            (
                Field::Unavailable(detail.clone()),
                Field::Unavailable(detail),
            )
        }
    };

    Ok(ServiceRecord {
        address,
        header,
        method,
        order,
        service_type,
        type_names,
        state,
        start,
        name,
        display_name,
        binary,
        pid,
        registry_binary,
        registry_dll,
        notes,
    })
}

/// Read the wide string a member points at, recording rather than swallowing
/// every way it can fail.
///
/// A null pointer is [`Field::Unavailable`] and not an empty string: a record
/// whose name pointer is null is damaged, and rendering it as a service with no
/// name puts a blank cell in a report that reads like a successful parse.
fn string_at_pointer(
    reader: &StructReader,
    symbols: &ServiceSymbols,
    config: &ServiceScanConfig,
    base: u64,
    offset: u64,
    what: &str,
    notes: &mut Vec<String>,
) -> Field<String> {
    let pointer = match at(base, offset)
        .and_then(|address| read_pointer(reader, address, symbols.pointer_size))
    {
        Ok(pointer) => pointer,
        Err(err) => {
            return Field::Unavailable(format!(
                "this service's {what} pointer is unreadable: {err}"
            ))
        }
    };
    if pointer == 0 {
        return Field::Unavailable(format!("this service's {what} pointer is null"));
    }
    match read_wide_string(reader, pointer, config.max_string_bytes) {
        Ok(text) => {
            if !text.terminated {
                notes.push(format!(
                    "this service's {what} ran to the {}-byte read limit without a terminator, so \
                     it may be longer than what is shown",
                    config.max_string_bytes
                ));
            }
            if !text.well_formed {
                notes.push(format!(
                    "this service's {what} contains code units that are not valid UTF-16, shown \
                     as replacement characters"
                ));
            }
            Field::Known(text.text)
        }
        Err(err) => Field::Unavailable(format!(
            "this service's {what} is at {pointer:#x}, which could not be read: {err}"
        )),
    }
}

// ── Whole-image convenience ─────────────────────────────────────────────────

/// Sweep every `services.exe` in the image for service records — `svcscan`.
///
/// One listing per `services.exe` found. The ordinary answer has exactly one;
/// more than one is itself worth reporting, which is why this does not collapse
/// them.
///
/// # Errors
///
/// [`ServiceError`] when the process list cannot be walked or the memory ranges
/// of `services.exe` cannot be established — the failures that make the
/// question unanswerable rather than the answer short.
pub fn scan_services(
    profile: &WindowsProfile,
    symbols: &ServiceSymbols,
    config: &ServiceScanConfig,
) -> Result<Vec<ServiceListing>, ServiceError> {
    find_service_targets(profile, config)?
        .iter()
        .map(|target| scan_services_in(profile, symbols, target, config))
        .collect()
}

/// Walk the service chain in every `services.exe` in the image — `svclist`.
///
/// # Errors
///
/// As [`scan_services`], plus [`ServiceError::Unsupported`] when this build has
/// no chain to walk.
pub fn list_services(
    profile: &WindowsProfile,
    symbols: &ServiceSymbols,
    config: &ServiceScanConfig,
) -> Result<Vec<ServiceListing>, ServiceError> {
    find_service_targets(profile, config)?
        .iter()
        .map(|target| list_services_in(profile, symbols, target, config))
        .collect()
}

// ── The difference between the two ──────────────────────────────────────────

/// What sweeping found that list walking did not, and the other way round.
///
/// The `svcdiff` finding: a service record present in memory but absent from the
/// Service Control Manager's own chain has been unlinked from it, which is how a
/// service hides from `sc query`, from `services.msc` and from every tool that
/// asks the SCM rather than the memory.
#[derive(Debug, Clone)]
pub struct ServiceDiff {
    /// The `_EPROCESS` both enumerations ran against.
    pub process: u64,
    /// How many records the sweep reported.
    pub scanned: usize,
    /// How many records the chain walk reported.
    pub listed: usize,
    /// Records the sweep found that the chain walk did not reach.
    ///
    /// Only populated when [`ServiceDiff::comparable`] is true. When it is
    /// false this is empty, because absence from an incomplete list is not
    /// evidence of anything.
    pub unlinked: Vec<ServiceRecord>,
    /// Records the chain walk reached that the sweep did not find.
    ///
    /// Not a rootkit signature — it means the sweep missed memory, most often
    /// because a page was not captured — but it bounds how much the sweep saw
    /// and so belongs beside the finding.
    pub listed_only: Vec<ServiceRecord>,
    /// Whether the two enumerations can be subtracted at all.
    pub comparable: bool,
    /// Why they can or cannot, and anything else worth stating.
    pub notes: Vec<String>,
}

impl ServiceDiff {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "scanned": self.scanned,
            "listed": self.listed,
            "comparable": self.comparable,
            "unlinked": self.unlinked.iter().map(ServiceRecord::to_json).collect::<Vec<_>>(),
            "listed_only": self.listed_only.iter().map(ServiceRecord::to_json).collect::<Vec<_>>(),
            "notes": self.notes,
        })
    }

    /// Everything a report must declare about this comparison.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        if self.comparable {
            return Vec::new();
        }
        vec![Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            format!(
                "the service chain in the services.exe at {:#x} was not walked in full, so no \
                 service can be shown to be missing from it",
                self.process
            ),
        )]
    }
}

/// Subtract a chain walk from a sweep — `svcdiff`.
///
/// Records are matched by **address**, not by name. A record found at
/// `0x1f2a3040` by sweeping and reached at `0x1f2a3040` by walking is the same
/// record; matching by name instead would miss a hidden service that reused a
/// legitimate name, and would falsely clear one whose name could not be read.
///
/// The comparison is refused, rather than made and qualified, when the chain
/// walk was not complete: a chain that stopped at an unreadable record reaches
/// fewer services than the SCM links, and every service past the stop would be
/// reported as unlinked. Upstream makes the subtraction unconditionally, which
/// turns one unacquired page into a page of rootkit findings.
pub fn diff_services(scan: &ServiceListing, list: &ServiceListing) -> ServiceDiff {
    let mut notes = Vec::new();
    let mut comparable = true;

    if scan.process != list.process {
        notes.push(format!(
            "these two enumerations ran against different processes, {:#x} and {:#x}, so they \
             describe different Service Control Managers and cannot be subtracted",
            scan.process, list.process
        ));
        comparable = false;
    }
    if !list.is_complete() {
        notes.push(
            "the service chain walk did not run to completion, so a service absent from it is \
             not shown to have been unlinked"
                .to_string(),
        );
        comparable = false;
    }
    if list.services.is_empty() {
        notes.push(
            "the service chain walk reached no records at all, which is a failure to find the \
             list head rather than a Service Control Manager linking nothing"
                .to_string(),
        );
        comparable = false;
    }
    if !scan.is_complete() {
        notes.push(
            "the sweep did not run to completion, so there may be unlinked services it did not \
             find; the ones reported here are a floor, not a total"
                .to_string(),
        );
    }

    let (unlinked, listed_only) = if comparable {
        let listed = list.by_address();
        let scanned = scan.by_address();
        (
            scan.services
                .iter()
                .filter(|record| !listed.contains(&record.address))
                .cloned()
                .collect(),
            list.services
                .iter()
                .filter(|record| !scanned.contains(&record.address))
                .cloned()
                .collect(),
        )
    } else {
        (Vec::new(), Vec::new())
    };

    ServiceDiff {
        process: scan.process,
        scanned: scan.services.len(),
        listed: list.services.len(),
        unlinked,
        listed_only,
        comparable,
        notes,
    }
}

/// Run both enumerations against every `services.exe` and subtract them.
///
/// # Errors
///
/// As [`scan_services`] and [`list_services`]. A build with no chain to walk
/// makes this fail as a whole; [`survey_services`] is the orchestrated form that
/// keeps the sweep in that case.
pub fn diff_services_in_image(
    profile: &WindowsProfile,
    symbols: &ServiceSymbols,
    config: &ServiceScanConfig,
) -> Result<Vec<ServiceDiff>, ServiceError> {
    let mut diffs = Vec::new();
    for target in find_service_targets(profile, config)? {
        let scan = scan_services_in(profile, symbols, &target, config)?;
        let list = list_services_in(profile, symbols, &target, config)?;
        diffs.push(diff_services(&scan, &list));
    }
    Ok(diffs)
}

// ── The orchestrated stage ──────────────────────────────────────────────────

/// One `services.exe`, swept and walked and subtracted.
///
/// The three together are the whole finding. The sweep alone lists services;
/// the sweep beside the chain walk is what shows one hiding from the Service
/// Control Manager, which is the only reason to read services out of memory
/// rather than out of the registry.
#[derive(Debug, Clone)]
pub struct ServiceSurvey {
    /// The swept enumeration — always attempted, and the reason this survey
    /// still has value on a build with no chain.
    pub scan: ServiceListing,
    /// The Service Control Manager's own chain, when this build has one and it
    /// could be walked.
    pub list: Option<ServiceListing>,
    /// Why the chain walk did not run, when it did not.
    ///
    /// Never an empty listing in its place: an empty chain makes every swept
    /// service look unlinked, which would turn one missing symbol into a page
    /// of rootkit findings.
    pub list_unavailable: Option<String>,
    /// The subtraction, when both enumerations ran.
    pub diff: Option<ServiceDiff>,
}

impl ServiceSurvey {
    /// The services present in memory and absent from the SCM's own chain.
    ///
    /// Empty when the comparison could not be made, which is why
    /// [`ServiceSurvey::is_complete`] has to be read beside it.
    pub fn unlinked(&self) -> &[ServiceRecord] {
        match &self.diff {
            Some(diff) => &diff.unlinked,
            None => &[],
        }
    }

    /// Whether both enumerations ran in full and could be subtracted.
    ///
    /// The question a report must ask before writing "no service was hidden on
    /// this machine".
    pub fn is_complete(&self) -> bool {
        self.scan.is_complete()
            && self.list.as_ref().is_some_and(ServiceListing::is_complete)
            && self.diff.as_ref().is_some_and(|diff| diff.comparable)
    }

    /// Everything a report must declare about this survey.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.scan.incomplete();
        match (&self.list, &self.diff) {
            (Some(list), Some(diff)) => {
                out.extend(list.incomplete());
                out.extend(diff.incomplete());
            }
            _ => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                self.list_unavailable.clone().unwrap_or_else(|| {
                    format!(
                        "the service chain of the services.exe at {:#x} was not walked, so no \
                         service can be shown to have been unlinked from it",
                        self.scan.process
                    )
                }),
            )),
        }
        out
    }

    /// Serializable form for artifact metadata.
    ///
    /// A superset of [`ServiceListing::to_json`] for the sweep, so a consumer
    /// reading the swept enumeration finds it where it has always been, with
    /// the chain walk and the subtraction beside it.
    ///
    /// `complete` is the **survey's** verdict, not the sweep's, and the sweep's
    /// own moves to `sweep_complete`. A consumer that reads one key to decide
    /// whether it may quote the record reads that key here; leaving the sweep's
    /// `true` in place would have it quote a swept list with no chain to
    /// compare against as proof that no service was hidden.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = self.scan.to_json();
        if let Some(object) = value.as_object_mut() {
            let sweep_complete = object
                .insert("complete".into(), serde_json::json!(self.is_complete()))
                .unwrap_or(serde_json::Value::Null);
            object.insert("sweep_complete".into(), sweep_complete);
            object.insert(
                "chain".into(),
                self.list
                    .as_ref()
                    .map(ServiceListing::to_json)
                    .unwrap_or(serde_json::Value::Null),
            );
            object.insert(
                "chain_unavailable".into(),
                match &self.list_unavailable {
                    Some(reason) => serde_json::json!(reason),
                    None => serde_json::Value::Null,
                },
            );
            object.insert(
                "diff".into(),
                self.diff
                    .as_ref()
                    .map(ServiceDiff::to_json)
                    .unwrap_or(serde_json::Value::Null),
            );
            object.insert(
                "unlinked_count".into(),
                serde_json::json!(self.unlinked().len()),
            );
            // The sweep's own `complete` is about the sweep. This one is about
            // the finding, and a caller stamping an artifact wants this.
            object.insert(
                "survey_complete".into(),
                serde_json::json!(self.is_complete()),
            );
            object.insert(
                "incomplete".into(),
                serde_json::json!(self
                    .incomplete()
                    .iter()
                    .map(Incomplete::to_json)
                    .collect::<Vec<_>>()),
            );
        }
        value
    }
}

/// Sweep, walk and subtract every `services.exe` in the image — the whole
/// `services` stage.
///
/// This is the entry point an orchestrator calls. One survey per
/// `services.exe`: the ordinary answer has exactly one element, and a machine
/// running containers has several, which is itself worth reporting and is why
/// they are not merged.
///
/// # What an examiner learns
///
/// Every service record in memory, whether the Service Control Manager still
/// links it, and — when both enumerations ran in full — which records it does
/// not. A service unlinked from the SCM's chain is invisible to `sc query`, to
/// `services.msc` and to every tool that asks the SCM rather than the memory.
///
/// # What a wrong answer looks like
///
/// A page of services reported as unlinked because the chain walk stopped at an
/// unacquired record. [`diff_services`] refuses the subtraction rather than
/// qualifying it, and the refusal travels here as
/// [`ServiceDiff::comparable`] being false.
///
/// # Errors
///
/// [`ServiceError`] only when the sweep itself is impossible: no `services.exe`
/// on the process list, or a build whose records cannot be decoded. A build
/// with no chain to walk — XP and Server 2003 — is **not** an error: the sweep
/// still runs and [`ServiceSurvey::list_unavailable`] says why the comparison
/// could not be made.
pub fn survey_services(
    profile: &WindowsProfile,
    symbols: &ServiceSymbols,
    config: &ServiceScanConfig,
) -> Result<Vec<ServiceSurvey>, ServiceError> {
    let mut out = Vec::new();
    for target in find_service_targets(profile, config)? {
        let scan = scan_services_in(profile, symbols, &target, config)?;
        let (list, list_unavailable) = match list_services_in(profile, symbols, &target, config) {
            Ok(list) => (Some(list), None),
            Err(err) => (
                None,
                Some(format!(
                    "the Service Control Manager's own chain in the services.exe at {:#x} was not \
                     walked, so no service can be shown to have been unlinked from it: {err}",
                    target.process
                )),
            ),
        };
        let diff = list.as_ref().map(|list| diff_services(&scan, list));
        out.push(ServiceSurvey {
            scan,
            list,
            list_unavailable,
            diff,
        });
    }
    Ok(out)
}

// ── The registry side ───────────────────────────────────────────────────────

/// The path under the SYSTEM hive that holds one key per installed service.
pub const SERVICES_KEY_CURRENT: &str = "CurrentControlSet\\Services";

/// The concrete control set, for an image whose `CurrentControlSet` symbolic
/// link was not resolvable.
pub const SERVICES_KEY_FALLBACK: &str = "ControlSet001\\Services";

/// The value naming the binary a service is configured to run.
pub const VALUE_IMAGE_PATH: &str = "ImagePath";

/// The subkey holding a shared-process service's parameters.
pub const KEY_PARAMETERS: &str = "Parameters";

/// The value naming the DLL a shared-process service actually runs.
pub const VALUE_SERVICE_DLL: &str = "ServiceDll";

/// Ceiling on service keys read out of the registry.
pub const MAX_REGISTRY_SERVICES: usize = 65_536;

/// What the registry says a service runs.
///
/// The configured side of the same fact the record holds live. `ImagePath` and
/// the record's binary disagreeing, or a running service having no key at all,
/// are both findings that need the two columns side by side.
#[derive(Debug, Clone)]
pub struct ServiceBinaryInfo {
    /// `ImagePath`, the binary the service is configured to run.
    pub image_path: Field<String>,
    /// `Parameters\ServiceDll`, the DLL a shared-process service runs.
    ///
    /// [`Field::NotApplicable`] for a service with no `Parameters` subkey, which
    /// is the ordinary state of an own-process service and of every driver.
    pub service_dll: Field<String>,
}

/// Every service key under the SYSTEM hive, and what it configures.
#[derive(Debug, Clone)]
pub struct ServiceRegistryMap {
    /// The `_CMHIVE` the keys came from. Provenance: cell indices are per-hive.
    pub hive: u64,
    /// The key path that resolved, as it resolved.
    pub key_path: String,
    /// Service names in the order the subkey index listed them.
    pub names: Vec<String>,
    /// Everything that stopped the enumeration being exhaustive.
    pub incomplete: Vec<Incomplete>,
    /// Keyed by the lowercased name, because registry key names are compared
    /// case-insensitively and a service record's name need not match its key's
    /// case.
    entries: HashMap<String, ServiceBinaryInfo>,
}

impl ServiceRegistryMap {
    /// What the registry configures for a service, by name.
    pub fn get(&self, name: &str) -> Option<&ServiceBinaryInfo> {
        self.entries.get(&name.to_lowercase())
    }

    /// How many service keys were read.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether no service key was read.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Whether every service key the hive declares was enumerated.
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty()
    }

    /// Read the service keys out of a hive whose address is already known.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Registry`] when the hive cannot be opened or neither
    /// control-set path resolves. A *value* that could not be read is not an
    /// error: it becomes [`Field::Unavailable`] on that service alone.
    pub fn from_hive(profile: &WindowsProfile, cmhive: u64) -> Result<Self, ServiceError> {
        // Opened from wherever this build keeps its bins: from Windows 10 build
        // 17063 that is the Registry process, and a kernel-space open there
        // returns holes where every service's ImagePath is.
        let hive = HiveSpace::open_for_image(profile, cmhive)?;
        let reader = CellReader::new(Arc::clone(&hive))?;

        let mut resolved = None;
        let mut first_error = None;
        for path in [SERVICES_KEY_CURRENT, SERVICES_KEY_FALLBACK] {
            match crate::registry::resolve_key(&reader, Some(path)) {
                Ok(chain) => match chain.last().cloned() {
                    Some(node) => {
                        resolved = Some((path, node));
                        break;
                    }
                    None => continue,
                },
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }
        let Some((key_path, node)) = resolved else {
            return Err(first_error.map(ServiceError::Registry).unwrap_or_else(|| {
                ServiceError::unsupported(format!(
                    "neither {SERVICES_KEY_CURRENT} nor {SERVICES_KEY_FALLBACK} resolved in \
                         the hive at {cmhive:#x}, so no service key list could be read"
                ))
            }));
        };

        let subkeys = reader.subkeys(&node);
        let mut incomplete = subkeys.incomplete.clone();
        if subkeys.keys.len() as u64 != subkeys.declared {
            incomplete.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} declares {} service key(s) and {} were enumerated, so the subkey index \
                     does not account for every service",
                    key_path,
                    subkeys.declared,
                    subkeys.keys.len()
                ),
            ));
        }

        let mut names = Vec::new();
        let mut entries = HashMap::new();
        for service in subkeys.keys.iter().take(MAX_REGISTRY_SERVICES) {
            let name = service.name.text.clone();
            names.push(name.clone());
            entries.insert(name.to_lowercase(), read_service_key(&reader, service));
        }
        if subkeys.keys.len() > MAX_REGISTRY_SERVICES {
            incomplete.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "{} lists {} service key(s), above the cap of {MAX_REGISTRY_SERVICES}",
                    key_path,
                    subkeys.keys.len()
                ),
            ));
        }

        Ok(Self {
            hive: cmhive,
            key_path: key_path.to_string(),
            names,
            incomplete,
            entries,
        })
    }

    /// Find the SYSTEM hive and read the service keys out of it.
    ///
    /// # Errors
    ///
    /// [`ServiceError::Registry`] when the hive list cannot be walked, and
    /// [`ServiceError::Unsupported`] when no loaded hive looks like the SYSTEM
    /// hive or none of the candidates yields a service key list. Refusing is
    /// the point: an empty map would silently blank the configured-binary
    /// column for every service.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, ServiceError> {
        let listing = hivelist::list_hives(profile)?;
        let candidates: Vec<u64> = listing
            .hives
            .iter()
            .filter(|hive| is_system_hive_name(hive.name.path()))
            .map(|hive| hive.address)
            .collect();
        if candidates.is_empty() {
            return Err(ServiceError::unsupported(
                "no loaded hive names the SYSTEM hive, so the services' registry keys cannot be \
                 reached",
            ));
        }
        let mut first_error = None;
        for cmhive in candidates {
            match Self::from_hive(profile, cmhive) {
                Ok(map) => return Ok(map),
                Err(err) => {
                    if first_error.is_none() {
                        first_error = Some(err);
                    }
                }
            }
        }
        Err(first_error.unwrap_or_else(|| {
            ServiceError::unsupported("a SYSTEM hive was found but yielded no service key list")
        }))
    }
}

/// Whether a hive's path names the machine's SYSTEM hive.
///
/// Two spellings, because which one a hive carries depends on which member its
/// name was read from: `\REGISTRY\MACHINE\SYSTEM` is the hive root path, and
/// `\Device\HarddiskVolume2\Windows\System32\config\SYSTEM` is the backing
/// file. Matching only one of the two silently finds no SYSTEM hive on half the
/// images.
pub fn is_system_hive_name(path: Option<&str>) -> bool {
    let Some(path) = path else { return false };
    let lowered = path.to_lowercase();
    if lowered.contains("\\machine\\system") {
        return true;
    }
    lowered
        .rsplit('\\')
        .next()
        .is_some_and(|file| file == "system")
}

/// Read `ImagePath` and `Parameters\ServiceDll` for one service key.
fn read_service_key(reader: &CellReader, service: &KeyNode) -> ServiceBinaryInfo {
    let image_path = value_text(reader, service, VALUE_IMAGE_PATH);
    let subkeys = reader.subkeys(service);
    let parameters = subkeys
        .keys
        .iter()
        .find(|key| key.name.text.eq_ignore_ascii_case(KEY_PARAMETERS));
    let service_dll = match parameters {
        Some(parameters) => value_text(reader, parameters, VALUE_SERVICE_DLL),
        None if subkeys.is_complete() => Field::NotApplicable,
        None => Field::Unavailable(format!(
            "this service's subkey index could not be read in full, so the absence of a \
             {KEY_PARAMETERS} subkey is not proof that it has none"
        )),
    };
    ServiceBinaryInfo {
        image_path,
        service_dll,
    }
}

/// One named value of one key, as text.
fn value_text(reader: &CellReader, node: &KeyNode, wanted: &str) -> Field<String> {
    let values = reader.values(node);
    let found = values
        .values
        .iter()
        .find(|value| value.name.text.eq_ignore_ascii_case(wanted));
    let Some(value) = found else {
        return if values.is_complete() {
            Field::NotApplicable
        } else {
            Field::Unavailable(format!(
                "this key's value list could not be read in full, so the absence of a {wanted} \
                 value is not proof that it has none"
            ))
        };
    };
    match &value.data {
        ValueData::Available {
            decoded: RegistryData::Text(text),
            ..
        } => Field::Known(text.text.clone()),
        ValueData::Available { decoded, .. } => Field::Unavailable(format!(
            "this key's {wanted} value decoded as {decoded:?} rather than as text, so it does not \
             name a path"
        )),
        ValueData::Unavailable(incomplete) => Field::Unavailable(incomplete.detail.clone()),
    }
}

// ── Service SIDs ────────────────────────────────────────────────────────────

/// One service's SID, and the exact input it was derived from.
///
/// The derivation is carried rather than implied: a SID nobody can re-derive is
/// an assertion, and this one can be re-derived by hand from
/// [`ServiceSid::hashed`] with any SHA-1 implementation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSid {
    /// The service's name, as the registry key spells it.
    pub service: String,
    /// The uppercased name that was actually hashed, UTF-16LE encoded.
    pub hashed: String,
    /// The SID.
    pub sid: String,
}

impl ServiceSid {
    /// Serializable form for artifact metadata.
    ///
    /// `derivation` is spelled out because the difference matters: nothing here
    /// was read out of the image.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "service": self.service,
            "sid": self.sid,
            "hashed": self.hashed,
            "derivation": "sha1(uppercase(name) as utf-16le) split into five little-endian \
                           32-bit sub-authorities under S-1-5-80",
            "read_from_image": false,
        })
    }
}

/// Every installed service's SID, computed from its name.
#[derive(Debug, Clone)]
pub struct ServiceSidListing {
    /// The `_CMHIVE` the service names came from.
    pub hive: u64,
    /// The key path the names were listed under.
    pub key_path: String,
    /// One entry per service key whose name was readable.
    pub sids: Vec<ServiceSid>,
    /// Names that were listed but whose SID could not be derived.
    pub unresolved: Vec<String>,
    /// Everything that stopped the listing being exhaustive.
    pub incomplete: Vec<Incomplete>,
}

impl ServiceSidListing {
    /// Whether every service key was listed and every SID derived.
    pub fn is_complete(&self) -> bool {
        self.incomplete.is_empty() && self.unresolved.is_empty()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "hive": self.hive,
            "key_path": self.key_path,
            "count": self.sids.len(),
            "sids": self.sids.iter().map(ServiceSid::to_json).collect::<Vec<_>>(),
            "unresolved": self.unresolved,
            "complete": self.is_complete(),
            "incomplete": self.incomplete.iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// The SID Windows derives for a service account, from the service's name.
///
/// The rule, unchanged since Vista introduced per-service SIDs: uppercase the
/// name, encode it UTF-16LE, take the SHA-1 of those bytes, read the twenty
/// bytes of digest as five little-endian 32-bit integers, and render them as
/// sub-authorities under `S-1-5-80`.
///
/// **Nothing is read from the image.** The service SID is not stored in the
/// service record and not stored in the registry key; it is a pure function of
/// the name, and a report must present it as computed rather than as recovered.
///
/// One deliberate difference from upstream: upstream interleaves NUL bytes into
/// the name and then encodes the result as UTF-8, which happens to equal
/// UTF-16LE for ASCII and is wrong for anything else. This encodes UTF-16LE, so
/// a service whose name is not ASCII gets the SID Windows actually derived. The
/// uppercasing is Unicode-aware, which differs from Windows' invariant-culture
/// mapping only for characters no service name contains.
///
/// Returns `None` only if the SHA-1 digest did not come back as the forty hex
/// characters SHA-1 always produces — a refusal rather than a SID with
/// substituted zeros, which would be a plausible-looking identifier nobody's
/// machine ever used.
pub fn service_sid(name: &str) -> Option<String> {
    let uppercased = name.to_uppercase();
    let mut bytes = Vec::with_capacity(uppercased.len() * 2);
    for unit in uppercased.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let digest = sha1_digest(&bytes)?;
    let mut parts = Vec::with_capacity(SERVICE_SID_SUBAUTHORITIES);
    for index in 0..SERVICE_SID_SUBAUTHORITIES {
        let start = index * 4;
        let word: [u8; 4] = digest
            .get(start..start + 4)
            .and_then(|slice| <[u8; 4]>::try_from(slice).ok())?;
        parts.push(u32::from_le_bytes(word).to_string());
    }
    Some(format!("{SERVICE_SID_PREFIX}-{}", parts.join("-")))
}

/// The SHA-1 of some bytes, as twenty bytes.
///
/// Goes through the workspace's own hashing, which returns hex, and decodes it
/// back. `None` when the digest is not forty hex characters, which SHA-1 never
/// produces — the branch exists so nothing downstream has to invent a byte.
fn sha1_digest(bytes: &[u8]) -> Option<[u8; 20]> {
    let hex = seance_core::hashing::compute_hashes(bytes).sha1;
    let decoded = hex_to_bytes(&hex)?;
    <[u8; 20]>::try_from(decoded.as_slice()).ok()
}

/// Decode an even-length lowercase or uppercase hex string.
fn hex_to_bytes(hex: &str) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }
    (0..hex.len() / 2)
        .map(|index| {
            let pair = hex.get(index * 2..index * 2 + 2)?;
            u8::from_str_radix(pair, 16).ok()
        })
        .collect()
}

/// Compute the SID of every service the registry lists — `getservicesids`.
///
/// Takes the map rather than re-reading the registry so that a run which
/// already enriched its services with `ImagePath` does not walk the SYSTEM hive
/// twice, and so that both views rest on the same enumeration of the same key.
pub fn list_service_sids(map: &ServiceRegistryMap) -> ServiceSidListing {
    let mut sids = Vec::new();
    let mut unresolved = Vec::new();
    for name in &map.names {
        match service_sid(name) {
            Some(sid) => sids.push(ServiceSid {
                service: name.clone(),
                hashed: name.to_uppercase(),
                sid,
            }),
            None => unresolved.push(name.clone()),
        }
    }
    ServiceSidListing {
        hive: map.hive,
        key_path: map.key_path.clone(),
        sids,
        unresolved,
        incomplete: map.incomplete.clone(),
    }
}

/// Find the SYSTEM hive, list the services, and compute their SIDs.
///
/// # Errors
///
/// As [`ServiceRegistryMap::from_profile`].
pub fn service_sids_from_profile(
    profile: &WindowsProfile,
) -> Result<ServiceSidListing, ServiceError> {
    Ok(list_service_sids(&ServiceRegistryMap::from_profile(
        profile,
    )?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{
        profile as test_profile, table, windows64_isf, windows_xp32_isf, Image,
    };

    // ── Where the synthetic fixtures put things ─────────────────────────────

    /// The 32-bit XP fixture: one record, its tag twenty-four bytes in.
    const XP_RECORD: u64 = 0x1000;
    const XP_SERVICE_PROCESS: u64 = 0x1400;
    const XP_NAME: u64 = 0x1500;
    const XP_DISPLAY: u64 = 0x1600;
    const XP_BINARY: u64 = 0x1700;

    /// The 64-bit Windows 11 fixture: two headers over a two-record chain.
    const W11_HEADER_ONE: u64 = 0x1000;
    const W11_HEADER_TWO: u64 = 0x1008;
    const W11_RECORD_ONE: u64 = 0x2000;
    const W11_RECORD_TWO: u64 = 0x3000;
    const W11_SERVICE_PROCESS: u64 = 0x4000;
    const W11_NAME_ONE: u64 = 0x5000;
    const W11_DISPLAY_ONE: u64 = 0x5100;
    const W11_NAME_TWO: u64 = 0x5200;
    const W11_DISPLAY_TWO: u64 = 0x5300;
    const W11_BINARY: u64 = 0x5400;
    const W11_DRIVER: u64 = 0x5500;

    /// The range the fixtures' tags live in.
    fn header_section() -> Vec<Range<u64>> {
        vec![0x1000..0x1100]
    }

    fn xp_section() -> Vec<Range<u64>> {
        vec![0x1000..0x1100]
    }

    /// A profile over one identity-mapped image, plus that image as a process
    /// space. Kernel and process spaces are the same layer here, which is what
    /// makes a pointer value also an image offset.
    fn fixture(
        image: Image,
        isf: String,
        architecture: Architecture,
        major: u32,
        minor: u32,
        build: u32,
    ) -> (WindowsProfile, ProcessSpace) {
        let layer = image.layer();
        let profile = test_profile(
            Arc::clone(&layer),
            table(&isf),
            architecture,
            major,
            minor,
            Some(build),
        );
        let space = ProcessSpace::supplied(layer, 0x1000);
        (profile, space)
    }

    /// Windows XP, over the symbol table XP actually had. The 32-bit table named
    /// `windows32_isf` declares a Vista `_OBJECT_HEADER`; a fixture called `xp_`
    /// that carries it proves the code works on a build that never shipped.
    fn xp_fixture(image: Image) -> (WindowsProfile, ProcessSpace) {
        fixture(image, windows_xp32_isf(), Architecture::X86, 5, 1, 2600)
    }

    fn win11_fixture(image: Image) -> (WindowsProfile, ProcessSpace) {
        fixture(image, windows64_isf(false), Architecture::X64, 10, 0, 22000)
    }

    /// Write one XP-era record. Offsets are `XP_X86`'s, spelled out so a change
    /// to the catalogue that this fixture does not follow shows up as a failure
    /// rather than as agreement.
    #[allow(clippy::too_many_arguments)]
    fn put_xp_record(
        image: &mut Image,
        at: u64,
        order: u32,
        service_type: u32,
        state: u32,
        start: u32,
        name: u32,
        display: u32,
        process_or_driver: u32,
    ) {
        image.put_u32(at + 8, name);
        image.put_u32(at + 12, display);
        image.put_u32(at + 16, order);
        image.write(at + 24, TAG_SERVICE_RECORD);
        image.put_u32(at + 36, process_or_driver);
        image.put_u32(at + 40, service_type);
        image.put_u32(at + 44, state);
        image.put_u32(at + 68, start);
    }

    /// A complete XP fixture: one running shared-process service.
    fn xp_image() -> Image {
        let mut image = Image::new();
        put_xp_record(
            &mut image,
            XP_RECORD,
            3,
            0x20, // SERVICE_WIN32_SHARE_PROCESS
            4,    // SERVICE_RUNNING
            2,    // SERVICE_AUTO_START
            XP_NAME as u32,
            XP_DISPLAY as u32,
            XP_SERVICE_PROCESS as u32,
        );
        image.put_u32(XP_SERVICE_PROCESS + 8, XP_BINARY as u32);
        image.put_u32(XP_SERVICE_PROCESS + 12, 880);
        image.put_utf16(XP_NAME, "Dnscache");
        image.put_utf16(XP_DISPLAY, "DNS Client");
        image.put_utf16(
            XP_BINARY,
            "C:\\WINDOWS\\system32\\svchost.exe -k NetworkService",
        );
        image
    }

    /// Write one Windows 10 2004 / Windows 11 record, at `WIN10_19041_X64`'s
    /// offsets.
    #[allow(clippy::too_many_arguments)]
    fn put_win11_record(
        image: &mut Image,
        at: u64,
        prev: u64,
        order: u32,
        service_type: u32,
        state: u32,
        start: u32,
        name: u64,
        display: u64,
        process_or_driver: u64,
    ) {
        image.put_u64(at + 16, prev);
        image.put_u32(at + 32, order);
        image.put_u32(at + 36, start);
        image.put_u64(at + 56, name);
        image.put_u64(at + 64, display);
        image.put_u32(at + 72, service_type);
        image.put_u32(at + 76, state);
        image.put_u64(at + 296, process_or_driver);
    }

    fn put_win11_header(image: &mut Image, at: u64, record: u64) {
        image.write(at, TAG_SERVICE_HEADER);
        image.put_u64(at + 16, record);
    }

    /// Two chained records: a running shared-process service and, before it, a
    /// running kernel driver.
    fn win11_image() -> Image {
        let mut image = Image::new();
        put_win11_header(&mut image, W11_HEADER_ONE, W11_RECORD_TWO);
        put_win11_record(
            &mut image,
            W11_RECORD_TWO,
            W11_RECORD_ONE,
            2,
            0x20, // SERVICE_WIN32_SHARE_PROCESS
            4,    // SERVICE_RUNNING
            2,    // SERVICE_AUTO_START
            W11_NAME_TWO,
            W11_DISPLAY_TWO,
            W11_SERVICE_PROCESS,
        );
        put_win11_record(
            &mut image,
            W11_RECORD_ONE,
            0,
            1,
            0x01, // SERVICE_KERNEL_DRIVER
            4,    // SERVICE_RUNNING
            0,    // SERVICE_BOOT_START
            W11_NAME_ONE,
            W11_DISPLAY_ONE,
            W11_DRIVER,
        );
        image.put_u64(W11_SERVICE_PROCESS + 24, W11_BINARY);
        image.put_u32(W11_SERVICE_PROCESS + 40, 1284);
        image.put_utf16(W11_NAME_ONE, "Beep");
        image.put_utf16(W11_DISPLAY_ONE, "BEEP Driver");
        image.put_utf16(W11_NAME_TWO, "Dnscache");
        image.put_utf16(W11_DISPLAY_TWO, "DNS Client");
        image.put_utf16(
            W11_BINARY,
            "C:\\Windows\\system32\\svchost.exe -k NetworkService",
        );
        image.put_utf16(W11_DRIVER, "\\SystemRoot\\System32\\drivers\\beep.sys");
        image
    }

    /// The same two-record chain, reached through the list head instead of a
    /// heap header: the head is a `_SERVICE_HEADER` like any other, and only
    /// its tag and its home in the image's own data set it apart.
    fn win11_list_head_image() -> Image {
        let mut image = win11_image();
        image.write(W11_HEADER_ONE, TAG_SERVICE_LIST_HEAD);
        image
    }

    fn sweep(
        profile: &WindowsProfile,
        space: &ProcessSpace,
        sections: Vec<Range<u64>>,
        config: &ServiceScanConfig,
    ) -> ServiceListing {
        let symbols = ServiceSymbols::from_profile(profile).expect("a catalogued build");
        let target = ServiceTarget::new(0x9000, Some(688), space.clone(), sections, Vec::new());
        scan_services_in(profile, &symbols, &target, config).expect("a runnable sweep")
    }

    /// Walk the list head out of the image ranges. `symbols` is a parameter
    /// rather than resolved here because the header a supplied symbol table
    /// describes is not always the catalogue's.
    fn walk(
        profile: &WindowsProfile,
        space: &ProcessSpace,
        symbols: &ServiceSymbols,
    ) -> ServiceListing {
        let target = ServiceTarget::new(
            0x9000,
            Some(688),
            space.clone(),
            header_section(),
            header_section(),
        );
        list_services_in(profile, symbols, &target, &ServiceScanConfig::default())
            .expect("a runnable walk")
    }

    fn named<'a>(listing: &'a ServiceListing, name: &str) -> &'a ServiceRecord {
        listing
            .services
            .iter()
            .find(|service| service.name_text() == Some(name))
            .unwrap_or_else(|| panic!("{name} is among the services found"))
    }

    // ── The catalogue and the choice between its entries ────────────────────

    #[test]
    fn every_catalogued_layout_is_internally_consistent() {
        // The three ways a layout can contradict itself all decode something
        // rather than fail, so the catalogue is checked rather than trusted.
        for layout in CATALOGUE {
            layout
                .validate()
                .unwrap_or_else(|err| panic!("{}: {err}", layout.name));
        }
    }

    #[test]
    fn the_layout_chosen_always_matches_the_pointer_width_it_was_chosen_for() {
        // A 32-bit layout selected for a 64-bit image reads every pointer four
        // bytes wide and every member at half its offset, which decodes rather
        // than fails.
        for build in [
            2600u32, 6000, 9200, 15063, 16299, 17763, 18362, 19041, 25398,
        ] {
            for (is_64bit, expected) in [(true, 8u64), (false, 4u64)] {
                let major = if build >= 10240 {
                    10
                } else if build >= 6000 {
                    6
                } else {
                    5
                };
                let minor = if build == 2600 { 1 } else { 0 };
                if let Some(layout) = select_layout(is_64bit, major, minor, build) {
                    assert_eq!(
                        layout.pointer_size,
                        expected,
                        "{} chose {} for a {}-bit image",
                        layout.name,
                        layout.pointer_size,
                        if is_64bit { 64 } else { 32 }
                    );
                }
            }
        }
    }

    #[test]
    fn every_catalogued_layout_is_reachable_and_named_once() {
        // A layout no release selects is one that was catalogued and then
        // orphaned by a threshold, which would show up as a build silently
        // falling back to an older shape.
        let mut names: Vec<&str> = CATALOGUE.iter().map(|layout| layout.name).collect();
        names.sort_unstable();
        let unique = names.len();
        names.dedup();
        assert_eq!(names.len(), unique, "two catalogue entries share a name");

        let releases: [(bool, u32, u32, u32); 16] = [
            (false, 5, 1, 2600),
            (true, 5, 1, 2600),
            (false, 6, 0, 6000),
            (true, 6, 0, 6000),
            (false, 6, 2, 9200),
            (true, 6, 2, 9200),
            (false, 10, 0, 15063),
            (true, 10, 0, 15063),
            (false, 10, 0, 16299),
            (true, 10, 0, 16299),
            (false, 10, 0, 17763),
            (false, 10, 0, 18362),
            (true, 10, 0, 18362),
            (false, 10, 0, 19041),
            (true, 10, 0, 19041),
            (true, 10, 0, 25398),
        ];
        let mut reached: Vec<&str> = releases
            .iter()
            .filter_map(|(is_64bit, major, minor, build)| {
                select_layout(*is_64bit, *major, *minor, *build).map(|layout| layout.name)
            })
            .collect();
        reached.sort_unstable();
        reached.dedup();
        let mut catalogued: Vec<&str> = CATALOGUE.iter().map(|layout| layout.name).collect();
        catalogued.sort_unstable();
        assert_eq!(reached, catalogued);
    }

    #[test]
    fn a_build_without_a_number_cannot_choose_a_service_record_layout() {
        // The whole reason KernelBuild::build is an Option: the record moved
        // between releases, so a stage that does not know the release must
        // refuse rather than pick the most likely layout.
        let mut profile = test_profile(
            Image::new().layer(),
            table(&windows64_isf(false)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        profile.build.build = None;
        let err = ServiceSymbols::from_profile(&profile).expect_err("a refusal");
        assert!(
            err.to_string().contains("build number"),
            "the refusal must name what is missing: {err}"
        );
        assert_eq!(err.class(), "unsupported_build");
    }

    #[test]
    fn an_arm64_image_is_refused_rather_than_decoded_with_the_x64_layout() {
        // ARM64 has the same pointer width as x64, so every x64 offset would
        // "work": the records would parse and the table would be unfalsifiable.
        let profile = test_profile(
            Image::new().layer(),
            table(&windows64_isf(false)),
            Architecture::Arm64,
            10,
            0,
            Some(22621),
        );
        let err = ServiceSymbols::from_profile(&profile).expect_err("a refusal");
        assert!(err.to_string().contains("ARM64"), "{err}");
    }

    #[test]
    fn windows_2000_has_no_catalogued_layout_and_is_refused() {
        assert_eq!(select_layout(false, 5, 0, 2195), None);
        assert_eq!(select_layout(true, 5, 0, 2195), None);
    }

    #[test]
    fn thirty_two_bit_server_2003_is_refused_rather_than_decoded_as_xp() {
        // Its services.exe is a different binary from XP's and no layout was
        // ever established for it. The 64-bit edition shares XP's, which is why
        // that one is catalogued and this one is not.
        assert_eq!(select_layout(false, 5, 2, 3790), None);
        assert_eq!(
            select_layout(true, 5, 2, 3790).map(|layout| layout.name),
            Some("services-xp-2003-x64")
        );
    }

    #[test]
    fn each_release_selects_the_layout_that_release_shipped() {
        let cases: [(bool, u32, u32, u32, &str); 16] = [
            (false, 5, 1, 2600, "services-xp-x86"),
            (true, 5, 1, 2600, "services-xp-2003-x64"),
            (false, 6, 0, 6000, "services-vista-x86"),
            (true, 6, 1, 7601, "services-vista-x64"),
            (false, 6, 2, 9200, "services-win8-x86"),
            (true, 6, 3, 9600, "services-win8-x64"),
            // Windows 10 before 1703 kept the Windows 8 record.
            (true, 10, 0, 14393, "services-win8-x64"),
            (false, 10, 0, 15063, "services-win10-15063-x86"),
            (true, 10, 0, 15063, "services-win10-15063-x64"),
            (false, 10, 0, 16299, "services-win10-16299-x86"),
            (true, 10, 0, 16299, "services-win10-16299-x64"),
            (false, 10, 0, 17763, "services-win10-17763-x86"),
            // The record did not move at 1809 on 64-bit.
            (true, 10, 0, 17763, "services-win10-16299-x64"),
            (true, 10, 0, 18362, "services-win10-18362-x64"),
            (false, 10, 0, 19041, "services-win10-19041-x86"),
            (true, 10, 0, 25398, "services-win10-25398-x64"),
        ];
        for (is_64bit, major, minor, build, expected) in cases {
            assert_eq!(
                select_layout(is_64bit, major, minor, build).map(|layout| layout.name),
                Some(expected),
                "{}-bit {major}.{minor} build {build}",
                if is_64bit { 64 } else { 32 }
            );
        }
    }

    #[test]
    fn windows_eleven_uses_the_layout_the_record_last_moved_to() {
        // 22000 and 22621 are both above 19041 and below 25398, so both read
        // the record at 19041's offsets. Choosing 25398's here would put the
        // type word eight bytes on and the process pointer forty bytes on.
        for build in [22000, 22621] {
            let layout = select_layout(true, 10, 0, build).expect("a catalogued build");
            assert_eq!(layout.name, "services-win10-19041-x64");
            assert_eq!(layout.record.service_type, 72);
            assert_eq!(layout.record.service_process, 296);
            assert_eq!(layout.record.service_process, layout.record.driver_name);
        }
    }

    #[test]
    fn the_process_pointer_and_the_driver_name_separate_at_25398() {
        // Every earlier release put both at one offset. Reading the driver name
        // at the process pointer's offset on 25398 yields the wrong string in
        // the binary column, and nothing about it looks wrong.
        let layout = select_layout(true, 10, 0, 25398).expect("a catalogued build");
        assert_eq!(layout.record.service_process, 336);
        assert_eq!(layout.record.driver_name, 296);
        assert_ne!(layout.record.service_process, layout.record.driver_name);
    }

    #[test]
    fn thirty_two_bit_windows_eight_gets_the_windows_eight_layout_not_vistas() {
        // Upstream's selection table marks its 32-bit Windows 8 entry as a
        // 64-bit one, so it never matches and 8 and 8.1 fall through to Vista.
        // The two shapes differ at every member that matters.
        let win8 = select_layout(false, 6, 2, 9200).expect("a catalogued build");
        assert_eq!(win8.name, "services-win8-x86");
        assert_ne!(win8.record.prev_entry, VISTA_X86.record.prev_entry);
        assert_ne!(win8.record.service_name, VISTA_X86.record.service_name);
    }

    #[test]
    fn a_build_that_predates_the_record_chain_has_no_list_to_walk() {
        let (profile, space) = xp_fixture(xp_image());
        let symbols = ServiceSymbols::from_profile(&profile).expect("a catalogued build");
        assert_eq!(symbols.generation, RecordGeneration::PreVista);
        assert!(!symbols.supports_list_walk());

        let target = ServiceTarget::new(0x9000, Some(688), space, xp_section(), header_section());
        let err = list_services_in(&profile, &symbols, &target, &ServiceScanConfig::default())
            .expect_err("a refusal rather than an empty list");
        assert!(err.to_string().contains("PrevEntry"), "{err}");
    }

    #[test]
    fn the_layout_source_travels_with_the_answer() {
        let (profile, _space) = win11_fixture(win11_image());
        let symbols = ServiceSymbols::from_profile(&profile).expect("a catalogued build");
        assert_eq!(symbols.source, ServiceLayoutSource::Catalogue);
        assert_eq!(symbols.layout.name, "services-win10-19041-x64");
        assert_eq!(symbols.to_json()["source"], "catalogue");
    }

    // ── Types, states and start types ───────────────────────────────────────

    #[test]
    fn the_service_type_word_names_every_published_flag_it_sets() {
        assert_eq!(
            service_type_names(0x01).as_deref(),
            Some("SERVICE_KERNEL_DRIVER")
        );
        assert_eq!(
            service_type_names(0x110).as_deref(),
            Some("SERVICE_WIN32_OWN_PROCESS|SERVICE_INTERACTIVE_PROCESS")
        );
        assert_eq!(
            service_type_names(0x20).as_deref(),
            Some("SERVICE_WIN32_SHARE_PROCESS")
        );
    }

    #[test]
    fn a_type_word_that_names_no_known_flag_is_unknown_rather_than_absent() {
        // Rendering this as an empty cell would read exactly like a service
        // with no type, which no real record has.
        assert_eq!(service_type_names(0), None);
        assert_eq!(service_type_names(0x8000_0000), None);
    }

    #[test]
    fn a_process_service_is_the_one_whose_binary_lives_behind_a_service_process() {
        for own in [0x10u32, 0x20, 0x100] {
            assert!(is_process_service(own), "{own:#x}");
        }
        for driver in [0x01u32, 0x02, 0x04, 0x08] {
            assert!(!is_process_service(driver), "{driver:#x}");
        }
    }

    #[test]
    fn states_and_start_types_round_trip_through_their_published_numbers() {
        assert_eq!(ServiceState::from_raw(4), Some(ServiceState::Running));
        assert_eq!(ServiceState::Running.as_str(), "SERVICE_RUNNING");
        assert_eq!(ServiceState::from_raw(0), None);
        assert_eq!(ServiceState::from_raw(8), None);
        assert_eq!(ServiceState::from_raw(-1), None);

        assert_eq!(ServiceStart::from_raw(0), Some(ServiceStart::BootStart));
        assert_eq!(ServiceStart::Disabled.as_str(), "SERVICE_DISABLED");
        assert_eq!(ServiceStart::from_raw(5), None);
        assert_eq!(ServiceStart::from_raw(-1), None);
    }

    // ── Reading the strings a record points at ──────────────────────────────

    fn string_reader(image: Image) -> StructReader {
        StructReader::new(image.layer(), table(&windows64_isf(false)))
    }

    #[test]
    fn a_wide_string_stops_at_its_terminator() {
        let mut image = Image::new();
        image.put_utf16(0x100, "Dnscache");
        let reader = string_reader(image);
        let text = read_wide_string(&reader, 0x100, MAX_SERVICE_STRING_BYTES)
            .expect("the string is readable");
        assert_eq!(text.text, "Dnscache");
        assert!(text.terminated);
        assert!(text.well_formed);
    }

    #[test]
    fn a_wide_string_that_reaches_its_cap_says_it_was_not_terminated() {
        // The difference between "the name is these eight characters" and "the
        // name begins with these eight characters" is a difference a report has
        // to be able to state.
        let mut image = Image::new();
        image.put_utf16(0x100, &"A".repeat(200));
        let reader = string_reader(image);
        let text = read_wide_string(&reader, 0x100, 16).expect("the string is readable");
        assert_eq!(text.text, "AAAAAAAA");
        assert!(!text.terminated, "the cap was reached, not the terminator");
    }

    #[test]
    fn an_empty_wide_string_is_empty_rather_than_unreadable() {
        let image = Image::new();
        let reader = string_reader(image);
        let text = read_wide_string(&reader, 0x100, MAX_SERVICE_STRING_BYTES)
            .expect("a terminator at the first unit is still a readable string");
        assert_eq!(text.text, "");
        assert!(text.terminated);
    }

    // ── Sweeping an XP image ────────────────────────────────────────────────

    #[test]
    fn an_xp_sweep_finds_the_record_in_front_of_its_own_tag() {
        // Pre-Vista records carry their own tag twenty-four bytes in, so the
        // record starts twenty-four bytes *before* the hit. Taking the hit
        // itself as the record would read the order out of the display name
        // pointer.
        let (profile, space) = xp_fixture(xp_image());
        let listing = sweep(
            &profile,
            &space,
            xp_section(),
            &ServiceScanConfig::default(),
        );
        assert_eq!(listing.services.len(), 1);
        let service = &listing.services[0];
        assert_eq!(service.address, XP_RECORD);
        assert_eq!(service.header, None, "XP has no service headers");
        assert_eq!(service.order, 3);
        assert_eq!(service.state, ServiceState::Running);
        assert_eq!(service.start, ServiceStart::AutoStart);
        assert_eq!(service.name_text(), Some("Dnscache"));
        assert_eq!(
            service.display_name.known().map(String::as_str),
            Some("DNS Client")
        );
        assert_eq!(
            service.binary.known().map(String::as_str),
            Some("C:\\WINDOWS\\system32\\svchost.exe -k NetworkService")
        );
        assert_eq!(service.pid.known().copied(), Some(880));
        assert!(listing.is_complete());
    }

    #[test]
    fn an_xp_record_whose_order_is_not_an_order_is_declined_and_counted() {
        let mut image = xp_image();
        image.put_u32(XP_RECORD + 16, 0x1_0000);
        let (profile, space) = xp_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            xp_section(),
            &ServiceScanConfig::default(),
        );
        assert!(listing.services.is_empty());
        assert_eq!(listing.skipped_total, 1);
        assert!(
            listing.skipped[0].reason.contains("load order"),
            "{}",
            listing.skipped[0].reason
        );
        // And the listing does not claim to be a complete account of the
        // machine's services.
        assert!(!listing.is_complete());
    }

    #[test]
    fn an_xp_record_whose_state_names_no_state_is_declined() {
        let mut image = xp_image();
        image.put_u32(XP_RECORD + 44, 99);
        let (profile, space) = xp_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            xp_section(),
            &ServiceScanConfig::default(),
        );
        assert!(listing.services.is_empty());
        assert_eq!(listing.skipped_total, 1);
        assert!(listing.skipped[0].reason.contains("names no service state"));
    }

    #[test]
    fn an_xp_record_whose_start_type_names_no_start_type_is_declined() {
        let mut image = xp_image();
        image.put_u32(XP_RECORD + 68, 9);
        let (profile, space) = xp_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            xp_section(),
            &ServiceScanConfig::default(),
        );
        assert!(listing.services.is_empty());
        assert_eq!(listing.skipped_total, 1);
        assert!(listing.skipped[0]
            .reason
            .contains("names no service start type"));
    }

    // ── Sweeping a Vista-or-later image ─────────────────────────────────────

    #[test]
    fn a_vista_or_later_sweep_walks_the_chain_back_from_a_header() {
        // One header reaches the newest record; everything older is reached
        // through PrevEntry. A walk that stopped at the header would report one
        // service on a machine that has two.
        let (profile, space) = win11_fixture(win11_image());
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        assert_eq!(listing.services.len(), 2);
        let addresses: Vec<u64> = listing.services.iter().map(|s| s.address).collect();
        assert_eq!(addresses, vec![W11_RECORD_TWO, W11_RECORD_ONE]);
        assert_eq!(
            listing.services[0].header,
            Some(W11_HEADER_ONE),
            "the header a record was reached through is provenance"
        );
        assert!(listing.is_complete());
    }

    #[test]
    fn a_record_two_headers_reach_is_reported_once() {
        let mut image = win11_image();
        put_win11_header(&mut image, W11_HEADER_TWO, W11_RECORD_ONE);
        let (profile, space) = win11_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        assert_eq!(listing.services.len(), 2, "not three");
        // Reaching an already-reported record is the chain catching up, not an
        // anomaly, so nothing is recorded as declined.
        assert_eq!(listing.skipped_total, 0);
    }

    #[test]
    fn a_chain_that_points_at_itself_stops_rather_than_looping() {
        let mut image = win11_image();
        image.put_u64(W11_RECORD_ONE + 16, W11_RECORD_ONE);
        let (profile, space) = win11_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        assert_eq!(listing.services.len(), 2);
        assert_eq!(listing.skipped_total, 1);
        assert!(listing.skipped[0].reason.contains("does not terminate"));
        assert!(!listing.is_complete());
    }

    #[test]
    fn a_header_tag_off_a_heap_boundary_is_declined_rather_than_followed() {
        // Four bytes reading "serH" inside a string are not the head of an
        // allocation, and the bytes at the record offsets behind them are
        // whatever the string contained.
        let mut image = Image::new();
        image.write(0x1004, TAG_SERVICE_HEADER);
        let (profile, space) = win11_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        assert!(listing.services.is_empty());
        assert_eq!(listing.skipped_total, 1);
        assert!(listing.skipped[0].reason.contains("boundary"));
    }

    #[test]
    fn the_list_head_in_the_image_reaches_the_chain_the_control_manager_still_links() {
        // The Sc27 head is the whole basis of svclist, and nothing else here
        // exercises it end to end. A head that stopped being followed would
        // render as a Service Control Manager linking nothing, which makes
        // every swept service look unlinked.
        let (profile, space) = win11_fixture(win11_list_head_image());
        let symbols = ServiceSymbols::from_profile(&profile).expect("a catalogued build");
        let listing = walk(&profile, &space, &symbols);

        assert_eq!(listing.method, ServiceMethod::Listed);
        let addresses: Vec<u64> = listing.services.iter().map(|s| s.address).collect();
        assert_eq!(addresses, vec![W11_RECORD_TWO, W11_RECORD_ONE]);
        assert_eq!(
            listing.services[0].header,
            Some(W11_HEADER_ONE),
            "the head a record was reached through is provenance"
        );
        assert_eq!(listing.skipped_total, 0);
        assert!(
            listing.notes.is_empty(),
            "a head that was found leaves nothing to qualify: {:?}",
            listing.notes
        );
    }

    #[test]
    fn a_list_head_whose_tag_is_not_its_first_member_is_read_from_the_headers_base() {
        // Every catalogued layout puts _SERVICE_HEADER.Tag at zero, so the hit
        // address happens to be the header's. A symbol table an examiner
        // supplied can name any offset, and taking the tag's address for the
        // header's then reads the record pointer eight bytes past the member
        // the table named: here that is a zero, and a head that points at no
        // record reports the Service Control Manager as linking nothing.
        let mut image = win11_image();
        image.write(W11_HEADER_ONE, &[0u8; 4]);
        image.write(W11_HEADER_ONE + 8, TAG_SERVICE_LIST_HEAD);
        let (profile, space) = win11_fixture(image);
        let mut symbols = ServiceSymbols::from_profile(&profile).expect("a catalogued build");
        symbols.source = ServiceLayoutSource::SymbolTable;
        symbols.layout.header.tag = 8;

        let listing = walk(&profile, &space, &symbols);

        let addresses: Vec<u64> = listing.services.iter().map(|s| s.address).collect();
        assert_eq!(
            addresses,
            vec![W11_RECORD_TWO, W11_RECORD_ONE],
            "the record pointer sits at the header's base plus its offset, not at the tag's"
        );
        assert_eq!(listing.services[0].header, Some(W11_HEADER_ONE));
        assert_eq!(listing.skipped_total, 0);
    }

    #[test]
    fn a_running_process_service_reports_its_binary_and_its_owning_pid() {
        let (profile, space) = win11_fixture(win11_image());
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        let service = named(&listing, "Dnscache");
        assert_eq!(
            service.binary.known().map(String::as_str),
            Some("C:\\Windows\\system32\\svchost.exe -k NetworkService")
        );
        assert_eq!(service.pid.known().copied(), Some(1284));
        assert_eq!(
            service.type_names.as_deref(),
            Some("SERVICE_WIN32_SHARE_PROCESS")
        );
    }

    #[test]
    fn a_driver_service_reports_its_driver_name_and_has_no_pid_to_report() {
        // A driver runs in no process, so its PID is not applicable rather than
        // unreadable, and rendering it as 0 would name the Idle process.
        let (profile, space) = win11_fixture(win11_image());
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        let service = named(&listing, "Beep");
        assert_eq!(
            service.binary.known().map(String::as_str),
            Some("\\SystemRoot\\System32\\drivers\\beep.sys")
        );
        assert_eq!(service.pid, Field::NotApplicable);
        assert_eq!(service.type_names.as_deref(), Some("SERVICE_KERNEL_DRIVER"));
    }

    #[test]
    fn a_service_that_is_not_running_has_no_live_binary_and_no_pid() {
        // Not an empty string and not zero: the record simply does not carry
        // them while the service is stopped.
        let mut image = win11_image();
        image.put_u32(W11_RECORD_TWO + 76, 1); // SERVICE_STOPPED
        let (profile, space) = win11_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        let service = named(&listing, "Dnscache");
        assert_eq!(service.state, ServiceState::Stopped);
        assert_eq!(service.binary, Field::NotApplicable);
        assert_eq!(service.pid, Field::NotApplicable);
    }

    #[test]
    fn a_null_name_pointer_is_unavailable_rather_than_an_empty_name() {
        // A service rendered with a blank name reads as a service whose name is
        // blank, which no service's is.
        let mut image = win11_image();
        image.put_u64(W11_RECORD_TWO + 56, 0);
        let (profile, space) = win11_fixture(image);
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        let service = listing
            .services
            .iter()
            .find(|service| service.address == W11_RECORD_TWO)
            .expect("the record is still a service record");
        assert!(service.name.is_unavailable());
        assert_eq!(service.name.to_json()["kind"], "unavailable");
    }

    #[test]
    fn a_service_with_no_registry_side_says_so_rather_than_showing_a_blank() {
        let (profile, space) = win11_fixture(win11_image());
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        let service = named(&listing, "Dnscache");
        assert!(service.registry_binary.is_unavailable());
        assert!(service.registry_dll.is_unavailable());
    }

    #[test]
    fn the_service_cap_stops_the_sweep_and_the_listing_says_so() {
        let (profile, space) = win11_fixture(win11_image());
        let config = ServiceScanConfig {
            max_services: 1,
            ..ServiceScanConfig::default()
        };
        let listing = sweep(&profile, &space, header_section(), &config);
        assert_eq!(listing.services.len(), 1);
        assert_eq!(
            listing.stop,
            ServiceStop::CapReached {
                what: "service(s)",
                cap: 1
            }
        );
        assert!(!listing.is_complete());
        assert!(listing
            .incomplete()
            .iter()
            .any(|entry| entry.reason == IncompleteReason::CapReached));
    }

    #[test]
    fn a_sweep_of_ranges_that_are_not_all_the_process_had_does_not_claim_completeness() {
        // Every byte offered was read, so `scan_complete` is true — but the
        // ranges offered were not every range the process had, and a listing
        // that only reported the first would say this was a complete account of
        // the machine's services.
        let (profile, space) = win11_fixture(win11_image());
        let symbols = ServiceSymbols::from_profile(&profile).expect("a catalogued build");
        let mut target = ServiceTarget::new(0x9000, Some(688), space, header_section(), Vec::new());
        target.ranges_complete = false;
        let listing = scan_services_in(&profile, &symbols, &target, &ServiceScanConfig::default())
            .expect("a runnable sweep");
        assert_eq!(
            listing.services.len(),
            2,
            "the sweep still found what it could"
        );
        assert!(listing.scan_complete, "every byte offered was read");
        assert!(
            !listing.is_complete(),
            "a sweep of an incomplete set of ranges is not a complete account"
        );
        assert!(listing
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("could not all be established")));
        assert_eq!(listing.to_json()["ranges_complete"], false);
    }

    #[test]
    fn a_sweep_found_on_a_truncated_process_list_does_not_claim_completeness() {
        // A machine can run more than one Service Control Manager. The sweep
        // below reads every byte of every range of the one it found, so its own
        // measures all say "complete" — but the process list that found it
        // stopped early, and a second services.exe past the stop was never
        // enumerated. Before this join the artifact said `content_complete:
        // true` over an account that could be missing a whole silo's services.
        let (profile, space) = win11_fixture(win11_image());
        let symbols = ServiceSymbols::from_profile(&profile).expect("a catalogued build");
        let mut target = ServiceTarget::new(0x9000, Some(688), space, header_section(), Vec::new());

        let whole = scan_services_in(&profile, &symbols, &target, &ServiceScanConfig::default())
            .expect("a runnable sweep");
        assert!(
            whole.is_complete(),
            "the same sweep over a list that walked to completion is complete: {:?}",
            whole.incomplete()
        );

        target.process_list_complete = false;
        let listing = scan_services_in(&profile, &symbols, &target, &ServiceScanConfig::default())
            .expect("a runnable sweep");
        assert_eq!(
            listing.services.len(),
            whole.services.len(),
            "the sweep did exactly the same work"
        );
        assert!(listing.scan_complete && listing.ranges_complete);
        assert!(
            !listing.is_complete(),
            "a listing found on a truncated process list is not a complete account"
        );
        assert!(listing
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("another services.exe may exist")));
        assert_eq!(listing.to_json()["process_list_complete"], false);
        assert_eq!(listing.to_json()["complete"], false);
    }

    #[test]
    fn an_unlinked_service_is_only_a_floor_when_the_sweeps_ranges_were_incomplete() {
        // The list walk was complete, so the finding stands; but the sweep was
        // never offered every range, so the set of unlinked services it found
        // is a floor and the report has to be told so.
        let mut scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![
                fake_record(0x2000, "Dnscache", ServiceMethod::Scanned),
                fake_record(0x3000, "Hidden", ServiceMethod::Scanned),
            ],
        );
        scan.ranges_complete = false;
        let list = fake_listing(
            0x9000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        let diff = diff_services(&scan, &list);
        assert!(diff.comparable);
        assert_eq!(diff.unlinked.len(), 1);
        assert!(diff
            .notes
            .iter()
            .any(|note| note.contains("floor, not a total")));
    }

    #[test]
    fn an_image_with_no_readable_service_control_manager_refuses_rather_than_reporting_none() {
        // The failure that matters most here: an empty Vec<ServiceTarget>
        // becomes an empty Vec<ServiceListing>, which renders as a machine
        // running no services. Every Windows machine runs one.
        let absent = no_targets_refusal(0, &[], true);
        assert_eq!(absent.class(), "unsupported_build");
        assert!(absent.to_string().contains("services.exe"), "{absent}");
        assert!(
            absent.to_string().contains("running no services"),
            "the refusal has to name what the empty answer would have read as: {absent}"
        );
        assert!(!absent.to_string().contains("did not walk to completion"));

        // A list that stopped early is a second reason the absence proves
        // nothing, and it is stated rather than implied.
        let partial = no_targets_refusal(0, &[], false);
        assert!(partial.to_string().contains("did not walk to completion"));

        // A services.exe that was found and could not be read is a different
        // failure from one that was never there, and says which.
        let unreadable = no_targets_refusal(
            2,
            &[
                "the address space of the services.exe at 0x9000 could not be built: no DTB"
                    .to_string(),
            ],
            true,
        );
        assert!(
            unreadable.to_string().contains("2 process(es)"),
            "{unreadable}"
        );
        assert!(unreadable.to_string().contains("could not be built"));
        assert!(!unreadable.to_string().contains("running no services"));
    }

    #[test]
    fn merging_ranges_reports_what_the_cap_made_it_drop() {
        // A dropped range is a stretch of the process nothing swept; losing the
        // count would let a sweep that covered less than it was asked to report
        // every record as though it had covered everything.
        let (kept, dropped) = merge_ranges(vec![0..0x10, 0x100..0x110, 0x200..0x210], 2);
        assert_eq!(kept, vec![0..0x10, 0x100..0x110]);
        assert_eq!(dropped, 1);

        // Touching ranges merge rather than counting against the cap, because a
        // tag lying across the join would otherwise be lost.
        let (merged, dropped) = merge_ranges(vec![0..0x100, 0x100..0x200], 1);
        assert_eq!(merged, vec![0..0x200]);
        assert_eq!(dropped, 0);

        // A range that ends where it starts describes nothing and is not a drop.
        let (empty, dropped) = merge_ranges(vec![0x100..0x100], 8);
        assert!(empty.is_empty());
        assert_eq!(dropped, 0);
    }

    #[test]
    fn a_sweep_that_found_nothing_and_a_sweep_that_could_not_run_do_not_look_alike() {
        // An image with no service records at all: an empty listing that is
        // *complete*, which is a different claim from the refusals above.
        let (profile, space) = win11_fixture(Image::new());
        let listing = sweep(
            &profile,
            &space,
            header_section(),
            &ServiceScanConfig::default(),
        );
        assert!(listing.services.is_empty());
        assert!(listing.is_complete());
        assert!(listing.incomplete().is_empty());
    }

    // ── The difference between the two enumerations ─────────────────────────

    fn fake_record(address: u64, name: &str, method: ServiceMethod) -> ServiceRecord {
        ServiceRecord {
            address,
            header: None,
            method,
            order: 1,
            service_type: 0x20,
            type_names: service_type_names(0x20),
            state: ServiceState::Running,
            start: ServiceStart::AutoStart,
            name: Field::Known(name.to_string()),
            display_name: Field::Known(name.to_string()),
            binary: Field::NotApplicable,
            pid: Field::NotApplicable,
            registry_binary: Field::NotApplicable,
            registry_dll: Field::NotApplicable,
            notes: Vec::new(),
        }
    }

    fn fake_listing(
        process: u64,
        method: ServiceMethod,
        services: Vec<ServiceRecord>,
    ) -> ServiceListing {
        ServiceListing {
            process,
            pid: Some(688),
            method,
            layout: "services-win10-19041-x64",
            services,
            skipped: Vec::new(),
            skipped_total: 0,
            hits: 0,
            sections: 1,
            bytes_scanned: 4096,
            unread_bytes: 0,
            unmapped_bytes: 0,
            scan_complete: true,
            scan_truncated: false,
            ranges_complete: true,
            process_list_complete: true,
            stop: ServiceStop::Exhausted,
            notes: Vec::new(),
        }
    }

    /// A shortfall that was never mapped is not a gap in the examination, and
    /// must not be described as one.
    ///
    /// Sweeping a reserved region on the Lone Wolf capture reported
    /// "2199081095168 byte(s) … were not examined, so a service record among
    /// them would not have been found" — 2.2 TB of address space no page ever
    /// backed. A service record cannot be in memory that was never committed,
    /// and the number was large enough to bury anything real beside it. On that
    /// image the mapped-and-unreadable total was zero.
    #[test]
    fn address_space_that_was_never_mapped_is_not_reported_as_a_gap() {
        let mut listing = fake_listing(0x9000, ServiceMethod::Scanned, Vec::new());
        listing.unread_bytes = 2_199_081_095_168;
        listing.unmapped_bytes = 2_199_081_095_168;
        listing.scan_complete = false;

        let details: Vec<String> = listing
            .incomplete()
            .iter()
            .map(|entry| entry.detail.clone())
            .collect();

        assert!(
            !details.iter().any(|d| d.contains("could not be read")),
            "no mapped byte failed to read, so nothing should claim one did: {details:?}"
        );
        assert!(
            details.iter().any(|d| d.contains("never mapped")),
            "the shortfall still has to be explained, or `complete: false` stands \
             with nothing accounting for it: {details:?}"
        );
    }

    /// The other half: a byte that was mapped and unreadable is a real gap and
    /// keeps its own sentence, with the unmapped bulk subtracted out.
    #[test]
    fn a_mapped_byte_that_could_not_be_read_is_still_reported() {
        let mut listing = fake_listing(0x9000, ServiceMethod::Scanned, Vec::new());
        listing.unread_bytes = 2_199_081_095_168 + 4096;
        listing.unmapped_bytes = 2_199_081_095_168;
        listing.scan_complete = false;

        let details: Vec<String> = listing
            .incomplete()
            .iter()
            .map(|entry| entry.detail.clone())
            .collect();

        assert!(
            details
                .iter()
                .any(|d| d.contains("4096 mapped byte(s)") && d.contains("could not be read")),
            "the real gap is the difference, not the total: {details:?}"
        );
    }

    #[test]
    fn a_service_found_by_sweeping_and_absent_from_the_chain_is_unlinked() {
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![
                fake_record(0x2000, "Dnscache", ServiceMethod::Scanned),
                fake_record(0x3000, "Hidden", ServiceMethod::Scanned),
            ],
        );
        let list = fake_listing(
            0x9000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        let diff = diff_services(&scan, &list);
        assert!(diff.comparable);
        assert_eq!(diff.scanned, 2);
        assert_eq!(diff.listed, 1);
        assert_eq!(diff.unlinked.len(), 1);
        assert_eq!(diff.unlinked[0].address, 0x3000);
        assert!(diff.listed_only.is_empty());
        assert!(diff.incomplete().is_empty());
    }

    #[test]
    fn records_are_matched_by_address_so_a_reused_name_cannot_hide_one() {
        // Two records with the same name at different addresses: matching by
        // name would clear the second, which is exactly the trick.
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![
                fake_record(0x2000, "Dnscache", ServiceMethod::Scanned),
                fake_record(0x3000, "Dnscache", ServiceMethod::Scanned),
            ],
        );
        let list = fake_listing(
            0x9000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        let diff = diff_services(&scan, &list);
        assert_eq!(diff.unlinked.len(), 1);
        assert_eq!(diff.unlinked[0].address, 0x3000);
    }

    #[test]
    fn nothing_is_called_unlinked_when_the_chain_walk_was_incomplete() {
        // A chain that stopped at an unreadable record reaches fewer services
        // than the SCM links, and every service past the stop would otherwise
        // be reported as hidden.
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![
                fake_record(0x2000, "Dnscache", ServiceMethod::Scanned),
                fake_record(0x3000, "WinDefend", ServiceMethod::Scanned),
            ],
        );
        let mut list = fake_listing(
            0x9000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        list.skipped_total = 1;
        let diff = diff_services(&scan, &list);
        assert!(!diff.comparable);
        assert!(diff.unlinked.is_empty());
        assert!(diff
            .notes
            .iter()
            .any(|note| note.contains("not shown to have been unlinked")));
        assert!(!diff.incomplete().is_empty());
    }

    #[test]
    fn nothing_is_called_unlinked_when_the_chain_walk_reached_no_records() {
        // A list head that was never found is a failure to look, not a Service
        // Control Manager linking nothing.
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Scanned)],
        );
        let list = fake_listing(0x9000, ServiceMethod::Listed, Vec::new());
        let diff = diff_services(&scan, &list);
        assert!(!diff.comparable);
        assert!(diff.unlinked.is_empty());
        assert!(diff.notes.iter().any(|note| note.contains("list head")));
    }

    #[test]
    fn two_enumerations_of_different_processes_are_not_subtracted() {
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Scanned)],
        );
        let list = fake_listing(
            0xA000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        let diff = diff_services(&scan, &list);
        assert!(!diff.comparable);
        assert!(diff
            .notes
            .iter()
            .any(|note| note.contains("different processes")));
    }

    #[test]
    fn an_incomplete_sweep_makes_the_unlinked_set_a_floor_and_says_so() {
        let mut scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![
                fake_record(0x2000, "Dnscache", ServiceMethod::Scanned),
                fake_record(0x3000, "Hidden", ServiceMethod::Scanned),
            ],
        );
        scan.unread_bytes = 4096;
        scan.scan_complete = false;
        let list = fake_listing(
            0x9000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        let diff = diff_services(&scan, &list);
        // The list was complete, so the finding still stands...
        assert!(diff.comparable);
        assert_eq!(diff.unlinked.len(), 1);
        // ...but the report is told it is not a total.
        assert!(diff
            .notes
            .iter()
            .any(|note| note.contains("floor, not a total")));
    }

    // ── The orchestrated stage ──────────────────────────────────────────────

    #[test]
    fn the_survey_carries_the_sweep_the_chain_and_the_subtraction_together() {
        // The stage this wires exists because the chain walk and the diff were
        // implemented and never run: the orchestrator swept and stopped, so
        // unlinked-service concealment was never an emitted finding.
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![
                fake_record(0x2000, "Dnscache", ServiceMethod::Scanned),
                fake_record(0x3000, "Hidden", ServiceMethod::Scanned),
            ],
        );
        let list = fake_listing(
            0x9000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        let diff = diff_services(&scan, &list);
        let survey = ServiceSurvey {
            scan,
            list: Some(list),
            list_unavailable: None,
            diff: Some(diff),
        };

        assert_eq!(survey.unlinked().len(), 1);
        assert_eq!(survey.unlinked()[0].address, 0x3000);
        assert!(survey.is_complete());
        assert!(survey.incomplete().is_empty());

        let json = survey.to_json();
        // The swept listing stays where a consumer has always found it.
        assert_eq!(json["method"], "scanned");
        assert_eq!(json["count"], 2);
        // With the two new views beside it.
        assert_eq!(json["chain"]["count"], 1);
        assert_eq!(json["diff"]["unlinked"][0]["address"], 0x3000);
        assert_eq!(json["unlinked_count"], 1);
        assert_eq!(json["survey_complete"], true);
    }

    #[test]
    fn a_build_with_no_chain_to_walk_keeps_its_sweep_and_claims_no_concealment() {
        // XP and Server 2003 have no PrevEntry. Failing the whole stage there
        // would cost the examiner the service list; reporting an empty chain
        // would make every service on the machine look unlinked.
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Scanned)],
        );
        let survey = ServiceSurvey {
            scan,
            list: None,
            list_unavailable: Some(
                "the 'services-xp-x86' service record has no PrevEntry".to_string(),
            ),
            diff: None,
        };

        assert_eq!(survey.scan.services.len(), 1, "the sweep is not lost");
        assert!(survey.unlinked().is_empty());
        assert!(
            !survey.is_complete(),
            "no chain means no claim about concealment"
        );
        assert!(survey
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("PrevEntry")));

        let json = survey.to_json();
        assert_eq!(json["chain"], serde_json::Value::Null);
        assert_eq!(json["diff"], serde_json::Value::Null);
        assert_eq!(json["survey_complete"], false);
        assert!(json["chain_unavailable"].is_string());
        // The sweep ran end to end, and a consumer that reads one key to decide
        // whether it may quote the record must not be handed that `true`: this
        // record has no chain to compare against and says nothing about
        // concealment.
        assert_eq!(json["complete"], false);
        assert_eq!(
            json["sweep_complete"], true,
            "the sweep's own verdict is kept, under a name that says whose it is"
        );
    }

    #[test]
    fn a_survey_whose_chain_walk_stopped_early_is_not_a_complete_survey() {
        let scan = fake_listing(
            0x9000,
            ServiceMethod::Scanned,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Scanned)],
        );
        let mut list = fake_listing(
            0x9000,
            ServiceMethod::Listed,
            vec![fake_record(0x2000, "Dnscache", ServiceMethod::Listed)],
        );
        list.skipped_total = 1;
        let diff = diff_services(&scan, &list);
        let survey = ServiceSurvey {
            scan,
            list: Some(list),
            list_unavailable: None,
            diff: Some(diff),
        };
        assert!(!survey.is_complete());
        assert!(survey.unlinked().is_empty());
        assert!(!survey.incomplete().is_empty());
    }

    // ── Service SIDs ────────────────────────────────────────────────────────

    #[test]
    fn the_service_sid_of_trusted_installer_matches_the_published_value() {
        assert_eq!(
            service_sid("TrustedInstaller").as_deref(),
            Some("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
        );
    }

    #[test]
    fn the_service_sid_is_the_same_however_the_name_is_cased() {
        // The name is uppercased before it is hashed, which is why a service
        // key's casing never changes the account's SID.
        let expected = service_sid("WinDefend");
        assert_eq!(service_sid("windefend"), expected);
        assert_eq!(service_sid("WINDEFEND"), expected);
        assert_eq!(
            expected.as_deref(),
            Some("S-1-5-80-1913148863-3492339771-4165695881-2087618961-4109116736")
        );
    }

    #[test]
    fn a_service_sid_is_five_sub_authorities_under_the_published_prefix() {
        let sid = service_sid("Dnscache").expect("a derivable SID");
        assert_eq!(
            sid,
            "S-1-5-80-859482183-879914841-863379149-1145462774-2388618682"
        );
        let parts: Vec<&str> = sid
            .strip_prefix("S-1-5-80-")
            .expect("the prefix")
            .split('-')
            .collect();
        assert_eq!(parts.len(), SERVICE_SID_SUBAUTHORITIES);
        assert!(parts.iter().all(|part| part.parse::<u32>().is_ok()));
    }

    #[test]
    fn a_service_sid_records_the_exact_string_that_was_hashed() {
        // The derivation has to be reproducible by hand, because nothing about
        // it was read out of the image.
        let map = ServiceRegistryMap {
            hive: 0xE1000000,
            key_path: SERVICES_KEY_CURRENT.to_string(),
            names: vec!["Dnscache".to_string()],
            incomplete: Vec::new(),
            entries: HashMap::new(),
        };
        let listing = list_service_sids(&map);
        assert_eq!(listing.sids.len(), 1);
        assert_eq!(listing.sids[0].service, "Dnscache");
        assert_eq!(listing.sids[0].hashed, "DNSCACHE");
        assert!(listing.unresolved.is_empty());
        assert!(listing.is_complete());
        assert_eq!(listing.sids[0].to_json()["read_from_image"], false);
    }

    #[test]
    fn a_service_sid_listing_inherits_whatever_the_key_listing_could_not_do() {
        let map = ServiceRegistryMap {
            hive: 0xE1000000,
            key_path: SERVICES_KEY_CURRENT.to_string(),
            names: vec!["Dnscache".to_string()],
            incomplete: vec![Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                "the subkey index could not be read in full",
            )],
            entries: HashMap::new(),
        };
        let listing = list_service_sids(&map);
        assert!(!listing.is_complete());
        assert_eq!(listing.incomplete.len(), 1);
    }

    #[test]
    fn hex_decoding_refuses_anything_that_is_not_a_digest() {
        assert_eq!(hex_to_bytes("00ff"), Some(vec![0x00, 0xFF]));
        assert_eq!(hex_to_bytes("0"), None, "an odd length is not bytes");
        assert_eq!(hex_to_bytes("zz"), None, "a non-hex digit is not a byte");
        // And the digest itself is exactly twenty bytes, which is what lets the
        // five sub-authorities be taken without inventing one.
        assert_eq!(sha1_digest(b"").map(|digest| digest.len()), Some(20));
    }

    // ── The registry side ───────────────────────────────────────────────────

    #[test]
    fn the_system_hive_is_recognised_by_either_of_its_two_spellings() {
        // Which spelling a hive carries depends on which member its name was
        // read from, so matching only one finds no SYSTEM hive on half the
        // images.
        assert!(is_system_hive_name(Some("\\REGISTRY\\MACHINE\\SYSTEM")));
        assert!(is_system_hive_name(Some(
            "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SYSTEM"
        )));
        assert!(is_system_hive_name(Some(
            "\\SystemRoot\\System32\\Config\\system"
        )));
        assert!(!is_system_hive_name(Some(
            "\\Device\\HarddiskVolume2\\Windows\\System32\\config\\SOFTWARE"
        )));
        assert!(!is_system_hive_name(Some(
            "\\Device\\HarddiskVolume2\\Users\\a\\NTUSER.DAT"
        )));
        assert!(!is_system_hive_name(None), "an unnamed hive names nothing");
    }

    #[test]
    fn a_registry_map_looks_a_service_up_however_its_name_is_cased() {
        let mut entries = HashMap::new();
        entries.insert(
            "dnscache".to_string(),
            ServiceBinaryInfo {
                image_path: Field::Known("%SystemRoot%\\system32\\svchost.exe -k".to_string()),
                service_dll: Field::Known("%SystemRoot%\\System32\\dnsrslvr.dll".to_string()),
            },
        );
        let map = ServiceRegistryMap {
            hive: 0xE1000000,
            key_path: SERVICES_KEY_CURRENT.to_string(),
            names: vec!["Dnscache".to_string()],
            incomplete: Vec::new(),
            entries,
        };
        assert!(map.get("DNSCACHE").is_some());
        assert!(map.get("Dnscache").is_some());
        assert!(map.get("nothing-of-the-sort").is_none());
        assert_eq!(map.len(), 1);
        assert!(!map.is_empty());
        assert!(map.is_complete());
    }

    #[test]
    fn the_registry_side_reaches_a_service_record_when_it_is_supplied() {
        let mut entries = HashMap::new();
        entries.insert(
            "dnscache".to_string(),
            ServiceBinaryInfo {
                image_path: Field::Known("%SystemRoot%\\system32\\svchost.exe -k".to_string()),
                service_dll: Field::Known("%SystemRoot%\\System32\\dnsrslvr.dll".to_string()),
            },
        );
        let map = Arc::new(ServiceRegistryMap {
            hive: 0xE1000000,
            key_path: SERVICES_KEY_CURRENT.to_string(),
            names: vec!["Dnscache".to_string()],
            incomplete: Vec::new(),
            entries,
        });
        let (profile, space) = win11_fixture(win11_image());
        let config = ServiceScanConfig {
            registry: Some(map),
            ..ServiceScanConfig::default()
        };
        let listing = sweep(&profile, &space, header_section(), &config);

        let dnscache = named(&listing, "Dnscache");
        assert_eq!(
            dnscache.registry_dll.known().map(String::as_str),
            Some("%SystemRoot%\\System32\\dnsrslvr.dll")
        );
        // And a service with no key of its own says exactly that, rather than
        // showing the same blank cell as a service nobody looked up.
        let beep = named(&listing, "Beep");
        assert!(beep.registry_binary.is_unavailable());
        assert!(
            beep.registry_binary.to_json()["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("no registry key")),
            "the reason has to name what was looked for"
        );
    }
}
