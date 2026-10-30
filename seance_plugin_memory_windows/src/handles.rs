//! Handle tables: everything a process had open, and what it was allowed to do
//! with each of them.
//!
//! A handle is the only way a user-mode process touches anything the kernel
//! owns. Every file it had open, every registry key, every mutex, every other
//! process whose memory it could read, is one entry in one table hanging off
//! `_EPROCESS.ObjectTable`. That table is the single best answer to "what was
//! this program actually doing", and unlike a log it cannot be edited after the
//! fact by anything short of kernel code.
//!
//! Three findings live in it and nowhere else:
//!
//! * **A process holding a handle to another process** with `PROCESS_VM_READ`
//!   or `PROCESS_VM_WRITE`. That is the handle credential dumping needs and the
//!   handle injection needs, and it is visible here even when the code that
//!   used it has been unloaded.
//! * **A file that no longer exists on disk.** The handle names it, the file
//!   object is still in memory, and the name survives the deletion.
//! * **A named mutex.** Malware families create one to avoid running twice, and
//!   the name is often the most specific indicator available.
//!
//! This module also carries the two other things a token says about a process —
//! its [`privileges`] and its [`sid`]s — because both are read from the same
//! `_EPROCESS`, and a report that says a process held a handle to LSASS without
//! saying whether it held `SeDebugPrivilege` has told half the story.
//!
//! # The table is a tree of pages, and its shape is in two bits
//!
//! `_HANDLE_TABLE.TableCode` is a pointer with the number of *levels* packed
//! into its low bits — the table's pages are page-aligned, so those bits are
//! free.
//!
//! | Levels | Shape | Capacity (x64) |
//! |---|---|---|
//! | 0 | one page of `_HANDLE_TABLE_ENTRY` | 256 handles |
//! | 1 | a page of pointers to level-0 pages | 131,072 |
//! | 2 | a page of pointers to level-1 pages | 67,108,864 |
//!
//! A level count above 2 is not a deeper table; it is `TableCode` not being a
//! table code, and it is refused rather than followed. The walk is iterative
//! over an explicit stack, cycle-safe through a visited set, and bounded by
//! [`HandleWalkConfig::max_tables`] and [`HandleWalkConfig::max_handles`],
//! because every pointer in it came out of the image.
//!
//! # The handle value is positional, not sequential
//!
//! The number a program passes to `CloseHandle` is not a counter. It is the
//! entry's *position* in the table, times four:
//!
//! ```text
//! handle = ((level_2_slot × slots_per_page + level_1_slot) × entries_per_page
//!           + entry_index) × 4
//! ```
//!
//! The multiplier is four because the bottom two bits of a handle are reserved
//! for flags. The position is what matters: a null pointer in a mid-level page
//! still consumes its slot, so an implementation that numbered handles by the
//! order it happened to find them would renumber every handle after the first
//! gap. Upstream Volatility's numbering is right for one- and two-level tables
//! and repeats itself on three-level ones; the arithmetic here is positional
//! throughout and agrees with upstream wherever upstream is right.
//!
//! # The object pointer is not a pointer
//!
//! Getting from an entry to the object is different on every generation, and
//! the wrong decode produces an `_OBJECT_HEADER` at a plausible address whose
//! type index, when it resolves at all, names some other kind of object:
//!
//! | Build | Entry member | Decode |
//! |---|---|---|
//! | XP – 7 | `Object` | an `_EX_FAST_REF`: mask off the low 3 (x86) or 4 (x64) bits |
//! | 8 – 11, x64 | `ObjectPointerBits` | a 44-bit field: shift left 4, then **sign-extend bit 47** |
//! | 8 – 11, x86 | `InfoTable` | mask off the low 3 bits |
//!
//! The sign extension is the one that bites. `ObjectPointerBits << 4` is a
//! 48-bit number, and a kernel address is that number with bits 63:48 copied
//! from bit 47. Volatility prints the truncated form; Séance keeps the
//! canonical one, so `0xffff8000_29800000` here is `0x800029800000` there. Both
//! name the same byte; only one of them is an address the processor would
//! accept.
//!
//! # The type index is deliberately obfuscated
//!
//! `_OBJECT_HEADER` does not store what kind of object it heads. Before Vista
//! it stores a pointer to an `_OBJECT_TYPE`; from Windows 7 it stores a
//! one-byte index into a kernel table; and from Windows 10 that index is XORed
//! with the header's own address and a per-boot cookie, so the same object type
//! has a different stored index at every address. Undoing it is
//! [`crate::poolscan::ObjectTypeMap`]'s job, and this module uses that rather
//! than a second implementation which could drift from it.
//!
//! On a build that uses the index, a walk with no type map is **refused**:
//! every row's type column would be blank, and a table of typeless handles
//! reads like a machine full of handles to nothing rather than like a check
//! that was not performed.

#[path = "handles_name.rs"]
pub mod name;
#[path = "handles_privileges.rs"]
pub mod privileges;
#[path = "handles_sid.rs"]
pub mod sid;
#[path = "handles_token.rs"]
pub mod token;

pub use name::{
    object_name, FileNameSymbols, HandleName, KeyNameSymbols, NameInfoLocation, NameSymbols,
    ProcessNameSymbols, ThreadNameSymbols,
};
pub use privileges::{
    list_privileges, privilege_name, PrivilegeConfig, PrivilegeOutcome, PrivilegeRecord,
    PrivilegeShape, PrivilegeSymbols, PRIVILEGES,
};
pub use sid::{
    decode_sid, list_sids, Sid, SidConfig, SidOutcome, SidRecord, SidRule, SidSymbols, SID_RULES,
    WELL_KNOWN_SIDS,
};
pub use token::{token_for, ProcessToken, TokenError, TokenSymbols};

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{required_size, BindError};
use seance_memory::object::{is_canonical, ObjError, StructReader};
use seance_memory::Incomplete;
use seance_symbols::SymbolError;

use crate::handles::token::first_member;
use crate::module::STAGE_HANDLES;
use crate::poolscan::{unicode_string, ObjectTypeMap, PoolError};
use crate::profile::WindowsProfile;

/// The process structure the handle table hangs off.
pub const TYPE_EPROCESS: &str = "_EPROCESS";

/// The handle table itself.
pub const TYPE_HANDLE_TABLE: &str = "_HANDLE_TABLE";

/// One slot of a level-0 handle table page.
pub const TYPE_HANDLE_TABLE_ENTRY: &str = "_HANDLE_TABLE_ENTRY";

/// The header in front of every executive object.
pub const TYPE_OBJECT_HEADER: &str = "_OBJECT_HEADER";

/// The object-manager type an object header names.
pub const TYPE_OBJECT_TYPE: &str = "_OBJECT_TYPE";

/// Size of one level of a handle table, in bytes.
///
/// Every level of the table is exactly one page on every architecture Windows
/// runs on, which is what makes the low bits of `TableCode` free for the level
/// count.
pub const HANDLE_TABLE_PAGE_SIZE: u64 = 4096;

/// Mask covering the bits of `TableCode` that are not part of the pointer.
pub const LEVEL_MASK: u64 = 7;

/// Mask covering the attribute bits carried below an `InfoTable` pointer.
///
/// Numerically the same three bits as [`LEVEL_MASK`] and deliberately a
/// separate constant: the two describe unrelated encodings, and a table code
/// whose level field ever widened would otherwise silently widen the mask that
/// decodes every 32-bit Windows 8 handle.
pub const INFO_TABLE_MASK: u64 = 7;

/// The deepest handle table Windows builds.
pub const MAX_HANDLE_TABLE_LEVELS: u32 = 2;

/// The multiplier between an entry's position and its handle value.
///
/// The bottom two bits of a handle are reserved for flags, so handle values
/// advance in fours. Numbering them one apart produces values no program ever
/// held.
pub const HANDLE_VALUE_STRIDE: u64 = 4;

/// How far the 44-bit object pointer field is shifted to become an address.
pub const OBJECT_POINTER_SHIFT: u32 = 4;

/// Width of the object pointer field, in bits.
///
/// Forty-four bits plus the four the shift restores is forty-eight, which is
/// exactly the canonical address width. A value wider than this is not this
/// encoding, and shifting it anyway would drop its top bits and land 16 TiB
/// from the object.
pub const OBJECT_POINTER_BITS: u32 = 44;

/// The bit a 48-bit address is sign-extended from to become canonical.
pub const CANONICAL_SIGN_BIT: u32 = 47;

/// Ceiling on handles one walk will return.
pub const MAX_HANDLES: usize = 1_000_000;

/// Ceiling on table pages one walk will visit.
///
/// A fully populated two-level table has 512 mid-level slots; reaching this
/// means the pointers are not table pointers.
pub const MAX_HANDLE_TABLES: usize = 8192;

/// Ceiling on individually recorded skipped entries. The *count* stays exact.
pub const MAX_RECORDED_SKIPS: usize = 512;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a handle table from being walked at all.
///
/// Note what is *not* here: an entry that did not decode to an object. That is
/// a fact about one slot, and it lands in [`HandleTable::skipped`] where an
/// examiner can count it.
#[derive(Debug, thiserror::Error)]
pub enum HandleError {
    /// This build's handle table cannot be walked with what is available, and
    /// no partial answer would be honest. The message names what is missing.
    #[error("a process's handle table cannot be walked on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// `TableCode` claims more levels than a handle table has.
    ///
    /// Not a deeper table: the value is not a table code, and following it
    /// would walk arbitrary memory as if it were pointers to handle pages.
    #[error(
        "the handle table of the process at {process:#x} has a TableCode of {table_code:#x}, \
         which claims {levels} level(s), and a handle table has at most 2"
    )]
    ImplausibleTableCode {
        /// The `_EPROCESS` whose table it is.
        process: u64,
        /// The raw value.
        table_code: u64,
        /// The level count it claimed.
        levels: u32,
    },

    /// A typed read failed for a reason that invalidates the whole walk rather
    /// than one entry.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the walk depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// A layout the walk cannot proceed without could not be bound to this
    /// build.
    ///
    /// `#[error(transparent)]` here is deliberate, and it is not the
    /// transparency that made the original defect undiagnosable: a
    /// [`BindError`] states the stage that stopped, every name that was tried
    /// and what stopping cost, where a bare [`SymbolError`] states only that
    /// some type was unknown.
    #[error(transparent)]
    Bind(#[from] BindError),

    /// The object-type map, which every handle's type is resolved through,
    /// could not be built.
    #[error(transparent)]
    Pool(#[from] PoolError),

    /// The token layout, which the naming and token stages share, could not be
    /// established.
    #[error(transparent)]
    Token(#[from] TokenError),
}

impl HandleError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            HandleError::Unsupported { .. } => "unsupported_build",
            HandleError::ImplausibleTableCode { .. } => "implausible_table_code",
            HandleError::Object(err) => err.class(),
            HandleError::Symbols(_) => "symbols",
            HandleError::Bind(err) => err.class(),
            HandleError::Pool(err) => err.class(),
            HandleError::Token(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            HandleError::Object(err) => err.incomplete_reason(),
            HandleError::Pool(err) => err.incomplete_reason(),
            HandleError::Token(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be walked" refusal.
    pub fn unsupported(detail: impl Into<String>) -> HandleError {
        HandleError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// How this build turns a handle table entry into an object header address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleDecode {
    /// XP through Windows 7: the entry holds the address as an `_EX_FAST_REF`,
    /// with attribute bits in the space below the pointer's alignment.
    FastRef {
        /// Path to the member holding it.
        path: String,
        /// Mask covering the bits that are not part of the address.
        mask: u64,
    },
    /// Windows 8 and later on x64: a 44-bit field that must be shifted left
    /// four and sign-extended from bit 47.
    PointerBits {
        /// Path to the field.
        path: String,
    },
    /// Windows 8 and later on x86: `InfoTable` with its low three bits masked
    /// off.
    InfoTable {
        /// Path to the member.
        path: String,
        /// Mask covering the bits that are not part of the address.
        mask: u64,
    },
}

impl HandleDecode {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            HandleDecode::FastRef { .. } => "fast_ref",
            HandleDecode::PointerBits { .. } => "pointer_bits",
            HandleDecode::InfoTable { .. } => "info_table",
        }
    }
}

/// How this build's object headers say what kind of object they head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectTypeSource {
    /// Windows 7 and later: an index into the kernel's object-type table,
    /// obfuscated from Windows 10 onwards.
    Index(String),
    /// Vista and earlier: a pointer straight to the `_OBJECT_TYPE`.
    Pointer(String),
}

impl ObjectTypeSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ObjectTypeSource::Index(_) => "type_index",
            ObjectTypeSource::Pointer(_) => "type_pointer",
        }
    }
}

/// Everything one image's handle tables are read through.
///
/// Resolved once per image and checked once, so a build whose layout is unknown
/// fails here naming the member that is missing rather than at handle three
/// thousand having already emitted rows read at the wrong offsets.
#[derive(Debug, Clone)]
pub struct HandleSymbols {
    /// Path to the handle-table pointer on `_EPROCESS`.
    pub object_table: String,
    /// Path to `TableCode` on `_HANDLE_TABLE`.
    pub table_code: String,
    /// Declared size of one `_HANDLE_TABLE_ENTRY`.
    pub entry_size: u64,
    /// How many entries a level-0 page holds.
    pub entries_per_leaf: u64,
    /// How many pointers a level-1 or level-2 page holds.
    pub pointers_per_page: u64,
    /// How an entry becomes an object header address.
    pub decode: HandleDecode,
    /// Path to the granted access mask on an entry.
    pub granted_access: String,
    /// How an object header names its type.
    pub type_source: ObjectTypeSource,
    /// Distance from an object header to the object it heads.
    pub body_offset: u64,
    /// Everything names are resolved through.
    pub names: NameSymbols,
    /// Pointer width in bytes, as the symbol table declares it.
    pub pointer_size: u64,
    /// The kernel's object-type table, read from this image at construction on
    /// every build that stores an object's kind as an *index* into it.
    ///
    /// Resolved here rather than left to the caller because the caller has no
    /// way of knowing whether this build needs one, and a default configuration
    /// that supplies none would refuse every handle table on Windows 8 and
    /// later — which is every modern image. [`HandleWalkConfig::type_map`]
    /// still overrides it, for an examiner supplying a table by hand.
    pub type_map: Option<Arc<ObjectTypeMap>>,
    /// Why [`HandleSymbols::type_map`] is absent on a build that needs one.
    ///
    /// `None` on a build that does not need one at all. Carried so that the
    /// refusal an examiner reads names the reason the kernel's table could not
    /// be read, rather than saying only that no table was supplied.
    pub type_map_unavailable: Option<String>,
}

impl HandleSymbols {
    /// Resolve every layout fact a handle-table walk of this image needs.
    ///
    /// # Errors
    ///
    /// [`HandleError::Unsupported`] naming the type or member that is missing.
    /// Nothing here is optional: a handle table cannot be walked at all without
    /// the table code, the entry size, a way to decode an entry and a way to
    /// name a type, and a walk missing any of them would produce a table that
    /// reads like a successful one.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, HandleError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        // `_HANDLE_TABLE_ENTRY` is deliberately not in this list: it is bound
        // below through the binding, which says which stage stopped and what
        // stopping cost rather than only that a type was unknown.
        for type_name in [TYPE_EPROCESS, TYPE_HANDLE_TABLE, TYPE_OBJECT_HEADER] {
            if !profile.symbols.has_type(type_name) {
                return Err(HandleError::unsupported(format!(
                    "the symbol table has no '{type_name}', so what a process had open cannot be \
                     read"
                )));
            }
        }

        let pointer_size = u64::from(reader.pointer_size()?);
        if pointer_size != profile.pointer_size() {
            return Err(HandleError::unsupported(format!(
                "the symbol table declares {pointer_size}-byte pointers and the image profile \
                 records {}-byte pointers, so one of the two does not describe this image",
                profile.pointer_size()
            )));
        }

        let object_table = first_member(&reader, TYPE_EPROCESS, &["ObjectTable"])?
            .ok_or_else(|| {
                HandleError::unsupported(format!(
                    "'{TYPE_EPROCESS}' has no ObjectTable, so a process's handles cannot be reached"
                ))
            })?
            .to_string();
        let table_code = first_member(&reader, TYPE_HANDLE_TABLE, &["TableCode"])?
            .ok_or_else(|| {
                HandleError::unsupported(format!(
                    "'{TYPE_HANDLE_TABLE}' has no TableCode, so the table's shape and location are \
                     unknown"
                ))
            })?
            .to_string();

        // Required, and correctly so: with no stride there is no second entry
        // to read, and a walk that stopped after the first would report a
        // process holding hundreds of handles as holding one.
        let entry_size = required_size(
            &profile.symbols,
            STAGE_HANDLES,
            &[TYPE_HANDLE_TABLE_ENTRY],
            "a handle table entry has no width, so no entry beyond the first can be located and \
             every process would be reported as holding almost nothing",
        )?;
        if entry_size == 0 || entry_size > HANDLE_TABLE_PAGE_SIZE {
            return Err(HandleError::unsupported(format!(
                "'{TYPE_HANDLE_TABLE_ENTRY}' declares a size of {entry_size} byte(s), which cannot \
                 divide a {HANDLE_TABLE_PAGE_SIZE}-byte table page"
            )));
        }
        let entries_per_leaf = HANDLE_TABLE_PAGE_SIZE / entry_size;
        let pointers_per_page = HANDLE_TABLE_PAGE_SIZE / pointer_size;

        // XP through Windows 7 first: those builds declare `Object`, and a
        // build that declares it is that shape whatever else it also declares.
        // Windows 8 removed it, which is exactly why the branch is on its
        // absence rather than on a build number.
        let decode =
            if let Some(path) = first_member(&reader, TYPE_HANDLE_TABLE_ENTRY, &["Object"])? {
                HandleDecode::FastRef {
                    path: path.to_string(),
                    mask: pointer_size.saturating_mul(2).saturating_sub(1),
                }
            } else if profile.is_64bit() {
                let path = first_member(&reader, TYPE_HANDLE_TABLE_ENTRY, &["ObjectPointerBits"])?
                    .ok_or_else(|| {
                        HandleError::unsupported(format!(
                            "'{TYPE_HANDLE_TABLE_ENTRY}' has neither Object nor ObjectPointerBits, \
                             so an entry cannot be turned into the object it names"
                        ))
                    })?
                    .to_string();
                HandleDecode::PointerBits { path }
            } else {
                let path = first_member(&reader, TYPE_HANDLE_TABLE_ENTRY, &["InfoTable"])?
                    .ok_or_else(|| {
                        HandleError::unsupported(format!(
                        "'{TYPE_HANDLE_TABLE_ENTRY}' has neither Object nor InfoTable, so an entry \
                         cannot be turned into the object it names"
                    ))
                    })?
                    .to_string();
                HandleDecode::InfoTable {
                    path,
                    // Three bits of attributes below the pointer, on every 32-bit
                    // build that uses this shape.
                    mask: INFO_TABLE_MASK,
                }
            };

        let granted_access = first_member(
            &reader,
            TYPE_HANDLE_TABLE_ENTRY,
            &["GrantedAccessBits", "GrantedAccess"],
        )?
        .ok_or_else(|| {
            HandleError::unsupported(format!(
                "'{TYPE_HANDLE_TABLE_ENTRY}' has neither GrantedAccessBits nor GrantedAccess, so \
                 what a process was permitted to do with a handle cannot be reported"
            ))
        })?
        .to_string();

        // The index first: a build that has both is the later one, and the
        // `Type` member of an early `_OBJECT_HEADER` does not exist there.
        let type_source =
            if let Some(path) = first_member(&reader, TYPE_OBJECT_HEADER, &["TypeIndex"])? {
                ObjectTypeSource::Index(path.to_string())
            } else if let Some(path) = first_member(&reader, TYPE_OBJECT_HEADER, &["Type"])? {
                if !profile.symbols.has_type(TYPE_OBJECT_TYPE) {
                    return Err(HandleError::unsupported(format!(
                        "'{TYPE_OBJECT_HEADER}.Type' points at '{TYPE_OBJECT_TYPE}', which the \
                         symbol table does not have, so a handle's type cannot be named"
                    )));
                }
                ObjectTypeSource::Pointer(path.to_string())
            } else {
                return Err(HandleError::unsupported(format!(
                    "'{TYPE_OBJECT_HEADER}' has neither TypeIndex nor Type, so what kind of object \
                     a handle refers to cannot be told"
                )));
            };

        let body_offset = reader
            .member_offset(TYPE_OBJECT_HEADER, "Body")
            .map_err(|err| {
                HandleError::unsupported(format!(
                    "'{TYPE_OBJECT_HEADER}.Body' could not be located, so the object behind a \
                     handle cannot be reached: {err}"
                ))
            })?
            .bytes();

        // Only builds that index into the table need it. Reading it on a build
        // whose object headers point straight at their `_OBJECT_TYPE` would be
        // work whose failure means nothing.
        let (type_map, type_map_unavailable) = match &type_source {
            ObjectTypeSource::Pointer(_) => (None, None),
            ObjectTypeSource::Index(_) => match ObjectTypeMap::from_profile(profile) {
                Ok(map) if map.is_empty() => (
                    None,
                    Some(
                        "the kernel's object-type table was located but held no readable entry, so \
                         an object header's type index cannot be resolved to a type name"
                            .to_string(),
                    ),
                ),
                // A table that was read is not yet a table that can be used:
                // from Windows 10 the stored index is mixed with the per-boot
                // cookie, and looking one up unmixed names the wrong kind of
                // object for about a fifth of the rows without marking any of
                // them.
                Ok(map) => match map.resolves_indexes(profile.build.build) {
                    Ok(()) => (Some(Arc::new(map)), None),
                    Err(reason) => (None, Some(reason)),
                },
                Err(err) => (
                    None,
                    Some(format!(
                        "the kernel's object-type table could not be read, so an object header's \
                         type index cannot be resolved to a type name: {err}"
                    )),
                ),
            },
        };

        Ok(Self {
            object_table,
            table_code,
            entry_size,
            entries_per_leaf,
            pointers_per_page,
            decode,
            granted_access,
            type_source,
            body_offset,
            names: NameSymbols::from_profile(profile)?,
            pointer_size,
            type_map,
            type_map_unavailable,
        })
    }

    /// The object-type table a walk will resolve type indexes through.
    ///
    /// The caller's table wins when it supplied one; otherwise the table read
    /// from the image at construction. `None` only on a build that needs one
    /// and could not have one, which [`list_handles`] refuses on.
    pub fn effective_type_map<'a>(
        &'a self,
        config: &'a HandleWalkConfig,
    ) -> Option<&'a ObjectTypeMap> {
        config.type_map.as_deref().or(self.type_map.as_deref())
    }

    /// Whether a walk of this build needs an object-type map to name anything.
    pub fn needs_type_map(&self) -> bool {
        matches!(self.type_source, ObjectTypeSource::Index(_))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            // No `_hex` siblings on this struct: these are symbol PATHS
            // ("_EPROCESS.ObjectTable"), not addresses. The hex form belongs on
            // the walk result below, where `object_table` really is a u64.
            "object_table": self.object_table,
            "table_code": self.table_code,
            "entry_size": self.entry_size,
            "entries_per_leaf": self.entries_per_leaf,
            "pointers_per_page": self.pointers_per_page,
            "decode": self.decode.as_str(),
            "granted_access": self.granted_access,
            "type_source": self.type_source.as_str(),
            "body_offset": self.body_offset,
            "pointer_size": self.pointer_size,
            "names": self.names.to_json(),
            "needs_type_map": self.needs_type_map(),
            "type_map_slots_read": self.type_map.as_ref().map(|map| map.entries_read()),
            "type_map_unavailable": self.type_map_unavailable,
        })
    }
}

/// Sign-extend a 48-bit address into the canonical 64-bit form.
///
/// x86-64 requires bits 63:48 to replicate bit 47, and every kernel address has
/// bit 47 set. A decoded object pointer that skipped this step is the same byte
/// with sixteen zero bits on top: it compares unequal to every other kernel
/// address in the analysis, and the processor would fault on it.
pub fn canonical_kernel_address(address: u64) -> u64 {
    if address & (1u64 << CANONICAL_SIGN_BIT) != 0 {
        address | !((1u64 << (CANONICAL_SIGN_BIT + 1)) - 1)
    } else {
        address
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One open handle.
#[derive(Debug, Clone)]
pub struct HandleRecord {
    /// The value the process itself would have passed to a Win32 call.
    pub handle_value: u64,
    /// Address of the `_HANDLE_TABLE_ENTRY` this came from, so the decode can
    /// be checked by hand.
    pub entry: u64,
    /// Address of the object's `_OBJECT_HEADER`.
    pub object_header: u64,
    /// Address of the object itself.
    pub body: u64,
    /// The object-manager type: `File`, `Process`, `Key`, `Mutant`, …
    pub object_type: String,
    /// The access mask the handle was granted.
    pub granted_access: Option<u64>,
    /// What the object is called.
    pub name: HandleName,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl HandleRecord {
    /// Serializable form for artifact metadata.
    ///
    /// The object's name appears twice, the same way a loaded module's does.
    /// `name` is the structured form, and it alone tells an object that has no
    /// name apart from one whose name could not be read. `object_name` is the
    /// flat string, present only when there is one.
    ///
    /// The flat alias is not decoration: the handle tables in the product —
    /// `MemoryHandlesPage` and the Process Inspector — resolve the object
    /// column from the key list `['name', 'object_name']`, and `object_name`
    /// was the half of that contract the producer never supplied. Read flat, a
    /// structured envelope yields nothing, and every row of every handle table
    /// printed "not recorded" while the file paths, key paths and target
    /// processes the walk had recovered never reached the examiner (B8-037).
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "handle_value": self.handle_value,
            "entry": self.entry,
            // Exact beside the number: every one of these is a kernel address
            // above 2^53, JSON numbers are IEEE doubles, and an address that
            // reaches a client rounded by a kilobyte names other memory.
            "entry_hex": format!("{:#x}", self.entry),
            "object_header": self.object_header,
            "object_header_hex": format!("{:#x}", self.object_header),
            "body": self.body,
            "body_hex": format!("{:#x}", self.body),
            "object_type": self.object_type,
            "granted_access": self.granted_access,
            "name": self.name.to_json(),
            "object_name": self.name.text(),
            "notes": self.notes,
        })
    }
}

/// One entry or table page the walk declined to use, and why.
#[derive(Debug, Clone)]
pub struct SkippedEntry {
    /// Where it was.
    pub address: u64,
    /// The handle value it would have had, for a level-0 entry.
    pub handle_value: Option<u64>,
    /// Why it was not reported, in the examiner's terms.
    pub reason: String,
}

/// Why a walk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandleStop {
    /// Every reachable entry was examined.
    Exhausted,
    /// A cap fired. The walk stopped; the table did not end.
    CapReached {
        /// What the cap was on.
        what: &'static str,
        /// The cap that fired.
        cap: usize,
    },
    /// The process has no handle table at all, which is a complete answer: it
    /// held no handles.
    NoTable,
}

impl HandleStop {
    /// Whether the table was enumerated end to end.
    pub fn is_complete(&self) -> bool {
        matches!(self, HandleStop::Exhausted | HandleStop::NoTable)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            HandleStop::Exhausted => "exhausted",
            HandleStop::CapReached { .. } => "cap_reached",
            HandleStop::NoTable => "no_table",
        }
    }
}

/// One process's open handles, and everything the walk could not do.
#[derive(Debug, Clone)]
pub struct HandleTable {
    /// The `_EPROCESS` the table belongs to.
    pub process: u64,
    /// Address of the `_HANDLE_TABLE`, or 0 when the process has none.
    pub object_table: u64,
    /// The raw `TableCode`, so its decode can be checked by hand.
    pub table_code: u64,
    /// How many levels of pages the table has.
    pub levels: u32,
    /// The handles, in ascending handle value.
    pub handles: Vec<HandleRecord>,
    /// Entries and pages the walk declined to use, capped by
    /// [`HandleWalkConfig::max_recorded_skips`].
    pub skipped: Vec<SkippedEntry>,
    /// How many were skipped in total. Exact even when the list above was
    /// capped.
    pub skipped_total: usize,
    /// Slots holding no object: handles that were never opened or have been
    /// closed. Ordinary, and counted separately from skips because they are not
    /// evidence of anything having gone wrong.
    pub free_slots: usize,
    /// How many table pages were visited.
    pub tables_visited: usize,
    /// Why the walk ended.
    pub stop: HandleStop,
    /// Whether this walk tried to name the object behind each handle.
    ///
    /// `false` records that [`HandleWalkConfig::resolve_names`] was off, so
    /// every row's name is [`HandleName::Unavailable`] because nothing looked
    /// rather than because a look failed. Without this the two render
    /// identically, and a table of handles to unnameable objects reads like a
    /// damaged image rather than like a cheaper walk.
    pub names_resolved: bool,
}

impl HandleTable {
    /// Whether the whole table was walked and nothing was skipped.
    ///
    /// The question a report must ask before writing "this process did not have
    /// that file open": a walk that stopped early says nothing about the
    /// entries it did not reach.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete() && self.skipped_total == 0
    }

    /// The handles of one object-manager type.
    pub fn of_type<'a>(&'a self, object_type: &'a str) -> impl Iterator<Item = &'a HandleRecord> {
        self.handles
            .iter()
            .filter(move |handle| handle.object_type == object_type)
    }

    /// The handle with a given value, if the process held one.
    pub fn at(&self, handle_value: u64) -> Option<&HandleRecord> {
        self.handles
            .iter()
            .find(|handle| handle.handle_value == handle_value)
    }

    /// Everything a report must declare about this table.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let HandleStop::CapReached { what, cap } = self.stop {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the handle table of the process at {:#x} stopped at its cap of {cap} {what}; \
                     the table continues",
                    self.process
                ),
            ));
        }
        if self.skipped_total > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} entr(ies) of the handle table of the process at {:#x} could not be \
                     decoded, so the objects behind them are not listed",
                    self.skipped_total, self.process
                ),
            ));
        }
        if !self.names_resolved {
            // One statement about the walk, not one per row: nothing looked, so
            // no individual handle's name failed to be read, and saying so per
            // handle would put a million read failures in a report that had
            // none.
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "object names were not resolved for the handle table of the process at {:#x}, \
                     so no row's name column is a statement about what that object is called",
                    self.process
                ),
            ));
            return out;
        }
        // Bounded the same way the skip list is: the per-handle detail is worth
        // having, and a table where every name failed must still not produce a
        // million formatted strings.
        let unnamed: Vec<&HandleRecord> = self
            .handles
            .iter()
            .filter(|handle| handle.name.is_unavailable())
            .collect();
        for handle in unnamed.iter().take(MAX_RECORDED_SKIPS) {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "handle {:#x} of the process at {:#x} refers to a {} whose name could not be \
                     read",
                    handle.handle_value, self.process, handle.object_type
                ),
            ));
        }
        let further = unnamed.len().saturating_sub(MAX_RECORDED_SKIPS);
        if further > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{further} further handle(s) of the process at {:#x} refer to objects whose \
                     names could not be read and are not listed individually",
                    self.process
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "process_hex": format!("{:#x}", self.process),
            "object_table": self.object_table,
            "object_table_hex": format!("{:#x}", self.object_table),
            "table_code": self.table_code,
            // `TableCode` is the table's kernel address with the level count in
            // its low bits, so it is a pointer and rounds like one. It is
            // published so the level decode can be checked by hand, and a
            // rounded value cannot be checked against anything.
            "table_code_hex": format!("{:#x}", self.table_code),
            "levels": self.levels,
            "handles": self.handles.iter().map(HandleRecord::to_json).collect::<Vec<_>>(),
            "handle_count": self.handles.len(),
            "free_slots": self.free_slots,
            "tables_visited": self.tables_visited,
            "names_resolved": self.names_resolved,
            "skipped_total": self.skipped_total,
            "skipped": self
                .skipped
                .iter()
                .map(|entry| serde_json::json!({
                    "address": entry.address,
                    "address_hex": format!("{:#x}", entry.address),
                    "handle_value": entry.handle_value,
                    "reason": entry.reason,
                }))
                .collect::<Vec<_>>(),
            "stop": self.stop.as_str(),
            "complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Caps and inputs for one handle-table walk.
#[derive(Debug, Clone)]
pub struct HandleWalkConfig {
    /// Ceiling on handles returned.
    pub max_handles: usize,
    /// Ceiling on table pages visited.
    pub max_tables: usize,
    /// Ceiling on individually recorded skips.
    pub max_recorded_skips: usize,
    /// An object-type map supplied by the caller, overriding the one
    /// [`HandleSymbols::from_profile`] read from the image.
    ///
    /// `None` — the default — is not "no map": the symbols carry the kernel's
    /// own table on every build that needs one. This exists for an examiner who
    /// has a table from elsewhere and wants it used instead.
    pub type_map: Option<Arc<ObjectTypeMap>>,
    /// Whether to name the object behind each handle.
    ///
    /// Naming costs several extra reads per handle — a file handle needs its
    /// device object's header as well — so a caller that only wants the shape
    /// of the table can turn it off. Names then read
    /// [`HandleName::Unavailable`] rather than [`HandleName::Unnamed`], because
    /// not having looked is not the same as having looked and found nothing.
    pub resolve_names: bool,
}

impl Default for HandleWalkConfig {
    fn default() -> Self {
        Self {
            max_handles: MAX_HANDLES,
            max_tables: MAX_HANDLE_TABLES,
            max_recorded_skips: MAX_RECORDED_SKIPS,
            type_map: None,
            resolve_names: true,
        }
    }
}

// ── The walk ────────────────────────────────────────────────────────────────

/// One table page still to be walked.
struct Pending {
    /// Where the page starts.
    page: u64,
    /// How many levels of pointers are below it.
    level: u32,
    /// Index of the first level-0 page beneath it, which is what makes handle
    /// values positional rather than sequential.
    leaf_base: u64,
}

/// Walk one process's handle table.
///
/// `process` is the address of an `_EPROCESS` in the **kernel** address space.
///
/// # Errors
///
/// Only for failures that make the whole walk meaningless: a build whose layout
/// the symbols cannot describe, an `_EPROCESS` whose `ObjectTable` cannot be
/// read, a `TableCode` that is not one, or a build that needs an object-type
/// map where neither the image nor the caller could produce one. An entry that
/// did not decode is not an error — it is counted in [`HandleTable::skipped`].
///
/// The last of those is a real refusal and not a routine one: the map comes off
/// the image in [`HandleSymbols::from_profile`], so reaching it means the
/// kernel's own object-type table was unreadable, and the message says which
/// symbol or read failed.
pub fn list_handles(
    profile: &WindowsProfile,
    symbols: &HandleSymbols,
    process: u64,
    config: &HandleWalkConfig,
) -> Result<HandleTable, HandleError> {
    if symbols.needs_type_map() && symbols.effective_type_map(config).is_none() {
        return Err(HandleError::unsupported(format!(
            "this build stores an object's kind as an index into the kernel's object-type table \
             and that table could not be read from this image, so every handle's type would be \
             blank — which reads as a machine full of handles to nothing rather than as a check \
             that was not made: {}",
            symbols.type_map_unavailable.as_deref().unwrap_or(
                "no reason was recorded, which itself means the table was never looked for"
            )
        )));
    }

    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let eprocess = reader.object(process, TYPE_EPROCESS)?;
    let object_table = eprocess.pointer(&symbols.object_table)?;

    let mut table = HandleTable {
        process,
        object_table,
        table_code: 0,
        levels: 0,
        handles: Vec::new(),
        skipped: Vec::new(),
        skipped_total: 0,
        free_slots: 0,
        tables_visited: 0,
        stop: HandleStop::NoTable,
        names_resolved: config.resolve_names,
    };
    if object_table == 0 {
        // A process that has exited has had its handle table torn down. That is
        // a complete answer — it held no handles — and it is distinguishable
        // from a failed walk because `stop` says so.
        return Ok(table);
    }

    let handle_table = reader.object(object_table, TYPE_HANDLE_TABLE)?;
    let table_code = handle_table
        .int(&symbols.table_code)?
        .as_u64()
        .ok_or_else(|| {
            SymbolError::malformed(format!(
                "'{TYPE_HANDLE_TABLE}.{}' is negative, which is not a table code",
                symbols.table_code
            ))
        })?;
    table.table_code = table_code;

    let levels = u32::try_from(table_code & LEVEL_MASK).unwrap_or(u32::MAX);
    if levels > MAX_HANDLE_TABLE_LEVELS {
        return Err(HandleError::ImplausibleTableCode {
            process,
            table_code,
            levels,
        });
    }
    table.levels = levels;
    let root = table_code & !LEVEL_MASK;
    if root == 0 {
        return Ok(table);
    }
    table.stop = HandleStop::Exhausted;

    // Depth first, left to right, over an explicit stack. A recursive walk over
    // pointers taken from an image overflows the host's stack on a corrupt
    // table, and a crash is not a finding.
    let mut stack = vec![Pending {
        page: root,
        level: levels,
        leaf_base: 0,
    }];
    let mut seen: HashSet<u64> = HashSet::new();

    'walk: while let Some(pending) = stack.pop() {
        if table.tables_visited >= config.max_tables {
            table.stop = HandleStop::CapReached {
                what: "table page(s)",
                cap: config.max_tables,
            };
            break;
        }
        // Cycle safety: a page reached twice means the table does not
        // terminate, and continuing would report the same handles forever.
        if !seen.insert(pending.page) {
            record_skip(
                &mut table,
                config,
                pending.page,
                None,
                "this table page was already walked, so the table contains a cycle".to_string(),
            );
            continue;
        }
        table.tables_visited += 1;

        // One probe read. A page that is entirely absent from the acquisition
        // would otherwise produce one failure per entry, all saying the same
        // thing, and drown the skip list in noise.
        if let Err(err) = reader.read_bytes(pending.page, 1) {
            record_skip(
                &mut table,
                config,
                pending.page,
                None,
                format!(
                    "the level-{} table page at {:#x} was not captured, so the handles in it are \
                     not listed: {err}",
                    pending.level, pending.page
                ),
            );
            continue;
        }

        if pending.level == 0 {
            for index in 0..symbols.entries_per_leaf {
                if table.handles.len() >= config.max_handles {
                    table.stop = HandleStop::CapReached {
                        what: "handle(s)",
                        cap: config.max_handles,
                    };
                    break 'walk;
                }
                let Some(entry_address) = index
                    .checked_mul(symbols.entry_size)
                    .and_then(|offset| pending.page.checked_add(offset))
                else {
                    break;
                };
                // Positional, not sequential: the slot's place in the tree is
                // the handle value, so a gap does not renumber what follows it.
                let Some(handle_value) = pending
                    .leaf_base
                    .checked_mul(symbols.entries_per_leaf)
                    .and_then(|base| base.checked_add(index))
                    .and_then(|position| position.checked_mul(HANDLE_VALUE_STRIDE))
                else {
                    break;
                };

                match examine(&reader, symbols, config, entry_address, handle_value) {
                    Examined::Free => table.free_slots += 1,
                    Examined::Handle(record) => table.handles.push(*record),
                    Examined::Skipped(reason) => record_skip(
                        &mut table,
                        config,
                        entry_address,
                        Some(handle_value),
                        reason,
                    ),
                }
            }
            continue;
        }

        // A mid-level page: every slot is a pointer to a page one level down,
        // and every slot counts towards the handle numbering whether or not it
        // is null.
        let Some(leaves_per_slot) = symbols.pointers_per_page.checked_pow(pending.level - 1) else {
            record_skip(
                &mut table,
                config,
                pending.page,
                None,
                format!(
                    "a level-{} table would hold more entries than a 64-bit handle value can \
                     number",
                    pending.level
                ),
            );
            continue;
        };
        let mut children = Vec::new();
        for slot in 0..symbols.pointers_per_page {
            let Some(at) = slot
                .checked_mul(symbols.pointer_size)
                .and_then(|offset| pending.page.checked_add(offset))
            else {
                break;
            };
            let child = match reader.read_pointer_at(at) {
                Ok(0) => continue,
                Ok(child) => child,
                Err(err) => {
                    record_skip(
                        &mut table,
                        config,
                        at,
                        None,
                        format!("a table pointer at {at:#x} could not be read: {err}"),
                    );
                    continue;
                }
            };
            let Some(leaf_base) = slot
                .checked_mul(leaves_per_slot)
                .and_then(|offset| pending.leaf_base.checked_add(offset))
            else {
                break;
            };
            children.push(Pending {
                page: child,
                level: pending.level - 1,
                leaf_base,
            });
        }
        // Pushed in reverse so the lowest-numbered child pops first, which
        // keeps the handles in ascending order.
        children.reverse();
        stack.extend(children);
    }

    Ok(table)
}

/// Record an entry the walk declined to use, keeping the list bounded without
/// losing the count.
fn record_skip(
    table: &mut HandleTable,
    config: &HandleWalkConfig,
    address: u64,
    handle_value: Option<u64>,
    reason: String,
) {
    table.skipped_total += 1;
    if table.skipped.len() < config.max_recorded_skips {
        table.skipped.push(SkippedEntry {
            address,
            handle_value,
            reason,
        });
    }
}

/// What one table slot turned out to be.
enum Examined {
    /// No object: a handle that was never opened or has been closed.
    Free,
    /// A handle. Boxed because the record is far larger than the other arms.
    Handle(Box<HandleRecord>),
    /// Something that is not a handle, and why.
    Skipped(String),
}

/// Decode one `_HANDLE_TABLE_ENTRY`.
fn examine(
    reader: &StructReader,
    symbols: &HandleSymbols,
    config: &HandleWalkConfig,
    entry_address: u64,
    handle_value: u64,
) -> Examined {
    let entry = match reader.object(entry_address, TYPE_HANDLE_TABLE_ENTRY) {
        Ok(entry) => entry,
        Err(err) => return Examined::Skipped(err.to_string()),
    };

    let raw = |path: &str| -> Result<u64, String> {
        entry
            .int(path)
            .map_err(|err| format!("'{path}' could not be read: {err}"))?
            .as_u64()
            .ok_or_else(|| format!("'{path}' is negative, which is not an address"))
    };

    let object_header = match &symbols.decode {
        HandleDecode::FastRef { path, mask } => match raw(path) {
            Ok(0) => return Examined::Free,
            Ok(value) => value & !mask,
            Err(detail) => return Examined::Skipped(detail),
        },
        HandleDecode::InfoTable { path, mask } => match raw(path) {
            Ok(0) => return Examined::Free,
            Ok(value) => value & !mask,
            Err(detail) => return Examined::Skipped(detail),
        },
        HandleDecode::PointerBits { path } => match raw(path) {
            Ok(0) => return Examined::Free,
            Ok(bits) => {
                // Checked *before* the shift, not after: `checked_shl` guards
                // the shift amount and not the value, so a symbol table
                // declaring a wider field would silently drop the top bits and
                // yield an address 16 TiB away that still parses.
                if bits >> OBJECT_POINTER_BITS != 0 {
                    return Examined::Skipped(format!(
                        "'{path}' holds {bits:#x}, which is wider than the \
                         {OBJECT_POINTER_BITS}-bit field this encoding uses"
                    ));
                }
                // The field is 44 bits wide and the shift makes it 48, so bit
                // 47 is the sign bit: a kernel address is that number with bits
                // 63:48 copied from it.
                canonical_kernel_address(bits << OBJECT_POINTER_SHIFT)
            }
            Err(detail) => return Examined::Skipped(detail),
        },
    };

    if object_header == 0 {
        return Examined::Free;
    }
    if !is_canonical(object_header, symbols.pointer_size as u8) {
        return Examined::Skipped(format!(
            "the entry decodes to {object_header:#x}, which is not a canonical address"
        ));
    }

    let header = match reader.object(object_header, TYPE_OBJECT_HEADER) {
        Ok(header) => header,
        Err(err) => return Examined::Skipped(err.to_string()),
    };

    let object_type = match &symbols.type_source {
        ObjectTypeSource::Index(path) => {
            let stored = match header.int(path) {
                Ok(value) => match value.as_u64() {
                    Some(value) => value,
                    None => {
                        return Examined::Skipped(format!(
                            "'{path}' is negative, which is not a type index"
                        ))
                    }
                },
                Err(err) => return Examined::Skipped(format!("'{path}' could not be read: {err}")),
            };
            let Some(map) = symbols.effective_type_map(config) else {
                // Refused before the walk starts, so this cannot fire; skipping
                // beats reporting an object of unknown kind.
                return Examined::Skipped(
                    "no object-type table was available to resolve the entry's type".to_string(),
                );
            };
            match map.name_for(object_header, stored) {
                Some(name) => name.to_string(),
                None => {
                    return Examined::Skipped(format!(
                        "the object header at {object_header:#x} carries a type index the \
                         kernel's object-type table does not have, so the entry is not a handle \
                         to anything this image describes"
                    ))
                }
            }
        }
        ObjectTypeSource::Pointer(path) => {
            let object_type =
                match header.follow(path) {
                    Ok(Some(object_type)) => object_type,
                    Ok(None) => return Examined::Skipped(
                        "the object header names a null object type, so the slot does not hold an \
                         object"
                            .to_string(),
                    ),
                    Err(err) => {
                        return Examined::Skipped(format!("'{path}' could not be followed: {err}"))
                    }
                };
            match unicode_string(&object_type, "Name") {
                Ok(Some(name)) => name,
                Ok(None) => {
                    return Examined::Skipped(
                        "the object type this entry names has an empty name, which no real object \
                         type has"
                            .to_string(),
                    )
                }
                Err(err) => {
                    return Examined::Skipped(format!(
                        "the object type at {:#x} could not be named: {err}",
                        object_type.address()
                    ))
                }
            }
        }
    };

    let mut notes = Vec::new();
    let granted_access = match entry.int(&symbols.granted_access) {
        Ok(value) => value.as_u64(),
        Err(err) => {
            notes.push(format!(
                "'{}' could not be read: {err}",
                symbols.granted_access
            ));
            None
        }
    };

    let Some(body) = object_header.checked_add(symbols.body_offset) else {
        return Examined::Skipped(format!(
            "the object of the header at {object_header:#x} would lie past the end of the address \
             space"
        ));
    };

    let name = if config.resolve_names {
        object_name(reader, &symbols.names, object_header, &object_type)
    } else {
        HandleName::Unavailable(
            "object names were not resolved for this walk, so this is not a claim that the object \
             has none"
                .to_string(),
        )
    };

    Examined::Handle(Box::new(HandleRecord {
        handle_value,
        entry: entry_address,
        object_header,
        body,
        object_type,
        granted_access,
        name,
        notes,
    }))
}

#[cfg(test)]
#[path = "handles_test_support.rs"]
pub(crate) mod test_support;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::handles::test_support::{
        win10_image, win10_isf, win10_profile, win10_profile_without, win10_type_map, xp_profile,
        WIN10_EPROCESS, WIN10_FILE_HEADER, WIN10_HANDLE_TABLE, WIN10_MUTANT_HEADER, XP_EPROCESS,
        XP_MUTANT_HEADER,
    };
    use crate::poolscan::test_support::{profile, table};
    use seance_memory::Architecture;

    fn win10_config() -> HandleWalkConfig {
        HandleWalkConfig {
            type_map: Some(Arc::new(win10_type_map())),
            ..HandleWalkConfig::default()
        }
    }

    fn win10_walk() -> HandleTable {
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        list_handles(&profile, &symbols, WIN10_EPROCESS, &win10_config()).expect("the table walks")
    }

    #[test]
    fn a_sign_extended_address_is_the_one_the_processor_would_accept() {
        // Bit 47 clear: a user-space address, unchanged.
        assert_eq!(
            canonical_kernel_address(0x0000_7FFF_FFFF_F000),
            0x0000_7FFF_FFFF_F000
        );
        // Bit 47 set: a kernel address, which is not that number.
        assert_eq!(
            canonical_kernel_address(0x0000_8000_2980_0000),
            0xFFFF_8000_2980_0000
        );
        assert_eq!(canonical_kernel_address(0x0000_FFFF_FFFF_FFFF), u64::MAX);
        assert!(is_canonical(
            canonical_kernel_address(0x0000_8000_2980_0000),
            8
        ));
    }

    #[test]
    fn the_layout_of_a_modern_build_resolves_to_the_shifted_field() {
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        assert!(matches!(symbols.decode, HandleDecode::PointerBits { .. }));
        assert_eq!(symbols.entry_size, 16);
        assert_eq!(symbols.entries_per_leaf, 256);
        assert_eq!(symbols.pointers_per_page, 512);
        assert!(symbols.needs_type_map());
        assert_eq!(symbols.granted_access, "GrantedAccessBits");
    }

    #[test]
    fn the_layout_of_windows_xp_resolves_to_the_fast_reference() {
        let profile = xp_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        assert_eq!(
            symbols.decode,
            HandleDecode::FastRef {
                path: "Object".to_string(),
                mask: 7,
            }
        );
        assert_eq!(symbols.entries_per_leaf, 512);
        assert!(
            !symbols.needs_type_map(),
            "XP object headers point straight at their type"
        );
    }

    #[test]
    fn handle_values_come_from_position_in_the_tree_and_not_from_arrival_order() {
        // The fixture's level-1 slot 0 is null and slot 1 holds the only leaf,
        // so the first handle is 256 entries into the numbering rather than
        // handle 0. Numbering by arrival would call it 0 and every handle in
        // the report would be wrong.
        let table = win10_walk();
        assert_eq!(table.levels, 1);
        let values: Vec<u64> = table.handles.iter().map(|h| h.handle_value).collect();
        assert_eq!(values, vec![1024, 1032, 1036, 1040, 1044]);
    }

    #[test]
    fn every_kind_of_object_is_named_the_way_its_type_requires() {
        let table = win10_walk();
        let named: Vec<(&str, Option<&str>)> = table
            .handles
            .iter()
            .map(|h| (h.object_type.as_str(), h.name.text()))
            .collect();
        assert_eq!(
            named,
            vec![
                ("Mutant", Some("\\BaseNamedObjects\\Mutex1")),
                (
                    "File",
                    Some("\\Device\\HarddiskVolume2\\Windows\\notepad.exe")
                ),
                ("Key", Some("Software\\Run")),
                ("Process", Some("explorer.exe Pid 1234")),
                ("Thread", Some("Tid 8 Pid 4")),
            ]
        );
    }

    #[test]
    fn the_granted_access_mask_is_carried_so_a_dangerous_handle_can_be_recognised() {
        let table = win10_walk();
        let process = table
            .of_type("Process")
            .next()
            .expect("the fixture holds a process handle");
        assert_eq!(process.granted_access, Some(0x001F_FFFF));
        assert_eq!(
            table.at(1024).and_then(|h| h.granted_access),
            Some(0x001F_0001)
        );
    }

    #[test]
    fn an_empty_slot_is_counted_as_free_rather_than_as_a_failure() {
        let table = win10_walk();
        // 256 entries in the leaf: five handles, one whose type does not
        // resolve and one whose header was never captured. The rest are free.
        assert_eq!(table.handles.len(), 5);
        assert_eq!(table.free_slots, 249);
    }

    #[test]
    fn an_entry_whose_type_index_is_not_in_the_kernels_table_is_skipped_and_counted() {
        let table = win10_walk();
        assert!(
            table
                .skipped
                .iter()
                .any(|entry| entry.reason.contains("object-type table does not have")),
            "{:?}",
            table.skipped
        );
    }

    #[test]
    fn an_entry_pointing_outside_the_acquisition_is_skipped_rather_than_invented() {
        let table = win10_walk();
        assert!(
            table
                .skipped
                .iter()
                .any(|entry| entry.handle_value == Some(1052)),
            "{:?}",
            table.skipped
        );
        assert_eq!(table.skipped_total, 2);
        assert!(
            !table.is_complete(),
            "a table with undecodable entries is not a complete one"
        );
        assert!(!table.incomplete().is_empty());
    }

    #[test]
    fn a_process_with_no_handle_table_is_a_complete_answer_and_not_a_failure() {
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        // Address 0 is a page of zeros, so `ObjectTable` reads as null.
        let table = list_handles(&profile, &symbols, 0, &win10_config()).expect("the walk runs");
        assert_eq!(table.stop, HandleStop::NoTable);
        assert!(table.handles.is_empty());
        assert!(table.is_complete());
        assert!(table.incomplete().is_empty());
    }

    /// A profile over the fixture with the table code overwritten.
    fn win10_profile_with_table_code(table_code: u64) -> WindowsProfile {
        let mut image = win10_image();
        image.put_u64(WIN10_HANDLE_TABLE + 8, table_code);
        profile(
            image.layer(),
            table(&win10_isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    #[test]
    fn a_table_code_claiming_more_levels_than_windows_builds_is_refused() {
        let profile = win10_profile_with_table_code(0x3000 | 5);
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let err = list_handles(&profile, &symbols, WIN10_EPROCESS, &win10_config())
            .expect_err("an impossible table code is refused");
        assert!(matches!(
            err,
            HandleError::ImplausibleTableCode { levels: 5, .. }
        ));
        assert_eq!(err.class(), "implausible_table_code");
    }

    #[test]
    fn a_modern_build_walks_its_handle_table_with_the_default_configuration() {
        // Every build from Windows 8 on stores an object's kind as an index
        // into the kernel's object-type table. Leaving that table for the
        // caller to supply refused the stage for every process on every modern
        // image — an honest failure, and a total loss of handle evidence on the
        // images that matter. The table is read from the image with the rest of
        // the layout instead.
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        assert!(symbols.needs_type_map());
        assert!(
            symbols.type_map.is_some(),
            "the kernel's own table, read at construction"
        );
        assert!(symbols.type_map_unavailable.is_none());

        let table = list_handles(
            &profile,
            &symbols,
            WIN10_EPROCESS,
            &HandleWalkConfig::default(),
        )
        .expect("a modern build needs nothing supplied by hand");
        assert_eq!(table.handles.len(), 5);
        assert!(
            table.handles.iter().all(|h| !h.object_type.is_empty()),
            "every row is typed, which is what the table is for"
        );
    }

    #[test]
    fn a_build_whose_object_type_table_cannot_be_read_is_refused_and_says_which_symbol_is_missing()
    {
        // The refusal must still exist and must still be reachable: an image
        // whose kernel does not name the type table cannot type a single
        // handle, and typeless rows read as a machine full of handles to
        // nothing.
        let isf = win10_isf()
            .replace("\"ObTypeIndexTable\"", "\"NotTheTypeIndexTable\"")
            .replace("\"ObpObjectTypes\"", "\"NotObpObjectTypes\"");
        let profile = profile(
            win10_image().layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout still resolves");
        assert!(symbols.needs_type_map());
        assert!(symbols.type_map.is_none());
        let reason = symbols
            .type_map_unavailable
            .as_deref()
            .expect("the reason is recorded on the symbols");
        assert!(reason.contains("ObTypeIndexTable"), "{reason}");

        let err = list_handles(
            &profile,
            &symbols,
            WIN10_EPROCESS,
            &HandleWalkConfig::default(),
        )
        .expect_err("a build that needs a type table and has none is refused");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("object-type table"), "{err}");
        assert!(
            err.to_string().contains("ObTypeIndexTable"),
            "the refusal names what was missing: {err}"
        );
    }

    #[test]
    fn a_modern_build_whose_header_cookie_is_missing_refuses_rather_than_naming_wrong_types() {
        // Reading the type table off the image is what makes the stage run at
        // all — and a table read on a Windows 10 build without the per-boot
        // cookie cannot resolve anything: the stored index is mixed with the
        // header's own address, so looking it up unmixed lands on some other
        // type about one row in five and on none the rest. A handle to a File
        // reported as a Key, in a list that otherwise reads as sound, is worse
        // than no list.
        let isf = win10_isf().replace("\"ObHeaderCookie\"", "\"NotObHeaderCookie\"");
        let profile = profile(
            win10_image().layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout still resolves");
        assert!(symbols.needs_type_map());
        assert!(
            symbols.type_map.is_none(),
            "a table that cannot be resolved is not a table this build may use"
        );
        let reason = symbols
            .type_map_unavailable
            .as_deref()
            .expect("the reason is recorded on the symbols");
        assert!(reason.contains("ObHeaderCookie"), "{reason}");

        let err = list_handles(
            &profile,
            &symbols,
            WIN10_EPROCESS,
            &HandleWalkConfig::default(),
        )
        .expect_err("a mixed index with no cookie to unmix it is refused");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("ObHeaderCookie"), "{err}");
    }

    #[test]
    fn a_type_table_supplied_by_hand_overrides_the_one_read_from_the_image() {
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let supplied = Arc::new(win10_type_map());
        let config = HandleWalkConfig {
            type_map: Some(Arc::clone(&supplied)),
            ..HandleWalkConfig::default()
        };
        assert!(std::ptr::eq(
            symbols
                .effective_type_map(&config)
                .expect("a table is available"),
            supplied.as_ref()
        ));
    }

    #[test]
    fn a_cap_shorter_than_the_table_stops_the_walk_and_says_the_table_continues() {
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let table = list_handles(
            &profile,
            &symbols,
            WIN10_EPROCESS,
            &HandleWalkConfig {
                max_handles: 2,
                ..win10_config()
            },
        )
        .expect("the table walks");
        assert_eq!(table.handles.len(), 2);
        assert!(matches!(table.stop, HandleStop::CapReached { .. }));
        assert!(!table.is_complete());
        assert!(!table.incomplete().is_empty());
    }

    #[test]
    fn skipping_names_does_not_claim_the_objects_are_unnamed() {
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let table = list_handles(
            &profile,
            &symbols,
            WIN10_EPROCESS,
            &HandleWalkConfig {
                resolve_names: false,
                ..win10_config()
            },
        )
        .expect("the table walks");
        assert!(table.handles.iter().all(|h| h.name.is_unavailable()));
        assert_eq!(table.handles.len(), 5);
        assert!(!table.names_resolved);
    }

    #[test]
    fn a_walk_that_did_not_look_for_names_says_that_once_and_not_once_per_handle() {
        // Every row's name is unavailable because nothing looked. Reporting
        // that as one read failure per handle would put five read failures in a
        // report that had none, and on a real process it would put a million.
        let profile = win10_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let table = list_handles(
            &profile,
            &symbols,
            WIN10_EPROCESS,
            &HandleWalkConfig {
                resolve_names: false,
                ..win10_config()
            },
        )
        .expect("the table walks");
        let names: Vec<String> = table
            .incomplete()
            .iter()
            .map(|entry| entry.detail.clone())
            .filter(|detail| detail.contains("name"))
            .collect();
        assert_eq!(names.len(), 1, "{names:?}");
        assert!(
            names[0].contains("not resolved"),
            "the reason must say nothing looked: {}",
            names[0]
        );
        assert!(!names[0].contains("could not be read"));
        assert_eq!(table.to_json()["names_resolved"], false);
    }

    #[test]
    fn the_table_code_carries_its_exact_form_beside_the_rounded_number() {
        // `TableCode` is the handle table's kernel address with the level count
        // in its low bits. It is published so an examiner can redo the level
        // decode by hand, and it rounds like every other pointer: parsed as an
        // IEEE double, a value above 2^53 is not the value that was read, and a
        // level decoded from it can come out wrong. The number stays for the
        // consumers that read it; the string is what may be quoted.
        let table = win10_walk();
        let json = table.to_json();
        assert_eq!(
            json["table_code_hex"],
            format!("{:#x}", table.table_code),
            "the exact form of TableCode must travel with it"
        );
        assert_eq!(
            json["object_table_hex"],
            format!("{:#x}", table.object_table)
        );
        assert_eq!(json["process_hex"], format!("{:#x}", table.process));
    }

    #[test]
    fn a_walk_that_did_look_reports_the_names_it_could_not_read_one_by_one() {
        let table = win10_walk();
        assert!(table.names_resolved);
        assert!(
            table
                .incomplete()
                .iter()
                .all(|entry| !entry.detail.contains("were not resolved")),
            "a walk that resolved names must not claim it did not"
        );
    }

    #[test]
    fn a_single_level_table_on_windows_xp_numbers_its_handles_from_zero() {
        let profile = xp_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let table = list_handles(
            &profile,
            &symbols,
            XP_EPROCESS,
            &HandleWalkConfig::default(),
        )
        .expect("the table walks");
        assert_eq!(table.levels, 0);
        assert_eq!(table.handles.len(), 1);
        let handle = &table.handles[0];
        assert_eq!(handle.handle_value, 0);
        assert_eq!(handle.object_type, "Mutant");
        assert_eq!(handle.granted_access, Some(0x001F_0003));
        assert_eq!(handle.name.text(), Some("\\Sessions\\1\\Windows"));
        assert!(table.is_complete());
    }

    /// The handle tables an examiner actually opens resolve the object column
    /// from the key list `['name', 'object_name']`, and `object_name` was the
    /// half of that contract this producer never supplied — so a consumer
    /// reading the column flat found nothing on either key and every row
    /// printed "not recorded" (B8-037).
    #[test]
    fn a_named_handle_publishes_its_name_as_a_flat_string_too() {
        let profile = xp_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let table = list_handles(
            &profile,
            &symbols,
            XP_EPROCESS,
            &HandleWalkConfig::default(),
        )
        .expect("the table walks");
        let json = table.to_json();
        let row = &json["handles"][0];
        assert_eq!(
            row["object_name"].as_str(),
            Some("\\Sessions\\1\\Windows"),
            "the flat alias is the form the product's handle tables read"
        );
        // The structured form stays beside it: it alone separates an object
        // that has no name from one whose name could not be read.
        assert_eq!(row["name"]["kind"], "name");
        assert_eq!(row["name"]["name"], "\\Sessions\\1\\Windows");
    }

    /// An object that genuinely has no name, and one whose name could not be
    /// read, both leave the flat alias null. The flat form must never invent a
    /// string for either, and the structured form is what keeps them apart.
    #[test]
    fn an_unnamed_or_unreadable_object_leaves_the_flat_alias_null() {
        let record = |name: HandleName| HandleRecord {
            handle_value: 4,
            entry: 0xFFFF_8000_0000_0000,
            object_header: 0xFFFF_8000_0000_0100,
            body: 0xFFFF_8000_0000_0130,
            object_type: "Event".to_string(),
            granted_access: Some(0x1F_0003),
            name,
            notes: Vec::new(),
        };

        let unnamed = record(HandleName::Unnamed).to_json();
        assert!(unnamed["object_name"].is_null());
        assert_eq!(unnamed["name"]["kind"], "unnamed");

        let unavailable = record(HandleName::Unavailable(
            "the page was not acquired".to_string(),
        ))
        .to_json();
        assert!(unavailable["object_name"].is_null());
        assert_eq!(unavailable["name"]["kind"], "unavailable");
        assert_eq!(unavailable["name"]["detail"], "the page was not acquired");
    }

    #[test]
    fn the_fast_reference_bits_are_masked_off_before_the_object_header_is_read() {
        // The fixture stores the header address with its low bits set; without
        // the mask the header would be read three bytes late and its type
        // pointer would be garbage.
        let profile = xp_profile();
        let symbols = HandleSymbols::from_profile(&profile).expect("the layout resolves");
        let table = list_handles(
            &profile,
            &symbols,
            XP_EPROCESS,
            &HandleWalkConfig::default(),
        )
        .expect("the table walks");
        assert_eq!(table.handles[0].object_header, XP_MUTANT_HEADER);
        assert_eq!(table.handles[0].object_header % 8, 0);
    }

    #[test]
    fn a_build_without_a_handle_table_entry_type_is_refused_by_name() {
        let profile = win10_profile_without(&["_HANDLE_TABLE_ENTRY"]);
        let err = HandleSymbols::from_profile(&profile).expect_err("the build is refused");
        assert_eq!(err.class(), "required_not_declared");

        // Fatal is right — there is no stride, so there is no second entry to
        // read. What the examiner gets has to say more than "unknown type": the
        // stage that stopped, the name that was looked for, and what stopping
        // cost. A bare SymbolError through a transparent variant says only the
        // second, which is what made the original of this class undiagnosable.
        let text = err.to_string();
        assert!(text.contains("_HANDLE_TABLE_ENTRY"), "{text}");
        assert!(text.contains(STAGE_HANDLES.key), "{text}");
        assert!(
            text.contains("no entry beyond the first can be located"),
            "the refusal must say what it cost: {text}"
        );
    }

    #[test]
    fn a_walk_records_which_object_header_each_row_came_from() {
        // Every claim in the table is checkable by hand only if the addresses
        // it was read from travel with it.
        let table = win10_walk();
        assert_eq!(table.handles[0].object_header, WIN10_MUTANT_HEADER);
        assert_eq!(table.handles[1].object_header, WIN10_FILE_HEADER);
        assert_eq!(
            table.handles[1].body,
            WIN10_FILE_HEADER + 48,
            "the body sits at the offset the symbol table declares"
        );
        assert_eq!(table.handles[0].entry, 0x4000);
    }
}
