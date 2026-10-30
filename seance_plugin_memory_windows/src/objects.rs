//! File objects, mutants and symbolic links recovered from the pool.
//!
//! Three object types whose *existence* is the evidence, and which no list walk
//! reaches:
//!
//! * **`_FILE_OBJECT`** (`Fil\xe5`, `File`) — one per open instance of a file.
//!   Sweeping them answers "which files were open when the plug was pulled",
//!   including files whose handles were closed shortly before acquisition and
//!   whose allocations have not yet been reused. A path here is not proof the
//!   file still exists on disk; it is proof the kernel had an object for it.
//! * **`_KMUTANT`** (`Mut\xe1`, `Muta`) — named mutants are how a great deal of
//!   malware avoids running twice, so the *name* is often the most identifying
//!   string in an image. An unnamed mutant is ordinary and says nothing.
//! * **`_OBJECT_SYMBOLIC_LINK`** (`Sym\xe2`, `Symb`) — the object manager's
//!   device-name aliases: `\??\C:` to `\Device\HarddiskVolume2`, and the
//!   `\GLOBAL??` entries a driver creates for itself. They are what turns a
//!   device path in some other finding into a drive letter an examiner
//!   recognises.
//!
//! # One sweep, not three
//!
//! All six tags go into a single [`crate::poolscan::pool_scan`] pass. Three
//! passes would read the whole image three times and, worse, could disagree
//! with each other about which bytes were readable. The objects are split by
//! the type each constraint decoded them as, afterwards.
//!
//! # What a wrong answer looks like
//!
//! The dangerous failure here is a *plausible* one. A four-byte tag match is
//! common by accident, and an allocation decoded at the wrong offset yields a
//! `_FILE_OBJECT` whose `FileName` points at bytes that decode as UTF-16 — a
//! file path that was never on the machine, in a table that reads exactly like
//! a correct one. Everything that guards against that lives in `poolscan`: the
//! structural checks, the object-manager type comparison, and the rule that one
//! allocation yields at most one object. This module's job is to ask for those
//! guards and to report honestly when one of them could not be applied — an
//! object admitted without its type being checked says so on its own row.
//!
//! # A name that is absent and a name that could not be read
//!
//! Kept apart everywhere, because they support opposite conclusions. A mutant
//! with no name is unremarkable; a mutant whose name was in a page that was
//! never acquired is a gap in the evidence. [`crate::handles::HandleName`] and
//! [`crate::modules::NameField`] both carry the distinction, and neither of
//! them is ever collapsed to an empty string here.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{Obj, ObjError, StructReader};
use seance_memory::{Incomplete, MemoryLayer};
use seance_symbols::SymbolError;

use crate::handles::token::first_member;
use crate::handles::{object_name, HandleName, NameSymbols};
use crate::modules::NameField;
use crate::poolscan::{
    builtin_constraints_for, pool_scan, unicode_string, ObjectTypeMap, PoolError, PoolObject,
    PoolScanConfig, PoolScanOutcome, PoolSymbols, ScanSpace,
};
use crate::profile::WindowsProfile;

/// The kernel's open-file object.
pub const TYPE_FILE_OBJECT: &str = "_FILE_OBJECT";

/// The kernel's mutant (what user mode calls a mutex).
pub const TYPE_KMUTANT: &str = "_KMUTANT";

/// The object manager's symbolic link.
pub const TYPE_SYMBOLIC_LINK: &str = "_OBJECT_SYMBOLIC_LINK";

/// Pool tag for a protected file object, as builds before Windows 8 wrote it.
pub const TAG_FILE_PROTECTED: [u8; 4] = *b"Fil\xe5";

/// Pool tag for a file object, as Windows 8 and later write it.
pub const TAG_FILE: [u8; 4] = *b"File";

/// Pool tag for a protected mutant.
pub const TAG_MUTANT_PROTECTED: [u8; 4] = *b"Mut\xe1";

/// Pool tag for a mutant.
pub const TAG_MUTANT: [u8; 4] = *b"Muta";

/// Pool tag for a protected symbolic link.
pub const TAG_SYMLINK_PROTECTED: [u8; 4] = *b"Sym\xe2";

/// Pool tag for a symbolic link.
pub const TAG_SYMLINK: [u8; 4] = *b"Symb";

/// The object-manager type name a file object carries.
pub const OBJECT_TYPE_FILE: &str = "File";

/// Ceiling on individually recorded notes. The *count* stays exact.
pub const MAX_RECORDED_NOTES: usize = 256;

/// Ceiling on objects of one kind this stage will report.
///
/// A busy machine has tens of thousands of file objects and a few thousand
/// mutants. Reaching this means the sweep is matching noise rather than that the
/// machine ran out of objects, and it is reported as a cap.
pub const MAX_PER_KIND: usize = 200_000;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops the object sweep before it can produce a result worth
/// reading.
///
/// Note what is *not* here: a tag match that was not an object, and a kind of
/// object this build does not declare. The first is counted by the sweep; the
/// second becomes a [`KindStatus`] saying the kind was not looked for and why,
/// which is a different claim from "there were none".
#[derive(Debug, thiserror::Error)]
pub enum ObjectsError {
    /// Not one of the three kinds can be recovered on this build, so no partial
    /// answer would be honest. The message names what is missing.
    #[error("no kernel objects of these kinds can be recovered on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// The pool layout, without which no allocation can be decoded at all.
    #[error(transparent)]
    Pool(#[from] PoolError),

    /// A typed read failed for a reason that invalidates the whole sweep rather
    /// than one object.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the sweep depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),
}

impl ObjectsError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            ObjectsError::Unsupported { .. } => "unsupported_build",
            ObjectsError::Pool(err) => err.class(),
            ObjectsError::Object(err) => err.class(),
            ObjectsError::Symbols(_) => "symbols",
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            ObjectsError::Pool(err) => err.incomplete_reason(),
            ObjectsError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be swept" refusal.
    pub fn unsupported(detail: impl Into<String>) -> ObjectsError {
        ObjectsError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// The members a file object is read through.
///
/// Every one but `file_name` is optional, and an absent one becomes a `None`
/// column rather than a `false`: "this build does not record whether the file
/// was open for writing" and "the file was not open for writing" are different
/// statements and only one of them is about the suspect's machine.
#[derive(Debug, Clone)]
pub struct FileObjectSymbols {
    /// Path within the device, as a `_UNICODE_STRING`.
    pub file_name: String,
    /// The device the file sits on, when this build records it.
    pub device_object: Option<String>,
    /// Whether the handle granted read access.
    pub read_access: Option<String>,
    /// Whether the handle granted write access.
    pub write_access: Option<String>,
    /// Whether the handle granted delete access.
    pub delete_access: Option<String>,
    /// Whether the file was opened permitting others to read.
    pub shared_read: Option<String>,
    /// Whether the file was opened permitting others to write.
    pub shared_write: Option<String>,
    /// Whether the file was opened permitting others to delete.
    pub shared_delete: Option<String>,
}

/// The members a mutant is read through.
#[derive(Debug, Clone)]
pub struct MutantSymbols {
    /// The thread that currently owns the mutant, when this build records it.
    pub owner_thread: Option<String>,
    /// Whether the owning thread exited without releasing it.
    pub abandoned: Option<String>,
    /// The dispatcher header's signal state: 1 when free, 0 or negative when
    /// held.
    pub signal_state: Option<String>,
}

/// The members a symbolic link is read through.
#[derive(Debug, Clone)]
pub struct SymbolicLinkSymbols {
    /// What the link points at, as a `_UNICODE_STRING`.
    pub link_target: String,
    /// When the link was created, as a FILETIME.
    pub creation_time: Option<String>,
}

/// Everything one image's file, mutant and symbolic-link objects are decoded
/// through.
///
/// Resolved once per image and checked once, so a build whose layout is unknown
/// fails here naming what is missing rather than after emitting rows read at the
/// wrong offsets.
#[derive(Debug, Clone)]
pub struct ObjectSymbols {
    /// The pool layout every allocation is decoded through.
    pub pool: PoolSymbols,
    /// How the object behind an object header is named, when it can be.
    pub names: Option<NameSymbols>,
    /// Why [`ObjectSymbols::names`] is absent, when it is. Every object that
    /// would have used it reports the reason rather than looking nameless.
    pub names_unavailable: Option<String>,
    /// The object manager's type index, used to reject an allocation whose tag
    /// matched by accident.
    pub type_map: Option<Arc<ObjectTypeMap>>,
    /// Why [`ObjectSymbols::type_map`] is absent, when it is.
    pub type_map_unavailable: Option<String>,
    /// File objects, when this build declares one.
    pub file: Option<FileObjectSymbols>,
    /// Why file objects are not swept for, when they are not.
    pub file_unavailable: Option<String>,
    /// Mutants, when this build declares one.
    pub mutant: Option<MutantSymbols>,
    /// Why mutants are not swept for, when they are not.
    pub mutant_unavailable: Option<String>,
    /// Symbolic links, when this build declares one.
    pub symlink: Option<SymbolicLinkSymbols>,
    /// Why symbolic links are not swept for, when they are not.
    pub symlink_unavailable: Option<String>,
}

impl ObjectSymbols {
    /// Resolve every layout fact the object sweep of this image needs.
    ///
    /// # What an examiner learns
    ///
    /// Which of the three kinds this image can be asked about at all. A kind
    /// whose structure the build's symbols do not describe is not swept for,
    /// and the reason travels into the artifact so that a report never shows an
    /// empty mutant table where it should show "mutants could not be read".
    ///
    /// # Errors
    ///
    /// [`ObjectsError::Unsupported`] when not one of the three kinds can be
    /// decoded, naming the types that were tried. Returning an empty result
    /// there would be a claim that the machine had no open files, no mutants
    /// and no symbolic links, which no running Windows system has ever been
    /// true of.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, ObjectsError> {
        let pool = PoolSymbols::from_profile(profile)?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        let (names, names_unavailable) = match NameSymbols::from_profile(profile) {
            Ok(names) => (Some(names), None),
            Err(err) => (
                None,
                Some(format!(
                    "the object-manager name of an object cannot be read on this build, so a \
                     mutant's or a symbolic link's own name is not available: {err}"
                )),
            ),
        };

        let (type_map, type_map_unavailable) = match ObjectTypeMap::from_profile(profile) {
            Ok(map) if map.is_empty() => (
                None,
                Some(
                    "the object manager's type table was located but held no readable entry, so \
                     an allocation cannot be checked against the type the kernel believes it has"
                        .to_string(),
                ),
            ),
            // A table that was read is not yet a table that can be used. From
            // Windows 10 an object header's stored `TypeIndex` is mixed with
            // the header's own address and the per-boot `ObHeaderCookie`;
            // resolving one without the cookie names the wrong kind of object
            // for about a fifth of the allocations and no kind at all for the
            // rest, and every row it touched would still carry
            // `type_verified`. The handle walk refuses such a map for the same
            // reason — see `HandleSymbols::from_profile`.
            Ok(map) => match map.resolves_indexes(profile.build.build) {
                Ok(()) => (Some(Arc::new(map)), None),
                Err(reason) => (None, Some(reason)),
            },
            Err(err) => (
                None,
                Some(format!(
                    "the object manager's type table could not be read, so an allocation cannot \
                     be checked against the type the kernel believes it has: {err}"
                )),
            ),
        };

        let (file, file_unavailable) = if !profile.symbols.has_type(TYPE_FILE_OBJECT) {
            (
                None,
                Some(format!(
                    "the symbol table has no '{TYPE_FILE_OBJECT}', so open files cannot be \
                     recovered from the pool"
                )),
            )
        } else {
            match first_member(&reader, TYPE_FILE_OBJECT, &["FileName"])? {
                Some(file_name) => (
                    Some(FileObjectSymbols {
                        file_name: file_name.to_string(),
                        device_object: first_member(&reader, TYPE_FILE_OBJECT, &["DeviceObject"])?
                            .map(str::to_string),
                        read_access: first_member(&reader, TYPE_FILE_OBJECT, &["ReadAccess"])?
                            .map(str::to_string),
                        write_access: first_member(&reader, TYPE_FILE_OBJECT, &["WriteAccess"])?
                            .map(str::to_string),
                        delete_access: first_member(&reader, TYPE_FILE_OBJECT, &["DeleteAccess"])?
                            .map(str::to_string),
                        shared_read: first_member(&reader, TYPE_FILE_OBJECT, &["SharedRead"])?
                            .map(str::to_string),
                        shared_write: first_member(&reader, TYPE_FILE_OBJECT, &["SharedWrite"])?
                            .map(str::to_string),
                        shared_delete: first_member(&reader, TYPE_FILE_OBJECT, &["SharedDelete"])?
                            .map(str::to_string),
                    }),
                    None,
                ),
                None => (
                    None,
                    Some(format!(
                        "'{TYPE_FILE_OBJECT}' has no FileName on this build, so a recovered file \
                         object could not be attributed to a path"
                    )),
                ),
            }
        };

        let (mutant, mutant_unavailable) = if profile.symbols.has_type(TYPE_KMUTANT) {
            (
                Some(MutantSymbols {
                    owner_thread: first_member(&reader, TYPE_KMUTANT, &["OwnerThread"])?
                        .map(str::to_string),
                    abandoned: first_member(&reader, TYPE_KMUTANT, &["Abandoned"])?
                        .map(str::to_string),
                    signal_state: first_member(
                        &reader,
                        TYPE_KMUTANT,
                        &["Header.SignalState", "Header.Header.SignalState"],
                    )?
                    .map(str::to_string),
                }),
                None,
            )
        } else {
            (
                None,
                Some(format!(
                    "the symbol table has no '{TYPE_KMUTANT}', so mutants cannot be recovered \
                     from the pool"
                )),
            )
        };

        let (symlink, symlink_unavailable) = if !profile.symbols.has_type(TYPE_SYMBOLIC_LINK) {
            (
                None,
                Some(format!(
                    "the symbol table has no '{TYPE_SYMBOLIC_LINK}', so the object manager's \
                     device aliases cannot be recovered from the pool"
                )),
            )
        } else {
            match first_member(&reader, TYPE_SYMBOLIC_LINK, &["LinkTarget"])? {
                Some(link_target) => (
                    Some(SymbolicLinkSymbols {
                        link_target: link_target.to_string(),
                        creation_time: first_member(
                            &reader,
                            TYPE_SYMBOLIC_LINK,
                            &["CreationTime.QuadPart"],
                        )?
                        .map(str::to_string),
                    }),
                    None,
                ),
                None => (
                    None,
                    Some(format!(
                        "'{TYPE_SYMBOLIC_LINK}' has no LinkTarget on this build, so a recovered \
                         link could not be said to point anywhere"
                    )),
                ),
            }
        };

        if file.is_none() && mutant.is_none() && symlink.is_none() {
            return Err(ObjectsError::unsupported(format!(
                "this build's symbols describe none of '{TYPE_FILE_OBJECT}', '{TYPE_KMUTANT}' and \
                 '{TYPE_SYMBOLIC_LINK}', so a sweep would have nothing to look for and its empty \
                 result would read as a machine with no open files, no mutants and no device \
                 aliases"
            )));
        }

        Ok(Self {
            pool,
            names,
            names_unavailable,
            type_map,
            type_map_unavailable,
            file,
            file_unavailable,
            mutant,
            mutant_unavailable,
            symlink,
            symlink_unavailable,
        })
    }

    /// The pool tags this build will actually be swept for.
    ///
    /// Both spellings of each tag, because the build number says which one the
    /// running kernel writes and says nothing about what is still lying in freed
    /// pool from before an upgrade.
    pub fn tags(&self) -> Vec<[u8; 4]> {
        let mut tags = Vec::new();
        if self.file.is_some() {
            tags.push(TAG_FILE_PROTECTED);
            tags.push(TAG_FILE);
        }
        if self.mutant.is_some() {
            tags.push(TAG_MUTANT_PROTECTED);
            tags.push(TAG_MUTANT);
        }
        if self.symlink.is_some() {
            tags.push(TAG_SYMLINK_PROTECTED);
            tags.push(TAG_SYMLINK);
        }
        tags
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "space": self.pool.space.as_str(),
            "names_available": self.names.is_some(),
            "names_unavailable": self.names_unavailable,
            "type_map_available": self.type_map.is_some(),
            "type_map_unavailable": self.type_map_unavailable,
            "file_available": self.file.is_some(),
            "file_unavailable": self.file_unavailable,
            "mutant_available": self.mutant.is_some(),
            "mutant_unavailable": self.mutant_unavailable,
            "symlink_available": self.symlink.is_some(),
            "symlink_unavailable": self.symlink_unavailable,
        })
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps for one object sweep.
#[derive(Debug, Clone)]
pub struct ObjectScanConfig {
    /// Geometry and caps for the underlying pool sweep.
    pub pool: PoolScanConfig,
    /// Ceiling on objects of one kind reported.
    pub max_per_kind: usize,
    /// Ceiling on individually recorded notes.
    pub max_recorded_notes: usize,
}

impl Default for ObjectScanConfig {
    fn default() -> Self {
        Self {
            pool: PoolScanConfig::default(),
            max_per_kind: MAX_PER_KIND,
            max_recorded_notes: MAX_RECORDED_NOTES,
        }
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// Which kind of object a row is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectKind {
    /// An open file.
    File,
    /// A mutant.
    Mutant,
    /// A symbolic link.
    SymbolicLink,
}

impl ObjectKind {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ObjectKind::File => "file",
            ObjectKind::Mutant => "mutant",
            ObjectKind::SymbolicLink => "symbolic_link",
        }
    }

    /// The structure the kernel allocates for this kind.
    pub fn type_name(self) -> &'static str {
        match self {
            ObjectKind::File => TYPE_FILE_OBJECT,
            ObjectKind::Mutant => TYPE_KMUTANT,
            ObjectKind::SymbolicLink => TYPE_SYMBOLIC_LINK,
        }
    }
}

/// Whether one kind was swept for, and if not, why not.
///
/// The type that keeps "no mutants were found" apart from "mutants were never
/// looked for". Both produce an empty list, and only one of them is a statement
/// about the machine.
#[derive(Debug, Clone)]
pub struct KindStatus {
    /// Which kind.
    pub kind: ObjectKind,
    /// Whether the sweep looked for it.
    pub swept: bool,
    /// Why it was not swept for, when it was not.
    pub detail: Option<String>,
    /// How many were recovered.
    pub found: usize,
    /// Whether the cap fired for this kind.
    pub capped: bool,
}

impl KindStatus {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind.as_str(),
            "type": self.kind.type_name(),
            "swept": self.swept,
            "detail": self.detail,
            "found": self.found,
            "capped": self.capped,
        })
    }
}

/// What the allocation an object was recovered from says about it.
///
/// Carried on every row because it is what distinguishes a live object from a
/// historical one, and because an object admitted without its object-manager
/// type being checked rests on its tag alone.
#[derive(Debug, Clone)]
pub struct Provenance {
    /// Where the allocation starts.
    pub pool_header: u64,
    /// Where the object's `_OBJECT_HEADER` is.
    pub object_header: Option<u64>,
    /// The tag, rendered so that every byte survives.
    pub tag: String,
    /// The allocation's size in bytes.
    pub allocation: u64,
    /// Whether the allocation is freed, which is to say whether this object is
    /// historical rather than live.
    pub freed: bool,
    /// The object-manager type the header named, when it was resolved.
    pub object_type: Option<String>,
    /// Whether the object-manager type was actually compared. `false` means the
    /// object's identity rests on its tag and its structure alone.
    pub type_verified: bool,
}

impl Provenance {
    /// Everything the sweep already established about the allocation.
    fn from_object(object: &PoolObject) -> Self {
        Self {
            pool_header: object.pool_header,
            object_header: object.object_header,
            tag: object.tag.clone(),
            allocation: object.allocation,
            freed: object.freed,
            object_type: object.object_type.clone(),
            type_verified: object.type_verified,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pool_header": self.pool_header,
            // Exact beside the number: pool and object-header addresses are
            // kernel addresses above 2^53, JSON numbers are IEEE doubles, and
            // an allocation address rounded by a kilobyte names a different
            // allocation.
            "pool_header_hex": format!("{:#x}", self.pool_header),
            "object_header": self.object_header,
            "object_header_hex": self
                .object_header
                .map(|address| format!("{address:#x}")),
            "tag": self.tag,
            "allocation": self.allocation,
            "freed": self.freed,
            "object_type": self.object_type,
            "type_verified": self.type_verified,
        })
    }
}

/// How a file object was opened, as the object records it.
///
/// Every field is `Option<bool>` on purpose: `None` means this build does not
/// declare the member, and rendering that as `false` would state that the file
/// was *not* open for writing when the truth is that the image cannot say.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileAccess {
    /// The handle granted read access.
    pub read: Option<bool>,
    /// The handle granted write access.
    pub write: Option<bool>,
    /// The handle granted delete access.
    pub delete: Option<bool>,
    /// Others were permitted to read.
    pub shared_read: Option<bool>,
    /// Others were permitted to write.
    pub shared_write: Option<bool>,
    /// Others were permitted to delete.
    pub shared_delete: Option<bool>,
}

impl FileAccess {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "read": self.read,
            "write": self.write,
            "delete": self.delete,
            "shared_read": self.shared_read,
            "shared_write": self.shared_write,
            "shared_delete": self.shared_delete,
        })
    }
}

/// One open file recovered from the pool.
#[derive(Debug, Clone)]
pub struct FileObjectRecord {
    /// Where the `_FILE_OBJECT` is, in the space that was swept.
    pub address: u64,
    /// The allocation it came out of.
    pub provenance: Provenance,
    /// The path within the device, exactly as `FileName` holds it.
    pub path: NameField,
    /// The device-qualified name, when the device could be resolved. Reported
    /// separately from [`FileObjectRecord::path`] because prefixing the wrong
    /// device would name a file on a volume the machine never touched.
    pub name: HandleName,
    /// The device object the file sits on.
    pub device: Option<u64>,
    /// How the file was opened.
    pub access: FileAccess,
    /// Everything odd about the object that did not disqualify it.
    pub notes: Vec<String>,
}

impl FileObjectRecord {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "provenance": self.provenance.to_json(),
            "path": self.path.to_json(),
            "name": self.name.to_json(),
            "device": self.device,
            "access": self.access.to_json(),
            "notes": self.notes,
        })
    }
}

/// One mutant recovered from the pool.
#[derive(Debug, Clone)]
pub struct MutantRecord {
    /// Where the `_KMUTANT` is, in the space that was swept.
    pub address: u64,
    /// The allocation it came out of.
    pub provenance: Provenance,
    /// The mutant's object-manager name. Most mutants have none, which is
    /// ordinary; a name that could not be read is not.
    pub name: HandleName,
    /// The thread holding the mutant, when the member exists and was readable.
    pub owner_thread: Option<u64>,
    /// Whether the owning thread exited without releasing it.
    pub abandoned: Option<bool>,
    /// The dispatcher signal state: 1 when the mutant is free.
    pub signal_state: Option<i64>,
    /// Everything odd about the object that did not disqualify it.
    pub notes: Vec<String>,
}

impl MutantRecord {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "provenance": self.provenance.to_json(),
            "name": self.name.to_json(),
            "owner_thread": self.owner_thread,
            "owner_thread_hex": self.owner_thread.map(|thread| format!("{thread:#x}")),
            "abandoned": self.abandoned,
            "signal_state": self.signal_state,
            "notes": self.notes,
        })
    }
}

/// One symbolic link recovered from the pool.
#[derive(Debug, Clone)]
pub struct SymbolicLinkRecord {
    /// Where the `_OBJECT_SYMBOLIC_LINK` is, in the space that was swept.
    pub address: u64,
    /// The allocation it came out of.
    pub provenance: Provenance,
    /// The link's own name — the alias, e.g. `C:`.
    pub name: HandleName,
    /// What the link points at, e.g. `\Device\HarddiskVolume2`.
    pub target: NameField,
    /// When the link was created, as a raw FILETIME. Left raw: converting it is
    /// the reporting layer's job and a zero here means "never set", not 1601.
    pub creation_time: Option<i64>,
    /// Everything odd about the object that did not disqualify it.
    pub notes: Vec<String>,
}

impl SymbolicLinkRecord {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "address_hex": format!("{:#x}", self.address),
            "provenance": self.provenance.to_json(),
            "name": self.name.to_json(),
            "target": self.target.to_json(),
            "creation_time": self.creation_time,
            "notes": self.notes,
        })
    }
}

/// What one object sweep found, and everything it could not do.
#[derive(Debug, Clone)]
pub struct ObjectScanOutcome {
    /// Open files, in ascending order of the address their tag was found at.
    pub files: Vec<FileObjectRecord>,
    /// Mutants, likewise.
    pub mutants: Vec<MutantRecord>,
    /// Symbolic links, likewise.
    pub links: Vec<SymbolicLinkRecord>,
    /// Which kinds were swept for, and which were not.
    pub kinds: Vec<KindStatus>,
    /// The underlying sweep, whose rejections and unread ranges bound what could
    /// have been found.
    pub sweep: PoolScanOutcome,
    /// Notes, capped by [`ObjectScanConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total. Exact even when the list was capped.
    pub notes_total: usize,
    /// Everything a report must declare about this result.
    pub incomplete: Vec<Incomplete>,
}

impl ObjectScanOutcome {
    /// Whether every kind was swept for, every mapped byte examined and every
    /// object returned.
    ///
    /// The question a report must ask before writing "this machine had no such
    /// object open": a sweep that stopped early, or that never looked for a
    /// kind, says nothing about what it did not reach.
    pub fn is_complete(&self) -> bool {
        self.kinds.iter().all(|kind| kind.swept && !kind.capped)
            && self.sweep.is_complete()
            && self.incomplete.is_empty()
    }

    /// Which address space was swept.
    pub fn space(&self) -> ScanSpace {
        self.sweep.space
    }

    /// The files whose path was read, for a caller building a path index.
    pub fn named_files(&self) -> impl Iterator<Item = (&FileObjectRecord, &str)> {
        self.files
            .iter()
            .filter_map(|file| file.path.name().map(|name| (file, name)))
    }

    /// Serializable form for artifact metadata.
    ///
    /// The sweep is summarised rather than embedded whole: its own object list
    /// is the same objects again, and a report that carried both could show two
    /// different counts of the same thing.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "files": self.files.iter().map(FileObjectRecord::to_json).collect::<Vec<_>>(),
            "file_count": self.files.len(),
            "mutants": self.mutants.iter().map(MutantRecord::to_json).collect::<Vec<_>>(),
            "mutant_count": self.mutants.len(),
            "links": self.links.iter().map(SymbolicLinkRecord::to_json).collect::<Vec<_>>(),
            "link_count": self.links.len(),
            "freed_count": self.freed_count(),
            "unverified_type_count": self.unverified_type_count(),
            "kinds": self.kinds.iter().map(KindStatus::to_json).collect::<Vec<_>>(),
            "sweep": {
                "space": self.sweep.space.as_str(),
                "candidates": self.sweep.candidates,
                "rejected_total": self.sweep.rejected_total,
                "rejected": self
                    .sweep
                    .rejected
                    .iter()
                    .map(|r| serde_json::json!({
                        "tag_address": r.tag_address,
                        "tag": r.tag,
                        "reason": r.reason,
                    }))
                    .collect::<Vec<_>>(),
                "truncated": self.sweep.truncated,
                "scan": self.sweep.scan.to_json(),
                "complete": self.sweep.is_complete(),
            },
            "notes": self.notes,
            "notes_total": self.notes_total,
            "complete": self.is_complete(),
            "incomplete": self.incomplete.iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }

    /// How many recovered objects came out of freed allocations.
    pub fn freed_count(&self) -> usize {
        self.files.iter().filter(|f| f.provenance.freed).count()
            + self.mutants.iter().filter(|m| m.provenance.freed).count()
            + self.links.iter().filter(|l| l.provenance.freed).count()
    }

    /// How many recovered objects were admitted without their object-manager
    /// type being compared.
    pub fn unverified_type_count(&self) -> usize {
        self.files
            .iter()
            .filter(|f| !f.provenance.type_verified)
            .count()
            + self
                .mutants
                .iter()
                .filter(|m| !m.provenance.type_verified)
                .count()
            + self
                .links
                .iter()
                .filter(|l| !l.provenance.type_verified)
                .count()
    }
}

// ── The sweep ───────────────────────────────────────────────────────────────

/// Sweep the image for file objects, mutants and symbolic links.
///
/// This is the stage entry point: the orchestrator calls it once per image with
/// [`ObjectSymbols::from_profile`] and an [`ObjectScanConfig`].
///
/// # What an examiner learns
///
/// Which files the kernel had open when the image was taken, which named
/// mutants existed, and which device aliases the object manager held — including
/// objects whose allocations had already been freed, which are the historical
/// ones no live-system tool can show. Every row says whether its allocation was
/// freed and whether the object manager's own type table agreed with the tag.
///
/// # What a wrong answer looks like
///
/// A file path in this table that was never on the machine, produced by an
/// allocation decoded at the wrong offset whose bytes happened to parse as a
/// `_UNICODE_STRING`. That is what the sweep's structural checks and the
/// object-manager type comparison exist to prevent, and a row admitted without
/// the type comparison says so on its face rather than resting quietly on four
/// bytes of tag.
///
/// # Errors
///
/// Only for failures that make the whole sweep meaningless: a pool layout that
/// cannot be established, or a scan configuration that cannot produce a correct
/// walk. An object that failed validation is not an error — it is counted in
/// [`PoolScanOutcome::rejected`], which this outcome carries.
pub fn scan_objects(
    profile: &WindowsProfile,
    symbols: &ObjectSymbols,
    config: &ObjectScanConfig,
) -> Result<ObjectScanOutcome, ObjectsError> {
    let tags = symbols.tags();
    if tags.is_empty() {
        // Unreachable through `ObjectSymbols::from_profile`, which refuses to
        // build symbols with no kind at all. Stated anyway, because a sweep with
        // no needles would return an empty result that reads as an absence of
        // objects.
        return Err(ObjectsError::unsupported(
            "no object kind on this build has a structure the sweep could decode, so there is \
             nothing to look for",
        ));
    }
    let constraints = builtin_constraints_for(&tags);
    if constraints.len() != tags.len() {
        return Err(ObjectsError::unsupported(format!(
            "{} of the {} pool tags these object kinds are allocated under are not among the \
             builtin constraints, so part of the sweep would silently not happen",
            tags.len().saturating_sub(constraints.len()),
            tags.len()
        )));
    }

    let pool_config = PoolScanConfig {
        // An explicitly configured map wins: a caller that built one for the
        // whole case should not have it replaced by a second read of the same
        // table.
        type_map: config
            .pool
            .type_map
            .clone()
            .or_else(|| symbols.type_map.clone()),
        ..config.pool.clone()
    };
    let sweep = pool_scan(profile, &symbols.pool, &constraints, &pool_config)?;

    // The allocation's bytes come from the layer that was swept; every pointer
    // inside it is a kernel virtual address. Built the same way `pool_scan`
    // builds its own reader, because getting the two the wrong way round does
    // not fail — it silently reads unrelated bytes that parse.
    let layer: Arc<dyn MemoryLayer> = match symbols.pool.space {
        ScanSpace::Physical => Arc::clone(&profile.physical),
        ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
    };
    let reader = StructReader::with_native(
        layer,
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    let mut out = ObjectScanOutcome {
        files: Vec::new(),
        mutants: Vec::new(),
        links: Vec::new(),
        kinds: Vec::new(),
        sweep,
        notes: Vec::new(),
        notes_total: 0,
        incomplete: Vec::new(),
    };
    let mut file_capped = false;
    let mut mutant_capped = false;
    let mut link_capped = false;

    // `out.sweep.objects` is borrowed for the loop, so the rows are built into
    // temporaries and moved in afterwards.
    let mut files = Vec::new();
    let mut mutants = Vec::new();
    let mut links = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut notes_total = 0usize;

    for object in &out.sweep.objects {
        match object.type_name.as_str() {
            TYPE_FILE_OBJECT => {
                if files.len() >= config.max_per_kind {
                    file_capped = true;
                    continue;
                }
                if let Some(file) = symbols.file.as_ref() {
                    files.push(read_file(&reader, symbols, file, object));
                }
            }
            TYPE_KMUTANT => {
                if mutants.len() >= config.max_per_kind {
                    mutant_capped = true;
                    continue;
                }
                if let Some(mutant) = symbols.mutant.as_ref() {
                    mutants.push(read_mutant(&reader, symbols, mutant, object));
                }
            }
            TYPE_SYMBOLIC_LINK => {
                if links.len() >= config.max_per_kind {
                    link_capped = true;
                    continue;
                }
                if let Some(link) = symbols.symlink.as_ref() {
                    links.push(read_link(&reader, symbols, link, object));
                }
            }
            other => push_note(
                &mut notes,
                &mut notes_total,
                config.max_recorded_notes,
                format!(
                    "the allocation at {:#x} was decoded as '{other}', which this stage did not \
                     ask for and does not report",
                    object.pool_header
                ),
            ),
        }
    }

    out.files = files;
    out.mutants = mutants;
    out.links = links;
    out.notes = notes;
    out.notes_total = notes_total;

    out.kinds = vec![
        KindStatus {
            kind: ObjectKind::File,
            swept: symbols.file.is_some(),
            detail: symbols.file_unavailable.clone(),
            found: out.files.len(),
            capped: file_capped,
        },
        KindStatus {
            kind: ObjectKind::Mutant,
            swept: symbols.mutant.is_some(),
            detail: symbols.mutant_unavailable.clone(),
            found: out.mutants.len(),
            capped: mutant_capped,
        },
        KindStatus {
            kind: ObjectKind::SymbolicLink,
            swept: symbols.symlink.is_some(),
            detail: symbols.symlink_unavailable.clone(),
            found: out.links.len(),
            capped: link_capped,
        },
    ];

    let incomplete = declare_incomplete(symbols, &out, config);
    out.incomplete = incomplete;
    Ok(out)
}

/// Everything about this result a report is obliged to state.
fn declare_incomplete(
    symbols: &ObjectSymbols,
    out: &ObjectScanOutcome,
    config: &ObjectScanConfig,
) -> Vec<Incomplete> {
    let mut incomplete = out.sweep.incomplete.clone();
    for kind in &out.kinds {
        if !kind.swept {
            incomplete.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "objects of kind '{}' were not swept for, so this result says nothing about \
                     whether the machine had any: {}",
                    kind.kind.as_str(),
                    kind.detail.as_deref().unwrap_or("no reason was recorded")
                ),
            ));
        }
        if kind.capped {
            incomplete.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the sweep stopped at its cap of {} object(s) of kind '{}'; the image was not \
                     exhausted",
                    config.max_per_kind,
                    kind.kind.as_str()
                ),
            ));
        }
    }
    if let Some(detail) = symbols.type_map_unavailable.as_deref() {
        incomplete.push(Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            format!(
                "every object here rests on its pool tag and its structure alone, because {detail}"
            ),
        ));
    }
    if symbols.names.is_none() {
        if let Some(detail) = symbols.names_unavailable.as_deref() {
            incomplete.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                detail.to_string(),
            ));
        }
    }
    if out.notes_total > out.notes.len() {
        incomplete.push(Incomplete::new(
            IncompleteReason::CapReached,
            format!(
                "{} note(s) were raised and only {} are listed individually",
                out.notes_total,
                out.notes.len()
            ),
        ));
    }
    incomplete
}

/// Record a note, keeping the list bounded without losing the count.
fn push_note(notes: &mut Vec<String>, total: &mut usize, cap: usize, note: String) {
    *total = total.saturating_add(1);
    if notes.len() < cap {
        notes.push(note);
    }
}

/// Read one recovered `_FILE_OBJECT`.
fn read_file(
    reader: &StructReader,
    symbols: &ObjectSymbols,
    file: &FileObjectSymbols,
    object: &PoolObject,
) -> FileObjectRecord {
    let mut notes = object.notes.clone();
    let provenance = Provenance::from_object(object);

    let (path, device, access) = match reader.object(object.address, TYPE_FILE_OBJECT) {
        Ok(obj) => {
            let path = name_field(&obj, &file.file_name);
            let device =
                file.device_object
                    .as_deref()
                    .and_then(|member| match obj.pointer(member) {
                        Ok(0) => None,
                        Ok(value) => Some(value),
                        Err(err) => {
                            notes.push(format!("'{member}' could not be read: {err}"));
                            None
                        }
                    });
            let access = FileAccess {
                read: optional_flag(&obj, file.read_access.as_deref(), &mut notes),
                write: optional_flag(&obj, file.write_access.as_deref(), &mut notes),
                delete: optional_flag(&obj, file.delete_access.as_deref(), &mut notes),
                shared_read: optional_flag(&obj, file.shared_read.as_deref(), &mut notes),
                shared_write: optional_flag(&obj, file.shared_write.as_deref(), &mut notes),
                shared_delete: optional_flag(&obj, file.shared_delete.as_deref(), &mut notes),
            };
            (path, device, access)
        }
        Err(err) => (
            NameField::Unavailable(format!(
                "'{TYPE_FILE_OBJECT}' at {:#x} could not be read: {err}",
                object.address
            )),
            None,
            FileAccess::default(),
        ),
    };

    // The device-qualified name goes through the same code path a handle table
    // uses, so a file named here and a file named there cannot disagree.
    let name = match (symbols.names.as_ref(), object.object_header) {
        (Some(names), Some(header)) => object_name(reader, names, header, OBJECT_TYPE_FILE),
        (Some(_), None) => HandleName::Unavailable(
            "this allocation carried no object header, so the device the file sits on could not \
             be resolved"
                .to_string(),
        ),
        (None, _) => HandleName::Unavailable(
            symbols
                .names_unavailable
                .clone()
                .unwrap_or_else(|| "object names could not be resolved on this build".to_string()),
        ),
    };

    FileObjectRecord {
        address: object.address,
        provenance,
        path,
        name,
        device,
        access,
        notes,
    }
}

/// Read one recovered `_KMUTANT`.
fn read_mutant(
    reader: &StructReader,
    symbols: &ObjectSymbols,
    mutant: &MutantSymbols,
    object: &PoolObject,
) -> MutantRecord {
    let mut notes = object.notes.clone();
    let provenance = Provenance::from_object(object);

    let (owner_thread, abandoned, signal_state) = match reader.object(object.address, TYPE_KMUTANT)
    {
        Ok(obj) => {
            let owner =
                mutant
                    .owner_thread
                    .as_deref()
                    .and_then(|member| match obj.pointer(member) {
                        Ok(0) => None,
                        Ok(value) => Some(value),
                        Err(err) => {
                            notes.push(format!("'{member}' could not be read: {err}"));
                            None
                        }
                    });
            let abandoned = optional_flag(&obj, mutant.abandoned.as_deref(), &mut notes);
            let signal = mutant
                .signal_state
                .as_deref()
                .and_then(|member| match obj.int(member) {
                    // Zero is the *held* state. Folding a value that does not
                    // fit in an `i64` into it would report an unread mutant as
                    // one some thread was holding, which is a statement about
                    // what was running on the machine.
                    Ok(value) => match value.as_i64() {
                        Some(state) => Some(state),
                        None => {
                            notes.push(format!(
                                "'{member}' holds {value}, which is not a dispatcher signal \
                                 state, so whether this mutant was held is unknown rather than yes"
                            ));
                            None
                        }
                    },
                    Err(err) => {
                        notes.push(format!("'{member}' could not be read: {err}"));
                        None
                    }
                });
            (owner, abandoned, signal)
        }
        Err(err) => {
            notes.push(format!(
                "'{TYPE_KMUTANT}' at {:#x} could not be read: {err}",
                object.address
            ));
            (None, None, None)
        }
    };

    MutantRecord {
        address: object.address,
        provenance,
        name: generic_object_name(reader, symbols, object),
        owner_thread,
        abandoned,
        signal_state,
        notes,
    }
}

/// Read one recovered `_OBJECT_SYMBOLIC_LINK`.
fn read_link(
    reader: &StructReader,
    symbols: &ObjectSymbols,
    link: &SymbolicLinkSymbols,
    object: &PoolObject,
) -> SymbolicLinkRecord {
    let mut notes = object.notes.clone();
    let provenance = Provenance::from_object(object);

    let (target, creation_time) = match reader.object(object.address, TYPE_SYMBOLIC_LINK) {
        Ok(obj) => {
            let target = name_field(&obj, &link.link_target);
            let created = link
                .creation_time
                .as_deref()
                .and_then(|member| match obj.int(member) {
                    Ok(value) => value.as_i64(),
                    Err(err) => {
                        notes.push(format!("'{member}' could not be read: {err}"));
                        None
                    }
                });
            (target, created)
        }
        Err(err) => (
            NameField::Unavailable(format!(
                "'{TYPE_SYMBOLIC_LINK}' at {:#x} could not be read: {err}",
                object.address
            )),
            None,
        ),
    };

    SymbolicLinkRecord {
        address: object.address,
        provenance,
        name: generic_object_name(reader, symbols, object),
        target,
        creation_time,
        notes,
    }
}

/// The object-manager name in front of a recovered object's header.
fn generic_object_name(
    reader: &StructReader,
    symbols: &ObjectSymbols,
    object: &PoolObject,
) -> HandleName {
    let Some(names) = symbols.names.as_ref() else {
        return HandleName::Unavailable(
            symbols
                .names_unavailable
                .clone()
                .unwrap_or_else(|| "object names could not be resolved on this build".to_string()),
        );
    };
    let Some(header) = object.object_header else {
        return HandleName::Unavailable(
            "this allocation carried no object header, so the object's own name could not be \
             reached"
                .to_string(),
        );
    };
    // Deliberately the generic route rather than [`object_name`]: the type name
    // this object carries is the one being reported, and dispatching on it would
    // make a mis-resolved type silently change how the name is read.
    crate::handles::name::generic_name(reader, names, header)
}

/// Read a `_UNICODE_STRING` member into a [`NameField`].
fn name_field(object: &Obj, path: &str) -> NameField {
    match unicode_string(object, path) {
        Ok(Some(name)) => NameField::Name(name),
        Ok(None) => NameField::Empty,
        Err(err) => NameField::Unavailable(err.to_string()),
    }
}

/// Read an optional boolean member, recording rather than swallowing a failure.
///
/// `None` covers both "this build does not declare the member" and "the member
/// could not be read", and the second leaves a note. Neither becomes `false`.
fn optional_flag(object: &Obj, path: Option<&str>, notes: &mut Vec<String>) -> Option<bool> {
    let path = path?;
    match object.int(path) {
        Ok(value) => Some(value.as_i128() != 0),
        Err(err) => {
            notes.push(format!("'{path}' could not be read: {err}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image};
    use seance_memory::Architecture;

    // Where the synthetic 64-bit fixture puts things.
    //
    // Every executive object sits in an allocation laid out the way a Windows
    // 8-and-later kernel lays one out: the pool header, then an
    // `_OBJECT_HEADER_NAME_INFO`, then the `_OBJECT_HEADER`, then the object.
    // The name info in front is what makes the fixture exercise the top-down
    // search rather than trivially matching at offset zero.
    const TYPE_TABLE_AT: u64 = 0xF000;
    const INFO_MASK_TABLE_AT: u64 = 0xF800;
    /// Where `ObHeaderCookie` lives in the fixture, and the byte held there.
    ///
    /// A Windows 10-or-later image that did not carry this would not be one an
    /// object sweep may resolve type indexes on at all, so the fixture carries
    /// it — see [`mixed_type_index`].
    const HEADER_COOKIE_AT: u64 = 0xFC00;
    const HEADER_COOKIE: u8 = 0x5A;
    const TYPE_FILE_AT: u64 = 0xF100;
    const TYPE_FILE_NAME_AT: u64 = 0xF180;
    const TYPE_MUTANT_AT: u64 = 0xF200;
    const TYPE_MUTANT_NAME_AT: u64 = 0xF280;
    const TYPE_LINK_AT: u64 = 0xF300;
    const TYPE_LINK_NAME_AT: u64 = 0xF380;

    const FILE_ALLOC: u64 = 0x1000;
    const MUTANT_ALLOC: u64 = 0x2000;
    const LINK_ALLOC: u64 = 0x3000;
    const DEVICE_ALLOC: u64 = 0x4000;

    const FILE_PATH_AT: u64 = 0x5000;
    const MUTANT_NAME_AT: u64 = 0x5100;
    const LINK_NAME_AT: u64 = 0x5200;
    const LINK_TARGET_AT: u64 = 0x5300;
    const DEVICE_NAME_AT: u64 = 0x5400;

    /// The thread the fixture's mutant is held by.
    const OWNER_THREAD: u64 = 0xABC0;

    /// Offsets the synthetic 64-bit object ISF declares.
    mod off {
        pub(super) const POOL_HEADER_SIZE: u64 = 16;
        pub(super) const POOL_BLOCK_SIZE: u64 = 0;
        pub(super) const POOL_TYPE: u64 = 2;
        pub(super) const POOL_TAG: u64 = 4;

        pub(super) const OH_POINTER_COUNT: u64 = 0;
        pub(super) const OH_TYPE_INDEX: u64 = 24;
        pub(super) const OH_INFO_MASK: u64 = 26;
        pub(super) const OH_BODY: u64 = 48;

        /// Size of `_OBJECT_HEADER_NAME_INFO`, which is also how far in front of
        /// the object header it sits when it is the only optional header.
        pub(super) const NAME_INFO_SIZE: u64 = 32;
        /// `_OBJECT_HEADER_NAME_INFO.Name`.
        pub(super) const NAME_INFO_NAME: u64 = 0;
        /// The `InfoMask` bit that announces a name info on this build: the
        /// second of the optional headers it declares, so bit 1.
        pub(super) const INFO_MASK_NAME: u8 = 0b10;

        /// Distance from the start of the allocation's usable space to the
        /// object header, which is exactly the name info this fixture puts
        /// there.
        pub(super) const HEADER_IN_ALLOCATION: u64 = NAME_INFO_SIZE;

        pub(super) const UNICODE_LENGTH: u64 = 0;
        pub(super) const UNICODE_MAX_LENGTH: u64 = 2;
        pub(super) const UNICODE_BUFFER: u64 = 8;

        pub(super) const FILE_DEVICE_OBJECT: u64 = 8;
        pub(super) const FILE_READ_ACCESS: u64 = 16;
        pub(super) const FILE_WRITE_ACCESS: u64 = 17;
        pub(super) const FILE_DELETE_ACCESS: u64 = 18;
        pub(super) const FILE_SHARED_READ: u64 = 19;
        pub(super) const FILE_SHARED_WRITE: u64 = 20;
        pub(super) const FILE_SHARED_DELETE: u64 = 21;
        pub(super) const FILE_NAME: u64 = 24;

        pub(super) const MUTANT_SIGNAL_STATE: u64 = 4;
        pub(super) const MUTANT_OWNER_THREAD: u64 = 24;
        pub(super) const MUTANT_ABANDONED: u64 = 32;

        pub(super) const LINK_CREATION_TIME: u64 = 0;
        pub(super) const LINK_TARGET: u64 = 8;

        pub(super) const OBJECT_TYPE_NAME: u64 = 0;
    }

    /// Where an allocation's `_OBJECT_HEADER` is.
    fn header_of(pool_base: u64) -> u64 {
        pool_base + off::POOL_HEADER_SIZE + off::HEADER_IN_ALLOCATION
    }

    /// Where an allocation's `_OBJECT_HEADER_NAME_INFO` is.
    fn name_info_of(pool_base: u64) -> u64 {
        pool_base + off::POOL_HEADER_SIZE
    }

    /// Where an allocation's object itself is.
    fn body_of(pool_base: u64) -> u64 {
        header_of(pool_base) + off::OH_BODY
    }

    /// A synthetic 64-bit Windows 10 ISF carrying the three object types, the
    /// object header, and every optional header a real build declares — the last
    /// of which is load-bearing, because the set of declared optional headers
    /// decides both what each `InfoMask` bit means and how far the top-down
    /// search for the object header is allowed to look.
    fn objects_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "1A2B3C4D5E6F70819293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 34404}}
  },
  "base_types": "#,
            crate::image_fixture::BASE_TYPES_X64,
            r#",
  "user_types": {
    "_POOL_HEADER": {"size": 16, "kind": "struct", "fields": {
      "BlockSize": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolType": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_QUAD": {"size": 8, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_OBJECT_HEADER": {"size": 56, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "HandleCount": {"offset": 8, "type": {"kind": "base", "name": "long"}},
      "TypeIndex": {"offset": 24, "type": {"kind": "base", "name": "unsigned char"}},
      "InfoMask": {"offset": 26, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 48, "type": {"kind": "struct", "name": "_QUAD"}}
    }},
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_OBJECT_HEADER_CREATOR_INFO": {"size": 32, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_NAME_INFO": {"size": 32, "kind": "struct", "fields": {
      "Name": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_OBJECT_HEADER_HANDLE_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_QUOTA_INFO": {"size": 32, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_PROCESS_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_AUDIT_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_EXTENDED_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_PADDING_INFO": {"size": 8, "kind": "struct", "fields": {
      "PaddingAmount": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_OBJECT_TYPE": {"size": 32, "kind": "struct", "fields": {
      "Name": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_DISPATCHER_HEADER": {"size": 24, "kind": "struct", "fields": {
      "SignalState": {"offset": 4, "type": {"kind": "base", "name": "long"}}
    }},
    "_DEVICE_OBJECT": {"size": 64, "kind": "struct", "fields": {
      "Type": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}}
    }},
    "_FILE_OBJECT": {"size": 216, "kind": "struct", "fields": {
      "Type": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "DeviceObject": {"offset": 8, "type": {"kind": "pointer",
                       "subtype": {"kind": "struct", "name": "_DEVICE_OBJECT"}}},
      "ReadAccess": {"offset": 16, "type": {"kind": "base", "name": "unsigned char"}},
      "WriteAccess": {"offset": 17, "type": {"kind": "base", "name": "unsigned char"}},
      "DeleteAccess": {"offset": 18, "type": {"kind": "base", "name": "unsigned char"}},
      "SharedRead": {"offset": 19, "type": {"kind": "base", "name": "unsigned char"}},
      "SharedWrite": {"offset": 20, "type": {"kind": "base", "name": "unsigned char"}},
      "SharedDelete": {"offset": 21, "type": {"kind": "base", "name": "unsigned char"}},
      "FileName": {"offset": 24, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_KMUTANT": {"size": 64, "kind": "struct", "fields": {
      "Header": {"offset": 0, "type": {"kind": "struct", "name": "_DISPATCHER_HEADER"}},
      "OwnerThread": {"offset": 24, "type": {"kind": "pointer",
                      "subtype": {"kind": "base", "name": "unsigned char"}}},
      "Abandoned": {"offset": 32, "type": {"kind": "base", "name": "unsigned char"}}
    }},
    "_OBJECT_SYMBOLIC_LINK": {"size": 80, "kind": "struct", "fields": {
      "CreationTime": {"offset": 0, "type": {"kind": "union", "name": "_LARGE_INTEGER"}},
      "LinkTarget": {"offset": 8, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }}
  },
  "enums": {},
  "symbols": {
    "ObTypeIndexTable": {"address": 61440},
    "ObpInfoMaskToOffset": {"address": 63488},
    "ObHeaderCookie": {"address": 64512}
  }
}"#,
        ]
        .concat()
    }

    /// The same ISF with no `ObHeaderCookie`, for the "an index that cannot be
    /// unmixed is not resolved" test.
    fn objects_isf_without_cookie() -> String {
        let isf = objects_isf().replace(",\n    \"ObHeaderCookie\": {\"address\": 64512}", "");
        assert!(
            !isf.contains("ObHeaderCookie"),
            "the fixture's cookie declaration must have been removed"
        );
        isf
    }

    /// The same ISF with `_KMUTANT` renamed away, for the "a kind this build
    /// cannot describe is not swept for" tests.
    fn objects_isf_without_mutant() -> String {
        objects_isf().replace(
            r#""_KMUTANT": {"size": 64,"#,
            r#""_KMUTANT_RENAMED": {"size": 64,"#,
        )
    }

    /// A `_UNICODE_STRING` at `at`, with its characters at `buffer`.
    fn put_unicode(image: &mut Image, at: u64, buffer: u64, text: &str) {
        let bytes = u16::try_from(text.encode_utf16().count() * 2).expect("a short fixture string");
        image.put_u16(at + off::UNICODE_LENGTH, bytes);
        image.put_u16(at + off::UNICODE_MAX_LENGTH, bytes);
        image.put_u64(at + off::UNICODE_BUFFER, buffer);
        image.put_utf16(buffer, text);
    }

    /// One pool allocation holding one executive object.
    ///
    /// Returns the address of the object's body.
    fn put_executive(
        image: &mut Image,
        pool_base: u64,
        tag: &[u8; 4],
        pool_type: u16,
        block_size: u16,
        type_index: u8,
    ) -> u64 {
        image.put_u16(pool_base + off::POOL_BLOCK_SIZE, block_size);
        image.put_u16(pool_base + off::POOL_TYPE, pool_type);
        image.write(pool_base + off::POOL_TAG, tag);
        let header = header_of(pool_base);
        image.put_u32(header + off::OH_POINTER_COUNT, 3);
        image.put_u8(
            header + off::OH_TYPE_INDEX,
            mixed_type_index(header, type_index),
        );
        image.put_u8(header + off::OH_INFO_MASK, 0);
        body_of(pool_base)
    }

    /// The byte a Windows 10-or-later kernel stores in `TypeIndex` for an
    /// object of table slot `real` whose header is at `header`.
    ///
    /// `real ^ (header >> 8) ^ ObHeaderCookie`, truncated to a byte. Writing
    /// the slot number straight into the header would make the fixture a
    /// pre-Windows-10 image wearing a Windows 11 build number, and would let a
    /// sweep that resolves indexes without the cookie look correct here while
    /// naming a fifth of a real image's objects wrongly.
    fn mixed_type_index(header: u64, real: u8) -> u8 {
        let mixed = (header >> 8) ^ u64::from(HEADER_COOKIE) ^ u64::from(real);
        (mixed & 0xFF) as u8
    }

    /// Give an allocation's object a name, by filling in the
    /// `_OBJECT_HEADER_NAME_INFO` in front of its header and setting the
    /// `InfoMask` bit that announces it.
    fn put_object_name(image: &mut Image, pool_base: u64, buffer: u64, text: &str) {
        image.put_u8(
            header_of(pool_base) + off::OH_INFO_MASK,
            off::INFO_MASK_NAME,
        );
        put_unicode(
            image,
            name_info_of(pool_base) + off::NAME_INFO_NAME,
            buffer,
            text,
        );
    }

    /// The object manager's type table: 1 is File, 2 is Mutant, 3 is
    /// SymbolicLink. Slot 0 is null, as a real table's is, and the first null
    /// after it ends the table.
    fn put_type_table(image: &mut Image) {
        image.put_u8(HEADER_COOKIE_AT, HEADER_COOKIE);
        image.put_u64(TYPE_TABLE_AT, 0);
        image.put_u64(TYPE_TABLE_AT + 8, TYPE_FILE_AT);
        image.put_u64(TYPE_TABLE_AT + 16, TYPE_MUTANT_AT);
        image.put_u64(TYPE_TABLE_AT + 24, TYPE_LINK_AT);
        image.put_u64(TYPE_TABLE_AT + 32, 0);
        put_unicode(
            image,
            TYPE_FILE_AT + off::OBJECT_TYPE_NAME,
            TYPE_FILE_NAME_AT,
            "File",
        );
        put_unicode(
            image,
            TYPE_MUTANT_AT + off::OBJECT_TYPE_NAME,
            TYPE_MUTANT_NAME_AT,
            "Mutant",
        );
        put_unicode(
            image,
            TYPE_LINK_AT + off::OBJECT_TYPE_NAME,
            TYPE_LINK_NAME_AT,
            "SymbolicLink",
        );
    }

    /// `ObpInfoMaskToOffset`, indexed by the low two bits of `InfoMask`.
    ///
    /// Index 2 means "a name info and no creator info", so the name info sits
    /// its own size in front of the object header. Index 1 means "a creator
    /// info and no name info", where a zero says the object has no name at all.
    fn put_info_mask_table(image: &mut Image) {
        let distances: [u8; 4] = [0, 0, off::NAME_INFO_SIZE as u8, off::NAME_INFO_SIZE as u8];
        for (index, distance) in distances.iter().enumerate() {
            image.put_u8(INFO_MASK_TABLE_AT + index as u64, *distance);
        }
    }

    /// An image holding one open file, one named mutant and one freed symbolic
    /// link, plus the tables that let their types and names be resolved.
    fn populated_image() -> Image {
        let mut image = Image::new();
        put_type_table(&mut image);
        put_info_mask_table(&mut image);

        // A device object, so the file's path can be device-qualified. It is
        // not swept for; it only has to be reachable and named.
        let device = put_executive(&mut image, DEVICE_ALLOC, b"Devi", 2, 16, 0);
        put_object_name(&mut image, DEVICE_ALLOC, DEVICE_NAME_AT, "HarddiskVolume2");

        let file = put_executive(&mut image, FILE_ALLOC, b"File", 2, 32, 1);
        image.put_u64(file + off::FILE_DEVICE_OBJECT, device);
        image.put_u8(file + off::FILE_READ_ACCESS, 1);
        image.put_u8(file + off::FILE_WRITE_ACCESS, 1);
        image.put_u8(file + off::FILE_DELETE_ACCESS, 0);
        image.put_u8(file + off::FILE_SHARED_READ, 1);
        image.put_u8(file + off::FILE_SHARED_WRITE, 0);
        image.put_u8(file + off::FILE_SHARED_DELETE, 0);
        put_unicode(
            &mut image,
            file + off::FILE_NAME,
            FILE_PATH_AT,
            "\\Windows\\System32\\evil.dll",
        );

        let mutant = put_executive(&mut image, MUTANT_ALLOC, b"Muta", 2, 16, 2);
        image.put_u32(mutant + off::MUTANT_SIGNAL_STATE, 0);
        image.put_u64(mutant + off::MUTANT_OWNER_THREAD, OWNER_THREAD);
        image.put_u8(mutant + off::MUTANT_ABANDONED, 0);
        put_object_name(
            &mut image,
            MUTANT_ALLOC,
            MUTANT_NAME_AT,
            "Global\\SingleInstanceMarker",
        );

        // A freed symbolic link: PoolType 0 marks a free allocation, which is
        // exactly the historical object a pool sweep exists to find.
        let link = put_executive(&mut image, LINK_ALLOC, b"Symb", 0, 16, 3);
        image.put_u64(link + off::LINK_CREATION_TIME, 132_000_000_000_000_000);
        put_unicode(
            &mut image,
            link + off::LINK_TARGET,
            LINK_TARGET_AT,
            "\\Device\\HarddiskVolume2",
        );
        put_object_name(&mut image, LINK_ALLOC, LINK_NAME_AT, "C:");

        image
    }

    fn win10_profile(image: Image, isf: &str) -> WindowsProfile {
        profile(
            image.layer(),
            table(isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    fn sweep(profile: &WindowsProfile) -> ObjectScanOutcome {
        let symbols = ObjectSymbols::from_profile(profile).expect("a describable build");
        scan_objects(profile, &symbols, &ObjectScanConfig::default()).expect("a runnable sweep")
    }

    // ── The three kinds ─────────────────────────────────────────────────────

    #[test]
    fn a_file_object_in_the_pool_yields_the_path_that_was_open() {
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let file = outcome
            .files
            .iter()
            .find(|f| f.address == body_of(FILE_ALLOC))
            .unwrap_or_else(|| panic!("the file object was recovered: {:?}", outcome.files));
        assert_eq!(
            file.path.name(),
            Some("\\Windows\\System32\\evil.dll"),
            "{:?}",
            file.path
        );
    }

    #[test]
    fn a_file_objects_path_is_qualified_with_the_device_it_sits_on() {
        // `\Windows\notepad.exe` on its own is ambiguous across volumes, so the
        // device prefix is what makes the row identify one file rather than one
        // file per volume.
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let file = outcome.files.first().expect("one file object");
        assert_eq!(
            file.name.text(),
            Some("\\Device\\HarddiskVolume2\\Windows\\System32\\evil.dll")
        );
    }

    #[test]
    fn a_file_objects_access_flags_are_read_as_the_object_recorded_them() {
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let file = outcome.files.first().expect("one file object");
        assert_eq!(file.access.read, Some(true));
        assert_eq!(file.access.write, Some(true));
        assert_eq!(file.access.delete, Some(false));
        assert_eq!(file.access.shared_read, Some(true));
        assert_eq!(file.access.shared_write, Some(false));
        assert_eq!(file.access.shared_delete, Some(false));
    }

    #[test]
    fn a_named_mutant_reports_the_name_malware_uses_to_avoid_running_twice() {
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let mutant = outcome.mutants.first().expect("one mutant");
        assert_eq!(mutant.name.text(), Some("Global\\SingleInstanceMarker"));
        assert_eq!(mutant.owner_thread, Some(OWNER_THREAD));
        assert_eq!(mutant.abandoned, Some(false));
        assert_eq!(mutant.signal_state, Some(0));
    }

    #[test]
    fn a_symbolic_link_maps_its_alias_onto_the_device_it_names() {
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let link = outcome.links.first().expect("one symbolic link");
        assert_eq!(link.name.text(), Some("C:"));
        assert_eq!(link.target.name(), Some("\\Device\\HarddiskVolume2"));
        assert_eq!(link.creation_time, Some(132_000_000_000_000_000));
    }

    #[test]
    fn an_object_recovered_from_a_freed_allocation_is_marked_as_historical() {
        // The whole point of a pool sweep: this link's allocation was already
        // freed, so no live-system tool could have shown it.
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let link = outcome.links.first().expect("one symbolic link");
        assert!(link.provenance.freed);
        let file = outcome.files.first().expect("one file object");
        assert!(!file.provenance.freed);
        assert_eq!(outcome.freed_count(), 1);
    }

    #[test]
    fn the_object_manager_type_is_compared_against_the_tag_and_recorded_as_verified() {
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let file = outcome.files.first().expect("one file object");
        assert_eq!(file.provenance.object_type.as_deref(), Some("File"));
        assert!(file.provenance.type_verified);
        assert_eq!(outcome.unverified_type_count(), 0);
    }

    #[test]
    fn the_named_files_view_offers_only_the_paths_that_were_actually_read() {
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let named: Vec<&str> = outcome.named_files().map(|(_, name)| name).collect();
        assert_eq!(named, vec!["\\Windows\\System32\\evil.dll"]);
    }

    // ── Failure paths ───────────────────────────────────────────────────────

    #[test]
    fn an_allocation_the_object_manager_calls_something_else_is_not_reported_as_a_file() {
        // The tag says File; the object manager's own table says Mutant.
        // Reporting it would put a path in the table that the kernel never
        // associated with a file, in a row that reads exactly like a correct
        // one.
        let mut image = populated_image();
        let header = header_of(FILE_ALLOC);
        image.put_u8(header + off::OH_TYPE_INDEX, mixed_type_index(header, 2));
        let outcome = sweep(&win10_profile(image, &objects_isf()));
        assert!(outcome.files.is_empty(), "{:?}", outcome.files);
        assert!(
            outcome.sweep.rejected.iter().any(|r| r.tag == "File"),
            "the sweep records the tag it rejected: {:?}",
            outcome.sweep.rejected
        );
        // The other two are untouched, so the rejection is specific and not a
        // collapse of the whole sweep.
        assert_eq!(outcome.mutants.len(), 1);
        assert_eq!(outcome.links.len(), 1);
    }

    #[test]
    fn a_type_table_that_cannot_be_unmixed_is_refused_rather_than_resolved_wrongly() {
        // From Windows 10 an object header's `TypeIndex` is mixed with the
        // header's own address and the per-boot `ObHeaderCookie`. Without the
        // cookie the unmixed byte lands on some other type about one time in
        // five and on no type the rest of the time, so a sweep that resolves
        // anyway either rejects sound objects as the wrong kind or admits them
        // under a name the kernel never gave them — with `type_verified` set on
        // the row either way. The handle walk has always refused such a map;
        // the object sweep took it.
        let profile = win10_profile(populated_image(), &objects_isf_without_cookie());
        let symbols = ObjectSymbols::from_profile(&profile).expect("a describable build");

        assert!(
            symbols.type_map.is_none(),
            "a map that cannot be unmixed must not be handed to the sweep"
        );
        let reason = symbols
            .type_map_unavailable
            .as_deref()
            .expect("the refusal states its reason");
        assert!(reason.contains("ObHeaderCookie"), "{reason}");
        assert!(reason.contains("22000"), "{reason}");

        let outcome =
            scan_objects(&profile, &symbols, &ObjectScanConfig::default()).expect("a sweep");
        // The objects are still recovered on their tag and structure — refusing
        // the map is not refusing the evidence.
        assert_eq!(outcome.files.len(), 1, "{:?}", outcome.files);
        assert_eq!(outcome.mutants.len(), 1);
        assert_eq!(outcome.links.len(), 1);
        // But not one of them may claim the object manager agreed.
        assert_eq!(outcome.unverified_type_count(), 3);
        assert!(!outcome.is_complete());
        assert!(
            outcome
                .incomplete
                .iter()
                .any(|i| i.detail.contains("ObHeaderCookie")),
            "the report must be told why no type was verified: {:?}",
            outcome.incomplete
        );

        // The same image with the cookie present resolves, so the refusal is
        // about the missing cookie and not about the fixture.
        let sound = sweep(&win10_profile(populated_image(), &objects_isf()));
        assert_eq!(sound.unverified_type_count(), 0);
    }

    #[test]
    fn a_kind_this_build_cannot_describe_is_reported_as_not_swept_for_not_as_absent() {
        // The distinction the whole stage turns on: an empty mutant list here
        // would read as a machine with no mutants, which is never true.
        let profile = win10_profile(populated_image(), &objects_isf_without_mutant());
        let symbols = ObjectSymbols::from_profile(&profile).expect("files and links still work");
        assert!(symbols.mutant.is_none());
        let outcome =
            scan_objects(&profile, &symbols, &ObjectScanConfig::default()).expect("a sweep");
        let mutants = outcome
            .kinds
            .iter()
            .find(|k| k.kind == ObjectKind::Mutant)
            .expect("mutants have a status");
        assert!(!mutants.swept);
        assert_eq!(mutants.found, 0);
        assert!(mutants
            .detail
            .as_deref()
            .expect("a stated reason")
            .contains("_KMUTANT"));
        assert!(!outcome.is_complete());
        assert!(outcome.incomplete.iter().any(|i| i
            .detail
            .contains("says nothing about whether the machine had any")));
        // And the kinds that could be described still ran.
        assert_eq!(outcome.files.len(), 1);
        assert_eq!(outcome.links.len(), 1);
    }

    #[test]
    fn a_kind_that_was_swept_for_and_found_nothing_is_complete_and_says_so() {
        // The opposite of the test above, and the reason the two must never
        // render the same way.
        let mut image = Image::new();
        put_type_table(&mut image);
        put_info_mask_table(&mut image);
        let outcome = sweep(&win10_profile(image, &objects_isf()));
        assert!(outcome.files.is_empty());
        assert!(outcome.mutants.is_empty());
        assert!(outcome.links.is_empty());
        assert!(
            outcome.kinds.iter().all(|kind| kind.swept),
            "{:?}",
            outcome.kinds
        );
        assert!(outcome.is_complete(), "{:?}", outcome.incomplete);
    }

    #[test]
    fn a_build_describing_none_of_the_three_kinds_is_refused_rather_than_swept() {
        let isf = objects_isf()
            .replace(
                r#""_FILE_OBJECT": {"size": 216,"#,
                r#""_FILE_OBJECT_RENAMED": {"size": 216,"#,
            )
            .replace(
                r#""_KMUTANT": {"size": 64,"#,
                r#""_KMUTANT_RENAMED": {"size": 64,"#,
            )
            .replace(
                r#""_OBJECT_SYMBOLIC_LINK": {"size": 80,"#,
                r#""_OBJECT_SYMBOLIC_LINK_RENAMED": {"size": 80,"#,
            );
        let profile = win10_profile(populated_image(), &isf);
        let err = ObjectSymbols::from_profile(&profile).expect_err("nothing can be decoded");
        let text = err.to_string();
        assert!(text.contains("_FILE_OBJECT"), "{text}");
        assert!(text.contains("_KMUTANT"), "{text}");
        assert!(text.contains("_OBJECT_SYMBOLIC_LINK"), "{text}");
        assert_eq!(err.class(), "unsupported_build");
    }

    #[test]
    fn a_file_object_whose_name_member_is_missing_makes_the_whole_kind_unavailable() {
        // Losing the path is losing the point of the row, so the kind is not
        // swept for at all rather than producing a list of pathless files.
        let isf = objects_isf().replace(
            r#""FileName": {"offset": 24, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}"#,
            r#""FileNameRenamed": {"offset": 24, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}"#,
        );
        let profile = win10_profile(populated_image(), &isf);
        let symbols = ObjectSymbols::from_profile(&profile).expect("mutants and links still work");
        assert!(symbols.file.is_none());
        assert!(symbols
            .file_unavailable
            .as_deref()
            .expect("a stated reason")
            .contains("FileName"));
    }

    #[test]
    fn a_name_that_could_not_be_read_is_not_reported_as_a_nameless_object() {
        // The mutant declares a name and its buffer pointer is null. An empty
        // name column here would say the mutant was unnamed, which is the
        // opposite of what the evidence shows.
        let mut image = populated_image();
        image.put_u64(
            name_info_of(MUTANT_ALLOC) + off::NAME_INFO_NAME + off::UNICODE_BUFFER,
            0,
        );
        let outcome = sweep(&win10_profile(image, &objects_isf()));
        let mutant = outcome.mutants.first().expect("the mutant is still found");
        assert!(
            mutant.name.is_unavailable(),
            "a declared length with a null buffer is a gap, not an absence: {:?}",
            mutant.name
        );
    }

    #[test]
    fn an_unnamed_mutant_is_reported_as_unnamed_and_not_as_unreadable() {
        let mut image = populated_image();
        // An `InfoMask` of zero: this object simply has no name info, which
        // most kernel objects do not.
        image.put_u8(header_of(MUTANT_ALLOC) + off::OH_INFO_MASK, 0);
        let outcome = sweep(&win10_profile(image, &objects_isf()));
        let mutant = outcome.mutants.first().expect("the mutant is still found");
        assert_eq!(mutant.name, HandleName::Unnamed);
    }

    #[test]
    fn a_file_object_whose_path_will_not_decode_keeps_its_row_and_says_why() {
        // Upstream drops the row. A file object that exists is evidence even
        // when the member naming it was never acquired intact.
        let mut image = populated_image();
        let file = body_of(FILE_ALLOC);
        // An odd byte length: no `_UNICODE_STRING` holds half a UTF-16 unit, so
        // the string is malformed rather than absent.
        image.put_u16(file + off::FILE_NAME + off::UNICODE_LENGTH, 0xFFFF);
        image.put_u16(file + off::FILE_NAME + off::UNICODE_MAX_LENGTH, 0xFFFF);
        let outcome = sweep(&win10_profile(image, &objects_isf()));
        let record = outcome.files.first().expect("the row survives");
        assert!(
            matches!(record.path, NameField::Unavailable(_)),
            "{:?}",
            record.path
        );
        assert!(!record.path.is_known());
    }

    #[test]
    fn a_cap_that_fires_is_reported_as_a_cap_and_never_as_the_end_of_the_image() {
        let profile = win10_profile(populated_image(), &objects_isf());
        let symbols = ObjectSymbols::from_profile(&profile).expect("a describable build");
        let config = ObjectScanConfig {
            max_per_kind: 0,
            ..ObjectScanConfig::default()
        };
        let outcome = scan_objects(&profile, &symbols, &config).expect("a runnable sweep");
        assert!(outcome.files.is_empty());
        assert!(
            outcome.kinds.iter().all(|kind| kind.capped),
            "{:?}",
            outcome.kinds
        );
        assert!(!outcome.is_complete());
        assert!(outcome
            .incomplete
            .iter()
            .any(|i| i.detail.contains("the image was not exhausted")));
    }

    #[test]
    fn every_recovered_object_reaches_the_artifact_json() {
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        let value = outcome.to_json();
        assert_eq!(value["file_count"], 1);
        assert_eq!(value["mutant_count"], 1);
        assert_eq!(value["link_count"], 1);
        assert_eq!(value["freed_count"], 1);
        assert_eq!(value["unverified_type_count"], 0);
        assert_eq!(value["complete"], true);
        assert_eq!(value["kinds"].as_array().expect("three kinds").len(), 3);
        assert_eq!(
            value["files"][0]["path"]["name"],
            "\\Windows\\System32\\evil.dll"
        );
        assert_eq!(value["links"][0]["provenance"]["freed"], true);
        assert_eq!(value["mutants"][0]["name"]["kind"], "name");
    }

    #[test]
    fn the_space_that_was_swept_travels_with_the_result() {
        // Which space was swept bounds what could have been found, so it is not
        // an implementation detail an examiner can be left to guess at.
        let outcome = sweep(&win10_profile(populated_image(), &objects_isf()));
        assert_eq!(outcome.space(), ScanSpace::KernelVirtual);
        assert_eq!(outcome.to_json()["sweep"]["space"], "kernel_virtual");
    }

    #[test]
    fn the_symbols_report_which_kinds_this_build_can_be_asked_about() {
        let profile = win10_profile(populated_image(), &objects_isf_without_mutant());
        let symbols = ObjectSymbols::from_profile(&profile).expect("two kinds remain");
        let value = symbols.to_json();
        assert_eq!(value["file_available"], true);
        assert_eq!(value["mutant_available"], false);
        assert_eq!(value["symlink_available"], true);
        assert!(value["mutant_unavailable"].is_string());
        assert_eq!(symbols.tags().len(), 4);
    }

    /// Zero in a dispatcher header's `SignalState` means the mutant is *held*.
    ///
    /// A value the build declares at a width this stage cannot represent must
    /// therefore not be folded into zero: that manufactures "some thread was
    /// holding this mutant when the plug was pulled" out of bytes nobody could
    /// read as a state at all.
    #[test]
    fn a_signal_state_that_is_not_a_state_is_not_reported_as_a_held_mutant() {
        let isf = objects_isf().replace(
            r#""SignalState": {"offset": 4, "type": {"kind": "base", "name": "long"}}"#,
            r#""SignalState": {"offset": 8, "type": {"kind": "base", "name": "unsigned long long"}}"#,
        );
        assert!(
            isf.contains(r#""SignalState": {"offset": 8,"#),
            "the fixture's SignalState must have been re-declared wide and unsigned"
        );
        let mut image = populated_image();
        // Past `i64::MAX`, so it cannot be represented as a signed state.
        image.put_u64(body_of(MUTANT_ALLOC) + 8, u64::MAX);
        let profile = win10_profile(image, &isf);
        let outcome = sweep(&profile);

        let mutant = outcome
            .mutants
            .first()
            .expect("the mutant is still recovered");
        assert_eq!(
            mutant.signal_state, None,
            "an unrepresentable value must not read as a held mutant"
        );
        assert!(
            mutant
                .notes
                .iter()
                .any(|note| note.contains("not a dispatcher signal state")),
            "the reason must reach the row: {:?}",
            mutant.notes
        );
    }
}
