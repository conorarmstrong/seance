//! Process tampering: where a running image stops matching the file it claims.
//!
//! A process is created from a file. The kernel records where it mapped that
//! file, the loader records where it thinks the image is, and the VAD backing
//! that address records which file — if any — is mapped there. On an untampered
//! system those three agree. Hollowing, ghosting and image replacement all work
//! by breaking one of them, and each break leaves a different residue:
//!
//! | Technique | What breaks |
//! |---|---|
//! | Hollowing | the image range is unmapped and replaced, so the VAD backing it is private rather than file-backed |
//! | Image-base rewriting | `_PEB.ImageBaseAddress` is edited to point somewhere the kernel never mapped |
//! | Doppelgänging / herpaderping | the VAD names a file, but not the one the process claims to be |
//! | Ghosting | the file was deleted before the section was created, so the process's `_FILE_OBJECT` is marked for deletion or is gone entirely |
//!
//! # This module reports signals, not verdicts
//!
//! A memory image cannot establish that a process is malicious, and nothing
//! here says so. What it can establish is a *disagreement between two records
//! that a normal process keeps consistent*, and that is what a
//! [`TamperSignal`] is: a named comparison, both values, and where each came
//! from. "The range backing this process's entry point is private memory with
//! `PAGE_EXECUTE_READWRITE` protection, and the loader names
//! `C:\Windows\System32\svchost.exe`" is a statement this image supports.
//! "This process is hollowed" is a conclusion an examiner draws, in a report
//! they sign.
//!
//! # Absence of a signal is not absence of tampering
//!
//! Every check here can fail to run: a build without `ImageFilePointer` cannot
//! be checked for ghosting, a paged-out PEB cannot be compared with anything, a
//! VAD tree that was not fully walked cannot support "there is no range at this
//! address". Each of those lands in [`ProcessTampering::not_checked`] naming
//! the check and the reason, and a process with an empty signal list and a
//! non-empty `not_checked` list has **not** been cleared. Rendering the two the
//! same is the failure this module is shaped to prevent, which is why no method
//! returns a bare boolean "clean".
//!
//! # What a wrong answer looks like
//!
//! * A mapped file whose *name* could not be read, reported as a range with no
//!   file behind it. That is the signature of hollowing, manufactured out of an
//!   unacquired page. [`MappedFile::Unavailable`] never becomes a signal here.
//! * A VAD tree that stopped at its cap, reported as "no range backs the image
//!   base". The range may be one node past where the walk stopped.
//! * A comparison of the VAD's `\Device\HarddiskVolume2\…` path against the
//!   PEB's `C:\…` path as whole strings. They never match, on any machine, so
//!   every process would be reported. Only the final component is compared, and
//!   the rule is written down in [`final_component`].
//! * `_EPROCESS.ImageFileName` compared as a whole against a longer name. The
//!   member is a fixed 15- or 16-byte array with no terminator when a name
//!   fills it, so `SomeVeryLongNam` is what the kernel holds for
//!   `SomeVeryLongName.exe`.

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{Obj, StructReader};
use seance_memory::translate::TableCache;
use seance_memory::Incomplete;

use crate::poolscan::unicode_string;
use crate::process::{
    process_address_space, Field, ProcessError, ProcessInventory, ProcessList, ProcessRecord,
    ProcessSymbols, TYPE_EPROCESS, TYPE_PEB, TYPE_PROCESS_PARAMETERS,
};
use crate::profile::WindowsProfile;
use crate::vad::{
    base_protection, list_vads, MappedFile, Vad, VadError, VadSymbols, VadTree, VadWalkConfig,
    TYPE_FILE_OBJECT,
};

// ── Names this stage reads through ──────────────────────────────────────────

/// `_EPROCESS` member holding the address the kernel mapped the process's
/// image at.
///
/// The load-bearing value of the whole module. It is written once, by the
/// kernel, when the section is mapped, and — unlike `_PEB.ImageBaseAddress` —
/// it is not in the process's own address space, so the process cannot edit it.
pub const MEMBER_SECTION_BASE_ADDRESS: &str = "SectionBaseAddress";

/// `_EPROCESS` member holding the `_FILE_OBJECT` the image was created from.
///
/// Added in Windows 10. Its absence on an older build is not a finding; its
/// being **null** on a build that has it is.
pub const MEMBER_IMAGE_FILE_POINTER: &str = "ImageFilePointer";

/// `_PEB` member holding where the loader believes the image is.
///
/// In the process's own address space, so the process can write it, which is
/// exactly why a disagreement with `SectionBaseAddress` is worth reporting.
pub const MEMBER_IMAGE_BASE_ADDRESS: &str = "ImageBaseAddress";

/// `_PEB` member pointing at the parameter block.
pub const MEMBER_PROCESS_PARAMETERS: &str = "ProcessParameters";

/// `_RTL_USER_PROCESS_PARAMETERS` member holding the path the process was
/// started from, as the loader recorded it.
pub const MEMBER_IMAGE_PATH_NAME: &str = "ImagePathName";

/// `_FILE_OBJECT` member set when the file is to be removed once the last
/// handle closes.
pub const MEMBER_DELETE_PENDING: &str = "DeletePending";

/// `_FILE_OBJECT` member holding the file's path.
pub const MEMBER_FILE_NAME: &str = "FileName";

/// The protection a legitimately mapped executable image carries.
///
/// An image section is mapped copy-on-write: the pages are executable, and a
/// write to one gives the process a private copy rather than modifying the
/// file. Anything else on the range backing a process's own executable means
/// the range was not created by mapping that executable.
pub const EXPECTED_IMAGE_PROTECTION: &str = "PAGE_EXECUTE_WRITECOPY";

/// WinNT protection bits that make a page executable.
pub const EXECUTE_BITS: u32 = 0x10 | 0x20 | 0x40 | 0x80;

/// WinNT protection bits that make a page **directly** writable.
///
/// Copy-on-write (`0x08`, `0x80`) is deliberately not here. A write to a
/// copy-on-write page does not change the mapped file, and every mapped image
/// on the machine is copy-on-write, so counting it as writable would report
/// every process. "Writable and executable" means the page can be modified in
/// place and then run, which is what shellcode needs and what a mapped image
/// never has.
pub const DIRECT_WRITE_BITS: u32 = 0x04 | 0x40;

/// The first Windows major version whose `_EPROCESS` declares
/// [`MEMBER_IMAGE_FILE_POINTER`].
pub const IMAGE_FILE_POINTER_MAJOR: u32 = 10;

/// Value of `_FILE_OBJECT.DeletePending` that means the file is going away.
pub const DELETE_PENDING_SET: u64 = 1;

/// Ceiling on processes one scan will examine.
///
/// Each one costs a VAD-tree walk and a page-table walk, so this bounds the
/// work a corrupt or crafted process list can demand. Reaching it is reported
/// as a cap, never as the end of the list.
pub const MAX_EXAMINED_PROCESSES: usize = 4_096;

/// Ceiling on individually recorded skipped processes. The *count* stays exact.
pub const MAX_RECORDED_SKIPS: usize = 256;

/// Ceiling on individually recorded notes per process. The *count* stays exact.
pub const MAX_RECORDED_NOTES: usize = 64;

/// How many mapped ranges a process must have before its image is compared.
///
/// A process caught during creation or teardown has a handful of VADs and no
/// meaningful image mapping yet, and comparing one produces a signal about the
/// acquisition rather than about the process. Upstream drops such processes
/// silently; here the checks are recorded as *not made*, with this number in
/// the reason, so the process still appears and nobody reads its empty signal
/// list as a clean bill of health. Set to zero to compare every process.
pub const MIN_IMAGE_VADS: usize = 5;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops this stage before it can examine anything.
///
/// Note what is *not* here: a check that could not be made for one process.
/// That is a fact about one structure, and it lands in
/// [`ProcessTampering::not_checked`] where an examiner can count it.
#[derive(Debug, thiserror::Error)]
pub enum HollowError {
    /// This build cannot be examined for tampering with what is available, and
    /// no partial answer would be honest. The message names what is missing.
    #[error("processes on this build cannot be examined for tampering: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// The VAD layout could not be established, so no process's mapped ranges
    /// can be read.
    #[error(transparent)]
    Vad(#[from] VadError),

    /// The process layout could not be established.
    #[error(transparent)]
    Process(#[from] ProcessError),
}

impl HollowError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            HollowError::Unsupported { .. } => "unsupported_build",
            HollowError::Vad(err) => err.class(),
            HollowError::Process(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            HollowError::Unsupported { .. } => IncompleteReason::UnresolvedStructure,
            HollowError::Vad(err) => err.incomplete_reason(),
            HollowError::Process(err) => err.incomplete_reason(),
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be examined" refusal.
    pub fn unsupported(detail: impl Into<String>) -> HollowError {
        HollowError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Resolve the first of `candidates` that this build's `type_name` actually has.
///
/// Dotted paths are resolved through the symbol table rather than
/// `has_member`, which only answers about a type's own top-level members.
///
/// This module used to carry its own copy, which returned a bare `Option` built
/// from `member_offset(..).is_ok()` and so reported "the symbol table could not
/// answer" as "this build has no such member". Those are opposite claims and the
/// shared helper keeps them apart; there is one definition of it so the two
/// cannot drift.
use seance_memory::binding::first_member;

/// A symbol-table failure as the one sentence the layout resolvers return.
///
/// Kept distinct from "this build has no such member" everywhere it is used:
/// the first says the evidence about layout is damaged, the second is a claim
/// about the machine the image came from.
fn unreadable_table(err: seance_memory::object::ObjError) -> String {
    format!("the symbol table could not be read, so this build's layout is unknown: {err}")
}

/// What the image-comparison checks need, when this build declares it.
///
/// Held together because they are useless apart: the whole comparison is
/// "where the kernel mapped the image" against "where the loader says it is",
/// and a build with one and not the other supports neither side of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageLayout {
    /// `_EPROCESS` member holding the pointer to the process environment block.
    pub peb: String,
    /// `_EPROCESS` member holding the kernel-recorded image base.
    pub section_base: String,
    /// `_PEB` member holding the loader's image base.
    pub image_base: String,
    /// `_PEB` member pointing at the parameter block, when this build has one.
    pub process_parameters: Option<String>,
    /// `_RTL_USER_PROCESS_PARAMETERS` member holding the started-from path,
    /// when this build has both it and [`ImageLayout::process_parameters`].
    pub image_path_name: Option<String>,
}

/// What the ghosting check needs, when this build declares it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GhostLayout {
    /// `_EPROCESS` member holding the image's file object.
    pub image_file_pointer: String,
    /// `_FILE_OBJECT` member holding the delete-pending flag, when this build
    /// declares one. Without it the pointer can still be checked for null.
    pub delete_pending: Option<String>,
    /// `_FILE_OBJECT` member holding the path, for reporting which file it is.
    pub file_name: Option<String>,
}

/// The member paths this build's tampering checks are read through.
///
/// Resolved once per image and checked once, so a build whose layout is
/// unknown fails here naming the members that were tried rather than at
/// process three hundred having already emitted comparisons made at the wrong
/// offsets.
///
/// The two check families are resolved independently. A build with an
/// `ImageFilePointer` and no `SectionBaseAddress` can still be examined for
/// ghosting, and one with the reverse can still have its image compared; only
/// a build with **neither** is refused outright.
#[derive(Debug, Clone)]
pub struct HollowSymbols {
    /// The process layout, used to build each process's own address space.
    pub process: ProcessSymbols,
    /// The VAD layout, used to find the range backing each process's image.
    pub vad: VadSymbols,
    /// The image-comparison layout, when this build supports it.
    pub image: Option<ImageLayout>,
    /// Why [`HollowSymbols::image`] is absent, when it is. Carried so the
    /// refusal an examiner sees names the missing member rather than leaving a
    /// blank column.
    pub image_unavailable: Option<String>,
    /// The ghosting layout, when this build supports it.
    pub ghost: Option<GhostLayout>,
    /// Why [`HollowSymbols::ghost`] is absent, when it is.
    pub ghost_unavailable: Option<String>,
    /// Whether a build of this family is expected to declare
    /// [`MEMBER_IMAGE_FILE_POINTER`] at all. False for everything before
    /// Windows 10, where its absence is ordinary rather than notable.
    pub expects_image_file_pointer: bool,
    /// Declared width of `_EPROCESS.ImageFileName`, in bytes.
    ///
    /// Needed to compare a name with a mapped file's: a recorded name at
    /// exactly this width was truncated, and is a prefix of the real one rather
    /// than a different name.
    pub image_name_width: u64,
}

impl HollowSymbols {
    /// Resolve every layout fact the tampering checks of this image need.
    ///
    /// # Errors
    ///
    /// [`HollowError::Unsupported`] naming **both** missing member sets when
    /// this build supports neither the image comparison nor the ghosting
    /// check, because there would then be nothing to report and an empty
    /// result would read like a clean machine.
    /// [`HollowError::Vad`] and [`HollowError::Process`] when the layouts this
    /// stage builds on cannot be described at all.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, HollowError> {
        let process = ProcessSymbols::from_profile(profile)?;
        let vad = VadSymbols::from_profile(profile)?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        let (image, image_unavailable) = match resolve_image(&reader, profile) {
            Ok(layout) => (Some(layout), None),
            Err(detail) => (None, Some(detail)),
        };
        let expects_image_file_pointer = profile.build.major >= IMAGE_FILE_POINTER_MAJOR;
        let (ghost, ghost_unavailable) =
            match resolve_ghost(&reader, profile, expects_image_file_pointer) {
                Ok(layout) => (Some(layout), None),
                Err(detail) => (None, Some(detail)),
            };

        if image.is_none() && ghost.is_none() {
            let image_detail = image_unavailable.unwrap_or_default();
            let ghost_detail = ghost_unavailable.unwrap_or_default();
            return Err(HollowError::unsupported(format!(
                "{image_detail}; and {ghost_detail}"
            )));
        }

        Ok(Self {
            image_name_width: process.image_name_len,
            process,
            vad,
            image,
            image_unavailable,
            ghost,
            ghost_unavailable,
            expects_image_file_pointer,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "image": self.image.as_ref().map(|image| serde_json::json!({
                "peb": image.peb,
                "section_base": image.section_base,
                "image_base": image.image_base,
                "process_parameters": image.process_parameters,
                "image_path_name": image.image_path_name,
            })),
            "image_unavailable": self.image_unavailable,
            "ghost": self.ghost.as_ref().map(|ghost| serde_json::json!({
                "image_file_pointer": ghost.image_file_pointer,
                "delete_pending": ghost.delete_pending,
                "file_name": ghost.file_name,
            })),
            "ghost_unavailable": self.ghost_unavailable,
            "expects_image_file_pointer": self.expects_image_file_pointer,
            "image_name_width": self.image_name_width,
        })
    }
}

/// Resolve the image-comparison side, or say in one sentence why it cannot be.
fn resolve_image(reader: &StructReader, profile: &WindowsProfile) -> Result<ImageLayout, String> {
    let section_base = first_member(reader, TYPE_EPROCESS, &[MEMBER_SECTION_BASE_ADDRESS])
        .map_err(unreadable_table)?
        .ok_or_else(|| {
            format!(
                "'{TYPE_EPROCESS}' has no {MEMBER_SECTION_BASE_ADDRESS}, so where the kernel \
                 mapped a process's image is unknown and nothing can be compared with it"
            )
        })?
        .to_string();
    let peb = first_member(reader, TYPE_EPROCESS, &["Peb"])
        .map_err(unreadable_table)?
        .ok_or_else(|| {
            format!(
                "'{TYPE_EPROCESS}' has no Peb, so the loader's own record of where the image is \
                 cannot be reached"
            )
        })?
        .to_string();
    if !profile.symbols.has_type(TYPE_PEB) {
        return Err(format!(
            "the symbol table has no '{TYPE_PEB}', so the loader's own record of where the image \
             is cannot be read"
        ));
    }
    let image_base = first_member(reader, TYPE_PEB, &[MEMBER_IMAGE_BASE_ADDRESS])
        .map_err(unreadable_table)?
        .ok_or_else(|| {
            format!(
                "'{TYPE_PEB}' has no {MEMBER_IMAGE_BASE_ADDRESS}, so the loader's image base \
                 cannot be compared with the kernel's"
            )
        })?
        .to_string();

    // The started-from path is a second, independent opinion about which file
    // the process is. It is optional: without it the mapped file is compared
    // only against the fifteen bytes of `ImageFileName`.
    let process_parameters = first_member(reader, TYPE_PEB, &[MEMBER_PROCESS_PARAMETERS])
        .map_err(unreadable_table)?
        .map(str::to_string);
    let image_path_name = if profile.symbols.has_type(TYPE_PROCESS_PARAMETERS) {
        first_member(reader, TYPE_PROCESS_PARAMETERS, &[MEMBER_IMAGE_PATH_NAME])
            .map_err(unreadable_table)?
            .map(str::to_string)
    } else {
        None
    };
    // Half of the pair is no use: the block cannot be reached without the
    // pointer, and the pointer leads nowhere without the member.
    let (process_parameters, image_path_name) = match (process_parameters, image_path_name) {
        (Some(pointer), Some(name)) => (Some(pointer), Some(name)),
        _ => (None, None),
    };

    Ok(ImageLayout {
        peb,
        section_base,
        image_base,
        process_parameters,
        image_path_name,
    })
}

/// Resolve the ghosting side, or say in one sentence why it cannot be.
fn resolve_ghost(
    reader: &StructReader,
    profile: &WindowsProfile,
    expected: bool,
) -> Result<GhostLayout, String> {
    let image_file_pointer = first_member(reader, TYPE_EPROCESS, &[MEMBER_IMAGE_FILE_POINTER])
        .map_err(unreadable_table)?
        .ok_or_else(|| {
            if expected {
                format!(
                    "'{TYPE_EPROCESS}' has no {MEMBER_IMAGE_FILE_POINTER}, although this build's \
                     major version is {} and builds from Windows {IMAGE_FILE_POINTER_MAJOR} \
                     onwards declare it, so either the symbol table does not match this kernel or \
                     a ghosted process cannot be detected from the process structure",
                    profile.build.major
                )
            } else {
                format!(
                    "'{TYPE_EPROCESS}' has no {MEMBER_IMAGE_FILE_POINTER}, which builds before \
                     Windows {IMAGE_FILE_POINTER_MAJOR} do not have, so a ghosted process cannot \
                     be detected from the process structure on this build"
                )
            }
        })?
        .to_string();
    if !profile.symbols.has_type(TYPE_FILE_OBJECT) {
        return Err(format!(
            "the symbol table has no '{TYPE_FILE_OBJECT}', so the file a process was created from \
             cannot be examined"
        ));
    }
    Ok(GhostLayout {
        image_file_pointer,
        delete_pending: first_member(reader, TYPE_FILE_OBJECT, &[MEMBER_DELETE_PENDING])
            .map_err(unreadable_table)?
            .map(str::to_string),
        file_name: first_member(reader, TYPE_FILE_OBJECT, &[MEMBER_FILE_NAME])
            .map_err(unreadable_table)?
            .map(str::to_string),
    })
}

// ── Checks ──────────────────────────────────────────────────────────────────

/// One comparison this stage makes.
///
/// Named as a type rather than as a string so that a check which could not be
/// made is recorded against the same identity as the signal it would have
/// produced, and a report can state "the protection of the image range was not
/// examined" rather than "no protection signal".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TamperCheck {
    /// The loader's image base against the kernel's.
    ImageBase,
    /// Locating the mapped range that backs the image base.
    ImageVad,
    /// Whether that range is backed by a file at all.
    ImageVadFile,
    /// Whether the file it names is the one the process claims to be.
    ImageVadPath,
    /// The protection that range carries.
    ImageVadProtection,
    /// Whether that range is private rather than shared.
    ImageVadPrivate,
    /// Whether the process still names the file it was created from.
    ImageFilePointer,
    /// Whether that file is marked for deletion.
    ImageFileDeletePending,
    /// Whether the **kernel's own** audit record of the image path agrees with
    /// the path the process publishes for itself.
    AuditImagePath,
}

impl TamperCheck {
    /// Every check this stage makes.
    pub const ALL: [TamperCheck; 9] = [
        TamperCheck::ImageBase,
        TamperCheck::ImageVad,
        TamperCheck::ImageVadFile,
        TamperCheck::ImageVadPath,
        TamperCheck::ImageVadProtection,
        TamperCheck::ImageVadPrivate,
        TamperCheck::ImageFilePointer,
        TamperCheck::ImageFileDeletePending,
        TamperCheck::AuditImagePath,
    ];

    /// The checks that need the image-comparison layout.
    pub const IMAGE: [TamperCheck; 6] = [
        TamperCheck::ImageBase,
        TamperCheck::ImageVad,
        TamperCheck::ImageVadFile,
        TamperCheck::ImageVadPath,
        TamperCheck::ImageVadProtection,
        TamperCheck::ImageVadPrivate,
    ];

    /// The checks that need the process's VAD tree.
    pub const VAD: [TamperCheck; 5] = [
        TamperCheck::ImageVad,
        TamperCheck::ImageVadFile,
        TamperCheck::ImageVadPath,
        TamperCheck::ImageVadProtection,
        TamperCheck::ImageVadPrivate,
    ];

    /// The checks that need the range backing the image to have been found.
    pub const BACKED: [TamperCheck; 4] = [
        TamperCheck::ImageVadFile,
        TamperCheck::ImageVadPath,
        TamperCheck::ImageVadProtection,
        TamperCheck::ImageVadPrivate,
    ];

    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            TamperCheck::ImageBase => "image_base",
            TamperCheck::ImageVad => "image_vad",
            TamperCheck::ImageVadFile => "image_vad_file",
            TamperCheck::ImageVadPath => "image_vad_path",
            TamperCheck::ImageVadProtection => "image_vad_protection",
            TamperCheck::ImageVadPrivate => "image_vad_private",
            TamperCheck::ImageFilePointer => "image_file_pointer",
            TamperCheck::ImageFileDeletePending => "image_file_delete_pending",
            TamperCheck::AuditImagePath => "audit_image_path",
        }
    }

    /// What the check would have established, for a report that has to explain
    /// what was not done.
    pub fn describe(self) -> &'static str {
        match self {
            TamperCheck::ImageBase => {
                "whether the loader's image base agrees with the address the kernel mapped the \
                 image at"
            }
            TamperCheck::ImageVad => "which mapped range backs the process's image base",
            TamperCheck::ImageVadFile => "whether that range is backed by a file",
            TamperCheck::ImageVadPath => {
                "whether the file backing that range is the one the process claims to be"
            }
            TamperCheck::ImageVadProtection => "what protection that range carries",
            TamperCheck::ImageVadPrivate => "whether that range is private rather than shared",
            TamperCheck::ImageFilePointer => {
                "whether the process still names the file it was created from"
            }
            TamperCheck::ImageFileDeletePending => {
                "whether the file the process was created from is marked for deletion"
            }
            TamperCheck::AuditImagePath => {
                "whether the kernel's own audit record of the image path agrees with the path \
                 the process publishes for itself"
            }
        }
    }
}

/// A check that could not be made, and why.
///
/// The counterweight to an empty signal list. A process carrying one of these
/// has not been examined for that check, and a report that renders it as
/// "nothing found" is asserting something this image does not support.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NotChecked {
    /// Which comparison was not made.
    pub check: TamperCheck,
    /// Why, in the examiner's terms.
    pub reason: String,
}

impl NotChecked {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "check": self.check.as_str(),
            "establishes": self.check.describe(),
            "reason": self.reason,
        })
    }
}

/// Which of the two image bases a range was located from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BaseSource {
    /// `_EPROCESS.SectionBaseAddress`, which the process cannot write.
    SectionBaseAddress,
    /// `_PEB.ImageBaseAddress`, which it can. Used only when the kernel's own
    /// record was unreadable, and always accompanied by a note saying so.
    PebImageBaseAddress,
}

impl BaseSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            BaseSource::SectionBaseAddress => "section_base_address",
            BaseSource::PebImageBaseAddress => "peb_image_base_address",
        }
    }

    /// The member the address came out of.
    pub fn member(self) -> &'static str {
        match self {
            BaseSource::SectionBaseAddress => "_EPROCESS.SectionBaseAddress",
            BaseSource::PebImageBaseAddress => "_PEB.ImageBaseAddress",
        }
    }
}

/// Which record a mapped file's name was compared against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// `_EPROCESS.ImageFileName`: kernel-held, fixed width, truncated.
    ImageFileName,
    /// `_RTL_USER_PROCESS_PARAMETERS.ImagePathName`: loader-held, full path,
    /// and writable by the process.
    PebImagePathName,
    /// `_EPROCESS.SeAuditProcessCreationInfo.ImageFileName.Name`: the full
    /// path the **kernel** recorded when it created the process, for auditing.
    /// It is in kernel memory and the process cannot write it.
    SeAuditImageFileName,
}

impl NameSource {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            NameSource::ImageFileName => "eprocess_image_file_name",
            NameSource::PebImagePathName => "peb_image_path_name",
            NameSource::SeAuditImageFileName => "se_audit_image_file_name",
        }
    }

    /// The member the name came out of.
    pub fn member(self) -> &'static str {
        match self {
            NameSource::ImageFileName => "_EPROCESS.ImageFileName",
            NameSource::PebImagePathName => "_RTL_USER_PROCESS_PARAMETERS.ImagePathName",
            NameSource::SeAuditImageFileName => {
                "_EPROCESS.SeAuditProcessCreationInfo.ImageFileName.Name"
            }
        }
    }
}

/// One disagreement between two records that an untampered process keeps
/// consistent.
///
/// Every variant carries **both** sides of the comparison, because a signal
/// without the values behind it is an assertion. None of them is a verdict:
/// each is a fact about this image that an examiner weighs against the rest of
/// the case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TamperSignal {
    /// The loader's image base and the kernel's do not agree.
    ///
    /// The PEB is in the process's own memory and any code running in the
    /// process can edit it; `SectionBaseAddress` is in kernel memory and it
    /// cannot. Several hollowing techniques rewrite the first as a necessary
    /// step, and some malware rewrites it alone, to mislead a tool that reads
    /// only the PEB.
    ImageBaseMismatch {
        /// `_PEB.ImageBaseAddress`.
        peb_image_base: u64,
        /// `_EPROCESS.SectionBaseAddress`.
        section_base: u64,
    },

    /// No mapped range covers the process's image base.
    ///
    /// Only ever reported when the VAD tree was walked in full: a tree that
    /// stopped early cannot support a statement about what it does not
    /// contain.
    NoVadAtImageBase {
        /// The address nothing covers.
        base: u64,
        /// Which record that address came from.
        source: BaseSource,
    },

    /// A range covers the image base but does not begin there.
    ///
    /// A mapped image begins at the start of its own allocation. An entry
    /// point that lands part-way into some other allocation means the address
    /// is not where the image was mapped.
    ImageBaseNotVadStart {
        /// The image base.
        base: u64,
        /// Which record it came from.
        source: BaseSource,
        /// Address of the range's node.
        vad: u64,
        /// First byte of the range.
        vad_start: u64,
        /// Last byte of the range.
        vad_end: u64,
    },

    /// The range backing the image is not backed by a file.
    ///
    /// The classic residue of hollowing: the original image was unmapped and
    /// replaced with private memory, which the VAD records as having no
    /// control area and therefore no file.
    ImageVadNotFileBacked {
        /// First byte of the range.
        base: u64,
        /// Address of the range's node.
        vad: u64,
        /// The pool tag in front of the node. `VadS` and `VadF` are the short
        /// form, which cannot map a file by construction.
        tag: String,
    },

    /// The range backing the image names a different file from the one the
    /// process claims to be.
    ///
    /// Only the final component of each path is compared; see
    /// [`final_component`] for why.
    ImageVadPathDiffers {
        /// First byte of the range.
        base: u64,
        /// Address of the range's node.
        vad: u64,
        /// The path the VAD's control area names.
        mapped_path: String,
        /// The name the process claims.
        claimed: String,
        /// Which record the claim came from.
        source: NameSource,
    },

    /// The range backing the image is private memory.
    ///
    /// A mapped image is shared: its pages come from a section object backed
    /// by the file. Private memory at the image base was allocated, not
    /// mapped.
    ImageVadPrivateMemory {
        /// First byte of the range.
        base: u64,
        /// Address of the range's node.
        vad: u64,
    },

    /// The range backing the image carries a protection a mapped image does
    /// not.
    ImageVadProtection {
        /// First byte of the range.
        base: u64,
        /// Address of the range's node.
        vad: u64,
        /// The protection, as this kernel's own table names it.
        protection: String,
        /// What a mapped image would carry.
        expected: &'static str,
        /// Whether the range can be written in place **and** executed.
        /// `None` when the kernel's protection table was not available to
        /// decide it, which is not the same as `false`.
        writable_and_executable: Option<bool>,
    },

    /// The process names no file object for its own image, on a build that
    /// records one.
    ///
    /// A process created from a file that was already deleted has nothing to
    /// point at. This is the residue of process ghosting.
    ///
    /// Read it beside the process's own nature: a process with **no user
    /// address space** — System, Registry, Memory Compression — was created
    /// from no file at all and legitimately names none.
    /// [`examine_processes`] never examines those, and records why in
    /// [`TamperScan::skipped`]; a caller driving [`examine_process`] itself has
    /// to make that distinction for themselves.
    ImageFilePointerNull {
        /// The member that was read, at the offset this build declares.
        member: String,
    },

    /// The file the process was created from is marked for deletion.
    ///
    /// The process is running an image that is on its way off the disk, or is
    /// already gone from every directory entry.
    ImageFileDeletePending {
        /// Address of the `_FILE_OBJECT`.
        file_object: u64,
        /// Its path, when the name was readable.
        path: Option<String>,
    },

    /// The kernel's own audit record of the image path and the path the
    /// process publishes for itself name different files.
    ///
    /// This is the PEB masquerade. `SeAuditProcessCreationInfo.ImageFileName`
    /// is written by the kernel when it creates the process and lives in
    /// **kernel** memory; `_RTL_USER_PROCESS_PARAMETERS.ImagePathName` lives in
    /// the process's own memory and any code in the process can rewrite it.
    /// Overwriting the second so that a tool reading the PEB reports the wrong
    /// program is a published, scripted technique.
    ///
    /// Only the final component of each path is compared; see
    /// [`final_component`].
    AuditPathDiffers {
        /// The path the kernel recorded.
        audit_path: String,
        /// The name the process publishes.
        claimed: String,
        /// Which record the claim came from.
        source: NameSource,
    },

    /// A string in the process parameters declares a length its own text does
    /// not match.
    ///
    /// `_UNICODE_STRING` carries `Length` and `MaximumLength` in bytes, and the
    /// loader sets both to fit the string it wrote. A string edited in place —
    /// to a shorter path, most often — leaves the declared lengths describing
    /// the *old* text. It is a marker of an edit and **not** proof of one: a
    /// buffer the loader reused legitimately, and a string the process set
    /// through `RtlInitUnicodeString` itself, can both produce it. All three
    /// numbers are reported so an examiner can see what was there.
    ProcessParameterStringInconsistent {
        /// Which member, as this build declares it.
        member: String,
        /// `Length`, in bytes.
        declared_length: u64,
        /// `MaximumLength`, in bytes.
        declared_maximum: u64,
        /// Characters actually decoded.
        decoded_characters: u64,
    },
}

impl TamperSignal {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            TamperSignal::ImageBaseMismatch { .. } => "image_base_mismatch",
            TamperSignal::NoVadAtImageBase { .. } => "no_vad_at_image_base",
            TamperSignal::ImageBaseNotVadStart { .. } => "image_base_not_vad_start",
            TamperSignal::ImageVadNotFileBacked { .. } => "image_vad_not_file_backed",
            TamperSignal::ImageVadPathDiffers { .. } => "image_vad_path_differs",
            TamperSignal::ImageVadPrivateMemory { .. } => "image_vad_private_memory",
            TamperSignal::ImageVadProtection { .. } => "image_vad_protection",
            TamperSignal::ImageFilePointerNull { .. } => "image_file_pointer_null",
            TamperSignal::ImageFileDeletePending { .. } => "image_file_delete_pending",
            TamperSignal::AuditPathDiffers { .. } => "audit_path_differs",
            TamperSignal::ProcessParameterStringInconsistent { .. } => {
                "process_parameter_string_inconsistent"
            }
        }
    }

    /// Which check produced it.
    pub fn check(&self) -> TamperCheck {
        match self {
            TamperSignal::ImageBaseMismatch { .. } => TamperCheck::ImageBase,
            TamperSignal::NoVadAtImageBase { .. } | TamperSignal::ImageBaseNotVadStart { .. } => {
                TamperCheck::ImageVad
            }
            TamperSignal::ImageVadNotFileBacked { .. } => TamperCheck::ImageVadFile,
            TamperSignal::ImageVadPathDiffers { .. } => TamperCheck::ImageVadPath,
            TamperSignal::ImageVadPrivateMemory { .. } => TamperCheck::ImageVadPrivate,
            TamperSignal::ImageVadProtection { .. } => TamperCheck::ImageVadProtection,
            TamperSignal::ImageFilePointerNull { .. } => TamperCheck::ImageFilePointer,
            TamperSignal::ImageFileDeletePending { .. } => TamperCheck::ImageFileDeletePending,
            TamperSignal::AuditPathDiffers { .. }
            | TamperSignal::ProcessParameterStringInconsistent { .. } => {
                TamperCheck::AuditImagePath
            }
        }
    }

    /// The observation, with both sides of the comparison in it.
    ///
    /// Deliberately a statement about the image and never about intent: an
    /// examiner reads this beside the rest of the case and draws the
    /// conclusion themselves.
    pub fn describe(&self) -> String {
        match self {
            TamperSignal::ImageBaseMismatch {
                peb_image_base,
                section_base,
            } => format!(
                "the loader records the image at {peb_image_base:#x} in the process's own memory, \
                 and the kernel records having mapped it at {section_base:#x}"
            ),
            TamperSignal::NoVadAtImageBase { base, source } => format!(
                "no mapped range covers {base:#x}, which {} names as this process's image base",
                source.member()
            ),
            TamperSignal::ImageBaseNotVadStart {
                base,
                source,
                vad,
                vad_start,
                vad_end,
            } => format!(
                "{} names {base:#x} as this process's image base, and the range covering it \
                 (node {vad:#x}) runs from {vad_start:#x} to {vad_end:#x}, so the image base is \
                 not the start of an allocation",
                source.member()
            ),
            TamperSignal::ImageVadNotFileBacked { base, vad, tag } => format!(
                "the range at {base:#x} that backs this process's image (node {vad:#x}, pool tag \
                 {tag:?}) is backed by no file"
            ),
            TamperSignal::ImageVadPathDiffers {
                base,
                vad,
                mapped_path,
                claimed,
                source,
            } => format!(
                "the range at {base:#x} that backs this process's image (node {vad:#x}) maps \
                 {mapped_path:?}, and {} names {claimed:?}",
                source.member()
            ),
            TamperSignal::ImageVadPrivateMemory { base, vad } => format!(
                "the range at {base:#x} that backs this process's image (node {vad:#x}) is \
                 private memory, which a mapped image is not"
            ),
            TamperSignal::ImageVadProtection {
                base,
                vad,
                protection,
                expected,
                writable_and_executable,
            } => {
                let tail = match writable_and_executable {
                    Some(true) => ", and it can be written in place and executed",
                    Some(false) => "",
                    None => ", and whether it is writable and executable could not be established",
                };
                format!(
                    "the range at {base:#x} that backs this process's image (node {vad:#x}) \
                     carries {protection}, where a mapped image carries {expected}{tail}"
                )
            }
            TamperSignal::ImageFilePointerNull { member } => format!(
                "this process names no file object for its own image: {member} is null on a build \
                 that records one"
            ),
            TamperSignal::ImageFileDeletePending { file_object, path } => match path {
                Some(path) => format!(
                    "the file this process was created from ({path:?}, file object \
                     {file_object:#x}) is marked for deletion"
                ),
                None => format!(
                    "the file this process was created from (file object {file_object:#x}) is \
                     marked for deletion, and its path could not be read"
                ),
            },
            TamperSignal::AuditPathDiffers {
                audit_path,
                claimed,
                source,
            } => format!(
                "the kernel's own audit record names {audit_path:?} as this process's image, and \
                 {} names {claimed:?}. The audit record is in kernel memory and the process \
                 cannot write it; the other is in the process's own memory and it can",
                source.member()
            ),
            TamperSignal::ProcessParameterStringInconsistent {
                member,
                declared_length,
                declared_maximum,
                decoded_characters,
            } => format!(
                "{member} declares {declared_length} byte(s) of text in a buffer of \
                 {declared_maximum}, and {decoded_characters} character(s) were decoded from it. \
                 A string edited in place leaves the declared lengths describing the text that \
                 used to be there; so does a buffer the loader reused, which is why this is a \
                 marker and not proof"
            ),
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = match self {
            TamperSignal::ImageBaseMismatch {
                peb_image_base,
                section_base,
            } => serde_json::json!({
                "peb_image_base": peb_image_base,
                "peb_image_base_hex": format!("{peb_image_base:#x}"),
                "section_base": section_base,
                "section_base_hex": format!("{section_base:#x}"),
            }),
            TamperSignal::NoVadAtImageBase { base, source } => serde_json::json!({
                "base": base,
                "base_hex": format!("{base:#x}"),
                "source": source.as_str(),
            }),
            TamperSignal::ImageBaseNotVadStart {
                base,
                source,
                vad,
                vad_start,
                vad_end,
            } => serde_json::json!({
                "base": base,
                "base_hex": format!("{base:#x}"),
                "source": source.as_str(),
                "vad": vad,
                "vad_hex": format!("{vad:#x}"),
                "vad_start": vad_start,
                "vad_start_hex": format!("{vad_start:#x}"),
                "vad_end": vad_end,
                "vad_end_hex": format!("{vad_end:#x}"),
            }),
            TamperSignal::ImageVadNotFileBacked { base, vad, tag } => serde_json::json!({
                "base": base,
                "base_hex": format!("{base:#x}"),
                "vad": vad,
                "vad_hex": format!("{vad:#x}"),
                "tag": tag,
            }),
            TamperSignal::ImageVadPathDiffers {
                base,
                vad,
                mapped_path,
                claimed,
                source,
            } => serde_json::json!({
                "base": base,
                "base_hex": format!("{base:#x}"),
                "vad": vad,
                "vad_hex": format!("{vad:#x}"),
                "mapped_path": mapped_path,
                "claimed": claimed,
                "source": source.as_str(),
            }),
            TamperSignal::ImageVadPrivateMemory { base, vad } => serde_json::json!({
                "base": base,
                "base_hex": format!("{base:#x}"),
                "vad": vad,
                "vad_hex": format!("{vad:#x}"),
            }),
            TamperSignal::ImageVadProtection {
                base,
                vad,
                protection,
                expected,
                writable_and_executable,
            } => serde_json::json!({
                "base": base,
                "base_hex": format!("{base:#x}"),
                "vad": vad,
                "vad_hex": format!("{vad:#x}"),
                "protection": protection,
                "expected": expected,
                "writable_and_executable": writable_and_executable,
            }),
            TamperSignal::ImageFilePointerNull { member } => serde_json::json!({
                "member": member,
            }),
            TamperSignal::ImageFileDeletePending { file_object, path } => serde_json::json!({
                "file_object": file_object,
                "file_object_hex": format!("{file_object:#x}"),
                "path": path,
            }),
            TamperSignal::AuditPathDiffers {
                audit_path,
                claimed,
                source,
            } => serde_json::json!({
                "audit_path": audit_path,
                "claimed": claimed,
                "source": source.as_str(),
                "audit_path_basis":
                    "`SeAuditProcessCreationInfo.ImageFileName` is written by the kernel when it \
                     creates the process and lives in KERNEL memory, where the process cannot \
                     write it. The path it is compared against lives in the process's own \
                     memory and any code in the process can rewrite it.",
            }),
            TamperSignal::ProcessParameterStringInconsistent {
                member,
                declared_length,
                declared_maximum,
                decoded_characters,
            } => serde_json::json!({
                "member": member,
                "declared_length": declared_length,
                "declared_maximum": declared_maximum,
                "decoded_characters": decoded_characters,
                "is_proof": false,
            }),
        };
        if let Some(object) = value.as_object_mut() {
            object.insert("signal".into(), serde_json::json!(self.as_str()));
            object.insert("check".into(), serde_json::json!(self.check().as_str()));
            object.insert("detail".into(), serde_json::json!(self.describe()));
        }
        value
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// What one process's records say about each other.
#[derive(Debug, Clone)]
pub struct ProcessTampering {
    /// Kernel address of the `_EPROCESS`.
    pub process: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// `_EPROCESS.ImageFileName`, when it was readable.
    pub image_file_name: Option<String>,
    /// `_EPROCESS.SectionBaseAddress`, when it was readable.
    pub section_base: Option<u64>,
    /// The `_PEB` address, when the process has one and it was readable.
    pub peb: Option<u64>,
    /// `_PEB.ImageBaseAddress`, when it was readable.
    pub peb_image_base: Option<u64>,
    /// The path the loader recorded the process as started from, when it was
    /// readable.
    pub image_path_name: Option<String>,
    /// The path the **kernel** recorded for auditing when it created the
    /// process, when it was readable. Kernel memory: the process cannot write
    /// it.
    pub audit_image_path: Option<String>,
    /// The mapped range that backs the image base, when one was found.
    pub image_vad: Option<Vad>,
    /// `_EPROCESS.ImageFilePointer`, when this build has one and it was
    /// readable. Zero is reported as a signal rather than stored here.
    pub image_file_object: Option<u64>,
    /// The path that file object names, when it was readable.
    pub image_file_path: Option<String>,
    /// Every disagreement found, in the order the checks ran.
    pub signals: Vec<TamperSignal>,
    /// Every check that could not be made, and why. **Read this before
    /// concluding anything from an empty signal list.**
    pub not_checked: Vec<NotChecked>,
    /// Everything odd that did not amount to a signal, capped by
    /// [`HollowConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total. Exact even when the list was capped.
    pub notes_total: usize,
}

impl ProcessTampering {
    /// Whether every check this stage makes was actually made.
    ///
    /// The question a report must answer before writing "nothing was found
    /// about this process". False means at least one comparison never
    /// happened, and the process is unexamined for it rather than clear.
    pub fn fully_examined(&self) -> bool {
        self.not_checked.is_empty()
    }

    /// Whether anything disagreed.
    pub fn has_signals(&self) -> bool {
        !self.signals.is_empty()
    }

    /// Whether this process was examined in full and nothing disagreed.
    ///
    /// The only combination that supports "this process's records are
    /// consistent". Both halves are required: signals empty *and* every check
    /// made.
    pub fn is_consistent(&self) -> bool {
        self.fully_examined() && !self.has_signals()
    }

    /// Everything a report must declare about this process.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        self.not_checked
            .iter()
            .map(|entry| {
                Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the process at {:#x} was not examined for {}: {}",
                        self.process,
                        entry.check.describe(),
                        entry.reason
                    ),
                )
            })
            .collect()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            // Exact beside every number: these are 64-bit addresses above 2^53
            // and JSON numbers are IEEE doubles, so the numeric form reaches a
            // client rounded — and this stage's whole finding is that two of
            // these addresses disagree, which a rounded pair can hide.
            "process_hex": format!("{:#x}", self.process),
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "section_base": self.section_base,
            "section_base_hex": self.section_base.map(|base| format!("{base:#x}")),
            "peb": self.peb,
            "peb_hex": self.peb.map(|peb| format!("{peb:#x}")),
            "peb_image_base": self.peb_image_base,
            "peb_image_base_hex": self.peb_image_base.map(|base| format!("{base:#x}")),
            "image_path_name": self.image_path_name,
            "audit_image_path": self.audit_image_path,
            "image_vad": self.image_vad.as_ref().map(Vad::to_json),
            "image_file_object": self.image_file_object,
            "image_file_object_hex": self
                .image_file_object
                .map(|object| format!("{object:#x}")),
            "image_file_path": self.image_file_path,
            "signals": self.signals.iter().map(TamperSignal::to_json).collect::<Vec<_>>(),
            "signal_count": self.signals.len(),
            "not_checked": self.not_checked.iter().map(NotChecked::to_json).collect::<Vec<_>>(),
            "fully_examined": self.fully_examined(),
            "consistent": self.is_consistent(),
            "notes": self.notes,
            "notes_total": self.notes_total,
        })
    }
}

/// A process the scan did not examine, and why.
#[derive(Debug, Clone)]
pub struct SkippedProcess {
    /// Kernel address of the `_EPROCESS`.
    pub process: u64,
    /// The process id, when it was readable.
    pub pid: Option<u64>,
    /// The image name, when it was readable.
    pub image_file_name: Option<String>,
    /// Why it was not examined, in the examiner's terms.
    pub reason: String,
}

impl SkippedProcess {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "process_hex": format!("{:#x}", self.process),
            "pid": self.pid,
            "image_file_name": self.image_file_name,
            "reason": self.reason,
        })
    }
}

/// Why a scan ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScanStop {
    /// Every process on the list was considered.
    Exhausted,
    /// The process cap fired. The scan stopped; the list did not end.
    CapReached {
        /// The cap that fired.
        cap: usize,
    },
}

impl ScanStop {
    /// Whether every process was considered.
    pub fn is_complete(&self) -> bool {
        matches!(self, ScanStop::Exhausted)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ScanStop::Exhausted => "exhausted",
            ScanStop::CapReached { .. } => "cap_reached",
        }
    }
}

/// One pass over a process list, and everything it could not do.
#[derive(Debug, Clone)]
pub struct TamperScan {
    /// One entry per process examined, whether or not anything disagreed.
    /// Processes without signals are kept: their [`NotChecked`] lists are how
    /// a report says which of them were actually cleared.
    pub examined: Vec<ProcessTampering>,
    /// Processes the scan declined to examine, capped by
    /// [`HollowConfig::max_recorded_skips`].
    pub skipped: Vec<SkippedProcess>,
    /// How many processes were skipped in total. Exact even when the list was
    /// capped.
    pub skipped_total: usize,
    /// Why the scan ended.
    pub stop: ScanStop,
    /// How complete the process list this scan walked was.
    ///
    /// The scan can only examine processes it was handed. A list that stopped
    /// short means "no tampering signals" is a floor, not the exculpatory
    /// finding it reads as, and this is what puts that on the artifact.
    pub inventory: ProcessInventory,
}

impl TamperScan {
    /// The processes something disagreed about.
    pub fn with_signals(&self) -> Vec<&ProcessTampering> {
        self.examined
            .iter()
            .filter(|process| process.has_signals())
            .collect()
    }

    /// Whether every process was examined and every check was made.
    ///
    /// False whenever a report must not say "no tampering was found on this
    /// machine".
    pub fn is_complete(&self) -> bool {
        self.inventory.is_complete()
            && self.stop.is_complete()
            && self.skipped_total == 0
            && self.examined.iter().all(ProcessTampering::fully_examined)
    }

    /// Everything a report must declare about this scan.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        // The list this scan walked comes first: a process the list never
        // reached was never a candidate, and no per-process note can say so.
        out.extend(self.inventory.incomplete.iter().cloned());
        if let ScanStop::CapReached { cap } = self.stop {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the tampering scan stopped at its cap of {cap} process(es); the process list \
                     continues"
                ),
            ));
        }
        if self.skipped_total > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} process(es) were not examined for tampering, so nothing here is a \
                     statement about them",
                    self.skipped_total
                ),
            ));
        }
        for process in &self.examined {
            out.extend(process.incomplete());
        }
        out
    }

    /// Serializable form for the tampering artifact.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "examined": self.examined.iter().map(ProcessTampering::to_json).collect::<Vec<_>>(),
            "examined_count": self.examined.len(),
            "signalled_count": self.with_signals().len(),
            "skipped": self.skipped.iter().map(SkippedProcess::to_json).collect::<Vec<_>>(),
            "skipped_total": self.skipped_total,
            "stop": self.stop.as_str(),
            "complete": self.is_complete(),
            // Stated rather than left to the stamp below, which only ever
            // *lowers* it. An absent `content_complete` reads downstream as
            // "the stage did not say", which is not what a scan that examined
            // every process it was handed means.
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        });
        self.inventory.stamp(&mut value);
        value
    }
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps and settings for one tampering scan.
#[derive(Debug, Clone)]
pub struct HollowConfig {
    /// Ceiling on processes one scan will examine.
    pub max_processes: usize,
    /// Ceiling on individually recorded skipped processes.
    pub max_recorded_skips: usize,
    /// Ceiling on individually recorded notes per process.
    pub max_recorded_notes: usize,
    /// How many mapped ranges a process must have before its image is
    /// compared. See [`MIN_IMAGE_VADS`].
    pub min_image_vads: usize,
    /// Whether to examine processes that had already exited.
    ///
    /// Off by default: an exited process's address space has been torn down,
    /// so every check would report on the teardown rather than on the process.
    /// Turning it on is a deliberate choice, and the resulting signals need
    /// reading with that in mind.
    pub include_exited: bool,
    /// How each process's VAD tree is walked. Carry the kernel's protection
    /// table on this, or every protection reads as unknown.
    pub vad: VadWalkConfig,
    /// Page-table entry memo, shared across every process in a scan. Entries
    /// are keyed by physical address and mean the same thing in every address
    /// space, so one cache for four hundred processes is right and four
    /// hundred caches is waste.
    pub page_table_cache: Option<Arc<TableCache>>,
}

impl Default for HollowConfig {
    fn default() -> Self {
        Self {
            max_processes: MAX_EXAMINED_PROCESSES,
            max_recorded_skips: MAX_RECORDED_SKIPS,
            max_recorded_notes: MAX_RECORDED_NOTES,
            min_image_vads: MIN_IMAGE_VADS,
            include_exited: false,
            vad: VadWalkConfig::default(),
            page_table_cache: None,
        }
    }
}

impl HollowConfig {
    /// The defaults, with the VAD walk bound to `profile` so that an
    /// allocation's protection can be named.
    ///
    /// Two of this stage's nine checks rest on the protection: an image mapped
    /// at other than [`EXPECTED_IMAGE_PROTECTION`], and private memory that is
    /// writable and executable at once. With the plain default they reported
    /// themselves *not checked* for every process on every machine, and said
    /// the kernel's `MmProtectToValue` had not been available — of a table the
    /// symbols publish. See [`VadWalkConfig::for_profile`].
    pub fn for_profile(profile: &WindowsProfile) -> Self {
        Self {
            vad: VadWalkConfig::for_profile(profile),
            ..Self::default()
        }
    }
}

// ── The examination ─────────────────────────────────────────────────────────

/// Examine every process on a list.
///
/// Never fails. A process whose VAD tree or address space could not be built
/// still appears, with the checks that needed them recorded as not made; a
/// process the scan declined to examine at all appears in
/// [`TamperScan::skipped`] with the reason. Nothing is dropped silently,
/// because a process missing from this result is indistinguishable from one
/// that was examined and found consistent.
pub fn examine_processes(
    profile: &WindowsProfile,
    symbols: &HollowSymbols,
    list: &ProcessList,
    config: &HollowConfig,
) -> TamperScan {
    let mut scan = TamperScan {
        examined: Vec::new(),
        skipped: Vec::new(),
        skipped_total: 0,
        stop: ScanStop::Exhausted,
        inventory: list.inventory(),
    };
    // One memo for the whole scan, so a page table shared between processes is
    // walked once.
    let mut config = config.clone();
    if config.page_table_cache.is_none() {
        config.page_table_cache = Some(Arc::new(TableCache::new()));
    }

    for process in &list.processes {
        if scan.examined.len() >= config.max_processes {
            scan.stop = ScanStop::CapReached {
                cap: config.max_processes,
            };
            break;
        }
        if let Some(reason) = skip_reason(process, &config) {
            scan.skipped_total = scan.skipped_total.saturating_add(1);
            if scan.skipped.len() < config.max_recorded_skips {
                scan.skipped.push(SkippedProcess {
                    process: process.address,
                    pid: process.pid.known().copied(),
                    image_file_name: process.image_file_name.known().cloned(),
                    reason,
                });
            }
            continue;
        }
        scan.examined
            .push(examine_process(profile, symbols, process, &config));
    }
    scan
}

/// Why the scan would not examine this process, if it would not.
///
/// Both reasons are about the process rather than about the image, and both
/// are recorded rather than acted on silently.
///
/// The first reason is guarded on this build declaring a `Peb` member at all.
/// [`crate::process::ProcessRecord::peb`] is `NotApplicable` for two different
/// facts — the process's `Peb` is null, and the symbol table has no `Peb` to
/// read — and only the first is a statement about the process. Acting on the
/// second would declare every process on such a build to have no user address
/// space, which is a claim the image does not support, and would leave the
/// ghosting checks — which never touch the PEB — unrun on all of them while the
/// result still read as a scan that found nothing.
fn skip_reason(process: &ProcessRecord, config: &HollowConfig) -> Option<String> {
    // `Field::NotApplicable` now means only what it says: this process has no
    // PEB. A build whose `_EPROCESS` declares no `Peb` member yields
    // `Field::NotDeclared`, which is a fact about the build and is reported
    // through `not_checked` rather than skipping the process — so the ghosting
    // checks, which never touch a PEB, still run. Consulting the symbols struct
    // to recover that distinction is no longer necessary.
    if matches!(process.peb, Field::NotApplicable) {
        return Some(
            "this process has no user address space, so it has no loader, no image base of its \
             own and no image file to compare — the ordinary state of System, Registry and Memory \
             Compression"
                .to_string(),
        );
    }
    if !config.include_exited && process.has_exited() == Some(true) {
        return Some(
            "this process had already exited when the image was taken, so its address space has \
             been torn down and every comparison would describe the teardown"
                .to_string(),
        );
    }
    None
}

/// Examine one process, building everything the checks need.
///
/// `process` is a record from [`crate::process::list_processes`]; its
/// `address` is an `_EPROCESS` in the **kernel** address space.
///
/// Never fails. A VAD tree that cannot be walked and an address space that
/// cannot be built are both recorded against the checks that needed them, and
/// the checks that did not need them still run — a build without a readable
/// PEB can still have its image file object examined for deletion.
pub fn examine_process(
    profile: &WindowsProfile,
    symbols: &HollowSymbols,
    process: &ProcessRecord,
    config: &HollowConfig,
) -> ProcessTampering {
    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let tree = list_vads(profile, &symbols.vad, process.address, &config.vad);
    let cache = config
        .page_table_cache
        .clone()
        .unwrap_or_else(|| Arc::new(TableCache::new()));
    let user = process_address_space(profile, &symbols.process, process.address, &cache)
        .map(|layer| StructReader::new(layer, Arc::clone(&profile.symbols)));

    examine_with(
        symbols,
        &kernel,
        user.as_ref().map_err(ToString::to_string),
        tree.as_ref().map_err(ToString::to_string),
        process,
        config,
    )
}

/// Examine one process with its address space and VAD tree already in hand.
///
/// For a caller that has walked the tree for another purpose, and for
/// fixtures. `user` **must** be a reader over the process's own address space:
/// handing it the kernel space does not fail, it reads whatever the kernel maps
/// at a user address, and every image-base comparison would then be a
/// comparison of unrelated bytes. That is the mistake this signature exists to
/// make visible.
pub fn examine_process_in(
    symbols: &HollowSymbols,
    kernel: &StructReader,
    user: &StructReader,
    tree: &VadTree,
    process: &ProcessRecord,
    config: &HollowConfig,
) -> ProcessTampering {
    examine_with(symbols, kernel, Ok(user), Ok(tree), process, config)
}

/// The examination proper.
///
/// `user` and `tree` are `Err(reason)` when they could not be built, so that
/// the reason travels to the checks that needed them instead of being replaced
/// by a generic absence.
fn examine_with(
    symbols: &HollowSymbols,
    kernel: &StructReader,
    user: Result<&StructReader, String>,
    tree: Result<&VadTree, String>,
    process: &ProcessRecord,
    config: &HollowConfig,
) -> ProcessTampering {
    let mut out = ProcessTampering {
        process: process.address,
        pid: process.pid.known().copied(),
        image_file_name: process.image_file_name.known().cloned(),
        section_base: None,
        peb: None,
        peb_image_base: None,
        image_path_name: None,
        audit_image_path: None,
        image_vad: None,
        image_file_object: None,
        image_file_path: None,
        signals: Vec::new(),
        not_checked: Vec::new(),
        notes: Vec::new(),
        notes_total: 0,
    };

    let eprocess = match kernel.object(process.address, TYPE_EPROCESS) {
        Ok(object) => object,
        Err(err) => {
            let reason = format!(
                "the process structure at {:#x} could not be read: {err}",
                process.address
            );
            for check in TamperCheck::ALL {
                not_checked(&mut out, check, reason.clone());
            }
            return out;
        }
    };

    check_ghosting(symbols, kernel, &eprocess, config, &mut out);
    check_image(symbols, user, tree, &eprocess, config, &mut out);
    // Last, because it compares the kernel's audit record against the path
    // `check_image` read out of the process's own memory.
    check_audit_path(kernel, &eprocess, symbols, config, &mut out);
    out
}

/// The PEB masquerade: does the kernel's own audit record of the image path
/// agree with the path the process publishes for itself?
///
/// # Why this is a separate opinion and not a third copy of the same one
///
/// `SeAuditProcessCreationInfo.ImageFileName` is written by the kernel at
/// process creation and lives in **kernel** memory. The process cannot write
/// it. `_RTL_USER_PROCESS_PARAMETERS.ImagePathName` lives in the process's own
/// memory and any code in the process can rewrite it — overwriting it so that a
/// tool reading the PEB reports the wrong program is a published, scripted
/// technique. `_EPROCESS.ImageFileName` is also kernel-held but is fifteen
/// bytes and truncated, so it cannot carry a path at all.
///
/// Declared on **all 1,650** of the 1,724 `ntkrnlmp.pdb` ISFs measured here
/// that declare `_EPROCESS`, so this check is not build-conditional in
/// practice — but its absence is still answered rather than assumed.
fn check_audit_path(
    kernel: &StructReader,
    eprocess: &Obj,
    symbols: &HollowSymbols,
    config: &HollowConfig,
    out: &mut ProcessTampering,
) {
    const AUDIT: &str = "SeAuditProcessCreationInfo.ImageFileName";

    let pointer = match eprocess.pointer(AUDIT) {
        Ok(pointer) => pointer,
        Err(err) => {
            not_checked(
                out,
                TamperCheck::AuditImagePath,
                format!(
                    "'{TYPE_EPROCESS}.{AUDIT}' could not be read on this build: {err}. The \
                     kernel's own record of this process's image path is what the path in the \
                     process's own memory would be compared against, so no masquerade could be \
                     ruled in or out."
                ),
            );
            return;
        }
    };
    if pointer == 0 {
        push_note(
            out,
            config,
            format!(
                "'{TYPE_EPROCESS}.{AUDIT}' is null, so the kernel recorded no image path for \
                 this process. That is what the System process and a process caught during \
                 creation both look like."
            ),
        );
        not_checked(
            out,
            TamperCheck::AuditImagePath,
            "the kernel recorded no audit image path for this process, so there was nothing to \
             compare the process's own claim against"
                .to_string(),
        );
        return;
    }

    let object = match kernel.object(pointer, "_OBJECT_NAME_INFORMATION") {
        Ok(object) => object,
        Err(err) => {
            not_checked(
                out,
                TamperCheck::AuditImagePath,
                format!("the audit name at {pointer:#x} could not be read: {err}"),
            );
            return;
        }
    };
    let audit = match unicode_string(&object, "Name") {
        Ok(Some(path)) => path,
        Ok(None) => {
            not_checked(
                out,
                TamperCheck::AuditImagePath,
                format!(
                    "the kernel's audit record at {pointer:#x} holds a zero-length path, so \
                     there is nothing to compare"
                ),
            );
            return;
        }
        Err(err) => {
            not_checked(
                out,
                TamperCheck::AuditImagePath,
                format!("the audit path at {pointer:#x} could not be decoded: {err}"),
            );
            return;
        }
    };
    out.audit_image_path = Some(audit.clone());
    let audit_leaf = final_component(&audit).to_string();

    let mut compared = false;
    if let Some(claimed) = out.image_path_name.clone().filter(|p| !p.is_empty()) {
        compared = true;
        if !eq_ignore_case(final_component(&claimed), &audit_leaf) {
            out.signals.push(TamperSignal::AuditPathDiffers {
                audit_path: audit.clone(),
                claimed,
                source: NameSource::PebImagePathName,
            });
        }
    }
    if let Some(recorded) = out.image_file_name.clone().filter(|n| !n.is_empty()) {
        compared = true;
        if !names_agree(&audit_leaf, &recorded, symbols.image_name_width) {
            out.signals.push(TamperSignal::AuditPathDiffers {
                audit_path: audit,
                claimed: recorded,
                source: NameSource::ImageFileName,
            });
        }
    }
    if !compared {
        not_checked(
            out,
            TamperCheck::AuditImagePath,
            format!(
                "the kernel's audit record names {audit_leaf:?}, and neither the loader's image \
                 path nor '{TYPE_EPROCESS}.ImageFileName' was readable, so there is nothing to \
                 compare it with"
            ),
        );
    }
}

/// The `_EPROCESS`-side ghosting checks: does the process still name the file
/// it was created from, and is that file on its way off the disk.
fn check_ghosting(
    symbols: &HollowSymbols,
    kernel: &StructReader,
    eprocess: &Obj,
    config: &HollowConfig,
    out: &mut ProcessTampering,
) {
    let Some(ghost) = symbols.ghost.as_ref() else {
        let reason = symbols.ghost_unavailable.clone().unwrap_or_else(|| {
            format!("this build declares no '{TYPE_EPROCESS}.{MEMBER_IMAGE_FILE_POINTER}'")
        });
        not_checked(out, TamperCheck::ImageFilePointer, reason.clone());
        not_checked(out, TamperCheck::ImageFileDeletePending, reason);
        return;
    };

    let pointer = match read_address(eprocess, &ghost.image_file_pointer) {
        Ok(value) => value,
        Err(reason) => {
            not_checked(out, TamperCheck::ImageFilePointer, reason.clone());
            not_checked(out, TamperCheck::ImageFileDeletePending, reason);
            return;
        }
    };
    if pointer == 0 {
        out.signals.push(TamperSignal::ImageFilePointerNull {
            member: format!("{TYPE_EPROCESS}.{}", ghost.image_file_pointer),
        });
        not_checked(
            out,
            TamperCheck::ImageFileDeletePending,
            "this process names no file object, so there is no delete-pending flag on it to read"
                .to_string(),
        );
        return;
    }
    out.image_file_object = Some(pointer);

    let file = match kernel.object(pointer, TYPE_FILE_OBJECT) {
        Ok(file) => file,
        Err(err) => {
            not_checked(
                out,
                TamperCheck::ImageFileDeletePending,
                format!("the file object at {pointer:#x} could not be read: {err}"),
            );
            return;
        }
    };

    if let Some(path) = ghost.file_name.as_deref() {
        match unicode_string(&file, path) {
            Ok(Some(name)) => out.image_file_path = Some(name),
            Ok(None) => push_note(
                out,
                config,
                format!("the file object at {pointer:#x} names a zero-length path"),
            ),
            Err(err) => push_note(
                out,
                config,
                format!("the path of the file object at {pointer:#x} could not be read: {err}"),
            ),
        }
    }

    let Some(delete_pending) = ghost.delete_pending.as_deref() else {
        not_checked(
            out,
            TamperCheck::ImageFileDeletePending,
            format!(
                "'{TYPE_FILE_OBJECT}' has no {MEMBER_DELETE_PENDING} on this build, so whether \
                 the file is going away cannot be read"
            ),
        );
        return;
    };
    match read_flag(&file, delete_pending) {
        Ok(DELETE_PENDING_SET) => out.signals.push(TamperSignal::ImageFileDeletePending {
            file_object: pointer,
            path: out.image_file_path.clone(),
        }),
        Ok(0) => {}
        // A flag byte holding neither 0 nor 1 is smear or a structure read at
        // the wrong offset. Treating a non-zero value as "set" would turn every
        // such byte into a finding.
        Ok(other) => not_checked(
            out,
            TamperCheck::ImageFileDeletePending,
            format!(
                "'{TYPE_FILE_OBJECT}.{delete_pending}' at {pointer:#x} holds {other}, which is \
                 neither set nor clear, so this byte is not a flag this image can be read through"
            ),
        ),
        Err(reason) => not_checked(out, TamperCheck::ImageFileDeletePending, reason),
    }
}

/// The image-comparison checks: where the image is, what backs it, and whether
/// what backs it is what the process says it is.
fn check_image(
    symbols: &HollowSymbols,
    user: Result<&StructReader, String>,
    tree: Result<&VadTree, String>,
    eprocess: &Obj,
    config: &HollowConfig,
    out: &mut ProcessTampering,
) {
    let Some(image) = symbols.image.as_ref() else {
        let reason = symbols
            .image_unavailable
            .clone()
            .unwrap_or_else(|| "this build declares no image base to compare".to_string());
        for check in TamperCheck::IMAGE {
            not_checked(out, check, reason.clone());
        }
        return;
    };

    // The kernel's record first: it is the one the process cannot edit.
    let section_base = read_address(eprocess, &image.section_base);
    if let Ok(value) = &section_base {
        out.section_base = Some(*value);
    }

    let peb_image_base = read_peb_image_base(image, user, eprocess, config, out);
    if let Ok(value) = &peb_image_base {
        out.peb_image_base = Some(*value);
    }

    match (section_base.as_ref(), peb_image_base.as_ref()) {
        (Ok(section), Ok(loader)) => {
            if section != loader {
                out.signals.push(TamperSignal::ImageBaseMismatch {
                    peb_image_base: *loader,
                    section_base: *section,
                });
            }
        }
        (Err(reason), _) | (Ok(_), Err(reason)) => {
            not_checked(out, TamperCheck::ImageBase, reason.clone());
        }
    }

    // Anchor the range lookup on the kernel's record wherever possible. Falling
    // back to the PEB's is stated, because that value is one the process itself
    // can write, and a range located from it is a range the process chose.
    let anchor = match (&section_base, &peb_image_base) {
        (Ok(base), _) => Ok((*base, BaseSource::SectionBaseAddress)),
        (Err(_), Ok(base)) => {
            push_note(
                out,
                config,
                format!(
                    "'{TYPE_EPROCESS}.{}' could not be read, so the range backing the image was \
                     located from '{TYPE_PEB}.{}', which the process itself can write",
                    image.section_base, image.image_base
                ),
            );
            Ok((*base, BaseSource::PebImageBaseAddress))
        }
        (Err(kernel_side), Err(loader_side)) => Err(format!("{kernel_side}; and {loader_side}")),
    };

    let tree = match tree {
        Ok(tree) => tree,
        Err(reason) => {
            for check in TamperCheck::VAD {
                not_checked(out, check, reason.clone());
            }
            return;
        }
    };
    if tree.vads.len() < config.min_image_vads {
        let reason = format!(
            "this process has {} mapped range(s), fewer than the {} this scan requires before \
             comparing an image; a process this sparse has not finished starting or has begun \
             tearing down, and a comparison would describe that rather than the process",
            tree.vads.len(),
            config.min_image_vads
        );
        for check in TamperCheck::VAD {
            not_checked(out, check, reason.clone());
        }
        return;
    }

    let (anchor, source) = match anchor {
        Ok(anchor) => anchor,
        Err(reason) => {
            for check in TamperCheck::VAD {
                not_checked(out, check, reason.clone());
            }
            return;
        }
    };

    // The range that *starts* at the image base is the mapping; a range that
    // merely covers it is a different allocation the base fell into, which is
    // itself worth reporting.
    let found = tree
        .vads
        .iter()
        .find(|vad| vad.start == anchor)
        .or_else(|| tree.containing(anchor));
    let Some(vad) = found else {
        if tree.is_complete() {
            out.signals.push(TamperSignal::NoVadAtImageBase {
                base: anchor,
                source,
            });
        } else {
            // Fail closed: a tree that stopped early cannot support a statement
            // about what it does not contain.
            not_checked(
                out,
                TamperCheck::ImageVad,
                format!(
                    "no mapped range covers {anchor:#x}, and this process's VAD tree was not \
                     walked in full, so the range may exist below a node the walk could not follow"
                ),
            );
        }
        for check in TamperCheck::BACKED {
            not_checked(
                out,
                check,
                format!("the range backing {anchor:#x} was not found"),
            );
        }
        return;
    };
    out.image_vad = Some(vad.clone());
    if vad.start != anchor {
        out.signals.push(TamperSignal::ImageBaseNotVadStart {
            base: anchor,
            source,
            vad: vad.address,
            vad_start: vad.start,
            vad_end: vad.end,
        });
    }

    check_backing_file(symbols, vad, out);
    check_private_memory(vad, out);
    check_protection(config, vad, out);
}

/// Whether the range backing the image is backed by a file, and whether that
/// file is the one the process claims.
fn check_backing_file(symbols: &HollowSymbols, vad: &Vad, out: &mut ProcessTampering) {
    let mapped = match &vad.file {
        MappedFile::Name(name) => Some(name.clone()),
        MappedFile::None | MappedFile::NotApplicable => {
            out.signals.push(TamperSignal::ImageVadNotFileBacked {
                base: vad.start,
                vad: vad.address,
                tag: vad.tag.clone(),
            });
            None
        }
        // The distinction the whole module turns on: a file whose *name* was
        // not readable is not a range with no file behind it, and reporting it
        // as one manufactures the signature of hollowing out of an unacquired
        // page.
        MappedFile::Unavailable(detail) => {
            not_checked(
                out,
                TamperCheck::ImageVadFile,
                format!(
                    "whether the range at {:#x} is backed by a file could not be established: \
                     {detail}",
                    vad.start
                ),
            );
            None
        }
    };

    let Some(mapped) = mapped else {
        not_checked(
            out,
            TamperCheck::ImageVadPath,
            format!(
                "the range at {:#x} names no file whose path could be compared with this \
                 process's",
                vad.start
            ),
        );
        return;
    };

    let mapped_name = final_component(&mapped);
    let mut compared = false;

    if let Some(recorded) = out.image_file_name.clone().filter(|name| !name.is_empty()) {
        compared = true;
        if !names_agree(mapped_name, &recorded, symbols.image_name_width) {
            out.signals.push(TamperSignal::ImageVadPathDiffers {
                base: vad.start,
                vad: vad.address,
                mapped_path: mapped.clone(),
                claimed: recorded,
                source: NameSource::ImageFileName,
            });
        }
    }
    if let Some(claimed) = out.image_path_name.clone().filter(|path| !path.is_empty()) {
        compared = true;
        if !eq_ignore_case(final_component(&claimed), mapped_name) {
            out.signals.push(TamperSignal::ImageVadPathDiffers {
                base: vad.start,
                vad: vad.address,
                mapped_path: mapped.clone(),
                claimed,
                source: NameSource::PebImagePathName,
            });
        }
    }
    if !compared {
        not_checked(
            out,
            TamperCheck::ImageVadPath,
            format!(
                "the range at {:#x} maps {mapped:?}, and neither \
                 '{TYPE_EPROCESS}.ImageFileName' nor the loader's {MEMBER_IMAGE_PATH_NAME} was \
                 readable, so there is nothing to compare it with",
                vad.start
            ),
        );
    }
}

/// Whether the range backing the image is private memory.
fn check_private_memory(vad: &Vad, out: &mut ProcessTampering) {
    match vad.private_memory {
        Some(true) => out.signals.push(TamperSignal::ImageVadPrivateMemory {
            base: vad.start,
            vad: vad.address,
        }),
        Some(false) => {}
        None => not_checked(
            out,
            TamperCheck::ImageVadPrivate,
            format!(
                "whether the range at {:#x} is private memory was not recorded: this build's VAD \
                 either has no such flag or it could not be read — see the range's own notes",
                vad.start
            ),
        ),
    }
}

/// What protection the range backing the image carries.
fn check_protection(config: &HollowConfig, vad: &Vad, out: &mut ProcessTampering) {
    let Some(protection) = vad.protection_names.as_ref() else {
        not_checked(
            out,
            TamperCheck::ImageVadProtection,
            format!(
                "the protection of the range at {:#x} could not be named: either this build's VAD \
                 records no protection index or this kernel's MmProtectToValue was not available \
                 to interpret it",
                vad.start
            ),
        );
        return;
    };
    // `protection_names` joins every bit the mask sets, and the upper half of
    // `MmProtectToValue` is the lower half with a guard, cache or write-combine
    // attribute added. So the same mapped image reads `PAGE_EXECUTE_WRITECOPY`
    // at index 7 and `PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE` at index 23, and a
    // comparison against the whole rendered string reports the second as
    // tampered. The access protection is what this check is about.
    let Some(base) = base_protection(protection) else {
        not_checked(
            out,
            TamperCheck::ImageVadProtection,
            format!(
                "the protection of the range at {:#x} names only cache or guard attributes \
                 ({protection}) and no access protection, so there is nothing to compare against \
                 what a mapped image carries",
                vad.start
            ),
        );
        return;
    };
    if base == EXPECTED_IMAGE_PROTECTION {
        return;
    }
    out.signals.push(TamperSignal::ImageVadProtection {
        base: vad.start,
        vad: vad.address,
        protection: protection.clone(),
        expected: EXPECTED_IMAGE_PROTECTION,
        writable_and_executable: writable_and_executable(config, vad.protection),
    });
}

/// Read the loader's image base out of the process's own PEB.
///
/// Also picks up the started-from path while the PEB is open, because reaching
/// it a second time would mean a second page-table walk for the same page.
fn read_peb_image_base(
    image: &ImageLayout,
    user: Result<&StructReader, String>,
    eprocess: &Obj,
    config: &HollowConfig,
    out: &mut ProcessTampering,
) -> Result<u64, String> {
    let user = user.map_err(|reason| {
        format!(
            "the process's own address space could not be built, so its PEB could not be read: \
             {reason}"
        )
    })?;
    let peb = read_address(eprocess, &image.peb)?;
    if peb == 0 {
        return Err(format!(
            "'{TYPE_EPROCESS}.{}' is null: this process has no user address space and therefore \
             no loader record of where its image is",
            image.peb
        ));
    }
    out.peb = Some(peb);

    let block = user
        .object(peb, TYPE_PEB)
        .map_err(|err| format!("the PEB at {peb:#x} could not be read: {err}"))?;
    read_image_path_name(image, user, &block, config, out);
    read_address(&block, &image.image_base)
}

/// Read the path the loader recorded the process as started from.
///
/// A second, independent opinion about which file the process is. Absent
/// members and unreadable pages both become notes rather than errors: the
/// image-base comparison does not depend on this, and losing it must not lose
/// that.
fn read_image_path_name(
    image: &ImageLayout,
    user: &StructReader,
    peb: &Obj,
    config: &HollowConfig,
    out: &mut ProcessTampering,
) {
    let (Some(parameters), Some(path)) = (
        image.process_parameters.as_deref(),
        image.image_path_name.as_deref(),
    ) else {
        return;
    };
    // Read the pointer and type the block explicitly rather than following the
    // member: some symbol packs declare `ProcessParameters` as an untyped
    // pointer, and following one of those fails on a build whose parameter
    // block is perfectly readable.
    let address = match read_address(peb, parameters) {
        Ok(address) => address,
        Err(reason) => {
            push_note(out, config, reason);
            return;
        }
    };
    if address == 0 {
        push_note(
            out,
            config,
            format!(
                "'{TYPE_PEB}.{parameters}' is null, which is what a process caught during \
                 creation looks like, so the loader records no path for it"
            ),
        );
        return;
    }
    let block = match user.object(address, TYPE_PROCESS_PARAMETERS) {
        Ok(block) => block,
        Err(err) => {
            push_note(
                out,
                config,
                format!("the parameter block at {address:#x} could not be read: {err}"),
            );
            return;
        }
    };
    // The declared lengths, read before the string itself. `unicode_string`
    // reads exactly `Length` bytes, so comparing the decoded length against
    // `Length` would be vacuous here -- it is what upstream compares, and in
    // Python it fires on any path holding a non-BMP character, where one code
    // point is two UTF-16 units. The invariant worth reading is the loader's
    // own: it allocates this buffer to fit the path and its terminator, so
    // `MaximumLength` is `Length` plus two. A string rewritten in place
    // usually leaves one of the two describing the text that used to be there.
    let declared = (
        block.unsigned(&format!("{path}.Length")).ok(),
        block.unsigned(&format!("{path}.MaximumLength")).ok(),
    );
    match unicode_string(&block, path) {
        Ok(Some(name)) => {
            if let (Some(length), Some(maximum)) = declared {
                if maximum != length.saturating_add(2) {
                    out.signals
                        .push(TamperSignal::ProcessParameterStringInconsistent {
                            member: format!("{TYPE_PROCESS_PARAMETERS}.{path}"),
                            declared_length: length,
                            declared_maximum: maximum,
                            decoded_characters: name.chars().count() as u64,
                        });
                }
            }
            out.image_path_name = Some(name);
        }
        Ok(None) => push_note(
            out,
            config,
            format!(
                "'{TYPE_PROCESS_PARAMETERS}.{path}' is zero-length, so the loader recorded no path"
            ),
        ),
        Err(err) => push_note(
            out,
            config,
            format!("'{TYPE_PROCESS_PARAMETERS}.{path}' could not be read: {err}"),
        ),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Read a member that holds an address, keeping the reason for any failure.
fn read_address(object: &Obj, path: &str) -> Result<u64, String> {
    match object.int(path) {
        Ok(value) => value.as_u64().ok_or_else(|| {
            format!(
                "'{}.{path}' is negative, which is not an address",
                object.type_name()
            )
        }),
        Err(err) => Err(format!(
            "'{}.{path}' could not be read: {err}",
            object.type_name()
        )),
    }
}

/// Read a member that holds a flag, keeping the reason for any failure.
fn read_flag(object: &Obj, path: &str) -> Result<u64, String> {
    match object.int(path) {
        Ok(value) => value.as_u64().ok_or_else(|| {
            format!(
                "'{}.{path}' is negative, which is not a flag",
                object.type_name()
            )
        }),
        Err(err) => Err(format!(
            "'{}.{path}' could not be read: {err}",
            object.type_name()
        )),
    }
}

/// Record a check that was not made, once.
///
/// A check recorded twice would make a report count the same gap twice and
/// would let a later, vaguer reason shadow an earlier, specific one. The first
/// reason is the one nearest the failure, so it is the one kept.
fn not_checked(out: &mut ProcessTampering, check: TamperCheck, reason: String) {
    if out.not_checked.iter().any(|entry| entry.check == check) {
        return;
    }
    out.not_checked.push(NotChecked { check, reason });
}

/// Record a note, keeping the list bounded without losing the count.
fn push_note(out: &mut ProcessTampering, config: &HollowConfig, note: String) {
    out.notes_total = out.notes_total.saturating_add(1);
    if out.notes.len() < config.max_recorded_notes {
        out.notes.push(note);
    }
}

/// Whether a protection index names memory that can be written in place and
/// executed.
///
/// `None` when the kernel's protection table was not available to decide it —
/// which is not `false`, and must not render as it.
fn writable_and_executable(config: &HollowConfig, index: Option<u64>) -> Option<bool> {
    let mask = config.vad.protections.as_deref()?.mask_for(index?)?;
    Some(mask & EXECUTE_BITS != 0 && mask & DIRECT_WRITE_BITS != 0)
}

/// The final component of a Windows path, whichever separator it uses.
///
/// Only the final component of two paths is ever compared here, and the reason
/// is that the two records name the same file in different namespaces. A VAD's
/// control area holds the native path, `\Device\HarddiskVolume2\Windows\…`,
/// while the loader holds the DOS path, `C:\Windows\…`. Comparing those as
/// whole strings never matches on any machine, so every process would be
/// reported and the report would be worthless. Comparing the final components
/// is a real comparison: a process claiming to be `svchost.exe` while running
/// an image mapped from `evil.exe` fails it.
///
/// What this deliberately does **not** catch is the same file name in a
/// different directory: a `svchost.exe` under `\Users\Public\Temp` against one
/// under `C:\Windows\System32`. Both full paths are carried on the signal and
/// on [`ProcessTampering::image_path_name`] so an examiner can see that for
/// themselves.
pub fn final_component(path: &str) -> &str {
    path.rsplit(['\\', '/']).next().unwrap_or(path)
}

/// Whether two Windows file names are the same name.
///
/// `to_lowercase` rather than `eq_ignore_ascii_case`: Windows file names are
/// not ASCII, and a fold that covers only ASCII would report a process whose
/// image name differs from itself in case outside it — which is a signal
/// manufactured by the comparison rather than found in the image.
fn eq_ignore_case(left: &str, right: &str) -> bool {
    left.to_lowercase() == right.to_lowercase()
}

/// Whether a mapped file's name and the kernel's recorded process name are the
/// same name.
///
/// `_EPROCESS.ImageFileName` is a fixed-width array — fifteen bytes on x64 —
/// and a name that fills it is a **prefix** of the real one rather than a
/// different name. Treating it as different reports every process whose name is
/// long.
///
/// # The off-by-one this had, and what it cost
///
/// The test was `recorded.len() >= width`, which is only true of an array
/// filled with **no** terminator. Windows 11 26200 stores at most fourteen
/// characters plus a NUL in its fifteen-byte array, so a truncated name decodes
/// to fourteen characters and the test never fired. Measured on the clean
/// capture in `tests/win11_corpus_analysis.rs`: **23 processes** were reported
/// as mapping a file other than the one they claim to be —
/// `fontdrvhost.ex`, `RuntimeBroker.`, `msedgewebview2`,
/// `StartMenuExper` and so on — every one of them a name cut off by the array's
/// own terminator. On a clean install.
///
/// So the rule is `recorded.len() + 1 >= width`: a name that reaches the last
/// byte the array can hold *before its terminator* is as much a truncation as
/// one that fills it outright. Both cases exist across builds and both are
/// prefixes.
fn names_agree(mapped: &str, recorded: &str, width: u64) -> bool {
    if eq_ignore_case(mapped, recorded) {
        return true;
    }
    let filled = u64::try_from(recorded.len()).is_ok_and(|len| len.saturating_add(1) >= width);
    filled && mapped.to_lowercase().starts_with(&recorded.to_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image};
    use crate::process::{ProcessTime, WalkDirection};
    use crate::vad::ProtectionTable;
    use seance_memory::object::ListStop;
    use seance_memory::Architecture;

    // Where the synthetic 64-bit fixture puts things. The image is mapped one
    // to one, so a kernel address and a user address are the same address and
    // one layer serves as both spaces.
    const EPROCESS_AT: u64 = 0x1000;
    const PEB_AT: u64 = 0x1200;
    const PARAMS_AT: u64 = 0x1300;
    const IMAGE_PATH_BUFFER: u64 = 0x1400;
    const PROCESS_FILE_OBJECT: u64 = 0x1500;
    const PROCESS_FILE_BUFFER: u64 = 0x1600;
    /// The kernel's own audit record, and the buffer its path lives in.
    const AUDIT_NAME_INFORMATION: u64 = 0x1700;
    const AUDIT_BUFFER: u64 = 0x1780;
    const IMAGE_VAD: u64 = 0x2000;
    const VAD_A: u64 = 0x3000;
    const VAD_B: u64 = 0x4000;
    const VAD_C: u64 = 0x5000;
    const VAD_D: u64 = 0x5800;
    const SUBSECTION_AT: u64 = 0x6000;
    const CONTROL_AREA_AT: u64 = 0x6100;
    const VAD_FILE_OBJECT: u64 = 0x6200;
    const VAD_FILE_BUFFER: u64 = 0x6300;
    const PROTECT_TABLE_AT: u64 = 0x7000;

    /// Where the fixture's process believes its image is, and where the kernel
    /// says it mapped it. Above the image's own length on purpose: the address
    /// is compared, never read.
    const IMAGE_BASE: u64 = 0x40_0000;
    const IMAGE_START_VPN: u32 = 0x400;
    const IMAGE_END_VPN: u32 = 0x40F;

    /// The native path the image VAD's control area names.
    const MAPPED_PATH: &str = r"\Device\HarddiskVolume2\Windows\System32\notepad.exe";
    /// The DOS path the loader records.
    const LOADER_PATH: &str = r"C:\Windows\System32\notepad.exe";
    /// The path the process's own file object names.
    const FILE_OBJECT_PATH: &str = r"\Device\HarddiskVolume2\Windows\System32\notepad.exe";
    /// What the kernel's own audit record holds. Deliberately the DOS form, as
    /// the real member carries, and naming the same file the loader does.
    const AUDIT_PATH: &str = r"\??\C:\Windows\System32\notepad.exe";

    /// Offsets the synthetic 64-bit ISF below declares.
    mod off {
        pub(super) const TAG_DISTANCE: u64 = 12;

        pub(super) const EPROCESS_PID: u64 = 0;
        pub(super) const EPROCESS_NAME: u64 = 8;
        pub(super) const EPROCESS_PEB: u64 = 56;
        pub(super) const EPROCESS_SECTION_BASE: u64 = 64;
        pub(super) const EPROCESS_IMAGE_FILE_POINTER: u64 = 72;
        pub(super) const EPROCESS_VAD_ROOT: u64 = 80;
        pub(super) const EPROCESS_DTB: u64 = 88;
        pub(super) const EPROCESS_AUDIT: u64 = 96;

        pub(super) const OBJECT_NAME_INFORMATION_NAME: u64 = 0;

        pub(super) const PEB_IMAGE_BASE: u64 = 0;
        pub(super) const PEB_PARAMETERS: u64 = 8;

        pub(super) const PARAMS_IMAGE_PATH: u64 = 0;

        pub(super) const UNICODE_LENGTH: u64 = 0;
        pub(super) const UNICODE_MAX_LENGTH: u64 = 2;
        pub(super) const UNICODE_BUFFER: u64 = 8;

        pub(super) const FILE_OBJECT_NAME: u64 = 0;
        pub(super) const FILE_OBJECT_DELETE_PENDING: u64 = 16;

        pub(super) const VAD_LEFT: u64 = 0;
        pub(super) const VAD_RIGHT: u64 = 8;
        pub(super) const VAD_START_VPN: u64 = 24;
        pub(super) const VAD_END_VPN: u64 = 28;
        pub(super) const VAD_FLAGS: u64 = 36;
        pub(super) const VAD_FLAGS1: u64 = 40;
        pub(super) const VAD_SUBSECTION: u64 = 48;

        pub(super) const SUBSECTION_CONTROL_AREA: u64 = 0;
        pub(super) const CONTROL_AREA_FILE_POINTER: u64 = 0;
    }

    /// A synthetic 64-bit Windows 10 ISF carrying everything this stage reads:
    /// a section base, an image file pointer, a PEB with a parameter block, a
    /// file object with a delete-pending flag, and a VAD tree.
    fn win10_isf(members: Members) -> String {
        let section_base = if members.section_base {
            r#""SectionBaseAddress": {"offset": 64, "type": {"kind": "pointer",
                "subtype": {"kind": "base", "name": "unsigned char"}}},"#
        } else {
            ""
        };
        let image_file_pointer = if members.image_file_pointer {
            r#""ImageFilePointer": {"offset": 72, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_FILE_OBJECT"}}},"#
        } else {
            ""
        };
        let peb_member = if members.peb {
            r#""Peb": {"offset": 56, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_PEB"}}},"#
        } else {
            ""
        };
        let delete_pending = if members.delete_pending {
            r#""DeletePending": {"offset": 16, "type": {"kind": "base", "name": "unsigned char"}},"#
        } else {
            ""
        };
        format!(
            r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "EE1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                         "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {base_types},
  "user_types": {{
    "_POOL_HEADER": {{"size": 16, "kind": "struct", "fields": {{
      "BlockSize": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolType": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolTag": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_LIST_ENTRY": {{"size": 16, "kind": "struct", "fields": {{
      "Flink": {{"offset": 0, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}},
      "Blink": {{"offset": 8, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}}}
    }}}},
    "_UNICODE_STRING": {{"size": 16, "kind": "struct", "fields": {{
      "Length": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "MaximumLength": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "Buffer": {{"offset": 8, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "base", "name": "unsigned short"}}}}}}
    }}}},
    "_LARGE_INTEGER": {{"size": 8, "kind": "union", "fields": {{
      "QuadPart": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    "_FILE_OBJECT": {{"size": 32, "kind": "struct", "fields": {{
      "FileName": {{"offset": 0, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}},
      {delete_pending}
      "Flags": {{"offset": 20, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_RTL_USER_PROCESS_PARAMETERS": {{"size": 64, "kind": "struct", "fields": {{
      "ImagePathName": {{"offset": 0, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}},
      "CommandLine": {{"offset": 16, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}}
    }}}},
    "_PEB": {{"size": 64, "kind": "struct", "fields": {{
      "ImageBaseAddress": {{"offset": 0, "type": {{"kind": "pointer",
                            "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ProcessParameters": {{"offset": 8, "type": {{"kind": "pointer",
                             "subtype": {{"kind": "struct",
                                          "name": "_RTL_USER_PROCESS_PARAMETERS"}}}}}}
    }}}},
    "_EX_FAST_REF": {{"size": 8, "kind": "union", "fields": {{
      "Object": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long long"}}}}
    }}}},
    "_CONTROL_AREA": {{"size": 32, "kind": "struct", "fields": {{
      "FilePointer": {{"offset": 0, "type": {{"kind": "union", "name": "_EX_FAST_REF"}}}}
    }}}},
    "_SUBSECTION": {{"size": 32, "kind": "struct", "fields": {{
      "ControlArea": {{"offset": 0, "type": {{"kind": "pointer",
                       "subtype": {{"kind": "struct", "name": "_CONTROL_AREA"}}}}}}
    }}}},
    "_RTL_BALANCED_NODE": {{"size": 24, "kind": "struct", "fields": {{
      "Left": {{"offset": 0, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}}}},
      "Right": {{"offset": 8, "type": {{"kind": "pointer",
                 "subtype": {{"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}}}},
      "ParentValue": {{"offset": 16, "type": {{"kind": "base",
                       "name": "unsigned long long"}}}}
    }}}},
    "_RTL_AVL_TREE": {{"size": 8, "kind": "struct", "fields": {{
      "Root": {{"offset": 0, "type": {{"kind": "pointer",
                "subtype": {{"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}}}}
    }}}},
    "_MMVAD_FLAGS": {{"size": 4, "kind": "struct", "fields": {{
      "Protection": {{"offset": 0, "type": {{"kind": "bitfield", "bit_position": 7,
                      "bit_length": 5, "type": {{"kind": "base", "name": "unsigned long"}}}}}}
    }}}},
    "_MMVAD_FLAGS1": {{"size": 4, "kind": "struct", "fields": {{
      "CommitCharge": {{"offset": 0, "type": {{"kind": "bitfield", "bit_position": 0,
                        "bit_length": 31, "type": {{"kind": "base", "name": "unsigned long"}}}}}},
      "PrivateMemory": {{"offset": 0, "type": {{"kind": "bitfield", "bit_position": 31,
                         "bit_length": 1, "type": {{"kind": "base", "name": "unsigned long"}}}}}}
    }}}},
    "_MMVAD_SHORT_U": {{"size": 4, "kind": "union", "fields": {{
      "VadFlags": {{"offset": 0, "type": {{"kind": "struct", "name": "_MMVAD_FLAGS"}}}}
    }}}},
    "_MMVAD_SHORT_U1": {{"size": 4, "kind": "union", "fields": {{
      "VadFlags1": {{"offset": 0, "type": {{"kind": "struct", "name": "_MMVAD_FLAGS1"}}}}
    }}}},
    "_MMVAD_SHORT": {{"size": 48, "kind": "struct", "fields": {{
      "VadNode": {{"offset": 0, "type": {{"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}},
      "StartingVpn": {{"offset": 24, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "EndingVpn": {{"offset": 28, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "u": {{"offset": 36, "type": {{"kind": "union", "name": "_MMVAD_SHORT_U"}}}},
      "u1": {{"offset": 40, "type": {{"kind": "union", "name": "_MMVAD_SHORT_U1"}}}}
    }}}},
    "_MMVAD": {{"size": 128, "kind": "struct", "fields": {{
      "Core": {{"offset": 0, "type": {{"kind": "struct", "name": "_MMVAD_SHORT"}}}},
      "Subsection": {{"offset": 48, "type": {{"kind": "pointer",
                      "subtype": {{"kind": "struct", "name": "_SUBSECTION"}}}}}}
    }}}},
    "_OBJECT_NAME_INFORMATION": {{"size": 16, "kind": "struct", "fields": {{
      "Name": {{"offset": 0, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}}
    }}}},
    "_SE_AUDIT_PROCESS_CREATION_INFO": {{"size": 8, "kind": "struct", "fields": {{
      "ImageFileName": {{"offset": 0, "type": {{"kind": "pointer",
                         "subtype": {{"kind": "struct",
                                      "name": "_OBJECT_NAME_INFORMATION"}}}}}}
    }}}},
    "_EPROCESS": {{"size": 256, "kind": "struct", "fields": {{
      "UniqueProcessId": {{"offset": 0, "type": {{"kind": "pointer",
                           "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "SeAuditProcessCreationInfo": {{"offset": 96, "type": {{"kind": "struct",
                                      "name": "_SE_AUDIT_PROCESS_CREATION_INFO"}}}},
      "ImageFileName": {{"offset": 8, "type": {{"kind": "array", "count": 15,
                         "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ActiveProcessLinks": {{"offset": 24, "type": {{"kind": "struct",
                              "name": "_LIST_ENTRY"}}}},
      "CreateTime": {{"offset": 40, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      "ExitTime": {{"offset": 48, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}},
      {peb_member}
      {section_base}
      {image_file_pointer}
      "VadRoot": {{"offset": 80, "type": {{"kind": "struct", "name": "_RTL_AVL_TREE"}}}},
      "DirectoryTableBase": {{"offset": 88, "type": {{"kind": "base",
                              "name": "unsigned long long"}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "MmProtectToValue": {{"address": 28672}}
  }}
}}"#,
            base_types = crate::image_fixture::BASE_TYPES_X64,
        )
    }

    /// Which optional members a fixture's "build" declares.
    #[derive(Debug, Clone, Copy)]
    struct Members {
        section_base: bool,
        image_file_pointer: bool,
        peb: bool,
        delete_pending: bool,
    }

    impl Default for Members {
        fn default() -> Self {
            Self {
                section_base: true,
                image_file_pointer: true,
                peb: true,
                delete_pending: true,
            }
        }
    }

    /// A `_UNICODE_STRING` at `at`, with its text at `buffer`.
    fn put_unicode(image: &mut Image, at: u64, buffer: u64, text: &str) {
        let bytes = u16::try_from(text.encode_utf16().count() * 2).expect("a short path");
        image.put_u16(at + off::UNICODE_LENGTH, bytes);
        image.put_u16(at + off::UNICODE_MAX_LENGTH, bytes.saturating_add(2));
        image.put_u64(at + off::UNICODE_BUFFER, buffer);
        image.put_utf16(buffer, text);
    }

    /// One VAD node, with its pool tag twelve bytes in front as a real
    /// allocation has.
    fn put_vad(
        image: &mut Image,
        at: u64,
        tag: &[u8; 4],
        start_vpn: u32,
        end_vpn: u32,
        left: u64,
        right: u64,
    ) {
        image.write(at - off::TAG_DISTANCE, tag);
        image.put_u64(at + off::VAD_LEFT, left);
        image.put_u64(at + off::VAD_RIGHT, right);
        image.put_u32(at + off::VAD_START_VPN, start_vpn);
        image.put_u32(at + off::VAD_END_VPN, end_vpn);
    }

    /// Set a node's protection index, which lives in bits 11:7 of `VadFlags`.
    fn put_protection(image: &mut Image, at: u64, index: u32) {
        image.put_u32(at + off::VAD_FLAGS, index << 7);
    }

    /// Mark a node as private memory, which is bit 31 of `VadFlags1`.
    fn put_private(image: &mut Image, at: u64) {
        image.put_u32(at + off::VAD_FLAGS1, 1 << 31);
    }

    /// The kernel's protection table, with index 7 as `PAGE_EXECUTE_WRITECOPY`
    /// and index 6 as `PAGE_EXECUTE_READWRITE`, as a real one has.
    fn put_protect_table(image: &mut Image) {
        let values: [u32; 8] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80];
        for (index, value) in values.iter().enumerate() {
            image.put_u32(PROTECT_TABLE_AT + (index as u64) * 4, *value);
        }
    }

    /// The untampered fixture: a five-range process whose every record agrees
    /// with every other.
    fn clean_image() -> Image {
        let mut image = Image::new();

        image.put_u64(EPROCESS_AT + off::EPROCESS_PID, 1234);
        image.write(EPROCESS_AT + off::EPROCESS_NAME, b"notepad.exe\0");
        image.put_u64(EPROCESS_AT + off::EPROCESS_PEB, PEB_AT);
        image.put_u64(EPROCESS_AT + off::EPROCESS_SECTION_BASE, IMAGE_BASE);
        image.put_u64(
            EPROCESS_AT + off::EPROCESS_IMAGE_FILE_POINTER,
            PROCESS_FILE_OBJECT,
        );
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, IMAGE_VAD);
        image.put_u64(EPROCESS_AT + off::EPROCESS_DTB, 0x1000);

        // The kernel's own audit record of the image path, which the process
        // cannot write. Clean: it names the same file the loader does.
        image.put_u64(EPROCESS_AT + off::EPROCESS_AUDIT, AUDIT_NAME_INFORMATION);
        put_unicode(
            &mut image,
            AUDIT_NAME_INFORMATION + off::OBJECT_NAME_INFORMATION_NAME,
            AUDIT_BUFFER,
            AUDIT_PATH,
        );

        image.put_u64(PEB_AT + off::PEB_IMAGE_BASE, IMAGE_BASE);
        image.put_u64(PEB_AT + off::PEB_PARAMETERS, PARAMS_AT);
        put_unicode(
            &mut image,
            PARAMS_AT + off::PARAMS_IMAGE_PATH,
            IMAGE_PATH_BUFFER,
            LOADER_PATH,
        );

        put_unicode(
            &mut image,
            PROCESS_FILE_OBJECT + off::FILE_OBJECT_NAME,
            PROCESS_FILE_BUFFER,
            FILE_OBJECT_PATH,
        );
        image.put_u8(PROCESS_FILE_OBJECT + off::FILE_OBJECT_DELETE_PENDING, 0);

        // Five ranges, which is the default minimum: the image's, and four
        // ordinary private allocations.
        put_vad(
            &mut image,
            IMAGE_VAD,
            b"Vad ",
            IMAGE_START_VPN,
            IMAGE_END_VPN,
            VAD_A,
            VAD_B,
        );
        put_protection(&mut image, IMAGE_VAD, 7);
        image.put_u64(IMAGE_VAD + off::VAD_SUBSECTION, SUBSECTION_AT);
        image.put_u64(
            SUBSECTION_AT + off::SUBSECTION_CONTROL_AREA,
            CONTROL_AREA_AT,
        );
        image.put_u64(
            CONTROL_AREA_AT + off::CONTROL_AREA_FILE_POINTER,
            VAD_FILE_OBJECT,
        );
        put_unicode(
            &mut image,
            VAD_FILE_OBJECT + off::FILE_OBJECT_NAME,
            VAD_FILE_BUFFER,
            MAPPED_PATH,
        );

        put_vad(&mut image, VAD_A, b"VadS", 0x10, 0x1F, 0, 0);
        put_vad(&mut image, VAD_B, b"VadS", 0x100, 0x10F, VAD_C, VAD_D);
        put_vad(&mut image, VAD_C, b"VadS", 0x200, 0x20F, 0, 0);
        put_vad(&mut image, VAD_D, b"VadS", 0x300, 0x30F, 0, 0);
        for node in [VAD_A, VAD_B, VAD_C, VAD_D] {
            put_protection(&mut image, node, 2);
            put_private(&mut image, node);
        }

        put_protect_table(&mut image);
        image
    }

    fn win10_profile(image: Image, members: Members) -> WindowsProfile {
        profile(
            image.layer(),
            table(&win10_isf(members)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    /// A profile, its resolved symbols and a config carrying the kernel's own
    /// protection table.
    struct Fixture {
        profile: WindowsProfile,
        symbols: HollowSymbols,
        config: HollowConfig,
    }

    impl Fixture {
        fn new(image: Image) -> Self {
            Self::with(image, Members::default())
        }

        fn with(image: Image, members: Members) -> Self {
            let profile = win10_profile(image, members);
            let symbols = HollowSymbols::from_profile(&profile).expect("a describable build");
            let protections = ProtectionTable::from_profile(&profile).ok().map(Arc::new);
            let config = HollowConfig {
                vad: VadWalkConfig {
                    protections,
                    ..VadWalkConfig::default()
                },
                ..HollowConfig::default()
            };
            Self {
                profile,
                symbols,
                config,
            }
        }

        fn reader(&self) -> StructReader {
            StructReader::new(
                Arc::clone(&self.profile.kernel_space),
                Arc::clone(&self.profile.symbols),
            )
        }

        fn tree(&self) -> VadTree {
            list_vads(
                &self.profile,
                &self.symbols.vad,
                EPROCESS_AT,
                &self.config.vad,
            )
            .expect("a walkable tree")
        }

        /// Examine the fixture's process. The image is mapped one to one, so
        /// the same reader serves as both the kernel space and the process's
        /// own.
        fn examine(&self, process: &ProcessRecord) -> ProcessTampering {
            let reader = self.reader();
            let tree = self.tree();
            examine_process_in(
                &self.symbols,
                &reader,
                &reader,
                &tree,
                process,
                &self.config,
            )
        }
    }

    /// A process record as `list_processes` would have produced it.
    fn record(name: &str) -> ProcessRecord {
        ProcessRecord {
            address: EPROCESS_AT,
            direction: WalkDirection::Forward,
            pid: Field::Known(1234),
            ppid: Field::Known(4),
            image_file_name: Field::Known(name.to_string()),
            image_name_well_formed: true,
            threads: Field::NotApplicable,
            handles: Field::NotApplicable,
            session_id: Field::NotApplicable,
            wow64: Field::NotApplicable,
            create_time: ProcessTime::NotRecorded,
            exit_time: ProcessTime::NotRecorded,
            peb: Field::Known(PEB_AT),
            notes: Vec::new(),
        }
    }

    fn signal_kinds(found: &ProcessTampering) -> Vec<&'static str> {
        found.signals.iter().map(TamperSignal::as_str).collect()
    }

    fn unchecked_kinds(found: &ProcessTampering) -> Vec<&'static str> {
        found
            .not_checked
            .iter()
            .map(|entry| entry.check.as_str())
            .collect()
    }

    // ── Layout resolution ───────────────────────────────────────────────────

    #[test]
    fn a_build_with_neither_a_section_base_nor_an_image_file_pointer_is_refused_naming_both() {
        let members = Members {
            section_base: false,
            image_file_pointer: false,
            ..Members::default()
        };
        let profile = win10_profile(clean_image(), members);
        let err = HollowSymbols::from_profile(&profile)
            .expect_err("a build with neither member cannot be examined");
        let message = err.to_string();
        assert!(
            message.contains(MEMBER_SECTION_BASE_ADDRESS),
            "the refusal must name the missing section base: {message}"
        );
        assert!(
            message.contains(MEMBER_IMAGE_FILE_POINTER),
            "the refusal must name the missing image file pointer: {message}"
        );
        assert_eq!(err.class(), "unsupported_build");
    }

    #[test]
    fn a_build_without_an_image_file_pointer_can_still_have_its_image_compared() {
        let members = Members {
            image_file_pointer: false,
            ..Members::default()
        };
        let profile = win10_profile(clean_image(), members);
        let symbols = HollowSymbols::from_profile(&profile).expect("the image side still resolves");
        assert!(symbols.image.is_some());
        assert!(symbols.ghost.is_none());
        let reason = symbols.ghost_unavailable.expect("a stated reason");
        assert!(
            reason.contains(MEMBER_IMAGE_FILE_POINTER),
            "the reason must name the member: {reason}"
        );
    }

    #[test]
    fn a_build_that_should_declare_an_image_file_pointer_and_does_not_says_so() {
        // Major version 10 with the member missing means the symbol table does
        // not describe this kernel, which is a different statement from "this
        // build predates the member" and must not read the same.
        let members = Members {
            image_file_pointer: false,
            ..Members::default()
        };
        let profile = win10_profile(clean_image(), members);
        let symbols = HollowSymbols::from_profile(&profile).expect("the image side still resolves");
        assert!(symbols.expects_image_file_pointer);
        let reason = symbols.ghost_unavailable.expect("a stated reason");
        assert!(
            reason.contains("does not match this kernel") || reason.contains("although"),
            "the reason must flag that the build should have had one: {reason}"
        );
    }

    #[test]
    fn a_build_without_a_peb_can_still_be_examined_for_ghosting() {
        let members = Members {
            peb: false,
            ..Members::default()
        };
        let profile = win10_profile(clean_image(), members);
        let symbols = HollowSymbols::from_profile(&profile).expect("the ghosting side resolves");
        assert!(symbols.ghost.is_some());
        assert!(symbols.image.is_none());
        let reason = symbols.image_unavailable.expect("a stated reason");
        assert!(
            reason.contains("Peb"),
            "the reason must name the member: {reason}"
        );
    }

    #[test]
    fn every_member_the_stage_reads_comes_out_of_the_symbol_table() {
        let fixture = Fixture::new(clean_image());
        let image = fixture.symbols.image.as_ref().expect("an image layout");
        assert_eq!(image.section_base, MEMBER_SECTION_BASE_ADDRESS);
        assert_eq!(image.image_base, MEMBER_IMAGE_BASE_ADDRESS);
        assert_eq!(image.peb, "Peb");
        assert_eq!(
            image.process_parameters.as_deref(),
            Some(MEMBER_PROCESS_PARAMETERS)
        );
        assert_eq!(
            image.image_path_name.as_deref(),
            Some(MEMBER_IMAGE_PATH_NAME)
        );
        let ghost = fixture.symbols.ghost.as_ref().expect("a ghost layout");
        assert_eq!(ghost.image_file_pointer, MEMBER_IMAGE_FILE_POINTER);
        assert_eq!(ghost.delete_pending.as_deref(), Some(MEMBER_DELETE_PENDING));
        assert_eq!(fixture.symbols.image_name_width, 15);
    }

    // ── The untampered case ─────────────────────────────────────────────────

    #[test]
    fn a_process_whose_records_all_agree_raises_nothing_and_is_examined_in_full() {
        let fixture = Fixture::new(clean_image());
        let found = fixture.examine(&record("notepad.exe"));

        assert_eq!(signal_kinds(&found), Vec::<&str>::new());
        assert_eq!(
            unchecked_kinds(&found),
            Vec::<&str>::new(),
            "every check must actually have been made: {:?}",
            found.not_checked
        );
        assert!(found.is_consistent());
        assert_eq!(found.section_base, Some(IMAGE_BASE));
        assert_eq!(found.peb_image_base, Some(IMAGE_BASE));
        assert_eq!(found.image_path_name.as_deref(), Some(LOADER_PATH));
        assert_eq!(found.image_file_object, Some(PROCESS_FILE_OBJECT));
        assert_eq!(found.image_file_path.as_deref(), Some(FILE_OBJECT_PATH));
        let vad = found.image_vad.expect("the range backing the image");
        assert_eq!(vad.start, IMAGE_BASE);
    }

    #[test]
    fn an_empty_signal_list_alone_never_means_a_process_is_consistent() {
        // The whole point of keeping the two lists apart: a process nothing was
        // checked on has no signals either.
        let mut image = clean_image();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, 0);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(!found.has_signals());
        assert!(!found.is_consistent());
        assert!(!found.fully_examined());
        assert!(!found.incomplete().is_empty());
    }

    // ── Hollowing signals ───────────────────────────────────────────────────

    #[test]
    fn an_image_base_the_loader_and_the_kernel_disagree_about_is_reported_with_both_values() {
        let mut image = clean_image();
        image.put_u64(PEB_AT + off::PEB_IMAGE_BASE, 0x66_0000);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        let signal = found
            .signals
            .iter()
            .find(|signal| matches!(signal, TamperSignal::ImageBaseMismatch { .. }))
            .expect("the disagreement is reported");
        assert_eq!(
            signal,
            &TamperSignal::ImageBaseMismatch {
                peb_image_base: 0x66_0000,
                section_base: IMAGE_BASE,
            }
        );
        // The range lookup still anchors on the kernel's value, so the image
        // VAD is the real one and its own checks pass.
        assert_eq!(
            found.image_vad.as_ref().map(|vad| vad.start),
            Some(IMAGE_BASE)
        );
        let detail = signal.describe();
        assert!(detail.contains("0x660000") && detail.contains("0x400000"));
    }

    #[test]
    fn a_range_backed_by_no_file_at_the_image_base_is_reported() {
        let mut image = clean_image();
        image.put_u64(IMAGE_VAD + off::VAD_SUBSECTION, 0);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(signal_kinds(&found).contains(&"image_vad_not_file_backed"));
        // With no file there is nothing to compare a path against, and that is
        // recorded rather than passing silently.
        assert!(unchecked_kinds(&found).contains(&"image_vad_path"));
    }

    #[test]
    fn a_mapped_file_whose_name_could_not_be_read_is_never_reported_as_no_file() {
        // The failure this module exists to avoid: an unacquired page turned
        // into the signature of hollowing.
        let mut image = clean_image();
        image.put_u64(IMAGE_VAD + off::VAD_SUBSECTION, 0x1F00_0000);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(
            !signal_kinds(&found).contains(&"image_vad_not_file_backed"),
            "an unreadable file must not become a finding: {:?}",
            found.signals
        );
        let entry = found
            .not_checked
            .iter()
            .find(|entry| entry.check == TamperCheck::ImageVadFile)
            .expect("the check is recorded as not made");
        assert!(!entry.reason.is_empty());
    }

    #[test]
    fn a_range_mapping_a_different_image_from_the_one_the_process_claims_is_reported() {
        let mut image = clean_image();
        put_unicode(
            &mut image,
            VAD_FILE_OBJECT + off::FILE_OBJECT_NAME,
            VAD_FILE_BUFFER,
            r"\Device\HarddiskVolume2\Users\Public\evil.exe",
        );
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        let differences: Vec<_> = found
            .signals
            .iter()
            .filter_map(|signal| match signal {
                TamperSignal::ImageVadPathDiffers { source, .. } => Some(*source),
                _ => None,
            })
            .collect();
        // Both records disagree with the mapped file, and both are reported:
        // the kernel's fifteen bytes and the loader's full path are separate
        // pieces of evidence.
        assert!(differences.contains(&NameSource::ImageFileName));
        assert!(differences.contains(&NameSource::PebImagePathName));
    }

    #[test]
    fn a_device_path_and_a_dos_path_naming_the_same_file_are_not_a_disagreement() {
        // `\Device\HarddiskVolume2\Windows\System32\notepad.exe` and
        // `C:\Windows\System32\notepad.exe` are the same file in two
        // namespaces. Comparing them whole would report every process on every
        // machine.
        let fixture = Fixture::new(clean_image());
        let found = fixture.examine(&record("notepad.exe"));
        assert!(!signal_kinds(&found).contains(&"image_vad_path_differs"));
    }

    #[test]
    fn a_process_name_truncated_by_the_fixed_width_of_image_file_name_is_not_a_disagreement() {
        // The kernel holds fifteen bytes. `averyverylongname.exe` becomes
        // `averyverylongn`, and reporting that as a different file would
        // report every process with a long name.
        let mut image = clean_image();
        put_unicode(
            &mut image,
            VAD_FILE_OBJECT + off::FILE_OBJECT_NAME,
            VAD_FILE_BUFFER,
            r"\Device\HarddiskVolume2\Windows\averyverylongname.exe",
        );
        put_unicode(
            &mut image,
            PARAMS_AT + off::PARAMS_IMAGE_PATH,
            IMAGE_PATH_BUFFER,
            r"C:\Windows\averyverylongname.exe",
        );
        let fixture = Fixture::new(image);
        // Fifteen characters, exactly the declared width, so the kernel had no
        // room for a terminator and the name it holds is a prefix.
        let found = fixture.examine(&record("averyverylongna"));

        assert!(
            !signal_kinds(&found).contains(&"image_vad_path_differs"),
            "a truncated name is a prefix, not a different file: {:?}",
            found.signals
        );
    }

    #[test]
    fn a_name_that_merely_shares_a_prefix_with_a_short_recorded_name_is_still_a_disagreement() {
        // The prefix rule applies only when the recorded name filled the array.
        // `note` is four bytes, so the kernel could have held more and did not.
        let mut image = clean_image();
        put_unicode(
            &mut image,
            PARAMS_AT + off::PARAMS_IMAGE_PATH,
            IMAGE_PATH_BUFFER,
            r"C:\Windows\note",
        );
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("note"));

        assert!(signal_kinds(&found).contains(&"image_vad_path_differs"));
    }

    #[test]
    fn a_private_range_at_the_image_base_is_reported() {
        let mut image = clean_image();
        put_private(&mut image, IMAGE_VAD);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(signal_kinds(&found).contains(&"image_vad_private_memory"));
    }

    #[test]
    fn a_writable_and_executable_range_at_the_image_base_is_reported_as_both() {
        let mut image = clean_image();
        // Index 6 is PAGE_EXECUTE_READWRITE in this kernel's own table.
        put_protection(&mut image, IMAGE_VAD, 6);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        let signal = found
            .signals
            .iter()
            .find_map(|signal| match signal {
                TamperSignal::ImageVadProtection {
                    protection,
                    writable_and_executable,
                    ..
                } => Some((protection.clone(), *writable_and_executable)),
                _ => None,
            })
            .expect("the protection is reported");
        assert_eq!(signal.0, "PAGE_EXECUTE_READWRITE");
        assert_eq!(signal.1, Some(true));
    }

    #[test]
    fn copy_on_write_execution_is_what_a_mapped_image_has_and_raises_nothing() {
        // PAGE_EXECUTE_WRITECOPY contains the word WRITE, and a check written
        // against the rendered string would report every mapped image on the
        // machine.
        let fixture = Fixture::new(clean_image());
        let found = fixture.examine(&record("notepad.exe"));
        assert!(!signal_kinds(&found).contains(&"image_vad_protection"));
    }

    #[test]
    fn a_mapped_image_on_a_non_cached_range_is_not_reported_as_tampered() {
        // The upper half of `MmProtectToValue` is the lower half with a cache
        // or guard attribute added, so the SAME access protection renders as
        // `PAGE_EXECUTE_WRITECOPY` at one index and
        // `PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE` at another. Comparing the whole
        // rendered string to one constant calls the second a hollowed image and
        // puts a tampering signal in a report about an ordinary process.
        let mut image = clean_image();
        image.put_u32(PROTECT_TABLE_AT + 7 * 4, 0x80 | 0x200);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(
            !signal_kinds(&found).contains(&"image_vad_protection"),
            "only the cache attribute differs; the access protection is exactly \
             what a mapped image has"
        );
    }

    #[test]
    fn a_protection_naming_only_a_cache_attribute_leaves_the_check_unmade() {
        // A table entry that sets a qualifier bit and no access bit names no
        // protection at all. Reading that as a mismatch would assert tampering
        // on the strength of an entry that could not be read.
        let mut image = clean_image();
        image.put_u32(PROTECT_TABLE_AT + 7 * 4, 0x200);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(!signal_kinds(&found).contains(&"image_vad_protection"));
        assert!(
            found
                .not_checked
                .iter()
                .any(|entry| entry.check == TamperCheck::ImageVadProtection),
            "an unmade check must be recorded, not silently passed"
        );
    }

    #[test]
    fn a_protection_that_cannot_be_named_leaves_the_check_unmade_rather_than_passing() {
        let mut image = clean_image();
        put_protection(&mut image, IMAGE_VAD, 6);
        let mut fixture = Fixture::new(image);
        // No protection table: the index cannot be turned into a protection.
        fixture.config.vad.protections = None;
        let found = fixture.examine(&record("notepad.exe"));

        assert!(!signal_kinds(&found).contains(&"image_vad_protection"));
        assert!(unchecked_kinds(&found).contains(&"image_vad_protection"));
    }

    #[test]
    fn nothing_backing_the_image_base_is_reported_only_when_the_tree_was_walked_in_full() {
        let mut image = clean_image();
        // Move the kernel's record somewhere no range covers.
        image.put_u64(EPROCESS_AT + off::EPROCESS_SECTION_BASE, 0x7000_0000);
        image.put_u64(PEB_AT + off::PEB_IMAGE_BASE, 0x7000_0000);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));
        assert!(signal_kinds(&found).contains(&"no_vad_at_image_base"));

        // The same image with a walk that stopped early: the range may exist
        // below a node the walk never reached, so nothing is claimed.
        let mut capped = Fixture::new({
            let mut image = clean_image();
            image.put_u64(EPROCESS_AT + off::EPROCESS_SECTION_BASE, 0x7000_0000);
            image.put_u64(PEB_AT + off::PEB_IMAGE_BASE, 0x7000_0000);
            image
        });
        capped.config.vad.max_nodes = 2;
        capped.config.min_image_vads = 0;
        let found = capped.examine(&record("notepad.exe"));
        assert!(
            !signal_kinds(&found).contains(&"no_vad_at_image_base"),
            "an unfinished walk cannot support a claim about what it did not reach: {:?}",
            found.signals
        );
        assert!(unchecked_kinds(&found).contains(&"image_vad"));
    }

    #[test]
    fn an_image_base_that_falls_inside_some_other_allocation_is_reported() {
        let mut image = clean_image();
        // One page into the range rather than at its start.
        image.put_u64(
            EPROCESS_AT + off::EPROCESS_SECTION_BASE,
            IMAGE_BASE + 0x1000,
        );
        image.put_u64(PEB_AT + off::PEB_IMAGE_BASE, IMAGE_BASE + 0x1000);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        let signal = found
            .signals
            .iter()
            .find(|signal| matches!(signal, TamperSignal::ImageBaseNotVadStart { .. }))
            .expect("the offset base is reported");
        assert_eq!(
            signal,
            &TamperSignal::ImageBaseNotVadStart {
                base: IMAGE_BASE + 0x1000,
                source: BaseSource::SectionBaseAddress,
                vad: IMAGE_VAD,
                vad_start: IMAGE_BASE,
                vad_end: IMAGE_BASE + 0x1_0000 - 1,
            }
        );
    }

    #[test]
    fn a_process_with_too_few_ranges_leaves_the_image_checks_unmade_rather_than_reporting_them() {
        let mut image = clean_image();
        // A two-range process: the image's range and one other.
        image.put_u64(IMAGE_VAD + off::VAD_RIGHT, 0);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        for check in TamperCheck::VAD {
            assert!(
                unchecked_kinds(&found).contains(&check.as_str()),
                "{} must be recorded as not made",
                check.as_str()
            );
        }
        // The image-base comparison does not need the ranges, so it still runs.
        assert!(!unchecked_kinds(&found).contains(&"image_base"));
    }

    // ── Ghosting signals ────────────────────────────────────────────────────

    #[test]
    fn a_process_that_names_no_file_object_for_its_image_is_reported() {
        let mut image = clean_image();
        image.put_u64(EPROCESS_AT + off::EPROCESS_IMAGE_FILE_POINTER, 0);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert_eq!(
            found
                .signals
                .iter()
                .find(|signal| matches!(signal, TamperSignal::ImageFilePointerNull { .. })),
            Some(&TamperSignal::ImageFilePointerNull {
                member: format!("{TYPE_EPROCESS}.{MEMBER_IMAGE_FILE_POINTER}"),
            })
        );
        // Nothing to read a flag off, and that is stated rather than passing.
        assert!(unchecked_kinds(&found).contains(&"image_file_delete_pending"));
    }

    #[test]
    fn a_file_marked_for_deletion_is_reported_with_the_path_it_names() {
        let mut image = clean_image();
        image.put_u8(PROCESS_FILE_OBJECT + off::FILE_OBJECT_DELETE_PENDING, 1);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert_eq!(
            found
                .signals
                .iter()
                .find(|signal| matches!(signal, TamperSignal::ImageFileDeletePending { .. })),
            Some(&TamperSignal::ImageFileDeletePending {
                file_object: PROCESS_FILE_OBJECT,
                path: Some(FILE_OBJECT_PATH.to_string()),
            })
        );
    }

    #[test]
    fn a_delete_pending_byte_that_is_neither_set_nor_clear_is_smear_rather_than_a_signal() {
        let mut image = clean_image();
        image.put_u8(PROCESS_FILE_OBJECT + off::FILE_OBJECT_DELETE_PENDING, 0x5A);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(!signal_kinds(&found).contains(&"image_file_delete_pending"));
        let entry = found
            .not_checked
            .iter()
            .find(|entry| entry.check == TamperCheck::ImageFileDeletePending)
            .expect("the check is recorded as not made");
        assert!(
            entry.reason.contains("90"),
            "the reason must carry the value that was found: {}",
            entry.reason
        );
    }

    #[test]
    fn a_build_without_a_delete_pending_member_says_so_rather_than_reporting_nothing() {
        let members = Members {
            delete_pending: false,
            ..Members::default()
        };
        let fixture = Fixture::with(clean_image(), members);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(!signal_kinds(&found).contains(&"image_file_delete_pending"));
        let entry = found
            .not_checked
            .iter()
            .find(|entry| entry.check == TamperCheck::ImageFileDeletePending)
            .expect("the check is recorded as not made");
        assert!(
            entry.reason.contains(MEMBER_DELETE_PENDING),
            "the reason must name the member: {}",
            entry.reason
        );
    }

    #[test]
    fn a_build_without_an_image_file_pointer_leaves_both_ghosting_checks_unmade() {
        let members = Members {
            image_file_pointer: false,
            ..Members::default()
        };
        let fixture = Fixture::with(clean_image(), members);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(unchecked_kinds(&found).contains(&"image_file_pointer"));
        assert!(unchecked_kinds(&found).contains(&"image_file_delete_pending"));
        // The image side is untouched by the missing member.
        assert!(!unchecked_kinds(&found).contains(&"image_base"));
    }

    // ── Degraded evidence ───────────────────────────────────────────────────

    #[test]
    fn a_process_whose_own_address_space_is_missing_still_has_its_file_object_examined() {
        // `examine_process` builds the address space itself, and this fixture's
        // layer publishes no paging mode, so it cannot be built. The checks
        // that need it are recorded; the ones that do not still run.
        let mut image = clean_image();
        image.put_u8(PROCESS_FILE_OBJECT + off::FILE_OBJECT_DELETE_PENDING, 1);
        let fixture = Fixture::new(image);
        let found = examine_process(
            &fixture.profile,
            &fixture.symbols,
            &record("notepad.exe"),
            &fixture.config,
        );

        assert!(signal_kinds(&found).contains(&"image_file_delete_pending"));
        let entry = found
            .not_checked
            .iter()
            .find(|entry| entry.check == TamperCheck::ImageBase)
            .expect("the comparison is recorded as not made");
        assert!(
            entry.reason.contains("address space"),
            "the reason must say what could not be built: {}",
            entry.reason
        );
    }

    #[test]
    fn a_check_that_could_not_be_made_is_recorded_once_with_the_reason_nearest_the_failure() {
        let mut image = clean_image();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, 0);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        let occurrences = found
            .not_checked
            .iter()
            .filter(|entry| entry.check == TamperCheck::ImageVadFile)
            .count();
        assert_eq!(occurrences, 1);
    }

    #[test]
    fn a_process_structure_that_cannot_be_read_leaves_every_check_named_as_unmade() {
        let fixture = Fixture::new(clean_image());
        let mut process = record("notepad.exe");
        process.address = 0x1F00_0000;
        let reader = fixture.reader();
        let tree = fixture.tree();
        let found = examine_process_in(
            &fixture.symbols,
            &reader,
            &reader,
            &tree,
            &process,
            &fixture.config,
        );

        assert_eq!(found.not_checked.len(), TamperCheck::ALL.len());
        assert!(found.signals.is_empty());
        assert!(!found.fully_examined());
    }

    // ── Scans ───────────────────────────────────────────────────────────────

    fn list(processes: Vec<ProcessRecord>) -> ProcessList {
        ProcessList {
            head: 0x900,
            links_offset: 24,
            processes,
            forward_stop: ListStop::Wrapped,
            backward_stop: None,
        }
    }

    /// The same list, but the walk stopped at its cap: the list continues.
    fn capped_list(processes: Vec<ProcessRecord>) -> ProcessList {
        ProcessList {
            head: 0x900,
            links_offset: 24,
            processes,
            forward_stop: ListStop::CapReached { cap: 1 },
            backward_stop: None,
        }
    }

    #[test]
    fn a_scan_carries_the_completeness_of_the_process_list_it_walked() {
        // "No tampering signals" is an exculpatory finding. Over a process list
        // that stopped at its cap it is not a finding at all — the process
        // doing the tampering may be one the list never reached. The scan does
        // exactly the same work in both halves here; only the list differs.
        let fixture = Fixture::new(clean_image());
        let process = record("notepad.exe");

        let whole = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![process.clone()]),
            &fixture.config,
        );
        assert!(
            whole.inventory.is_complete(),
            "a list walked end to end yields a complete inventory"
        );

        let truncated = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &capped_list(vec![process]),
            &fixture.config,
        );
        assert_eq!(
            truncated.examined.len(),
            whole.examined.len(),
            "the scan did exactly the same work; only the list it rested on differs"
        );
        assert_eq!(truncated.skipped_total, 0);
        assert_eq!(truncated.stop, ScanStop::Exhausted);
        assert!(
            !truncated.inventory.is_complete(),
            "a capped list must reach the scan as a floor"
        );
        assert!(
            !truncated.is_complete(),
            "a flawless scan over a short list must not report a total"
        );
        let body = truncated.to_json();
        assert_eq!(body["content_complete"], false);
        assert_eq!(body["process_inventory_incomplete"], true);
        assert_eq!(body["process_inventory"]["count_is_floor"], true);
        assert!(
            truncated
                .incomplete()
                .iter()
                .any(|entry| entry.detail.contains("active process list")),
            "the reason the list fell short must travel with the scan: {:?}",
            truncated.incomplete()
        );
    }

    #[test]
    fn a_scan_that_did_everything_asked_of_it_is_still_a_floor_over_a_short_list() {
        // The inventory join in isolation: an otherwise flawless scan.
        let flawless = TamperScan {
            examined: Vec::new(),
            skipped: Vec::new(),
            skipped_total: 0,
            stop: ScanStop::Exhausted,
            inventory: crate::process::ProcessInventory {
                head: 0x900,
                listed: 3,
                complete: true,
                incomplete: Vec::new(),
            },
        };
        assert!(flawless.is_complete());
        assert_eq!(flawless.to_json()["content_complete"], true);

        let over_a_floor = TamperScan {
            inventory: crate::process::ProcessInventory {
                head: 0x900,
                listed: 3,
                complete: false,
                incomplete: vec![Incomplete::new(
                    IncompleteReason::CapReached,
                    "the process list stopped at its cap".to_string(),
                )],
            },
            ..flawless
        };
        assert!(!over_a_floor.is_complete());
        assert_eq!(over_a_floor.to_json()["content_complete"], false);
    }

    #[test]
    fn a_scan_skips_a_process_with_no_user_address_space_and_says_why() {
        let fixture = Fixture::new(clean_image());
        let mut system = record("System");
        system.peb = Field::NotApplicable;
        let scan = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![system]),
            &fixture.config,
        );

        assert!(scan.examined.is_empty());
        assert_eq!(scan.skipped_total, 1);
        assert!(scan.skipped[0].reason.contains("no user address space"));
        assert!(!scan.is_complete());
        assert!(!scan.incomplete().is_empty());
    }

    #[test]
    fn a_build_that_declares_no_peb_does_not_have_every_process_declared_to_have_no_address_space()
    {
        // A build whose `_EPROCESS` declares no `Peb` yields
        // `Field::NotDeclared`, which is a fact about the build. Skipping on it
        // would silently declare every process on the machine to have no user
        // address space — a claim about each process that this image does not
        // support — and would leave the ghosting checks, which never touch the
        // PEB, unrun on all of them.
        //
        // The two used to share `Field::NotApplicable`, so this test could only
        // be written by knowing which caller had produced the value. They are
        // now separate variants and the fixture states which case it means.
        let mut image = clean_image();
        image.put_u8(PROCESS_FILE_OBJECT + off::FILE_OBJECT_DELETE_PENDING, 1);
        let members = Members {
            peb: false,
            ..Members::default()
        };
        let fixture = Fixture::with(image, members);
        let mut process = record("notepad.exe");
        process.peb = Field::NotDeclared { member: "Peb" };

        let scan = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![process]),
            &fixture.config,
        );

        assert_eq!(
            scan.skipped_total, 0,
            "a missing member is a fact about the build, not about the process: {:?}",
            scan.skipped
        );
        assert_eq!(scan.examined.len(), 1);
        let found = &scan.examined[0];
        assert!(
            signal_kinds(found).contains(&"image_file_delete_pending"),
            "the checks that do not need a PEB must still run: {:?}",
            found.signals
        );
        let entry = found
            .not_checked
            .iter()
            .find(|entry| entry.check == TamperCheck::ImageBase)
            .expect("the image comparison is recorded as not made");
        assert!(
            entry.reason.contains("Peb"),
            "the reason must name the member the build lacks: {}",
            entry.reason
        );
    }

    #[test]
    fn a_process_whose_peb_pointer_is_null_is_still_skipped_on_a_build_that_declares_one() {
        // The other half of the same distinction: on a build that does declare
        // `Peb`, a `NotApplicable` really does mean this process has none.
        let fixture = Fixture::new(clean_image());
        let mut system = record("System");
        system.peb = Field::NotApplicable;
        let scan = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![system]),
            &fixture.config,
        );

        assert_eq!(scan.skipped_total, 1);
        assert!(scan.examined.is_empty());
    }

    #[test]
    fn a_scan_skips_an_exited_process_unless_it_is_asked_not_to() {
        let fixture = Fixture::new(clean_image());
        let mut exited = record("notepad.exe");
        // All three fields name the same instant. They did not: the FILETIME was
        // 2021-06-01 and the other two were 2021-06-04, and a fixture whose own
        // fields disagree is where a wrong expectation about the conversion gets
        // written down.
        exited.exit_time = ProcessTime::At {
            filetime: 132_672_384_000_000_000,
            unix_seconds: 1_622_764_800,
            rfc3339: "2021-06-04T00:00:00Z".to_string(),
        };
        let scan = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![exited.clone()]),
            &fixture.config,
        );
        assert_eq!(scan.skipped_total, 1);

        let config = HollowConfig {
            include_exited: true,
            ..fixture.config.clone()
        };
        let scan = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![exited]),
            &config,
        );
        assert_eq!(scan.skipped_total, 0);
        assert_eq!(scan.examined.len(), 1);
    }

    #[test]
    fn a_scan_that_reaches_its_cap_says_the_list_continued() {
        let fixture = Fixture::new(clean_image());
        let config = HollowConfig {
            max_processes: 1,
            ..fixture.config.clone()
        };
        let scan = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![record("notepad.exe"), record("notepad.exe")]),
            &config,
        );

        assert_eq!(scan.examined.len(), 1);
        assert_eq!(scan.stop, ScanStop::CapReached { cap: 1 });
        assert!(!scan.is_complete());
        assert!(scan
            .incomplete()
            .iter()
            .any(|entry| entry.detail.contains("continues")));
    }

    #[test]
    fn a_scan_keeps_processes_it_found_nothing_about_so_their_unmade_checks_are_visible() {
        let fixture = Fixture::new(clean_image());
        let scan = examine_processes(
            &fixture.profile,
            &fixture.symbols,
            &list(vec![record("notepad.exe")]),
            &fixture.config,
        );

        assert_eq!(scan.examined.len(), 1);
        assert!(scan.with_signals().is_empty());
        // The address space could not be built in this fixture, so the scan is
        // not complete and must not read as a clean machine.
        assert!(!scan.is_complete());
    }

    // ── Path and name rules ─────────────────────────────────────────────────

    #[test]
    fn the_final_component_of_a_path_is_taken_from_either_separator() {
        assert_eq!(
            final_component(r"\Device\HarddiskVolume2\Windows\notepad.exe"),
            "notepad.exe"
        );
        assert_eq!(final_component(r"C:\Windows\notepad.exe"), "notepad.exe");
        assert_eq!(final_component("/usr/bin/thing"), "thing");
        assert_eq!(final_component("notepad.exe"), "notepad.exe");
        assert_eq!(final_component(""), "");
    }

    #[test]
    fn names_are_compared_without_regard_to_case() {
        assert!(names_agree("NOTEPAD.EXE", "notepad.exe", 15));
        assert!(names_agree("notepad.exe", "NotePad.Exe", 15));
    }

    #[test]
    fn a_recorded_name_shorter_than_the_array_is_compared_whole() {
        assert!(!names_agree("notepad.exe", "note", 15));
        assert!(names_agree("note", "note", 15));
    }

    #[test]
    fn a_recorded_name_that_filled_the_array_is_treated_as_a_prefix() {
        assert!(names_agree("averyverylongname.exe", "averyverylongn", 14));
        assert!(!names_agree("somethingelse.exe", "averyverylongn", 14));
    }

    /// **A name cut off by the array's own terminator is a prefix too.**
    ///
    /// The off-by-one this pins cost 23 false signals on a clean Windows 11
    /// capture: the array is fifteen bytes, the kernel stores fourteen
    /// characters and a NUL, and a test of `len >= width` never fired. Every
    /// process with a name over fourteen characters — `fontdrvhost.exe`,
    /// `RuntimeBroker.exe`, `msedgewebview2.exe` — was reported as mapping a
    /// different file from the one it claims to be.
    #[test]
    fn a_name_cut_off_by_the_arrays_terminator_is_also_a_prefix() {
        // Fourteen characters in a fifteen-byte array: full, terminator
        // included.
        assert!(names_agree("fontdrvhost.exe", "fontdrvhost.ex", 15));
        assert!(names_agree("RuntimeBroker.exe", "RuntimeBroker.", 15));
        assert!(names_agree("msedgewebview2.exe", "msedgewebview2", 15));
        // And it is still a prefix test, not a licence: a shorter name, or one
        // that is not a prefix, still disagrees.
        assert!(!names_agree("notepad.exe", "fontdrvhost.ex", 15));
        assert!(!names_agree("notepad.exe", "note", 15));
    }

    #[test]
    fn copy_on_write_is_not_counted_as_writable_when_deciding_write_plus_execute() {
        // Every mapped image on the machine is copy-on-write and executable.
        // Counting that as "writable and executable" would flag all of them.
        let table =
            ProtectionTable::from_values(vec![0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80]);
        let config = HollowConfig {
            vad: VadWalkConfig {
                protections: Some(Arc::new(table)),
                ..VadWalkConfig::default()
            },
            ..HollowConfig::default()
        };
        assert_eq!(writable_and_executable(&config, Some(7)), Some(false));
        assert_eq!(writable_and_executable(&config, Some(6)), Some(true));
        assert_eq!(writable_and_executable(&config, Some(2)), Some(false));
        // Past the end of this kernel's table: unknown, never false.
        assert_eq!(writable_and_executable(&config, Some(31)), None);
        assert_eq!(writable_and_executable(&config, None), None);
    }

    #[test]
    fn a_protection_index_with_no_table_is_unknown_rather_than_not_writable() {
        let config = HollowConfig::default();
        assert_eq!(writable_and_executable(&config, Some(6)), None);
    }

    // ── Reporting ───────────────────────────────────────────────────────────

    #[test]
    fn every_signal_carries_both_sides_of_its_comparison_in_its_json() {
        let mut image = clean_image();
        image.put_u64(PEB_AT + off::PEB_IMAGE_BASE, 0x66_0000);
        put_private(&mut image, IMAGE_VAD);
        put_protection(&mut image, IMAGE_VAD, 6);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(found.signals.len() >= 3);
        for signal in &found.signals {
            let json = signal.to_json();
            assert_eq!(json["signal"], signal.as_str());
            assert_eq!(json["check"], signal.check().as_str());
            assert!(!signal.describe().is_empty());
            assert!(json["detail"].as_str().is_some_and(|text| !text.is_empty()));
        }
        let json = found.to_json();
        assert_eq!(json["consistent"], false);
        assert_eq!(json["fully_examined"], true);
    }

    // ── The PEB masquerade ──────────────────────────────────────────────────

    /// **The masquerade: the process publishes a path the kernel's own audit
    /// record contradicts.**
    ///
    /// Overwriting `_RTL_USER_PROCESS_PARAMETERS.ImagePathName` so a tool
    /// reading the PEB reports the wrong program is a published, scripted
    /// technique. `SeAuditProcessCreationInfo.ImageFileName` is in kernel
    /// memory and the process cannot reach it, which is what makes the
    /// comparison worth anything.
    #[test]
    fn a_peb_path_the_kernels_audit_record_contradicts_is_a_signal() {
        let mut image = clean_image();
        // The process now claims to be svchost.exe. The kernel still records
        // notepad.exe, and so does the mapped file.
        put_unicode(
            &mut image,
            PARAMS_AT + off::PARAMS_IMAGE_PATH,
            IMAGE_PATH_BUFFER,
            r"C:\Windows\System32\svchost.exe",
        );
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        let audit: Vec<&TamperSignal> = found
            .signals
            .iter()
            .filter(|s| matches!(s, TamperSignal::AuditPathDiffers { .. }))
            .collect();
        assert_eq!(
            audit.len(),
            1,
            "one comparison disagrees: {:?}",
            found.signals
        );
        match audit[0] {
            TamperSignal::AuditPathDiffers {
                audit_path,
                claimed,
                source,
            } => {
                assert_eq!(audit_path, AUDIT_PATH);
                assert!(claimed.ends_with("svchost.exe"), "got {claimed}");
                assert_eq!(*source, NameSource::PebImagePathName);
            }
            other => panic!("expected an audit-path signal, got {other:?}"),
        }
        // Both sides are in the JSON, and the basis says why the kernel's copy
        // is worth comparing against.
        let json = audit[0].to_json();
        assert_eq!(json["check"], "audit_image_path");
        assert!(json["audit_path"].as_str().is_some());
        assert!(json["claimed"].as_str().is_some());
        assert!(json["audit_path_basis"]
            .as_str()
            .unwrap_or_default()
            .contains("cannot write it"));
        assert!(found.has_signals());
        assert!(
            found.fully_examined(),
            "the check was made, and it disagreed"
        );
    }

    /// The other direction: `_EPROCESS.ImageFileName` itself disagreeing with
    /// the kernel's audit record. Both are kernel-held, so this is a torn or
    /// reused structure rather than a masquerade — and it is still reported,
    /// with the source named, so an examiner can tell which it is.
    #[test]
    fn the_truncated_kernel_name_is_compared_against_the_audit_record_too() {
        let fixture = Fixture::new(clean_image());
        let found = fixture.examine(&record("cmd.exe"));
        let audit: Vec<&TamperSignal> = found
            .signals
            .iter()
            .filter(|s| matches!(s, TamperSignal::AuditPathDiffers { .. }))
            .collect();
        assert!(
            audit.iter().any(|s| matches!(
                s,
                TamperSignal::AuditPathDiffers {
                    source: NameSource::ImageFileName,
                    ..
                }
            )),
            "the truncated name is compared as well: {:?}",
            found.signals
        );
    }

    /// **A fifteen-byte truncation is not a different name.** The comparison
    /// honours the width `_EPROCESS.ImageFileName` declares, or every process
    /// with a long name would be reported as masquerading as itself.
    #[test]
    fn a_name_truncated_by_the_members_width_is_not_a_disagreement() {
        let mut image = clean_image();
        // A fifteen-character name, truncated exactly at the member's width,
        // whose audit path holds the whole thing.
        put_unicode(
            &mut image,
            AUDIT_NAME_INFORMATION + off::OBJECT_NAME_INFORMATION_NAME,
            AUDIT_BUFFER,
            r"C:\Windows\System32\averylongprocesname.exe",
        );
        put_unicode(
            &mut image,
            PARAMS_AT + off::PARAMS_IMAGE_PATH,
            IMAGE_PATH_BUFFER,
            r"C:\Windows\System32\averylongprocesname.exe",
        );
        let fixture = Fixture::new(image);
        // Exactly fifteen characters: the member's declared width, which is
        // what makes it a truncation rather than a shorter name. Fourteen
        // would be a name that simply differs, and `names_agree` is right to
        // say so.
        let found = fixture.examine(&record("averylongproces"));
        assert!(
            !found
                .signals
                .iter()
                .any(|s| matches!(s, TamperSignal::AuditPathDiffers { .. })),
            "a truncation is a prefix, not a different name: {:?}",
            found.signals
        );
    }

    /// **A null audit pointer leaves the check unmade**, which is what the
    /// System process looks like — and is not a clean result.
    #[test]
    fn a_process_with_no_audit_record_leaves_the_check_unmade() {
        let mut image = clean_image();
        image.put_u64(EPROCESS_AT + off::EPROCESS_AUDIT, 0);
        let fixture = Fixture::new(image);
        let found = fixture.examine(&record("notepad.exe"));

        assert!(
            !found
                .signals
                .iter()
                .any(|s| matches!(s, TamperSignal::AuditPathDiffers { .. })),
            "nothing was compared, so nothing is claimed"
        );
        assert!(
            unchecked_kinds(&found).contains(&"audit_image_path"),
            "the unmade check is named: {:?}",
            found.not_checked
        );
        assert!(!found.fully_examined());
        assert!(!found.is_consistent(), "an unmade check is not a clean one");
    }

    /// The audit path is published on the record even when it agrees, so a
    /// report can show the comparison rather than only its verdict.
    #[test]
    fn the_audit_path_is_published_even_when_it_agrees() {
        let fixture = Fixture::new(clean_image());
        let found = fixture.examine(&record("notepad.exe"));
        assert_eq!(found.audit_image_path.as_deref(), Some(AUDIT_PATH));
        assert_eq!(found.to_json()["audit_image_path"], AUDIT_PATH);
    }

    #[test]
    fn every_check_names_what_it_would_have_established() {
        for check in TamperCheck::ALL {
            assert!(!check.as_str().is_empty());
            assert!(!check.describe().is_empty());
        }
    }
}
