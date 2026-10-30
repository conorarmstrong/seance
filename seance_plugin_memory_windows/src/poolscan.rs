//! Pool scanning: recovering kernel objects the kernel no longer links to.
//!
//! Every executive object on Windows — a process, a thread, a file, a driver, a
//! mutant, a registry hive — is a *pool allocation*, and every pool allocation
//! begins with a `_POOL_HEADER` carrying a four-byte tag naming what the kernel
//! allocated it for. `Proc` is a process. `File` is a file object. `MmLd` is a
//! loaded kernel module.
//!
//! That tag is what makes memory forensics different from reading a live
//! system. A list walk shows what the kernel currently links to; a pool sweep
//! shows what the *allocator* still holds, which includes:
//!
//! * objects freed before the image was acquired — a process that exited an
//!   hour ago, a file that was closed, a connection that was torn down;
//! * objects a rootkit unlinked from the kernel's lists to hide them, which is
//!   the classic direct-kernel-object-manipulation attack and which a list walk
//!   cannot see by construction.
//!
//! An object present in a sweep and absent from the corresponding list walk is
//! a finding. An object present in both is ordinary. Running only one and
//! describing it as the other is a mis-statement about the evidence, which is
//! why this module exists separately from the list-walking stages.
//!
//! # Finding the object inside the allocation
//!
//! The tag is not the object. Getting from a tag match to the first byte of the
//! object is the whole difficulty of this module, it is different on every
//! generation of Windows, and an error of sixteen bytes produces a *complete,
//! plausible, wrong* object: a process with a believable PID and a name made of
//! whatever bytes happened to be sixteen bytes early.
//!
//! ```text
//!  pool_base ─┬─ _POOL_HEADER ──────────────┐ PoolTag lives inside this
//!             │                             │
//!             ├─ padding                    │  } present only sometimes,
//!             ├─ optional object headers    │  } in a build-dependent set
//!             │                             │
//!             ├─ _OBJECT_HEADER ────────────┤  } executive objects only
//!             │      ...                    │
//!             └─ Body ← the object          ┘
//! ```
//!
//! Three shapes, and the module implements all three rather than picking one:
//!
//! 1. **Not an executive object** (`MmLd`, `CM10`, `AtmT`). There is no object
//!    header at all; the structure starts immediately after the pool header.
//! 2. **Executive, Windows 7 and earlier** — *bottom-up*. The object is placed
//!    so that it ends at the end of the allocation, so its start is
//!    `pool_base + BlockSize × alignment − round_up(sizeof(type), alignment)`.
//! 3. **Executive, Windows 8 and later** — *top-down*. The optional headers
//!    (`_OBJECT_HEADER_NAME_INFO`, `_OBJECT_HEADER_QUOTA_INFO`, …) are present
//!    or absent per object, so the object header's position is not fixed. Each
//!    aligned offset in the allocation is tested as a candidate object header,
//!    and one is accepted when it has a believable `PointerCount` and an
//!    `InfoMask` whose headers fit in the space in front of it.
//!
//! Which of (2) and (3) applies is decided by the build number, and a profile
//! without one fails closed ([`PoolError::BuildUnknown`]) rather than choosing.
//!
//! # Nothing here is a constant that should have been a symbol
//!
//! `_POOL_HEADER` is 8 bytes on x86 and 16 on x64; `PoolTag` sits at offset 4 in
//! both; `_OBJECT_HEADER.Body` moves between builds; which optional headers
//! exist changes with the build and *shifts the meaning of every `InfoMask`
//! bit*. Every one of those numbers is read from the symbol table for the build
//! in hand. A member this build does not have is an error naming the member.
//!
//! ## A pre-flight proves what this build will read, and nothing else
//!
//! [`PoolSymbols::from_profile`] resolves the layout once so a missing member is
//! reported at construction rather than at candidate three thousand. That is
//! only sound while the pre-flight is *the same set* the chosen branch reads.
//! Proving a member in statement position — calling `member_offset` for its
//! `Err` and throwing the offset away — is how the two drift apart, and it once
//! made `_OBJECT_HEADER.InfoMask`, a Vista-and-later field that only the
//! top-down search reads, fatal on Windows XP for eight stages that never touch
//! an object header. Two greps find the shape:
//!
//! ```text
//! rg -n 'member_offset\([^)]*\)\?;'
//! rg -n 'size_of\([^)]*\)\?;'
//! ```
//!
//! A hit is legitimate only if every candidate on *every* build reaches the read
//! — `_POOL_HEADER.BlockSize` and `.PoolType` are, and stay. A hit that only one
//! branch reads belongs inside that branch, with a message naming the member.
//! Absence there is a fact about the build (`not_declared`), never an
//! [`IncompleteReason`]: the other branch's sweep is complete.
//!
//! The one number that is genuinely not a symbol is the **pool allocator's
//! granularity**: 16 bytes on 64-bit Windows, 8 on 32-bit. That is a property
//! of the allocator rather than of any structure, and it is derived here from
//! the pointer width the symbol table declares rather than from the host Séance
//! happens to be running on.
//!
//! # Where the sweep runs
//!
//! Before Windows 10 these allocations live in non-paged physical memory, and
//! sweeping the **physical** layer finds every one of them — including those the
//! kernel virtual address space no longer maps, which are exactly the historical
//! objects the sweep exists for. From Windows 10 the pool is laid out such that
//! the sweep must run against the **kernel virtual** layer instead. Which space
//! was swept is recorded on the outcome, because it bounds what could have been
//! found.
//!
//! # What a rejected candidate is
//!
//! A four-byte tag matches by accident constantly: in compressed data, in a
//! string table, in the middle of a JPEG. A candidate that fails validation is
//! **discarded and counted**, never emitted with defaults filled in. The count
//! of rejections is exact; the per-candidate detail is capped, because a sweep
//! of a large image produces hundreds of thousands of coincidences and none of
//! them is evidence.

use std::collections::BTreeMap;
use std::ops::Range;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::{BindError, BuildBinding, MemberSet, MemberSpec, TypeSpec, TypeUse};
use seance_memory::object::{Obj, ObjError, PlausibilityFailure, StructReader};
use seance_memory::scan::{
    scan_layer, scan_range, MultiStringScanner, ScanConfig, ScanError, ScanOutcome,
};
use seance_memory::{Incomplete, MemoryLayer};
use seance_symbols::SymbolError;

use crate::automagic::kernel::{KERNEL_HALF_START_X64, KERNEL_HALF_START_X86};
use crate::module::STAGE_POOL_SCAN;
use crate::profile::WindowsProfile;

/// The kernel type carrying the allocation tag.
pub const TYPE_POOL_HEADER: &str = "_POOL_HEADER";

/// The kernel type in front of every executive object's body.
pub const TYPE_OBJECT_HEADER: &str = "_OBJECT_HEADER";

/// The object-manager type whose `Name` gives an object type its name.
pub const TYPE_OBJECT_TYPE: &str = "_OBJECT_TYPE";

/// Symbol naming the table of `_OBJECT_TYPE` pointers, on Windows 7 and later.
pub const SYMBOL_TYPE_INDEX_TABLE: &str = "ObTypeIndexTable";

/// The same table's name on builds that predate `ObTypeIndexTable`.
pub const SYMBOL_OBJECT_TYPES: &str = "ObpObjectTypes";

/// Symbol naming the byte Windows 10 and later mix into `TypeIndex`.
pub const SYMBOL_HEADER_COOKIE: &str = "ObHeaderCookie";

/// First Windows build whose object headers store a *mixed* `TypeIndex`.
///
/// From Windows 10 RTM the stored index is
/// `real ^ (header_address >> 8) ^ ObHeaderCookie`, so the same object type has
/// a different stored index at every address. Before it, the index is the index.
pub const FIRST_MIXED_TYPE_INDEX_BUILD: u32 = 10240;

/// The optional object headers, in the order their `InfoMask` bits are
/// assigned.
///
/// **The order is load-bearing and the list is filtered per build.** A bit in
/// `InfoMask` does not name a header type directly: bit *i* means "the *i*th
/// header type that this build actually declares is present". Builds differ —
/// `_OBJECT_HEADER_PADDING_INFO` does not exist before 9200,
/// `_OBJECT_HEADER_HANDLE_REVOCATION_INFO` exists only around 10586 — so a
/// build missing one type shifts the meaning of every bit above it. Assuming a
/// fixed bit-to-type mapping computes the wrong distance from the pool header
/// to the object, which lands the object body in the middle of the headers.
pub const OPTIONAL_HEADER_TYPES: [&str; 9] = [
    "_OBJECT_HEADER_CREATOR_INFO",
    "_OBJECT_HEADER_NAME_INFO",
    "_OBJECT_HEADER_HANDLE_INFO",
    "_OBJECT_HEADER_QUOTA_INFO",
    "_OBJECT_HEADER_PROCESS_INFO",
    "_OBJECT_HEADER_AUDIT_INFO",
    "_OBJECT_HEADER_EXTENDED_INFO",
    "_OBJECT_HEADER_HANDLE_REVOCATION_INFO",
    "_OBJECT_HEADER_PADDING_INFO",
];

/// Everything a sweep of **any** build reads out of the symbol table.
///
/// # What an examiner learns
///
/// Which structure layout the sweep used, and — for anything this build does
/// not declare — that the field does not exist on this operating system rather
/// than that the analysis failed to find it. [`PoolSymbols::layout_json`]
/// carries it onto the stage record.
///
/// # Why these four are required and nothing else is
///
/// `PoolTag` locates a scan hit inside its allocation; `BlockSize` gives the
/// allocation its length; `PoolType` is what separates a paged allocation from
/// a non-paged or freed one. Every candidate on every build is decoded through
/// all three, in both placements, so a build without one cannot produce a
/// single trustworthy row. `_POOL_HEADER` itself is required for the same
/// reason.
///
/// `_OBJECT_HEADER` and its `Body` are **not** required: a build whose table
/// has no object header at all still supports the tag sweep, and the
/// constraints that need an object header are refused individually, naming what
/// is missing. See [`PoolSymbols::body_offset`].
const POOL_LAYOUT: MemberSet = MemberSet::new(
    STAGE_POOL_SCAN,
    &[
        TypeSpec::new("pool_header", &[TYPE_POOL_HEADER]).required(
            "a pool allocation cannot be sized or located, so no candidate object can be found \
             at all",
        ),
        TypeSpec::new("object_header", &[TYPE_OBJECT_HEADER]),
    ],
    &[
        MemberSpec::new("pool_tag", &[TYPE_POOL_HEADER], &["PoolTag"]).required(
            "the four bytes a scan matched cannot be placed inside the allocation they belong \
             to, so no allocation base can be computed and no object follows from a tag",
        ),
        MemberSpec::new("block_size", &[TYPE_POOL_HEADER], &["BlockSize"]).required(
            "an allocation's length is unknown, and length is what every candidate on every \
             build is sized and bounds-checked through",
        ),
        MemberSpec::new("pool_type", &[TYPE_POOL_HEADER], &["PoolType"]).required(
            "a paged allocation cannot be told from a non-paged or a freed one, so the sweep \
             would admit allocations the object it is looking for is never made from",
        ),
        MemberSpec::new("body", &[TYPE_OBJECT_HEADER], &["Body"]),
    ],
);

/// The `_OBJECT_HEADER` members the **top-down** search reads, and only it.
///
/// # Bound only on the build that reads them
///
/// [`probe_object_header`] reads both at every aligned offset it tries, so a
/// build that places objects top-down and does not declare one of them cannot
/// be swept at all — so both are marked required *here*, in a declaration that
/// is bound only when [`PoolSymbols::top_down`] is true, rather than in
/// [`POOL_LAYOUT`], which every build binds.
///
/// Neither member exists before Vista: Windows XP and Server 2003 carry
/// `NameInfoOffset` / `HandleInfoOffset` / `QuotaInfoOffset` as direct bytes
/// instead of an `InfoMask` bitmap, and their bottom-up placement
/// ([`bottom_up`]) reads neither member.
///
/// **Proving these on a bottom-up build is a defect, not caution.** It refuses a
/// sweep the build can perform completely, for a field nothing on that path
/// would ever read — and the refusal propagates to every stage built on
/// [`PoolSymbols`]. Their absence on such a build is `not_declared`, never
/// incompleteness: an incomplete flag there would tell an examiner evidence was
/// missed when the sweep in fact missed nothing. That is the defect that left a
/// real Windows XP capture with three of twenty stages complete.
const TOP_DOWN_LAYOUT: MemberSet = MemberSet::new(
    STAGE_POOL_SCAN,
    &[],
    &[
        MemberSpec::new("pointer_count", &[TYPE_OBJECT_HEADER], &["PointerCount"]).required(
            "this build places an executive object at the top of its allocation, so every \
             candidate offset is tested by reading a reference count there, and with no \
             reference count no candidate can be accepted or rejected",
        ),
        MemberSpec::new("info_mask", &[TYPE_OBJECT_HEADER], &["InfoMask"]).required(
            "this build places an executive object at the top of its allocation, so the \
             optional headers sitting in front of the body are located from that bitmap, and \
             without it the body's address cannot be computed",
        ),
    ],
);

/// Which of [`OPTIONAL_HEADER_TYPES`] carries the padding amount.
const PADDING_INFO_TYPE: &str = "_OBJECT_HEADER_PADDING_INFO";

/// The member of `_OBJECT_HEADER_PADDING_INFO` holding the padding length.
const PADDING_AMOUNT_MEMBER: &str = "PaddingAmount";

/// Ceiling on a believable `_OBJECT_HEADER.PointerCount`.
///
/// A live object is referenced by handles and by kernel pointers; sixteen
/// million references is not a machine state, it is the bytes at that offset not
/// being a reference count. The same bound upstream uses, and it is the single
/// most discriminating test the top-down search has.
pub const MAX_POINTER_COUNT: i64 = 0x0100_0000;

/// Pool allocation granularity on a 64-bit kernel, in bytes.
pub const POOL_ALIGNMENT_64: u64 = 16;

/// Pool allocation granularity on a 32-bit kernel, in bytes.
pub const POOL_ALIGNMENT_32: u64 = 8;

/// First Windows major version whose pool sweep runs in the kernel's virtual
/// address space rather than in physical memory.
pub const FIRST_VIRTUAL_SCAN_MAJOR: u32 = 10;

/// First Windows major version using the Vista pool-type encoding.
///
/// Vista is 6.0. The parity of `_POOL_HEADER.PoolType` means the opposite thing
/// on either side of this line, so a paged allocation on XP and a non-paged
/// allocation on Vista are the same bit pattern.
pub const FIRST_VISTA_MAJOR: u32 = 6;

/// Earliest process creation time this module will believe, as a FILETIME.
///
/// 1990-01-01T00:00:00Z, in 100 ns ticks since 1601-01-01. Deliberately an
/// **absolute** window rather than upstream's "between 1998 and ten years from
/// now": a bound that moves with the wall clock makes the same image yield
/// different results in different years, and a result that cannot be reproduced
/// is not evidence.
pub const MIN_PROCESS_FILETIME: u64 = 122_756_256_000_000_000;

/// Latest process creation time this module will believe, as a FILETIME.
///
/// 2100-01-01T00:00:00Z.
pub const MAX_PROCESS_FILETIME: u64 = 157_469_184_000_000_000;

/// Ceiling on `_UNICODE_STRING.Length` this module will act on, in **bytes**.
///
/// `Length` is a `USHORT` counting bytes, not characters, so 65534 is the
/// largest even value it can hold. Capping before allocating matters because
/// the length came out of the image.
pub const MAX_UNICODE_STRING_BYTES: u64 = 65_534;

/// Ceiling on entries read from the object-type index table.
///
/// `TypeIndex` is a byte, so 256 is the whole space; the table is normally
/// around seventy entries long.
pub const MAX_OBJECT_TYPES: u64 = 256;

/// Ceiling on objects one sweep will return.
///
/// A busy machine has a few hundred processes and a few tens of thousands of
/// file objects. Reaching this means the sweep is matching noise, and it is
/// reported as a cap rather than as the end of the results.
pub const MAX_OBJECTS: usize = 1_000_000;

/// Ceiling on individually recorded rejections. The *count* stays exact.
pub const MAX_RECORDED_REJECTIONS: usize = 512;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a pool sweep before it can produce a result worth
/// reading.
///
/// Note what is *not* here: a candidate that failed validation. That is an
/// answer about one four-byte coincidence, and it lands in
/// [`PoolScanOutcome::rejected`] where an examiner can count it.
#[derive(Debug, thiserror::Error)]
pub enum PoolError {
    /// This build cannot be swept with what is available, and no partial answer
    /// would be honest. The message names exactly what is missing.
    #[error("kernel objects cannot be recovered from the pool on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// The Windows build number was never established.
    ///
    /// It decides whether the object sits at the top or the bottom of its
    /// allocation. Guessing puts every object at the wrong address, and every
    /// one of them still parses.
    #[error(
        "the Windows build number was never established, so it cannot be decided whether this \
         build places an executive object at the top or the bottom of its pool allocation"
    )]
    BuildUnknown,

    /// The same pool tag was given two different meanings.
    ///
    /// A sweep cannot report an allocation as two kinds of object at once, and
    /// silently keeping one of the two would make the result depend on
    /// declaration order.
    #[error("the pool tag {tag} is claimed by more than one constraint")]
    DuplicateTag {
        /// The tag, rendered printably.
        tag: String,
    },

    /// A declaration the sweep marked required could not be bound to this
    /// build.
    ///
    /// Transparent because [`BindError`]'s own message is already the sentence
    /// an examiner needs: it names the stage, the member, every name that was
    /// tried, and what the sweep cannot do without it. A build-variant member
    /// this kernel simply does not have never reaches here — that is
    /// `not_declared`, and it is an answer.
    #[error(transparent)]
    Binding(#[from] BindError),

    /// A typed read failed for a reason that invalidates the whole sweep rather
    /// than one candidate.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the sweep depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// The sweep itself could not be run.
    #[error("scanning for pool tags failed: {0}")]
    Scan(#[from] ScanError),
}

impl PoolError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            PoolError::Unsupported { .. } => "unsupported_build",
            PoolError::BuildUnknown => "build_unknown",
            PoolError::DuplicateTag { .. } => "duplicate_tag",
            // Same class as the hand-written refusal it replaced: from an
            // examiner's side, "this build does not declare a member the sweep
            // has to read" is the build being unsupported, whichever code path
            // discovered it.
            PoolError::Binding(_) => "unsupported_build",
            PoolError::Object(err) => err.class(),
            PoolError::Symbols(_) => "symbols",
            PoolError::Scan(_) => "scan",
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            PoolError::Object(err) => err.incomplete_reason(),
            PoolError::Scan(_) => IncompleteReason::ShortRead,
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be swept" refusal.
    pub fn unsupported(detail: impl Into<String>) -> PoolError {
        PoolError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Constraints ─────────────────────────────────────────────────────────────

/// Which pool types a constraint will accept an allocation from.
///
/// All three matter and they are not interchangeable. A **freed** allocation is
/// the historical object a sweep exists to find, so `free` is set on the
/// constraints for objects whose past instances are evidence. Accepting paged
/// pool for an object the kernel only ever allocates non-paged multiplies the
/// false-positive rate without finding anything real.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolTypes {
    /// Accept paged-pool allocations.
    pub paged: bool,
    /// Accept non-paged-pool allocations.
    pub nonpaged: bool,
    /// Accept freed allocations.
    pub free: bool,
}

impl PoolTypes {
    /// Accept any allocation, imposing no pool-type constraint.
    pub const fn any() -> Self {
        Self {
            paged: true,
            nonpaged: true,
            free: true,
        }
    }

    /// Accept non-paged and freed allocations: the shape for most executive
    /// objects.
    pub const fn nonpaged_or_free() -> Self {
        Self {
            paged: false,
            nonpaged: true,
            free: true,
        }
    }

    /// Accept paged and freed allocations.
    pub const fn paged_or_free() -> Self {
        Self {
            paged: true,
            nonpaged: false,
            free: true,
        }
    }

    /// Whether a raw `_POOL_HEADER.PoolType` value is admitted.
    ///
    /// **The encoding flipped at Vista.** Before Vista an odd `PoolType` is
    /// non-paged and an even non-zero one is paged; from Vista it is the other
    /// way round. Zero is a freed allocation in both. Reading one encoding with
    /// the other swaps paged and non-paged, which silently changes which
    /// allocations a constraint accepts.
    pub fn admits(self, pool_type: u64, vista_or_later: bool) -> bool {
        if pool_type == 0 {
            return self.free;
        }
        let odd = pool_type % 2 == 1;
        let is_paged = if vista_or_later { odd } else { !odd };
        if is_paged {
            self.paged
        } else {
            self.nonpaged
        }
    }
}

/// The type-specific believability test applied to a candidate object.
///
/// The structural checks — alignment, containment, full backing, canonical
/// pointers — rule out most coincidences, but not all: a page of zeros is
/// structurally a perfectly good `_EPROCESS`. Each variant here is the cheapest
/// question that only a real object of that type can answer, and it is the
/// difference between a process list and a list of addresses where a process
/// could have been.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObjectValidity {
    /// Nothing beyond the structural checks.
    None,
    /// `_EPROCESS`: an image name that starts with a non-NUL byte, and a
    /// creation time inside [`MIN_PROCESS_FILETIME`]..=[`MAX_PROCESS_FILETIME`].
    ///
    /// The System process is PID 4 and legitimately has no creation time, so it
    /// is exempted from the time test by name *and* by PID — exempting on either
    /// alone would let every zeroed page in the image through as a process.
    Process,
    /// `_FILE_OBJECT`: a file name of non-zero length whose buffer is an
    /// address the kernel address space actually maps.
    File,
    /// `_ETHREAD`: a thread id and an owning process id that are both multiples
    /// of four, which every id NT hands out is.
    Thread,
}

impl ObjectValidity {
    /// Members this policy reads.
    ///
    /// Checked once, before the sweep, so that a build naming one of them
    /// differently fails the whole stage naming the member rather than
    /// rejecting every object of the type — which would produce an empty table,
    /// and an empty table reads as a machine with no such objects.
    pub fn required_members(self) -> &'static [&'static str] {
        match self {
            ObjectValidity::None => &[],
            ObjectValidity::Process => &["ImageFileName", "UniqueProcessId", "CreateTime.QuadPart"],
            ObjectValidity::File => &["FileName.Length", "FileName.Buffer"],
            ObjectValidity::Thread => &["Cid.UniqueThread", "Cid.UniqueProcess"],
        }
    }
}

/// One pool tag and everything known about what it marks.
///
/// Built by [`builtin_constraints`] for the objects Windows tags itself, and
/// constructible by a caller that has its own tag knowledge.
#[derive(Debug, Clone)]
pub struct PoolConstraint {
    /// The four-byte tag as it appears in `_POOL_HEADER.PoolTag`.
    pub tag: [u8; 4],
    /// The structure the allocation holds.
    pub type_name: String,
    /// The object-manager type name, for allocations that carry an
    /// `_OBJECT_HEADER`. `None` means the structure follows the pool header
    /// directly with no object header at all.
    pub object_type: Option<String>,
    /// Which pool types the allocation may come from.
    pub page_type: PoolTypes,
    /// Smallest believable allocation, in bytes, or `None` for no lower bound.
    pub min_size: Option<u64>,
    /// Largest believable allocation, in bytes, or `None` for no upper bound.
    pub max_size: Option<u64>,
    /// Whether to skip comparing the object header's type against
    /// [`PoolConstraint::object_type`].
    ///
    /// Set for the objects whose tags are already unambiguous. It is not a
    /// licence to skip the *structural* checks, which always run.
    pub skip_type_test: bool,
    /// Structures allocated together with the main one, which count towards the
    /// size used to place the object bottom-up. `_DRIVER_OBJECT` is followed by
    /// a `_DRIVER_EXTENSION` in the same allocation, and omitting it puts the
    /// driver object one extension too high.
    pub additional_structures: Vec<String>,
    /// The type-specific believability test.
    pub validity: ObjectValidity,
}

impl PoolConstraint {
    /// A constraint with no size, type or validity restriction.
    pub fn new(tag: [u8; 4], type_name: impl Into<String>) -> Self {
        Self {
            tag,
            type_name: type_name.into(),
            object_type: None,
            page_type: PoolTypes::any(),
            min_size: None,
            max_size: None,
            skip_type_test: false,
            additional_structures: Vec::new(),
            validity: ObjectValidity::None,
        }
    }

    /// Mark the allocation as carrying an `_OBJECT_HEADER` of a named type.
    pub fn executive(mut self, object_type: impl Into<String>) -> Self {
        self.object_type = Some(object_type.into());
        self
    }

    /// Restrict which pool types the allocation may come from.
    pub fn page_type(mut self, page_type: PoolTypes) -> Self {
        self.page_type = page_type;
        self
    }

    /// Require the allocation to be at least this many bytes.
    pub fn min_size(mut self, bytes: u64) -> Self {
        self.min_size = Some(bytes);
        self
    }

    /// Require the allocation to be at most this many bytes.
    pub fn max_size(mut self, bytes: u64) -> Self {
        self.max_size = Some(bytes);
        self
    }

    /// Do not compare the object header's type index against the object type.
    pub fn skip_type_test(mut self) -> Self {
        self.skip_type_test = true;
        self
    }

    /// Add a structure allocated together with the main one.
    pub fn with_additional(mut self, type_name: impl Into<String>) -> Self {
        self.additional_structures.push(type_name.into());
        self
    }

    /// Apply a type-specific believability test.
    pub fn validity(mut self, validity: ObjectValidity) -> Self {
        self.validity = validity;
        self
    }

    /// The tag rendered for a report: printable bytes as themselves, others as
    /// `\xNN`.
    ///
    /// Half of the pre-Windows-8 tags have their top bit set (`Pro\xe3` marks a
    /// protected allocation), so a renderer that assumed ASCII would show three
    /// characters and lose the byte that distinguishes the tag.
    pub fn tag_string(&self) -> String {
        render_tag(&self.tag)
    }
}

/// A four-byte pool tag rendered so that every byte survives.
pub fn render_tag(tag: &[u8; 4]) -> String {
    let mut out = String::with_capacity(4);
    for &byte in tag {
        if (0x20..0x7F).contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("\\x{byte:02x}"));
        }
    }
    out
}

/// The pool tags Windows itself allocates its executive objects under.
///
/// Both spellings of each tag are included regardless of build, because the
/// build number tells you which one the running kernel *writes* and says nothing
/// about what is still lying in freed pool from before an upgrade, or about a
/// hibernation image carrying both. Including a tag the kernel does not write
/// costs a few extra needles in one pass; omitting one loses whichever objects
/// happened to be allocated under it, which is a short list that looks
/// complete.
///
/// The pre-Windows-8 spellings set the top bit of the last byte (`Pro\xe3`,
/// `Fil\xe5`, `Dri\xf6`) to mark a *protected* allocation.
pub fn builtin_constraints() -> Vec<PoolConstraint> {
    vec![
        // Atom tables. Not an executive object: no object header.
        PoolConstraint::new(*b"AtmT", "_RTL_ATOM_TABLE")
            .min_size(200)
            .page_type(PoolTypes::any()),
        // Processes, before and from Windows 8.
        PoolConstraint::new(*b"Pro\xe3", "_EPROCESS")
            .executive("Process")
            .min_size(600)
            .skip_type_test()
            .page_type(PoolTypes::nonpaged_or_free())
            .validity(ObjectValidity::Process),
        PoolConstraint::new(*b"Proc", "_EPROCESS")
            .executive("Process")
            .min_size(600)
            .skip_type_test()
            .page_type(PoolTypes::nonpaged_or_free())
            .validity(ObjectValidity::Process),
        // Threads, before and from Windows 8.
        PoolConstraint::new(*b"Thr\xe5", "_ETHREAD")
            .executive("Thread")
            .min_size(600)
            .skip_type_test()
            .page_type(PoolTypes::nonpaged_or_free())
            .validity(ObjectValidity::Thread),
        PoolConstraint::new(*b"Thre", "_ETHREAD")
            .executive("Thread")
            .min_size(600)
            .page_type(PoolTypes::nonpaged_or_free())
            .validity(ObjectValidity::Thread),
        // File objects.
        PoolConstraint::new(*b"Fil\xe5", "_FILE_OBJECT")
            .executive("File")
            .min_size(150)
            .page_type(PoolTypes::nonpaged_or_free())
            .validity(ObjectValidity::File),
        PoolConstraint::new(*b"File", "_FILE_OBJECT")
            .executive("File")
            .min_size(150)
            .page_type(PoolTypes::nonpaged_or_free())
            .validity(ObjectValidity::File),
        // Mutants.
        PoolConstraint::new(*b"Mut\xe1", "_KMUTANT")
            .executive("Mutant")
            .min_size(64)
            .page_type(PoolTypes::nonpaged_or_free()),
        PoolConstraint::new(*b"Muta", "_KMUTANT")
            .executive("Mutant")
            .min_size(64)
            .page_type(PoolTypes::nonpaged_or_free()),
        // Driver objects. Before Windows 8 the driver extension shares the
        // allocation and counts towards the bottom-up placement.
        PoolConstraint::new(*b"Dri\xf6", "_DRIVER_OBJECT")
            .executive("Driver")
            .min_size(248)
            .page_type(PoolTypes::nonpaged_or_free())
            .with_additional("_DRIVER_EXTENSION"),
        PoolConstraint::new(*b"Driv", "_DRIVER_OBJECT")
            .executive("Driver")
            .min_size(248)
            .page_type(PoolTypes::nonpaged_or_free()),
        // Loaded kernel modules. Not an executive object.
        PoolConstraint::new(*b"MmLd", "_LDR_DATA_TABLE_ENTRY")
            .min_size(76)
            .page_type(PoolTypes::nonpaged_or_free()),
        // Symbolic links.
        PoolConstraint::new(*b"Sym\xe2", "_OBJECT_SYMBOLIC_LINK")
            .executive("SymbolicLink")
            .min_size(72)
            .page_type(PoolTypes::paged_or_free()),
        PoolConstraint::new(*b"Symb", "_OBJECT_SYMBOLIC_LINK")
            .executive("SymbolicLink")
            .min_size(72)
            .page_type(PoolTypes::paged_or_free()),
        // Registry hives. Not an executive object.
        PoolConstraint::new(*b"CM10", "_CMHIVE")
            .min_size(800)
            .skip_type_test()
            .page_type(PoolTypes::paged_or_free()),
    ]
}

/// The builtin constraints whose tags appear in `tags`.
///
/// For a stage that wants only processes, or only file objects, without
/// restating the constraint.
pub fn builtin_constraints_for(tags: &[[u8; 4]]) -> Vec<PoolConstraint> {
    builtin_constraints()
        .into_iter()
        .filter(|constraint| tags.contains(&constraint.tag))
        .collect()
}

// ── Symbols ─────────────────────────────────────────────────────────────────

/// One optional object header this build declares, and the `InfoMask` bit that
/// announces it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptionalHeader {
    /// The type name.
    pub type_name: &'static str,
    /// Its declared size in bytes.
    pub size: u64,
    /// The `InfoMask` bit that means "this header is present".
    pub bit: u32,
}

/// Which address space a sweep ran against.
///
/// Recorded on the outcome because it bounds what could have been found: a
/// physical sweep reaches allocations the virtual address space no longer maps,
/// and a virtual sweep reaches only what is mapped now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanSpace {
    /// The physical layer.
    Physical,
    /// The kernel virtual address space.
    KernelVirtual,
}

impl ScanSpace {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ScanSpace::Physical => "physical",
            ScanSpace::KernelVirtual => "kernel_virtual",
        }
    }

    /// What a sweep of this space cannot reach, whatever it finds.
    ///
    /// Not an incompleteness: the sweep did examine every byte it set out to,
    /// and a sweep that found nothing in a space it read in full is a real
    /// answer about that space. It is a **scope** limit, and it travels onto
    /// the artifact because "the pool scan was complete" invites the reading
    /// "and so nothing was hidden anywhere", which neither space supports on
    /// its own.
    pub fn limits(self) -> &'static str {
        match self {
            ScanSpace::Physical => {
                "a physical sweep reaches allocations the kernel's address space no longer maps, \
                 and cannot reach a page that was resident only in the page file"
            }
            ScanSpace::KernelVirtual => {
                "a kernel-virtual sweep reaches only what the kernel still maps, so a freed pool \
                 allocation whose page has been unmapped survives in physical memory and is not \
                 reachable from here"
            }
        }
    }
}

/// The offset of a member the declaration marked [`Necessity::Required`].
///
/// [`MemberSet::bind`] has already refused a build that does not declare it, so
/// `None` here means the symbol table answered two different ways about the same
/// member. That is written as a refusal rather than an `expect`, because an
/// analysis stage runs inside an ingest and a panic takes the whole ingest down
/// where a refusal costs one stage.
///
/// [`Necessity::Required`]: seance_memory::binding::Necessity::Required
fn required_offset(binding: &BuildBinding, key: &'static str) -> Result<u64, PoolError> {
    binding.member(key)?.offset().ok_or_else(|| {
        PoolError::unsupported(format!(
            "the pool layout resolved '{key}' to no offset after binding required it, so the \
             symbol table answered two different ways about the same member"
        ))
    })
}

/// The layout knowledge one image's pool allocations are decoded through.
///
/// Built once per image and checked once: every type and member the sweep will
/// read **on this build** is proved to exist here, so a build whose layout is
/// unknown fails at construction naming what is missing rather than at candidate
/// three thousand, having already emitted rows read at the wrong offsets.
///
/// "On this build" is the whole of it. The pre-flight covers exactly the branch
/// [`PoolSymbols::top_down`] selects; a member only the other branch reads is
/// not proved, because refusing an image over a field nothing will read denies
/// an examiner a sweep the image can support in full. That is why there are two
/// declarations, [`POOL_LAYOUT`] and [`TOP_DOWN_LAYOUT`], and the second is
/// bound only when this build takes the branch that reads it.
#[derive(Debug, Clone)]
pub struct PoolSymbols {
    /// Offset of `PoolTag` inside `_POOL_HEADER`, so a tag match becomes an
    /// allocation base.
    pub pool_tag_offset: u64,
    /// Size of `_POOL_HEADER`, so an allocation base becomes the first byte
    /// after it.
    pub pool_header_size: u64,
    /// Offset of `Body` inside `_OBJECT_HEADER`, or `None` on a build whose
    /// table has no `_OBJECT_HEADER` at all — which means executive objects
    /// cannot be located and constraints that need one are refused.
    pub body_offset: Option<u64>,
    /// Size of `_OBJECT_HEADER`, when this build declares one.
    pub object_header_size: Option<u64>,
    /// The optional headers this build declares, in `InfoMask` bit order.
    ///
    /// Read only by the top-down search. A build with no `InfoMask` — XP, 2003 —
    /// still declares the header types, so this list is populated there and
    /// simply never consulted; it is not a statement that the build has a bitmap.
    pub optional_headers: Vec<OptionalHeader>,
    /// Index into [`PoolSymbols::optional_headers`] of the padding header.
    pub padding_index: Option<usize>,
    /// Total bytes the optional headers can occupy, which bounds how far in
    /// front of the body an object header can start.
    pub max_optional_headers: u64,
    /// Pool allocation granularity: 16 on a 64-bit kernel, 8 on a 32-bit one.
    pub alignment: u64,
    /// Lowest address of the kernel half of this machine's address space:
    /// `0xFFFF_8000_0000_0000` on a 64-bit kernel, `0x8000_0000` on a 32-bit
    /// one.
    ///
    /// Where a [`ScanSpace::KernelVirtual`] sweep begins — see
    /// [`kernel_half_sweep`]. Unused by a physical sweep, which has no halves.
    pub kernel_floor: u64,
    /// Whether this build uses the Vista pool-type encoding.
    pub vista_or_later: bool,
    /// Whether this build places executive objects top-down (Windows 8 and
    /// later) rather than bottom-up.
    pub top_down: bool,
    /// Which address space the sweep must run in.
    pub space: ScanSpace,
    /// What this build's symbol table actually provided for [`POOL_LAYOUT`].
    ///
    /// Carried rather than discarded so [`PoolSymbols::layout_json`] can put it
    /// on the stage record. Without it a report says a column is empty and
    /// cannot say whether the kernel had no such field or the sweep looked
    /// under a name this kernel does not use.
    pub binding: BuildBinding,
    /// The same, for [`TOP_DOWN_LAYOUT`], on the builds that take that branch.
    ///
    /// `None` on a bottom-up build — XP, 2003, 7 — because those two members
    /// were never asked for there. That is the distinction the whole binding
    /// exists for: not asked is not the same as asked and absent.
    pub top_down_binding: Option<BuildBinding>,
}

impl PoolSymbols {
    /// Resolve every layout fact a sweep of this image needs.
    ///
    /// # What an examiner learns
    ///
    /// Which structure layout every later row was decoded through, recorded on
    /// the stage record by [`PoolSymbols::layout_json`]. A member this build
    /// does not declare appears there as `not_declared`, which is the claim
    /// "the kernel running on this machine had no such field" — not "the
    /// analysis could not run".
    ///
    /// # Errors
    ///
    /// [`PoolError::BuildUnknown`] when the build number was never established,
    /// because the top-down/bottom-up decision rests on it.
    /// [`PoolError::Binding`] when a declaration [`POOL_LAYOUT`] marked required
    /// is absent from this build, and — only on a build that places objects
    /// top-down — when one of [`TOP_DOWN_LAYOUT`]'s is. Its message names the
    /// stage, the member, every name that was tried and what the sweep cannot do
    /// without it.
    /// [`PoolError::Unsupported`] when the symbol table contradicts the profile
    /// or itself: a pointer width that disagrees, or a `_POOL_HEADER` whose
    /// declared size cannot hold its own tag.
    ///
    /// A member this build simply does not have is **none of those**. It lands
    /// in the binding as `not_declared` and the sweep runs.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, PoolError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        // The pointer width the symbol table declares and the one the profile
        // recorded must agree. If they do not, one of the two does not describe
        // this image, and every address computed from the wrong one is wrong by
        // a whole pool header.
        let declared = u64::from(reader.pointer_size()?);
        if declared != profile.pointer_size() {
            return Err(PoolError::unsupported(format!(
                "the symbol table declares {declared}-byte pointers and the image profile records \
                 {}-byte pointers, so one of the two does not describe this image",
                profile.pointer_size()
            )));
        }
        let alignment = if declared == 8 {
            POOL_ALIGNMENT_64
        } else {
            POOL_ALIGNMENT_32
        };
        // Where the kernel half of this machine's address space begins, which
        // is where a kernel-virtual sweep starts. A width that is neither 4 nor
        // 8 describes no machine, and guessing one would either sweep the wrong
        // half of the space or skip the pool entirely.
        let kernel_floor = kernel_half_start(declared).ok_or_else(|| {
            PoolError::unsupported(format!(
                "the symbol table declares {declared}-byte pointers, which is neither 4 nor 8 and \
                 so names no address space for the sweep to run in"
            ))
        })?;

        let top_down = profile
            .build
            .is_win8_or_later()
            .ok_or(PoolError::BuildUnknown)?;

        // One declaration for everything every build reads, resolved in one
        // place. `_POOL_HEADER`, `PoolTag`, `BlockSize` and `PoolType` are
        // marked required inside it, each with the sentence an examiner is shown
        // when this build has none of the names it can appear under.
        let binding = POOL_LAYOUT.bind(&reader)?;

        let pool_tag_offset = required_offset(&binding, "pool_tag")?;
        let pool_header_size = binding.type_of("pool_header")?.size().ok_or_else(|| {
            PoolError::unsupported(
                "the pool layout resolved '_POOL_HEADER' to no size after binding required it, \
                 so the symbol table answered two different ways about the same type",
            )
        })?;
        if pool_header_size == 0 {
            return Err(PoolError::unsupported(format!(
                "'{TYPE_POOL_HEADER}' declares a size of 0, so the object that follows it would \
                 start at the tag"
            )));
        }
        if pool_tag_offset >= pool_header_size {
            return Err(PoolError::unsupported(format!(
                "'{TYPE_POOL_HEADER}.PoolTag' sits at offset {pool_tag_offset} in a header of \
                 {pool_header_size} byte(s), which cannot be this image's layout"
            )));
        }
        // `BlockSize` and `PoolType` are required inside POOL_LAYOUT and so are
        // already proved. They are looked up by key rather than re-resolved,
        // because a second lookup is a second chance for the two to disagree.
        let block_size_offset = required_offset(&binding, "block_size")?;
        let pool_type_offset = required_offset(&binding, "pool_type")?;
        if block_size_offset >= pool_header_size || pool_type_offset >= pool_header_size {
            return Err(PoolError::unsupported(format!(
                "'{TYPE_POOL_HEADER}' declares BlockSize at {block_size_offset} and PoolType at \
                 {pool_type_offset} in a header of {pool_header_size} byte(s), which cannot be \
                 this image's layout"
            )));
        }

        let (body_offset, object_header_size) = match binding.type_of("object_header")?.resolution()
        {
            TypeUse::Declared { size, .. } => {
                // The type is declared, so `Body` has to be: an object header
                // with no body member gives no route from an allocation to the
                // object inside it, and every later address would be a guess.
                let body = binding.member("body")?.offset().ok_or_else(|| {
                    PoolError::unsupported(format!(
                        "this build declares '{TYPE_OBJECT_HEADER}' and no 'Body' member on it, so \
                         there is no route from a pool allocation to the object it holds"
                    ))
                })?;
                (Some(body), Some(*size))
            }
            // No `_OBJECT_HEADER` at all. The tag sweep still runs; the
            // constraints that need an object header are refused one by one,
            // naming what is missing.
            TypeUse::NotDeclared => (None, None),
            // The table was asked and could not answer. That is damage to the
            // evidence about layout, and it must not render as "this build has
            // no object header" — which would silently drop every executive
            // object the image holds.
            TypeUse::Unavailable { detail } => {
                return Err(PoolError::unsupported(format!(
                    "the symbol table could not say whether this build declares \
                     '{TYPE_OBJECT_HEADER}': {detail}"
                )))
            }
        };

        // Only what THIS build's placement reads. Proving a member the chosen
        // branch never touches turns a build variation into a whole-sweep
        // refusal — see [`TOP_DOWN_LAYOUT`]. Two conditions, and both are about
        // whether the members will actually be read: a bottom-up build never
        // reaches the top-down search, and a build with no `_OBJECT_HEADER` at
        // all has no header to probe on either path — it sweeps for the
        // constraints that carry no object header and refuses the rest by name.
        // In both cases `top_down_binding` is `None`, which says the question
        // was never put, rather than a record of two members reported absent.
        let top_down_binding = if top_down && object_header_size.is_some() {
            Some(TOP_DOWN_LAYOUT.bind(&reader)?)
        } else {
            None
        };

        let mut optional_headers = Vec::new();
        let mut padding_index = None;
        for type_name in OPTIONAL_HEADER_TYPES {
            if !profile.symbols.has_type(type_name) {
                continue;
            }
            let size = reader.size_of(type_name)?.bytes();
            if type_name == PADDING_INFO_TYPE {
                padding_index = Some(optional_headers.len());
            }
            let bit = u32::try_from(optional_headers.len()).unwrap_or(u32::MAX);
            optional_headers.push(OptionalHeader {
                type_name,
                size,
                bit,
            });
        }
        let max_optional_headers = optional_headers
            .iter()
            .try_fold(0u64, |total, header| total.checked_add(header.size))
            .ok_or_else(|| {
                PoolError::unsupported(
                    "the declared sizes of this build's optional object headers do not fit in 64 \
                     bits",
                )
            })?;

        let space = if profile.build.major >= FIRST_VIRTUAL_SCAN_MAJOR {
            ScanSpace::KernelVirtual
        } else {
            ScanSpace::Physical
        };

        Ok(Self {
            pool_tag_offset,
            pool_header_size,
            body_offset,
            object_header_size,
            optional_headers,
            padding_index,
            max_optional_headers,
            alignment,
            kernel_floor,
            vista_or_later: profile.build.major >= FIRST_VISTA_MAJOR,
            top_down,
            space,
            binding,
            top_down_binding,
        })
    }

    /// The layout this build provided, as the stage record must carry it.
    ///
    /// # What an examiner learns
    ///
    /// For every type and member the sweep declared: whether this kernel build
    /// had it, which of the accepted names it had it under, and where. That is
    /// what makes a blank column readable — "the kernel build running on this
    /// machine has no such structure member" rather than an empty cell — and it
    /// is what a defence expert needs in order to repeat the analysis against
    /// the same symbol pack.
    ///
    /// `top_down` is stated alongside, because it is the reason
    /// `top_down_members` is `null` on an XP or Windows 7 image: those two
    /// members were never asked for, which is a different claim from asking and
    /// finding them absent.
    pub fn layout_json(&self) -> serde_json::Value {
        serde_json::json!({
            "top_down": self.top_down,
            "members": self.binding.to_json(),
            "top_down_members": self
                .top_down_binding
                .as_ref()
                .map(BuildBinding::to_json),
        })
    }

    /// Distance from the first byte of an object to the pool tag in front of it.
    ///
    /// For a caller holding a structure that was *not* found by scanning — a VAD
    /// reached through a process's tree — that wants the tag of the allocation
    /// it lives in. Derived as `sizeof(_POOL_HEADER) − offsetof(PoolTag)`, which
    /// works out at 4 on x86 and 12 on x64, rather than being written down as
    /// those two numbers.
    ///
    /// Only meaningful for a structure allocated directly after its pool header,
    /// with no object header in between.
    pub fn tag_distance(&self) -> u64 {
        self.pool_header_size.saturating_sub(self.pool_tag_offset)
    }
}

// ── Object type map ─────────────────────────────────────────────────────────

/// The object manager's index of executive object types.
///
/// `_OBJECT_HEADER` does not store the name of the type it heads; it stores a
/// one-byte index into a kernel table, and on Windows 10 and later that index
/// is additionally mixed with the object header's own address and a per-boot
/// cookie. Resolving it is what turns "an allocation tagged `File`" into "an
/// object the kernel itself considers a File", which is the check that rejects
/// an allocation whose tag matched by accident.
#[derive(Debug, Clone, Default)]
pub struct ObjectTypeMap {
    by_index: BTreeMap<u8, String>,
    cookie: Option<u8>,
    entries: usize,
}

impl ObjectTypeMap {
    /// Read the table out of the kernel's own memory.
    ///
    /// # Errors
    ///
    /// [`PoolError::Unsupported`] when neither [`SYMBOL_TYPE_INDEX_TABLE`] nor
    /// [`SYMBOL_OBJECT_TYPES`] is in the symbol table, or when the table's
    /// entries cannot be described. A caller that gets this back must not treat
    /// the type test as passed; [`pool_scan`] records it as an unperformed
    /// check rather than admitting or dropping objects silently.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, PoolError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let table_rva = match profile.symbols.symbol_address(SYMBOL_TYPE_INDEX_TABLE) {
            Ok(address) => address,
            Err(_) => profile
                .symbols
                .symbol_address(SYMBOL_OBJECT_TYPES)
                .map_err(|_| {
                    PoolError::unsupported(format!(
                        "the symbol table has neither '{SYMBOL_TYPE_INDEX_TABLE}' nor \
                         '{SYMBOL_OBJECT_TYPES}', so an object header's type index cannot be \
                         resolved to a type name"
                    ))
                })?,
        };
        if !profile.symbols.has_type(TYPE_OBJECT_TYPE) {
            return Err(PoolError::unsupported(format!(
                "the symbol table has no '{TYPE_OBJECT_TYPE}', so the object-type table cannot be \
                 read"
            )));
        }
        let table = profile
            .kernel_base
            .value
            .checked_add(table_rva)
            .ok_or_else(|| {
                PoolError::unsupported(
                    "the object-type table's address does not fit in the 64-bit address space",
                )
            })?;

        let pointer_size = u64::from(reader.pointer_size()?);
        let mut by_index = BTreeMap::new();
        let mut entries = 0usize;
        for index in 0..MAX_OBJECT_TYPES {
            let within = index.checked_mul(pointer_size).ok_or_else(|| {
                PoolError::unsupported("the object-type table wraps the address space")
            })?;
            let Some(slot) = table.checked_add(within) else {
                break;
            };
            // The table ends where the image does. What was read is still the
            // table, and `entries_read` says how much of it was recovered.
            let Ok(pointer) = reader.read_pointer_at(slot) else {
                break;
            };
            entries += 1;
            // Slot 0 is always null; the first null after it ends the table.
            if pointer == 0 {
                if index > 0 {
                    break;
                }
                continue;
            }
            let Ok(object_type) = reader.object(pointer, TYPE_OBJECT_TYPE) else {
                continue;
            };
            if let Ok(Some(name)) = unicode_string(&object_type, "Name") {
                if let Ok(slot_index) = u8::try_from(index) {
                    by_index.insert(slot_index, name);
                }
            }
        }

        // The cookie exists only from Windows 10. Its absence is a fact about
        // the build, not a failure: the stored index is then used unmixed.
        let cookie = match profile.symbols.symbol_address(SYMBOL_HEADER_COOKIE) {
            Ok(rva) => profile
                .kernel_base
                .value
                .checked_add(rva)
                .and_then(|address| reader.read_bytes(address, 1).ok())
                .and_then(|bytes| bytes.first().copied()),
            Err(_) => None,
        };

        Ok(Self {
            by_index,
            cookie,
            entries,
        })
    }

    /// A map with no entries, for a caller that has none and wants the type
    /// test recorded as unperformed rather than silently skipped.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether the table carried any usable entry.
    pub fn is_empty(&self) -> bool {
        self.by_index.is_empty()
    }

    /// How many table slots were read.
    pub fn entries_read(&self) -> usize {
        self.entries
    }

    /// The per-boot cookie, when this build has one.
    pub fn cookie(&self) -> Option<u8> {
        self.cookie
    }

    /// Whether an index read on `build` can be resolved through this map, or a
    /// sentence saying why it cannot.
    ///
    /// From [`FIRST_MIXED_TYPE_INDEX_BUILD`] the stored index is mixed with the
    /// header's own address and the per-boot cookie. Without the cookie the
    /// unmixed index is a byte that means nothing: it lands on some other type
    /// about one time in five — this map holds a few dozen of the 256 slots —
    /// and on no type the rest of the time. So a caller that resolves anyway
    /// produces a table naming the wrong kind of object for a fifth of its rows,
    /// with nothing on the row to say so, which is worse than no table at all.
    ///
    /// An unknown build is treated as mixing: a map that cannot be shown to be
    /// resolvable is not one a report may rest on.
    ///
    /// # What a wrong answer looks like
    ///
    /// A handle to a `File` reported as a `Key`, in a list that otherwise reads
    /// as sound, because the image's symbol table happened not to carry
    /// [`SYMBOL_HEADER_COOKIE`].
    pub fn resolves_indexes(&self, build: Option<u32>) -> Result<(), String> {
        if self.cookie.is_some() {
            return Ok(());
        }
        match build {
            Some(build) if build < FIRST_MIXED_TYPE_INDEX_BUILD => Ok(()),
            Some(build) => Err(format!(
                "build {build} mixes an object header's type index with the per-boot \
                 '{SYMBOL_HEADER_COOKIE}', and that cookie is neither in the symbol table nor \
                 readable in the image, so a stored index cannot be turned back into the type \
                 the kernel gave the object"
            )),
            None => Err(format!(
                "the Windows build number was never established, so it cannot be decided whether \
                 this image mixes an object header's type index with '{SYMBOL_HEADER_COOKIE}' — \
                 and that cookie was not read, so resolving an index would be a guess"
            )),
        }
    }

    /// The type name for an object header's raw `TypeIndex`.
    ///
    /// On Windows 10 and later the stored index is
    /// `real ^ (header_address >> 8) ^ cookie`, truncated to a byte, so the same
    /// object type has a different stored index at every address. Undoing it
    /// needs the header's address, which is why this takes it.
    pub fn name_for(&self, header_address: u64, stored_index: u64) -> Option<&str> {
        let index = match self.cookie {
            Some(cookie) => {
                let mixed = (header_address >> 8) ^ u64::from(cookie) ^ stored_index;
                (mixed & 0xFF) as u8
            }
            None => (stored_index & 0xFF) as u8,
        };
        self.by_index.get(&index).map(String::as_str)
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One object recovered from a pool allocation.
#[derive(Debug, Clone)]
pub struct PoolObject {
    /// Where the allocation starts: the first byte of its `_POOL_HEADER`.
    pub pool_header: u64,
    /// Where the object's `_OBJECT_HEADER` starts, for executive objects.
    pub object_header: Option<u64>,
    /// Where the object itself starts, in the space that was swept.
    pub address: u64,
    /// The tag the allocation carries, rendered printably.
    pub tag: String,
    /// The structure the allocation was decoded as.
    pub type_name: String,
    /// `_POOL_HEADER.BlockSize`, in allocation granules.
    pub block_size: u64,
    /// The raw `_POOL_HEADER.PoolType`.
    pub pool_type: u64,
    /// The allocation's size in bytes: `block_size × alignment`.
    pub allocation: u64,
    /// Whether the allocation is a freed one, which is to say whether this
    /// object is historical rather than live.
    pub freed: bool,
    /// The object-manager type the header names, when it was resolved.
    pub object_type: Option<String>,
    /// Whether the object-manager type was actually compared against the
    /// constraint. `false` means the comparison did not happen — because the
    /// constraint skips it, or because no type map was available — and the
    /// object's identity rests on its tag and its structure alone.
    pub type_verified: bool,
    /// Everything odd about the object that did not disqualify it.
    ///
    /// A row with notes is still evidence; a row whose gaps were quietly filled
    /// in is not.
    pub notes: Vec<String>,
}

impl PoolObject {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pool_header": self.pool_header,
            "object_header": self.object_header,
            "address": self.address,
            "tag": self.tag,
            "type": self.type_name,
            "block_size": self.block_size,
            "pool_type": self.pool_type,
            "allocation": self.allocation,
            "freed": self.freed,
            "object_type": self.object_type,
            "type_verified": self.type_verified,
            "notes": self.notes,
        })
    }
}

/// One tag match that was not an object, and why.
#[derive(Debug, Clone)]
pub struct Rejected {
    /// Where the tag matched.
    pub tag_address: u64,
    /// The tag, rendered printably.
    pub tag: String,
    /// Why the candidate was discarded, in the examiner's terms.
    pub reason: String,
}

/// What one sweep found, and everything it could not do.
#[derive(Debug, Clone)]
pub struct PoolScanOutcome {
    /// Recovered objects, in the order their tags were found, which is
    /// ascending by address.
    pub objects: Vec<PoolObject>,
    /// Rejected candidates, capped by
    /// [`PoolScanConfig::max_recorded_rejections`].
    pub rejected: Vec<Rejected>,
    /// How many candidates were rejected in total. Exact even when the list
    /// above was capped.
    pub rejected_total: usize,
    /// How many tag matches were examined.
    pub candidates: usize,
    /// Which address space was swept.
    pub space: ScanSpace,
    /// The part of that space the sweep covered, when it was bounded rather
    /// than swept whole — see [`kernel_half_sweep`].
    ///
    /// `None` means every address the layer has. It travels onto the stage
    /// record because a bounded sweep that found nothing is silent about the
    /// addresses outside its bound, and the scan's own unread list cannot say
    /// so: those addresses were never part of the walk.
    pub swept: Option<Range<u64>>,
    /// The underlying scan's own account of what it read and what it could not.
    pub scan: ScanOutcome,
    /// Whether the object cap fired. The sweep stopped; the image did not run
    /// out of objects.
    pub truncated: bool,
    /// Everything a report must declare about this result.
    pub incomplete: Vec<Incomplete>,
    /// The structure layout this build provided, from
    /// [`PoolSymbols::layout_json`].
    ///
    /// Carried on the outcome because the outcome is what becomes the stage
    /// record. Without it a report shows an empty column and cannot say whether
    /// the kernel had no such field or the sweep looked under a name this kernel
    /// does not use.
    pub layout: serde_json::Value,
}

impl PoolScanOutcome {
    /// Whether every mapped byte was examined and every object returned.
    ///
    /// The question a report must ask before writing "no such objects were
    /// found": an incomplete sweep that found nothing says nothing about the
    /// machine.
    pub fn is_complete(&self) -> bool {
        !self.truncated && self.scan.is_complete() && self.incomplete.is_empty()
    }

    /// The objects decoded as a named type.
    pub fn of_type<'a>(&'a self, type_name: &'a str) -> impl Iterator<Item = &'a PoolObject> {
        self.objects
            .iter()
            .filter(move |object| object.type_name == type_name)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "objects": self.objects.iter().map(PoolObject::to_json).collect::<Vec<_>>(),
            "object_count": self.objects.len(),
            "candidates": self.candidates,
            "rejected_total": self.rejected_total,
            "rejected": self
                .rejected
                .iter()
                .map(|r| serde_json::json!({
                    "tag_address": r.tag_address,
                    "tag": r.tag,
                    "reason": r.reason,
                }))
                .collect::<Vec<_>>(),
            "space": self.space.as_str(),
            // What a complete sweep of this space still cannot say. Without it
            // "pool_scan: complete" reads as "nothing was hidden anywhere".
            "space_limits": self.space.limits(),
            // Which addresses of it were actually walked. `null` is the whole
            // layer; a range is a deliberate bound, and everything outside it
            // is a question this sweep did not ask.
            "swept": self.swept.as_ref().map(|range| serde_json::json!({
                "from": range.start,
                "to": range.end,
                "why": "a pool allocation is kernel memory, so the sweep covers the kernel half \
                        of the address space and says nothing about the user half",
            })),
            // Which structure members this build actually declared, so a blank
            // column can be read as "the kernel had no such field" rather than
            // as an empty result.
            "layout": self.layout,
            "scan": self.scan.to_json(),
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "incomplete": self
                .incomplete
                .iter()
                .map(|i| serde_json::json!({"reason": i.reason.as_str(), "detail": i.detail}))
                .collect::<Vec<_>>(),
        })
    }
}

/// Caps and geometry for one sweep.
#[derive(Debug, Clone)]
pub struct PoolScanConfig {
    /// Chunking and caps for the underlying byte scan.
    pub scan: ScanConfig,
    /// Ceiling on objects returned.
    pub max_objects: usize,
    /// Ceiling on individually recorded rejections.
    pub max_recorded_rejections: usize,
    /// The object-type map, when one could be built. `None` means the
    /// object-manager type test cannot be performed, which is then recorded on
    /// every object it would have applied to *and* on the outcome.
    pub type_map: Option<Arc<ObjectTypeMap>>,
}

impl Default for PoolScanConfig {
    fn default() -> Self {
        Self {
            scan: ScanConfig::default(),
            max_objects: MAX_OBJECTS,
            max_recorded_rejections: MAX_RECORDED_REJECTIONS,
            type_map: None,
        }
    }
}

// ── The sweep ───────────────────────────────────────────────────────────────

/// Sweep the image for the allocations `constraints` describe.
///
/// # Errors
///
/// Only for failures that make the whole sweep meaningless: two constraints
/// claiming one tag, a symbol table that cannot describe a pool allocation, or
/// a scan configuration that cannot produce a correct walk. A candidate that
/// failed validation is not an error — it is counted in
/// [`PoolScanOutcome::rejected`].
pub fn pool_scan(
    profile: &WindowsProfile,
    symbols: &PoolSymbols,
    constraints: &[PoolConstraint],
    config: &PoolScanConfig,
) -> Result<PoolScanOutcome, PoolError> {
    if constraints.is_empty() {
        return Err(PoolError::unsupported(
            "no pool constraints were supplied, so the sweep would have nothing to look for and \
             its empty result would read as an absence of objects",
        ));
    }

    // One tag may mean one thing. Two constraints on a tag would make the
    // result depend on declaration order.
    let mut needles: Vec<[u8; 4]> = Vec::with_capacity(constraints.len());
    for constraint in constraints {
        if needles.contains(&constraint.tag) {
            return Err(PoolError::DuplicateTag {
                tag: constraint.tag_string(),
            });
        }
        needles.push(constraint.tag);
    }

    // Every member each validity policy reads is proved to exist now. Doing it
    // per candidate would reject every object of a type whose member this build
    // names differently, and an empty table reads as an absence of objects.
    let checker = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    for constraint in constraints {
        if constraint.validity == ObjectValidity::None {
            continue;
        }
        if !profile.symbols.has_type(&constraint.type_name) {
            // A type this build does not declare cannot produce candidates at
            // all; the failure surfaces per candidate, naming the type.
            continue;
        }
        for member in constraint.validity.required_members() {
            // A deliberate existence proof, not a discarded offset: these are
            // the members the chosen validity policy will read on every
            // candidate, so a build without one cannot tell a real object from
            // a tag that matched by accident. `require_member` says that in the
            // type, where `member_offset(..)?;` used to say nothing.
            checker
                .require_member(&constraint.type_name, member)
                .map_err(|err| {
                    PoolError::unsupported(format!(
                        "'{}.{member}' is needed to tell a real object from a tag that matched by \
                         accident, and this build's symbols do not have it: {err}",
                        constraint.type_name
                    ))
                })?;
        }
    }
    if symbols.body_offset.is_none() {
        if let Some(constraint) = constraints.iter().find(|c| c.object_type.is_some()) {
            return Err(PoolError::unsupported(format!(
                "'{TYPE_OBJECT_HEADER}' is not in this build's symbols, so the body of the \
                 executive object tagged {} cannot be located inside its allocation",
                constraint.tag_string()
            )));
        }
    }

    let scanner = MultiStringScanner::new("windows-pool-tags", &needles)?;
    let layer: Arc<dyn MemoryLayer> = match symbols.space {
        ScanSpace::Physical => Arc::clone(&profile.physical),
        ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
    };
    let swept = match symbols.space {
        // The pool is in the kernel half, and on x86-64 a walk that starts at
        // zero never gets there — see [`kernel_half_sweep`].
        ScanSpace::KernelVirtual => kernel_half_sweep(symbols.kernel_floor, layer.max_address()),
        ScanSpace::Physical => None,
    };
    let outcome = match swept.clone() {
        Some(range) => scan_range(layer.as_ref(), &scanner, range, &config.scan)?,
        None => scan_layer(layer.as_ref(), &scanner, &config.scan)?,
    };

    // The allocation's bytes are read from the swept layer; every pointer
    // inside it is a kernel virtual address. Getting these two the wrong way
    // round does not fail: it silently reads unrelated bytes that parse.
    let reader = StructReader::with_native(
        Arc::clone(&layer),
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );

    let mut objects = Vec::new();
    let mut rejected = Vec::new();
    let mut rejected_total = 0usize;
    let mut candidates = 0usize;
    let mut truncated = false;
    let mut unverified_types = 0usize;

    for hit in &outcome.hits {
        // The scanner cannot report a pattern the caller did not supply, so
        // this cannot fire; skipping beats indexing into the wrong constraint
        // and decoding the allocation as some other kind of object.
        let Some(constraint) = constraints.get(hit.pattern_id as usize) else {
            continue;
        };
        candidates += 1;
        if objects.len() >= config.max_objects {
            truncated = true;
            break;
        }
        match examine(&reader, symbols, constraint, hit.address, config) {
            Ok(found) => {
                for object in found {
                    if !object.type_verified && constraint.object_type.is_some() {
                        unverified_types += 1;
                    }
                    objects.push(object);
                }
            }
            Err(reason) => {
                rejected_total += 1;
                if rejected.len() < config.max_recorded_rejections {
                    rejected.push(Rejected {
                        tag_address: hit.address,
                        tag: constraint.tag_string(),
                        reason,
                    });
                }
            }
        }
    }

    let mut incomplete = Vec::new();
    if !outcome.is_complete() {
        incomplete.push(Incomplete::new(
            IncompleteReason::ShortRead,
            unswept_detail(symbols.space, outcome.unread_bytes),
        ));
    }
    if truncated {
        incomplete.push(Incomplete::new(
            IncompleteReason::CapReached,
            format!(
                "the sweep stopped at its cap of {} object(s); the image was not exhausted",
                config.max_objects
            ),
        ));
    }
    if rejected_total > rejected.len() {
        incomplete.push(Incomplete::new(
            IncompleteReason::CapReached,
            format!(
                "{rejected_total} candidates were rejected and only {} are listed individually",
                rejected.len()
            ),
        ));
    }
    if unverified_types > 0 {
        incomplete.push(Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            format!(
                "{unverified_types} object(s) were admitted without their object-manager type \
                 being checked, because no object-type map was available"
            ),
        ));
    }

    Ok(PoolScanOutcome {
        objects,
        rejected,
        rejected_total,
        candidates,
        space: symbols.space,
        swept,
        scan: outcome,
        truncated,
        incomplete,
        layout: symbols.layout_json(),
    })
}

/// What a sweep's unread bytes mean in the space it swept.
///
/// The two spaces do not mean the same thing by "not read", and rendering them
/// alike is the difference between a gap in the evidence and a part of the
/// address space that never held anything.
///
/// * **Physical.** Every byte between the acquired regions is memory the capture
///   tool did not take. An object lying there is an object the acquisition lost.
/// * **Kernel virtual.** Most of a 128 TiB kernel half translates nowhere at
///   all, and an address with no page-table entry holds nothing to find — it is
///   not lost evidence and must not be counted as any. Mixed into the same
///   total, though, are the pages that *do* translate and whose frames the
///   capture did not take, and those are lost. The region enumeration does not
///   carry the layer's own reason for a hole, so this sweep cannot separate the
///   two, and it says so rather than picking whichever reading is convenient.
pub(crate) fn unswept_detail(space: ScanSpace, unread_bytes: u64) -> String {
    match space {
        ScanSpace::Physical => format!(
            "{unread_bytes} byte(s) of the physical address space were not swept, so an object \
             lying in them would not be listed"
        ),
        ScanSpace::KernelVirtual => format!(
            "{unread_bytes} byte(s) of the swept range of the kernel_virtual address space were \
             not read. Most of a kernel address space translates nowhere and holds nothing to \
             find; the rest is pages the acquisition did not capture, where an object would not \
             be listed. This sweep cannot tell the two apart, so the total is an upper bound on \
             what was lost and not a measure of it"
        ),
    }
}

/// Where the kernel half of an address space of this pointer width begins.
///
/// `None` for a width that is neither 4 nor 8: no such machine exists, and a
/// guessed floor would either skip the pool or sweep the wrong half.
pub(crate) fn kernel_half_start(pointer_size: u64) -> Option<u64> {
    match pointer_size {
        8 => Some(KERNEL_HALF_START_X64),
        4 => Some(KERNEL_HALF_START_X86),
        _ => None,
    }
}

/// The kernel half of an address space whose top is `max_address`, or `None`
/// when that layer has no kernel half.
///
/// A pool allocation is kernel memory by definition, so a sweep of the kernel
/// virtual space starts at the kernel half and not at address zero. That is not
/// only an economy. On x86-64 the halves are separated by the non-canonical
/// gap, and an address inside it is not an address at all: enumerating the
/// mapped regions of the space upward from zero reaches the gap, is told the
/// address does not exist, and stops there — so a sweep that begins at zero
/// examines the user half, never reaches the kernel half where every pool
/// allocation is, and reports no objects while claiming it was not truncated.
/// That is what `windows.psscan` did on the Windows 11 reference image: 0 rows
/// against Volatility's 103.
///
/// `None` when the layer ends below the floor — every synthetic fixture, and a
/// partial acquisition. Those are swept whole, exactly as before, so this can
/// only ever add coverage. A *physical* sweep has no halves at all and never
/// asks: the pool's bytes are wherever the acquisition put them.
pub(crate) fn kernel_half_sweep(kernel_floor: u64, max_address: u64) -> Option<Range<u64>> {
    if max_address <= kernel_floor {
        return None;
    }
    // The top of the space, exclusive, so the recorded range is the one that
    // was walked rather than one that runs past the layer. It saturates rather
    // than wrapping, which on a full 64-bit space leaves the single top byte
    // unswept; no pool header can begin there, since the tag alone is four
    // bytes.
    Some(kernel_floor..max_address.saturating_add(1))
}

/// Turn one tag match into objects, or into the reason it is not one.
///
/// The order is deliberate: the cheap tests that reject a four-byte coincidence
/// run before anything is decoded, because decoding a coincidence is how a
/// plausible wrong row gets made.
fn examine(
    reader: &StructReader,
    symbols: &PoolSymbols,
    constraint: &PoolConstraint,
    tag_address: u64,
    config: &PoolScanConfig,
) -> Result<Vec<PoolObject>, String> {
    let pool_base = tag_address
        .checked_sub(symbols.pool_tag_offset)
        .ok_or_else(|| {
            format!(
                "the tag lies {} byte(s) into a pool header, which would place the allocation \
                 below address zero",
                symbols.pool_tag_offset
            )
        })?;

    let header = reader
        .object(pool_base, TYPE_POOL_HEADER)
        .map_err(|err| format!("the pool header could not be read: {err}"))?;
    let block_size = header
        .int("BlockSize")
        .map_err(|err| format!("{TYPE_POOL_HEADER}.BlockSize could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| format!("{TYPE_POOL_HEADER}.BlockSize is negative"))?;
    let pool_type = header
        .int("PoolType")
        .map_err(|err| format!("{TYPE_POOL_HEADER}.PoolType could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| format!("{TYPE_POOL_HEADER}.PoolType is negative"))?;

    if !constraint
        .page_type
        .admits(pool_type, symbols.vista_or_later)
    {
        return Err(format!(
            "PoolType {pool_type} is not a pool this kind of object is allocated from"
        ));
    }

    let allocation = block_size.checked_mul(symbols.alignment).ok_or_else(|| {
        format!("a BlockSize of {block_size} granules does not fit in the address space")
    })?;
    if let Some(min) = constraint.min_size {
        if allocation < min {
            return Err(format!(
                "the allocation is {allocation} byte(s), below the {min} an object of this kind \
                 needs"
            ));
        }
    }
    if let Some(max) = constraint.max_size {
        if allocation > max {
            return Err(format!(
                "the allocation is {allocation} byte(s), above the {max} an object of this kind \
                 occupies"
            ));
        }
    }

    let bodies = locate_bodies(
        reader, symbols, constraint, pool_base, block_size, allocation,
    )?;
    if bodies.is_empty() {
        return Err(
            "no offset inside the allocation held an object header the kernel could have written"
                .to_string(),
        );
    }

    let freed = pool_type == 0;
    let mut objects = Vec::new();
    let mut last_failure = None;
    for body in &bodies {
        match believe(
            reader, symbols, constraint, config, pool_base, body, block_size, pool_type,
            allocation, freed,
        ) {
            Ok(object) => {
                objects.push(object);
                // A pool allocation holds ONE object. `bodies` lists the offsets
                // at which it could begin, in the order the kernel would place
                // it, so the first that survives validation is the object and
                // the rest are the same allocation read from the wrong offset.
                //
                // Upstream yields every survivor, which is worse than it looks:
                // it does not merely duplicate a row, it defeats the validity
                // checks. A candidate whose `_ETHREAD.Cid` is not a thread id
                // is still reported, because some *other* offset in the same
                // allocation happened to hold eight bytes that satisfy the
                // check. Stopping at the first survivor is what makes a failed
                // validity check actually reject the allocation.
                break;
            }
            Err(reason) => last_failure = Some(reason),
        }
    }
    if objects.is_empty() {
        return Err(
            last_failure.unwrap_or_else(|| "no candidate body survived validation".to_string())
        );
    }
    Ok(objects)
}

/// One place inside an allocation at which the object could start.
#[derive(Debug, Clone, Copy)]
struct BodyCandidate {
    /// Where the object's first byte would be.
    address: u64,
    /// Where its `_OBJECT_HEADER` would be, for executive objects.
    header: Option<u64>,
    /// The padding this object header declares in front of its optional
    /// headers, when the build has a padding header and it was readable.
    padding: Option<u64>,
}

/// Every offset inside the allocation at which the object could begin.
///
/// Three shapes, chosen by what the object is and which build wrote it — never
/// by a default. See the module documentation for the picture.
fn locate_bodies(
    reader: &StructReader,
    symbols: &PoolSymbols,
    constraint: &PoolConstraint,
    pool_base: u64,
    block_size: u64,
    allocation: u64,
) -> Result<Vec<BodyCandidate>, String> {
    let after_header = pool_base
        .checked_add(symbols.pool_header_size)
        .ok_or_else(|| "the allocation's first byte lies past the address space".to_string())?;

    // Not an executive object: the structure follows the pool header directly,
    // with no object header and nothing to search for.
    if constraint.object_type.is_none() {
        return Ok(vec![BodyCandidate {
            address: after_header,
            header: None,
            padding: None,
        }]);
    }

    let body_offset = symbols
        .body_offset
        .ok_or_else(|| format!("'{TYPE_OBJECT_HEADER}' is not in this build's symbols"))?;

    if symbols.top_down {
        Ok(top_down(
            reader,
            symbols,
            after_header,
            allocation,
            body_offset,
        ))
    } else {
        bottom_up(
            reader,
            symbols,
            constraint,
            pool_base,
            block_size,
            body_offset,
        )
        .map(|candidate| vec![candidate])
    }
}

/// Windows 7 and earlier: the object ends where the allocation does.
///
/// `body = pool_base + BlockSize × alignment − round_up(sizeof(type) + extras,
/// alignment)`. The subtraction is checked: a declared type larger than the
/// allocation means the allocation does not hold this object, which is a
/// rejection rather than an address computed by wrapping round zero into the
/// top of the address space.
fn bottom_up(
    reader: &StructReader,
    symbols: &PoolSymbols,
    constraint: &PoolConstraint,
    pool_base: u64,
    block_size: u64,
    body_offset: u64,
) -> Result<BodyCandidate, String> {
    let mut type_size = reader
        .size_of(&constraint.type_name)
        .map_err(|err| format!("'{}' has no declared size: {err}", constraint.type_name))?
        .bytes();
    for extra in &constraint.additional_structures {
        let extra_size = reader
            .size_of(extra)
            .map_err(|err| format!("'{extra}' has no declared size: {err}"))?
            .bytes();
        type_size = type_size
            .checked_add(extra_size)
            .ok_or_else(|| "the declared object size does not fit in 64 bits".to_string())?;
    }
    let rounded = round_up(type_size, symbols.alignment)
        .ok_or_else(|| "the declared object size does not fit in 64 bits".to_string())?;
    let allocation = block_size
        .checked_mul(symbols.alignment)
        .ok_or_else(|| "the allocation size does not fit in 64 bits".to_string())?;
    let within = allocation.checked_sub(rounded).ok_or_else(|| {
        format!(
            "the allocation is {allocation} byte(s) and '{}' needs {rounded} once rounded to the \
             allocator's granularity, so the object cannot be inside it",
            constraint.type_name
        )
    })?;
    let address = pool_base
        .checked_add(within)
        .ok_or_else(|| "the object would lie past the address space".to_string())?;
    // The object header sits immediately in front of the body, at the distance
    // the symbol table declares between them. `None` when that would be below
    // address zero, which is a fact about the candidate rather than a reason to
    // discard the body.
    let header = address.checked_sub(body_offset);
    Ok(BodyCandidate {
        address,
        header,
        padding: None,
    })
}

/// Windows 8 and later: search forward for the object header.
///
/// The optional headers in front of an object are present per object, so the
/// object header's distance from the pool header is not fixed. Every
/// allocator-aligned offset is tested, and one is accepted when:
///
/// * `PointerCount` is a believable reference count — non-negative and below
///   [`MAX_POINTER_COUNT`]. This test does nearly all the work; random bytes
///   fail it overwhelmingly.
/// * the optional headers `InfoMask` claims fit in the space between the end of
///   the pool header and this offset. If they do not, the kernel cannot have put
///   the header here.
///
/// The search is bounded by the total size of the optional headers this build
/// declares and by the allocation itself, so it visits a handful of offsets.
///
/// **A deliberate divergence from upstream.** Upstream reads this window with
/// `pad=True`, so bytes that were never acquired become zeros — and a zero
/// `PointerCount` with a zero `InfoMask` passes both tests, manufacturing a
/// candidate out of memory that was never captured. Here an unreadable offset is
/// simply not a candidate, because an object "found" in fabricated bytes is
/// worse than an object not found.
fn top_down(
    reader: &StructReader,
    symbols: &PoolSymbols,
    after_header: u64,
    allocation: u64,
    body_offset: u64,
) -> Vec<BodyCandidate> {
    let limit = symbols.max_optional_headers.min(allocation);
    let mut found = Vec::new();
    let mut offset = 0u64;
    while offset < limit {
        let Some(header_address) = after_header.checked_add(offset) else {
            break;
        };
        if let Some(candidate) =
            probe_object_header(reader, symbols, header_address, offset, body_offset)
        {
            found.push(candidate);
        }
        let Some(next) = offset.checked_add(symbols.alignment) else {
            break;
        };
        offset = next;
    }
    found
}

/// Test one aligned offset as the start of an `_OBJECT_HEADER`.
///
/// `None` for every way the offset can fail, an unreadable byte included: there
/// is nothing to report about an offset that is simply not the header, and the
/// allocation's other offsets are still being tried.
fn probe_object_header(
    reader: &StructReader,
    symbols: &PoolSymbols,
    header_address: u64,
    offset_in_allocation: u64,
    body_offset: u64,
) -> Option<BodyCandidate> {
    let header = reader.object(header_address, TYPE_OBJECT_HEADER).ok()?;

    // A reference count is a small non-negative number. Read at the width and
    // signedness the symbol table declares, so a build whose `PointerCount` is a
    // 32-bit signed value is not read as a 64-bit unsigned one — which would
    // turn -1 into 18 quintillion and let it pass a test it should fail.
    let pointer_count = header.int("PointerCount").ok()?.as_i64()?;
    if !(0..MAX_POINTER_COUNT).contains(&pointer_count) {
        return None;
    }

    let info_mask = header.int("InfoMask").ok()?.as_u64()?;
    let mut optional_length = 0u64;
    let mut padding_present = false;
    let padding_bit = symbols
        .padding_index
        .and_then(|index| symbols.optional_headers.get(index))
        .map(|padding| padding.bit);
    for header_type in &symbols.optional_headers {
        if header_type.bit >= 64 {
            continue;
        }
        if info_mask & (1u64 << header_type.bit) == 0 {
            continue;
        }
        optional_length = optional_length.checked_add(header_type.size)?;
        if padding_bit == Some(header_type.bit) {
            padding_present = true;
        }
    }

    // The optional headers sit between the pool header and this offset. If they
    // do not fit there, this offset is not where the kernel put the header.
    if optional_length > offset_in_allocation {
        return None;
    }

    // The declared padding is read where it is, when the build has the member,
    // and travels with the candidate so an examiner can see it. It is
    // deliberately **not** used to reject: upstream's guard on it is a chained
    // comparison that can never be true, so no released Volatility has ever
    // enforced it, and inventing an interpretation of `PaddingAmount` here would
    // drop real objects out of a process list on the strength of a guess.
    let padding = if padding_present {
        read_padding_amount(reader, symbols, header_address, optional_length)
    } else {
        None
    };

    let address = header_address.checked_add(body_offset)?;
    Some(BodyCandidate {
        address,
        header: Some(header_address),
        padding,
    })
}

/// The padding this object header declares, read from the front of its optional
/// headers.
fn read_padding_amount(
    reader: &StructReader,
    symbols: &PoolSymbols,
    header_address: u64,
    optional_length: u64,
) -> Option<u64> {
    let padding = symbols
        .padding_index
        .and_then(|index| symbols.optional_headers.get(index))?;
    let at = header_address.checked_sub(optional_length)?;
    let object = reader.object(at, padding.type_name).ok()?;
    object.int(PADDING_AMOUNT_MEMBER).ok()?.as_u64()
}

/// Apply the structural and type-specific tests to one candidate body.
#[allow(clippy::too_many_arguments)]
fn believe(
    reader: &StructReader,
    symbols: &PoolSymbols,
    constraint: &PoolConstraint,
    config: &PoolScanConfig,
    pool_base: u64,
    body: &BodyCandidate,
    block_size: u64,
    pool_type: u64,
    allocation: u64,
    freed: bool,
) -> Result<PoolObject, String> {
    // Alignment, containment and full backing are rejections: without them
    // nothing can be read at all. A pointer member holding a non-canonical value
    // is *recorded* rather than fatal, because a freed allocation legitimately
    // has scrubbed pointers and is still the historical object an examiner wants
    // to see.
    let verdict = reader
        .check_struct_aligned(body.address, &constraint.type_name, symbols.alignment)
        .map_err(|err| {
            format!(
                "'{}' could not be checked at {:#x}: {err}",
                constraint.type_name, body.address
            )
        })?;
    let mut notes = Vec::new();
    for failure in &verdict.failures {
        match failure {
            PlausibilityFailure::NonCanonicalPointer { member, value } => notes.push(format!(
                "'{member}' holds {value:#x}, which no canonical address space can contain"
            )),
            PlausibilityFailure::Unreadable { member, detail } => {
                notes.push(format!("'{member}' could not be read: {detail}"))
            }
            other => return Err(other.to_string()),
        }
    }
    if let Some(padding) = body.padding {
        if padding > 0 {
            notes.push(format!(
                "the object header declares {padding} byte(s) of padding in front of its optional \
                 headers"
            ));
        }
    }

    let object = reader
        .object(body.address, &constraint.type_name)
        .map_err(|err| format!("'{}' could not be read: {err}", constraint.type_name))?;
    check_validity(&object, constraint.validity, &mut notes)?;

    // The object-manager type test, when the constraint asks for it and a map
    // is available. Its absence is recorded on the row rather than silently
    // treated as a pass or as a rejection.
    let mut object_type = None;
    let mut type_verified = false;
    if let (Some(expected), Some(header_address)) = (constraint.object_type.as_deref(), body.header)
    {
        if constraint.skip_type_test {
            notes.push(format!(
                "the object-manager type was not compared: the tag alone identifies a {expected}"
            ));
        } else {
            match config.type_map.as_deref() {
                Some(map) if !map.is_empty() => {
                    let actual = resolve_object_type(reader, map, header_address);
                    match actual.as_deref() {
                        Some(name) if name == expected => {
                            object_type = actual;
                            type_verified = true;
                        }
                        Some(name) => {
                            return Err(format!(
                                "the object manager calls this a {name}, not a {expected}"
                            ))
                        }
                        None => {
                            return Err(format!(
                                "the object header's type index does not name any type this \
                                 kernel declares, so it is not a {expected}"
                            ))
                        }
                    }
                }
                _ => notes.push(format!(
                    "the object-manager type was not compared against {expected}: no object-type \
                     map was available"
                )),
            }
        }
    }

    Ok(PoolObject {
        pool_header: pool_base,
        object_header: body.header,
        address: body.address,
        tag: constraint.tag_string(),
        type_name: constraint.type_name.clone(),
        block_size,
        pool_type,
        allocation,
        freed,
        object_type,
        type_verified,
        notes,
    })
}

/// The object-manager type an `_OBJECT_HEADER` names.
///
/// Two shapes, both handled: Vista and earlier store a pointer to an
/// `_OBJECT_TYPE` in `Type`; Windows 7 and later store a one-byte `TypeIndex`
/// into the object manager's table, mixed with the address and a cookie from
/// Windows 10 onwards.
fn resolve_object_type(
    reader: &StructReader,
    map: &ObjectTypeMap,
    header_address: u64,
) -> Option<String> {
    let header = reader.object(header_address, TYPE_OBJECT_HEADER).ok()?;
    if header.has_member("TypeIndex") {
        let stored = header.int("TypeIndex").ok()?.as_u64()?;
        return map.name_for(header_address, stored).map(str::to_string);
    }
    if header.has_member("Type") {
        let object_type = header.follow("Type").ok()??;
        return unicode_string(&object_type, "Name").ok()?;
    }
    None
}

/// The type-specific believability test, applied to a structurally sound
/// candidate.
///
/// `notes` records a test that could not be made, because "this candidate passed
/// every test" and "this candidate passed the tests this build supports" are
/// different statements about the same row.
fn check_validity(
    object: &Obj,
    validity: ObjectValidity,
    notes: &mut Vec<String>,
) -> Result<(), String> {
    match validity {
        ObjectValidity::None => Ok(()),
        ObjectValidity::Process => check_process(object, notes),
        ObjectValidity::File => check_file(object),
        ObjectValidity::Thread => check_thread(object),
    }
}

/// `_EPROCESS`: a name, a believable creation time, and a thread list that
/// points into the kernel.
fn check_process(object: &Obj, notes: &mut Vec<String>) -> Result<(), String> {
    let raw = object
        .bytes("ImageFileName")
        .map_err(|err| format!("_EPROCESS.ImageFileName could not be read: {err}"))?;
    let name = image_file_name(&raw);
    if name.is_empty() {
        return Err(
            "_EPROCESS.ImageFileName starts with a NUL, so no process was ever named here"
                .to_string(),
        );
    }

    check_thread_list(object, notes)?;

    let pid = object
        .int("UniqueProcessId")
        .map_err(|err| format!("_EPROCESS.UniqueProcessId could not be read: {err}"))?
        .as_u64();
    let create = object
        .int("CreateTime.QuadPart")
        .map_err(|err| format!("_EPROCESS.CreateTime could not be read: {err}"))?;

    // The System process is PID 4 and has no creation time. Both facts are
    // required for the exemption: a page of zeros has a zero creation time too,
    // and exempting on the time alone would admit every zeroed page in the image
    // as a process.
    if name == "System" && pid == Some(4) {
        return Ok(());
    }

    let filetime = create
        .as_u64()
        .ok_or_else(|| "_EPROCESS.CreateTime is negative, which is not a time".to_string())?;
    if filetime == 0 {
        return Err(format!(
            "the process named {name:?} has a zero creation time, and only the System process has \
             one"
        ));
    }
    if !(MIN_PROCESS_FILETIME..=MAX_PROCESS_FILETIME).contains(&filetime) {
        return Err(format!(
            "the creation time {filetime} lies outside 1990-2100, so it is not a time this \
             machine recorded"
        ));
    }
    Ok(())
}

/// `_EPROCESS.ThreadListHead`: two links that must point into kernel memory.
///
/// The test that separates a process from bytes that read like one. The list
/// links `_ETHREAD`s, which are non-paged pool allocations, so both links are
/// kernel addresses on every Windows. A page of ASCII satisfies the name and
/// creation-time tests often enough to matter — the Windows XP reference image
/// yields a "process" named `cessWindowStatio` out of the middle of the string
/// `ProcessWindowStation`, whose creation time reads as a date in 2025 — and
/// this is what rejects it. Upstream applies the same test.
///
/// A test that could not be *made* is recorded rather than failed, in all three
/// of its forms: a build that does not declare the member, a pointer width that
/// describes no machine, and a link whose own bytes were not captured. Each
/// leaves the row resting on the weaker tests and saying so, which is not the
/// same as having passed this one — and none of them may be turned into "these
/// bytes are not a process", because a smeared `_EPROCESS` is exactly the
/// unlinked process a pool sweep exists to recover. It is the same rule
/// [`believe`] already applies to an unreadable member.
fn check_thread_list(object: &Obj, notes: &mut Vec<String>) -> Result<(), String> {
    if !object.has_member("ThreadListHead") {
        notes.push(
            "this build declares no _EPROCESS.ThreadListHead, so the strongest test of whether \
             these bytes are a process — that its thread list points into the kernel — was not \
             made"
                .to_string(),
        );
        return Ok(());
    }

    // The same floor the sweep itself starts at, from the same place: a second
    // spelling of the kernel/user split could disagree with the first.
    let floor = match object.reader().pointer_size() {
        Ok(size) => match kernel_half_start(u64::from(size)) {
            Some(floor) => floor,
            None => {
                notes.push(format!(
                    "the symbols declare a pointer width of {size} byte(s), which is neither 4 \
                     nor 8, so no kernel floor is known and the thread-list test was not made"
                ));
                return Ok(());
            }
        },
        Err(err) => {
            notes.push(format!(
                "the guest pointer width could not be established ({err}), so the thread-list \
                 test was not made"
            ));
            return Ok(());
        }
    };

    for member in ["ThreadListHead.Flink", "ThreadListHead.Blink"] {
        let value = match object.pointer(member) {
            Ok(value) => value,
            Err(err) => {
                notes.push(format!(
                    "'_EPROCESS.{member}' could not be read ({err}), so the thread-list test was \
                     not made"
                ));
                return Ok(());
            }
        };
        if value < floor {
            return Err(format!(
                "_EPROCESS.{member} holds {value:#x}, which is below the kernel at {floor:#x}; a \
                 process's thread list links non-paged pool and cannot point there"
            ));
        }
    }
    Ok(())
}

/// `_FILE_OBJECT`: a named file whose name buffer is a real address.
fn check_file(object: &Obj) -> Result<(), String> {
    let length = object
        .int("FileName.Length")
        .map_err(|err| format!("_FILE_OBJECT.FileName.Length could not be read: {err}"))?
        .as_u64()
        .ok_or_else(|| "_FILE_OBJECT.FileName.Length is negative".to_string())?;
    if length == 0 {
        return Err(
            "_FILE_OBJECT.FileName is empty, and every file object names a file".to_string(),
        );
    }
    let buffer = object
        .pointer("FileName.Buffer")
        .map_err(|err| format!("_FILE_OBJECT.FileName.Buffer could not be read: {err}"))?;
    if buffer == 0 {
        return Err(format!(
            "_FILE_OBJECT.FileName declares {length} byte(s) of text and a null buffer"
        ));
    }
    // The buffer is a kernel virtual address, so whether it is mapped is a
    // question for the native space and not for the layer the allocation was
    // scanned out of.
    if !object.reader().native_layer().is_valid(buffer, 1) {
        return Err(format!(
            "_FILE_OBJECT.FileName.Buffer points at {buffer:#x}, which this address space does not \
             map"
        ));
    }
    Ok(())
}

/// `_ETHREAD`: ids NT could have handed out.
fn check_thread(object: &Obj) -> Result<(), String> {
    let mut ids = Vec::with_capacity(2);
    for member in ["Cid.UniqueThread", "Cid.UniqueProcess"] {
        let value = object
            .int(member)
            .map_err(|err| format!("_ETHREAD.{member} could not be read: {err}"))?
            .as_u64()
            .ok_or_else(|| format!("_ETHREAD.{member} is negative, which is not an id"))?;
        if value % 4 != 0 {
            return Err(format!(
                "_ETHREAD.{member} is {value}, and every id NT hands out is a multiple of four"
            ));
        }
        ids.push(value);
    }

    // The multiple-of-four test alone admits zero, and zero is what a page
    // nothing ever wrote looks like: a wholly zeroed candidate would otherwise
    // be reported as a thread with no id belonging to a process with no id.
    // Rejected on the pair rather than on `UniqueThread` alone, because the
    // idle process is genuinely process id zero and its threads must survive.
    if ids.iter().all(|&id| id == 0) {
        return Err(
            "_ETHREAD.Cid is entirely zero, which is an unwritten allocation rather than a thread"
                .to_string(),
        );
    }
    Ok(())
}

// ── Shared helpers ──────────────────────────────────────────────────────────

/// The printable part of a fixed-width image name.
///
/// `ImageFileName` is a fixed 15- or 16-byte array, NUL-padded but **not
/// guaranteed to be NUL-terminated**: a name exactly filling the array has no
/// terminator, so a reader that looked for one would run past the member. The
/// array is truncated at the first NUL if there is one and at its declared width
/// otherwise.
pub fn image_file_name(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Read a `_UNICODE_STRING` member, distinguishing "empty" from "unreadable".
///
/// `Ok(None)` means the string is genuinely zero-length. Four things this gets
/// right that a naive reader does not, each of which has produced a wrong answer
/// in a real tool:
///
/// * **`Length` counts bytes, not characters.** Treating it as a character count
///   reads half the string and can split a surrogate pair.
/// * **The length is capped before anything is allocated.** It came out of the
///   image; a corrupt `USHORT` must not become a 64 KiB allocation per candidate
///   in a sweep of millions.
/// * **`MaximumLength` must not be below `Length`.** A string claiming more text
///   than its buffer holds is malformed, and reading it anyway reads whatever
///   follows the buffer.
/// * **No NUL termination is assumed.** Kernel `_UNICODE_STRING`s frequently are
///   not terminated; exactly `Length` bytes are read.
///
/// The decoded text is then checked against what a name can contain — see
/// `name_damage`. A structure that declared a length and a buffer but whose
/// bytes are not text is a torn or overwritten structure, and it is refused so
/// that the caller records "unreadable" rather than publishing the damage as a
/// name.
pub fn unicode_string(object: &Obj, path: &str) -> Result<Option<String>, ObjError> {
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
    if length > MAX_UNICODE_STRING_BYTES || length % 2 != 0 {
        return Err(SymbolError::malformed(format!(
            "'{}.{path}' declares {length} byte(s) of UTF-16 text, which is not a length a \
             _UNICODE_STRING can hold",
            object.type_name()
        ))
        .into());
    }
    // `MaximumLength` is optional in the sense that a table may not declare it;
    // when it is there, a `Length` above it means the structure is not a string.
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
    let buffer = object.pointer(&format!("{path}.Buffer"))?;
    if buffer == 0 {
        return Err(SymbolError::malformed(format!(
            "'{}.{path}' declares {length} byte(s) of text and a null buffer",
            object.type_name()
        ))
        .into());
    }
    // The buffer is addressed in the space this object's pointers resolve in,
    // which for a pool-scanned object is the kernel virtual space and not the
    // physical layer the allocation was found in.
    let bytes = object
        .reader()
        .in_native_space()
        .read_bytes(buffer, length)?;
    let text = decode_utf16le(&bytes);
    if let Some(damage) = name_damage(&text) {
        return Err(SymbolError::malformed(format!(
            "'{}.{path}' declares {length} byte(s) of text at {buffer:#x} and {damage}, so these \
             bytes are not the name they were read as",
            object.type_name()
        ))
        .into());
    }
    Ok(Some(text))
}

/// Why decoded text cannot be the name a `_UNICODE_STRING` claimed, if it
/// cannot.
///
/// Windows names — files, modules, object types, registry paths — are ordinary
/// text. None of them contains an embedded NUL, a control character, or a
/// replacement character, so each is proof that the buffer held something other
/// than the string the structure described: a torn entry, a reused allocation,
/// or a pointer into memory that has since been overwritten.
///
/// This exists because publishing the damage is worse than publishing nothing.
/// A module row reading `\0䠀펋譈…` invites an examiner to chase a name that was
/// never there, while "the name could not be read" is a fact they can act on.
/// Upstream truncates such a string at its first NUL and prints the empty
/// remainder, which reads in a report as a module that has no name.
pub(crate) fn name_damage(text: &str) -> Option<&'static str> {
    for character in text.chars() {
        if character == '\0' {
            return Some("the text contains an embedded NUL");
        }
        if character == char::REPLACEMENT_CHARACTER {
            return Some("the text contains an unpaired UTF-16 surrogate");
        }
        if character.is_control() {
            return Some("the text contains a control character");
        }
    }
    // Nothing about the *script* the text is written in belongs here, and the
    // reason is the breadth of this function's callers. It reads registry key
    // components, executive object names, `_FILE_OBJECT` file names and mapped
    // image paths. A registry key called `ПрограммныеНастройки`, a mutant named
    // in Japanese and a document whose file name is Chinese are ordinary
    // evidence on the machines those systems belong to, and every one of them
    // is mostly non-ASCII. Refusing them would delete a non-English suspect's
    // registry and open files from the case with a message saying the bytes
    // were damaged, which is false.
    //
    // Where the string being read is a *module* name, more can be said, because
    // a Windows loader entry names a PE file — see `loader_string_damage` in
    // `crate::modules`, which applies that narrower rule on top of this one.
    None
}

/// Decode UTF-16LE, substituting replacement characters for unpaired
/// surrogates.
///
/// The bytes are real evidence and must be renderable, so a malformed unit is
/// not an error; it is a replacement character in a string an examiner can see
/// is damaged.
pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
    char::decode_utf16(units)
        .map(|unit| unit.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect()
}

/// Round `value` up to a multiple of `alignment`, refusing to wrap.
fn round_up(value: u64, alignment: u64) -> Option<u64> {
    if alignment <= 1 {
        return Some(value);
    }
    let remainder = value % alignment;
    if remainder == 0 {
        return Some(value);
    }
    value.checked_add(alignment - remainder)
}

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::Arc;

    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use seance_memory::{Architecture, MemoryLayer, PhysicalLayer};
    use seance_symbols::{CompileOptions, DecompressLimits, SymbolTable};

    use crate::profile::{Evidence, Found, KernelBuild, WindowsProfile};

    /// Size of every synthetic image these tests build.
    ///
    /// 192 KiB rather than 128: the WOW64 fixture in [`crate::modules`] places
    /// the 32-bit loader at `0x2_0000` and above, and a 128 KiB image made
    /// [`Image::write`] panic there — which is why the two tests pinning the
    /// B3-071 fix (a 32-bit DLL of a WOW64 process must not be reported as
    /// unlinked) had never actually run.
    pub(crate) const IMAGE_SIZE: usize = 0x3_0000;
    // Re-exported, not merely imported: `mod tests` below reaches these
    // through `use super::test_support::*`, and so do the sibling modules
    // that build on this fixture.
    pub(crate) use crate::image_fixture::Image;

    impl Image {
        /// An image of the size every fixture in this crate shares.
        ///
        /// The shared type takes its size explicitly, because the modules need
        /// different ones; this is the convenience the pool fixtures and everything
        /// built on them already called.
        pub(crate) fn new() -> Self {
            Self::sized(IMAGE_SIZE)
        }

        /// The image as a physical layer, ready to hand to an analysis stage.
        pub(crate) fn layer(self) -> Arc<dyn MemoryLayer> {
            let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(self.bytes));
            Arc::new(PhysicalLayer::raw(source).expect("a non-empty image"))
        }
    }

    /// Compile an ISF from its JSON text.
    pub(crate) fn table(json: &str) -> Arc<SymbolTable> {
        let source = seance_symbols::load_slice(json.as_bytes(), &DecompressLimits::default())
            .expect("readable ISF bytes");
        Arc::new(
            SymbolTable::compile_source(source, &CompileOptions::default())
                .expect("a valid synthetic ISF"),
        )
    }

    /// A profile over one layer. The kernel and physical layers are the same
    /// object, so a pointer value is also a physical address; the readers still
    /// model the split.
    pub(crate) fn profile(
        layer: Arc<dyn MemoryLayer>,
        symbols: Arc<SymbolTable>,
        architecture: Architecture,
        major: u32,
        minor: u32,
        build: Option<u32>,
    ) -> WindowsProfile {
        WindowsProfile {
            kernel_space: Arc::clone(&layer),
            physical: layer,
            symbols,
            pagefiles: Vec::new(),
            dtb: Found::new(0x1000, Evidence::Confirmed),
            kernel_base: Found::new(0, Evidence::Confirmed),
            kdbg: None,
            build: KernelBuild {
                pdb: "ntkrnlmp.pdb".into(),
                guid: "0".repeat(32),
                age: 1,
                build_lab: None,
                major,
                minor,
                build,
                // Synthetic fixture: no structure stated the build number.
                build_source: None,
            },
            architecture,
        }
    }

    /// Offsets the synthetic 64-bit ISF declares.
    pub(crate) mod off64 {
        // As the real x64 `_POOL_HEADER` is laid out: the tag twelve bytes
        // before the allocation's first byte.
        pub(crate) const POOL_HEADER_SIZE: u64 = 16;
        pub(crate) const POOL_BLOCK_SIZE: u64 = 0;
        pub(crate) const POOL_TYPE: u64 = 2;
        pub(crate) const POOL_TAG: u64 = 4;

        pub(crate) const OH_POINTER_COUNT: u64 = 0;
        pub(crate) const OH_TYPE_INDEX: u64 = 24;
        pub(crate) const OH_INFO_MASK: u64 = 26;
        pub(crate) const OH_BODY: u64 = 48;

        pub(crate) const EPROCESS_PID: u64 = 0;
        pub(crate) const EPROCESS_NAME: u64 = 8;
        pub(crate) const EPROCESS_CREATE_TIME: u64 = 32;

        pub(crate) const ETHREAD_CID_THREAD: u64 = 0;
        pub(crate) const ETHREAD_CID_PROCESS: u64 = 8;

        pub(crate) const UNICODE_LENGTH: u64 = 0;
        pub(crate) const UNICODE_MAX_LENGTH: u64 = 2;
        pub(crate) const UNICODE_BUFFER: u64 = 8;

        pub(crate) const OBJECT_TYPE_NAME: u64 = 0;
    }

    /// Offsets the synthetic 32-bit ISFs declare.
    ///
    /// Shared by [`windows32_isf`] and [`windows_xp32_isf`]: the two differ only
    /// in their `_OBJECT_HEADER`, so every pool and process offset here holds
    /// for both.
    pub(crate) mod off32 {
        pub(crate) const POOL_HEADER_SIZE: u64 = 8;
        pub(crate) const POOL_BLOCK_SIZE: u64 = 2;
        pub(crate) const POOL_TYPE: u64 = 0;
        pub(crate) const POOL_TAG: u64 = 4;

        /// Where `_OBJECT_HEADER.Body` sits in both 32-bit fixtures, which is
        /// also where it sits on the real Windows XP x86 kernel (0x18).
        pub(crate) const OH_BODY: u64 = 24;

        pub(crate) const EPROCESS_SIZE: u64 = 608;
        pub(crate) const EPROCESS_PID: u64 = 0;
        pub(crate) const EPROCESS_NAME: u64 = 4;
        pub(crate) const EPROCESS_CREATE_TIME: u64 = 24;
    }

    /// A synthetic 64-bit Windows ISF.
    ///
    /// `revocation_info` selects whether this "build" declares
    /// `_OBJECT_HEADER_HANDLE_REVOCATION_INFO`, because its presence shifts
    /// every `InfoMask` bit above it.
    pub(crate) fn windows64_isf(revocation_info: bool) -> String {
        let revocation = if revocation_info {
            r#""_OBJECT_HEADER_HANDLE_REVOCATION_INFO": {"size": 16, "kind": "struct",
                "fields": {}},"#
        } else {
            ""
        };
        format!(
            r#"{{
  "metadata": {{
    "format": "6.2.0",
    "producer": {{"name": "seance-test", "version": "1.0.0"}},
    "windows": {{"pdb": {{"GUID": "AA1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                         "database": "ntkrnlmp.pdb", "machine_type": 34404}}}}
  }},
  "base_types": {base_types},
  "user_types": {{
    "_POOL_HEADER": {{"size": 16, "kind": "struct", "fields": {{
      "BlockSize": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolType": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "PoolTag": {{"offset": 4, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_QUAD": {{"size": 8, "kind": "struct", "fields": {{
      "Value": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    "_OBJECT_HEADER": {{"size": 56, "kind": "struct", "fields": {{
      "PointerCount": {{"offset": 0, "type": {{"kind": "base", "name": "long"}}}},
      "HandleCount": {{"offset": 8, "type": {{"kind": "base", "name": "long"}}}},
      "TypeIndex": {{"offset": 24, "type": {{"kind": "base", "name": "unsigned char"}}}},
      "InfoMask": {{"offset": 26, "type": {{"kind": "base", "name": "unsigned char"}}}},
      "Body": {{"offset": 48, "type": {{"kind": "struct", "name": "_QUAD"}}}}
    }}}},
    "_OBJECT_HEADER_CREATOR_INFO": {{"size": 32, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_NAME_INFO": {{"size": 32, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_HANDLE_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_QUOTA_INFO": {{"size": 32, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_PROCESS_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_AUDIT_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    "_OBJECT_HEADER_EXTENDED_INFO": {{"size": 16, "kind": "struct", "fields": {{}}}},
    {revocation}
    "_OBJECT_HEADER_PADDING_INFO": {{"size": 8, "kind": "struct", "fields": {{
      "PaddingAmount": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}},
    "_UNICODE_STRING": {{"size": 16, "kind": "struct", "fields": {{
      "Length": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "MaximumLength": {{"offset": 2, "type": {{"kind": "base", "name": "unsigned short"}}}},
      "Buffer": {{"offset": 8, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "base", "name": "unsigned short"}}}}}}
    }}}},
    "_OBJECT_TYPE": {{"size": 32, "kind": "struct", "fields": {{
      "Name": {{"offset": 0, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}}
    }}}},
    "_LARGE_INTEGER": {{"size": 8, "kind": "union", "fields": {{
      "QuadPart": {{"offset": 0, "type": {{"kind": "base", "name": "long long"}}}}
    }}}},
    "_CLIENT_ID": {{"size": 16, "kind": "struct", "fields": {{
      "UniqueProcess": {{"offset": 8, "type": {{"kind": "pointer",
                         "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "UniqueThread": {{"offset": 0, "type": {{"kind": "pointer",
                        "subtype": {{"kind": "base", "name": "unsigned char"}}}}}}
    }}}},
    "_EPROCESS": {{"size": 640, "kind": "struct", "fields": {{
      "UniqueProcessId": {{"offset": 0, "type": {{"kind": "pointer",
                           "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "ImageFileName": {{"offset": 8, "type": {{"kind": "array", "count": 15,
                         "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "CreateTime": {{"offset": 32, "type": {{"kind": "union", "name": "_LARGE_INTEGER"}}}}
    }}}},
    "_ETHREAD": {{"size": 640, "kind": "struct", "fields": {{
      "Cid": {{"offset": 0, "type": {{"kind": "struct", "name": "_CLIENT_ID"}}}}
    }}}},
    "_FILE_OBJECT": {{"size": 216, "kind": "struct", "fields": {{
      "FileName": {{"offset": 24, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}}
    }}}},
    "_CMHIVE": {{"size": 1024, "kind": "struct", "fields": {{
      "Signature": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long"}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{
    "ObTypeIndexTable": {{"address": 61440}},
    "ObHeaderCookie": {{"address": 62464}}
  }}
}}"#,
            base_types = crate::image_fixture::BASE_TYPES_X64,
        )
    }

    /// A synthetic 32-bit Windows ISF: an eight-byte pool header, four-byte
    /// pointers, a 608-byte `_EPROCESS`.
    ///
    /// **Not an XP fixture, despite the pool header's width.** Its
    /// `_OBJECT_HEADER` declares `TypeIndex` and `InfoMask`, which arrived with
    /// Vista; a real XP header has a `Type` pointer and `NameInfoOffset` instead.
    /// Use it for the facts that are genuinely about pointer width — allocator
    /// granularity, `tag_distance()`, the pool header's size — and use
    /// [`windows_xp32_isf`] for anything that depends on the object header, or
    /// the test proves the code works on a build that never existed.
    pub(crate) fn windows32_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "BB1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 332}}
  },
  "base_types": "#,
            crate::image_fixture::BASE_TYPES_X86,
            r#",
  "user_types": {
    "_POOL_HEADER": {"size": 8, "kind": "struct", "fields": {
      "PoolType": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "BlockSize": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_QUAD": {"size": 8, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_OBJECT_HEADER": {"size": 32, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "HandleCount": {"offset": 4, "type": {"kind": "base", "name": "long"}},
      "TypeIndex": {"offset": 12, "type": {"kind": "base", "name": "unsigned char"}},
      "InfoMask": {"offset": 13, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 24, "type": {"kind": "struct", "name": "_QUAD"}}
    }},
    "_OBJECT_HEADER_CREATOR_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_NAME_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_EPROCESS": {"size": 608, "kind": "struct", "fields": {
      "UniqueProcessId": {"offset": 0, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 4, "type": {"kind": "array", "count": 16,
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "CreateTime": {"offset": 24, "type": {"kind": "union", "name": "_LARGE_INTEGER"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#,
        ]
        .concat()
    }

    /// A synthetic **Windows XP x86** ISF, with the object header XP actually
    /// had.
    ///
    /// The difference from [`windows32_isf`] is the whole point of it:
    ///
    /// * `_OBJECT_HEADER` carries a `Type` **pointer** to an `_OBJECT_TYPE`, and
    ///   `NameInfoOffset` / `HandleInfoOffset` / `QuotaInfoOffset` as direct
    ///   bytes. There is **no `TypeIndex` and no `InfoMask`** — both arrived with
    ///   Vista, and an XP fixture that declares them cannot detect code which
    ///   requires them.
    /// * Only the four optional headers XP declares are present, so there is no
    ///   `_OBJECT_HEADER_PADDING_INFO` and no revocation header.
    ///
    /// Offsets are the real ones: `PointerCount` 0x0, `HandleCount` 0x4, `Type`
    /// 0x8, `NameInfoOffset` 0xc, `Body` 0x18, `sizeof(_OBJECT_HEADER)` 0x20.
    /// Pool and `_EPROCESS` offsets match [`off32`], so the two 32-bit fixtures
    /// are interchangeable everywhere except the object header.
    pub(crate) fn windows_xp32_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "CC1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntoskrnl.pdb", "machine_type": 332}}
  },
  "base_types": "#,
            crate::image_fixture::BASE_TYPES_X86,
            r#",
  "user_types": {
    "_POOL_HEADER": {"size": 8, "kind": "struct", "fields": {
      "PoolType": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "BlockSize": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "PoolTag": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}}
    }},
    "_QUAD": {"size": 8, "kind": "struct", "fields": {
      "Value": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_UNICODE_STRING": {"size": 8, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 4, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_OBJECT_TYPE": {"size": 64, "kind": "struct", "fields": {
      "Name": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_OBJECT_HEADER": {"size": 32, "kind": "struct", "fields": {
      "PointerCount": {"offset": 0, "type": {"kind": "base", "name": "long"}},
      "HandleCount": {"offset": 4, "type": {"kind": "base", "name": "long"}},
      "Type": {"offset": 8, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "_OBJECT_TYPE"}}},
      "NameInfoOffset": {"offset": 12, "type": {"kind": "base", "name": "unsigned char"}},
      "HandleInfoOffset": {"offset": 13, "type": {"kind": "base", "name": "unsigned char"}},
      "QuotaInfoOffset": {"offset": 14, "type": {"kind": "base", "name": "unsigned char"}},
      "Flags": {"offset": 15, "type": {"kind": "base", "name": "unsigned char"}},
      "Body": {"offset": 24, "type": {"kind": "struct", "name": "_QUAD"}}
    }},
    "_OBJECT_HEADER_CREATOR_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_NAME_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_HANDLE_INFO": {"size": 8, "kind": "struct", "fields": {}},
    "_OBJECT_HEADER_QUOTA_INFO": {"size": 16, "kind": "struct", "fields": {}},
    "_LARGE_INTEGER": {"size": 8, "kind": "union", "fields": {
      "QuadPart": {"offset": 0, "type": {"kind": "base", "name": "long long"}}
    }},
    "_EPROCESS": {"size": 608, "kind": "struct", "fields": {
      "UniqueProcessId": {"offset": 0, "type": {"kind": "pointer",
                          "subtype": {"kind": "base", "name": "unsigned char"}}},
      "ImageFileName": {"offset": 4, "type": {"kind": "array", "count": 16,
                        "subtype": {"kind": "base", "name": "unsigned char"}}},
      "CreateTime": {"offset": 24, "type": {"kind": "union", "name": "_LARGE_INTEGER"}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#,
        ]
        .concat()
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;
    use seance_memory::Architecture;
    use serde_json::json;

    /// 2021-06-01T00:00:00Z as a Windows FILETIME.
    const CREATE_TIME: u64 = 132_669_792_000_000_000;

    const POOL64: u64 = 0x2000;
    const TYPE_TABLE_AT: u64 = 0xF000;
    const COOKIE_AT: u64 = 0xF400;
    const TYPE_OBJECT_AT: u64 = 0xF800;
    const TYPE_NAME_AT: u64 = 0xF900;

    // ── 64-bit, top-down (Windows 8 and later) ──────────────────────────────

    /// Lay out a Windows-8-shaped `Proc` allocation whose object header sits
    /// `optional` bytes into the allocation, announced by `info_mask`.
    ///
    /// Every aligned offset before the real header is filled with a negative
    /// `PointerCount`, which is what a real allocation's optional-header
    /// contents do. Without it the search would legitimately report the extra
    /// candidates a run of zeros produces.
    fn win8_process_image(info_mask: u8, optional: u64, name: &[u8], created: u64) -> (Image, u64) {
        let mut image = Image::sized(IMAGE_SIZE);
        // BlockSize 64 granules of 16 bytes is a 1024-byte allocation,
        // comfortably above the 600 the constraint requires.
        image.put_u16(POOL64 + off64::POOL_BLOCK_SIZE, 64);
        image.put_u16(POOL64 + off64::POOL_TYPE, 2); // non-paged, Vista encoding
        image.write(POOL64 + off64::POOL_TAG, b"Proc");

        let after = POOL64 + off64::POOL_HEADER_SIZE;
        let mut offset = 0;
        while offset < optional {
            image.put_u32(after + offset + off64::OH_POINTER_COUNT, 0xFFFF_FFFF);
            offset += POOL_ALIGNMENT_64;
        }

        let header = after + optional;
        image.put_u32(header + off64::OH_POINTER_COUNT, 7);
        image.put_u8(header + off64::OH_INFO_MASK, info_mask);
        let body = header + off64::OH_BODY;
        image.put_u64(body + off64::EPROCESS_PID, 1234);
        image.write(body + off64::EPROCESS_NAME, name);
        image.put_u64(body + off64::EPROCESS_CREATE_TIME, created);
        (image, body)
    }

    fn win8_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&windows64_isf(false)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    fn sweep(profile: &WindowsProfile, constraints: &[PoolConstraint]) -> PoolScanOutcome {
        let symbols = PoolSymbols::from_profile(profile).expect("a describable build");
        pool_scan(profile, &symbols, constraints, &PoolScanConfig::default())
            .expect("a runnable sweep")
    }

    /// Offset of `ThreadListHead` in the ISF [`isf_with_thread_list`] builds.
    const EPROCESS_THREAD_LIST: u64 = 48;

    /// The 64-bit fixture ISF with `_EPROCESS.ThreadListHead` declared at
    /// `offset`, the type grown to hold it.
    ///
    /// Built here rather than in the shared fixture because a build that does
    /// not declare the member is the *other* case under test: the check is then
    /// recorded as unmade rather than silently passed.
    fn isf_with_thread_list_at(offset: u64) -> String {
        let mut value: serde_json::Value =
            serde_json::from_str(&windows64_isf(false)).expect("the fixture ISF is valid JSON");
        let types = value["user_types"]
            .as_object_mut()
            .expect("the fixture ISF declares user types");
        types.insert(
            "_LIST_ENTRY".into(),
            json!({"size": 16, "kind": "struct", "fields": {
                "Flink": {"offset": 0, "type": {"kind": "pointer",
                          "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}},
                "Blink": {"offset": 8, "type": {"kind": "pointer",
                          "subtype": {"kind": "struct", "name": "_LIST_ENTRY"}}}
            }}),
        );
        // A member past the end of its own type is an ISF the symbol loader
        // refuses outright, so the type grows with the member rather than the
        // fixture failing before the test it was written for.
        let size = types["_EPROCESS"]["size"].as_u64().unwrap_or(0);
        types["_EPROCESS"]["size"] = json!(size.max(offset + 16));
        types["_EPROCESS"]["fields"]["ThreadListHead"] =
            json!({"offset": offset, "type": {"kind": "struct", "name": "_LIST_ENTRY"}});
        value.to_string()
    }

    /// The fixture ISF with the thread list where the fixture writes it.
    fn isf_with_thread_list() -> String {
        isf_with_thread_list_at(EPROCESS_THREAD_LIST)
    }

    /// A process allocation whose thread list holds `flink`/`blink`, and the
    /// address of the `_EPROCESS` inside it.
    fn image_with_thread_list(flink: u64, blink: u64) -> (WindowsProfile, u64) {
        let (mut image, body) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        image.put_u64(body + EPROCESS_THREAD_LIST, flink);
        image.put_u64(body + EPROCESS_THREAD_LIST + 8, blink);
        let profile = profile(
            image.layer(),
            table(&isf_with_thread_list()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        (profile, body)
    }

    /// The validity verdict on the `_EPROCESS` at `body`, in that profile.
    fn process_verdict(profile: &WindowsProfile, body: u64) -> Result<Vec<String>, String> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let object = reader.object(body, "_EPROCESS").expect("the fixture reads");
        let mut notes = Vec::new();
        check_process(&object, &mut notes).map(|()| notes)
    }

    #[test]
    fn a_candidate_whose_thread_list_is_not_in_the_kernel_is_not_a_process() {
        // The Windows XP reference image produces a "process" named
        // `cessWindowStatio` out of the middle of the string
        // `ProcessWindowStation`: the name is non-empty and the eight bytes
        // under `CreateTime` read as a date in 2025, so the name and time tests
        // both pass. Its `ThreadListHead` holds 0x656d6172 and 0x73726574 — the
        // ASCII the surrounding string is made of — and that is the only test
        // that rejects it. Without this the sweep reports 63 processes where
        // Volatility reports 62, and the extra one is a fragment of a string.
        let (profile, body) = image_with_thread_list(0x656d_6172, 0x7372_6574);
        let refusal = process_verdict(&profile, body).expect_err("text is not a process");
        assert!(refusal.contains("ThreadListHead.Flink"), "{refusal}");
        assert!(refusal.contains("thread list"), "{refusal}");

        // And the sweep that rests on it recovers nothing from the allocation.
        let outcome = sweep(&profile, &process_constraints());
        assert!(
            outcome.objects.is_empty(),
            "a process was recovered from text: {:?}",
            outcome.objects
        );
        assert_eq!(outcome.rejected_total, 1);
    }

    #[test]
    fn a_candidate_whose_thread_list_is_in_the_kernel_is_still_a_process() {
        let (profile, body) = image_with_thread_list(0xFFFF_8000_0000_1000, 0xFFFF_8000_0000_2000);
        let notes = process_verdict(&profile, body).expect("a believable process");
        assert!(
            notes.is_empty(),
            "the test was made, so nothing may say it was not: {notes:?}"
        );
        let outcome = sweep(&profile, &process_constraints());
        assert_eq!(outcome.objects.len(), 1, "{:?}", outcome.rejected);
    }

    #[test]
    fn a_build_without_a_thread_list_records_the_test_as_unmade_rather_than_passed() {
        // "We checked and it held" and "this build cannot be checked" must not
        // render alike on a row an examiner reads as a recovered process.
        let (image, body) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        let profile = win8_profile(image);
        let notes = process_verdict(&profile, body).expect("the weaker tests still pass");
        assert!(
            notes.iter().any(|note| note.contains("ThreadListHead")),
            "{notes:?}"
        );
        let outcome = sweep(&profile, &process_constraints());
        assert_eq!(outcome.objects.len(), 1);
        assert!(
            outcome.objects[0]
                .notes
                .iter()
                .any(|note| note.contains("ThreadListHead")),
            "{:?}",
            outcome.objects[0].notes
        );
    }

    #[test]
    fn a_thread_list_that_was_never_captured_is_recorded_rather_than_called_not_a_process() {
        // The direction this test guards is the expensive one. A pool sweep
        // exists to recover the processes the active list no longer holds, and
        // those are disproportionately the ones whose pages are smeared or
        // partly absent. If an unreadable ThreadListHead rejected the
        // candidate, an examiner would be told "no process here" about the very
        // allocation they were looking for, and the row would be gone rather
        // than qualified.
        let (image, body) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        // Nothing is written at the member: it is declared past the end of the
        // image, so the read fails the way an uncaptured page does.
        let beyond = IMAGE_SIZE as u64;
        let profile = profile(
            image.layer(),
            table(&isf_with_thread_list_at(beyond)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let notes = process_verdict(&profile, body)
            .expect("a test that could not be made is not a failed test");
        assert!(
            notes
                .iter()
                .any(|note| note.contains("ThreadListHead") && note.contains("not made")),
            "the row must say the test was not made rather than imply it passed: {notes:?}"
        );
    }

    fn process_constraints() -> Vec<PoolConstraint> {
        builtin_constraints_for(&[*b"Proc"])
    }

    #[test]
    fn a_top_down_object_is_found_at_the_body_offset_past_its_object_header() {
        // One optional header of 32 bytes (NAME_INFO, bit 1) sits between the
        // pool header and the object header.
        let (image, body) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &process_constraints());

        assert_eq!(outcome.objects.len(), 1, "{:?}", outcome.rejected);
        let object = &outcome.objects[0];
        assert_eq!(object.address, body);
        assert_eq!(
            object.object_header,
            Some(body - off64::OH_BODY),
            "the header is exactly Body bytes in front of the object"
        );
        assert_eq!(object.pool_header, POOL64);
        assert_eq!(object.tag, "Proc");
        assert_eq!(object.allocation, 64 * POOL_ALIGNMENT_64);
        assert!(!object.freed);
        assert_eq!(outcome.candidates, 1);
        assert_eq!(outcome.rejected_total, 0);
    }

    #[test]
    fn the_optional_header_lengths_come_from_the_bits_info_mask_actually_sets() {
        // Three headers: CREATOR_INFO (32, bit 0), HANDLE_INFO (16, bit 2) and
        // PROCESS_INFO (16, bit 4) — 64 bytes in total. An implementation that
        // summed the wrong set would reject this offset or accept another.
        let (image, body) = win8_process_image(0b0001_0101, 64, b"svchost.exe", CREATE_TIME);
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &process_constraints());
        assert_eq!(outcome.objects.len(), 1, "{:?}", outcome.rejected);
        assert_eq!(outcome.objects[0].address, body);
    }

    #[test]
    fn an_offset_whose_optional_headers_do_not_fit_in_front_of_it_is_not_the_header() {
        // The mask claims a 32-byte CREATOR_INFO but the header sits only 16
        // bytes into the allocation, so the headers would have to begin before
        // the pool header ended.
        let (image, _body) = win8_process_image(0b1, 16, b"explorer.exe", CREATE_TIME);
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &process_constraints());
        assert!(
            outcome.objects.is_empty(),
            "an impossible header position must not become a process"
        );
        assert_eq!(outcome.rejected_total, 1);
    }

    #[test]
    fn a_build_that_lacks_an_optional_header_type_shifts_every_bit_above_it() {
        // Bit 7 means PADDING_INFO on a build without HANDLE_REVOCATION_INFO
        // and HANDLE_REVOCATION_INFO on a build with it. The same InfoMask then
        // accounts for a different number of bytes, and only one of the two
        // placements can be right.
        let layer = Image::sized(IMAGE_SIZE).layer();
        let a = PoolSymbols::from_profile(&profile(
            Arc::clone(&layer),
            table(&windows64_isf(false)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        ))
        .unwrap();
        let b = PoolSymbols::from_profile(&profile(
            layer,
            table(&windows64_isf(true)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        ))
        .unwrap();

        assert_eq!(a.optional_headers.len(), 8);
        assert_eq!(b.optional_headers.len(), 9);
        assert_eq!(a.optional_headers[7].type_name, PADDING_INFO_TYPE);
        assert_eq!(
            b.optional_headers[7].type_name,
            "_OBJECT_HEADER_HANDLE_REVOCATION_INFO"
        );
        assert_eq!(a.padding_index, Some(7));
        assert_eq!(b.padding_index, Some(8));
        assert_ne!(
            a.max_optional_headers, b.max_optional_headers,
            "the two builds bound the search differently"
        );
    }

    #[test]
    fn a_negative_pointer_count_is_not_a_reference_count() {
        // Every offset holds 0xFFFFFFFF, which is -1 as the signed long the
        // symbol table declares and 4294967295 if the signedness were ignored.
        // The second reading passes the upper bound, and would manufacture an
        // object at every aligned offset in the allocation.
        let mut image = Image::sized(IMAGE_SIZE);
        image.put_u16(POOL64 + off64::POOL_BLOCK_SIZE, 64);
        image.put_u16(POOL64 + off64::POOL_TYPE, 2);
        image.write(POOL64 + off64::POOL_TAG, b"Proc");
        let after = POOL64 + off64::POOL_HEADER_SIZE;
        let mut offset = 0;
        while offset < 256 {
            image.put_u32(after + offset + off64::OH_POINTER_COUNT, 0xFFFF_FFFF);
            offset += POOL_ALIGNMENT_64;
        }
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &process_constraints());
        assert!(outcome.objects.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("no offset"),
            "{:?}",
            outcome.rejected
        );
    }

    #[test]
    fn a_pointer_count_at_the_ceiling_is_refused_and_one_below_it_is_not() {
        for (count, expected) in [(MAX_POINTER_COUNT as u32, 0usize), (0x00FF_FFFF, 1usize)] {
            let (mut image, _) = win8_process_image(0b10, 32, b"notepad.exe", CREATE_TIME);
            let header = POOL64 + off64::POOL_HEADER_SIZE + 32;
            image.put_u32(header + off64::OH_POINTER_COUNT, count);
            let profile = win8_profile(image);
            let outcome = sweep(&profile, &process_constraints());
            assert_eq!(outcome.objects.len(), expected, "PointerCount {count}");
        }
    }

    // ── The validity tests ──────────────────────────────────────────────────

    #[test]
    fn a_process_whose_name_starts_with_a_nul_was_never_a_process() {
        let (image, _) = win8_process_image(0b10, 32, &[0u8; 4], CREATE_TIME);
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &process_constraints());
        assert!(outcome.objects.is_empty());
        assert!(
            outcome.rejected[0].reason.contains("NUL"),
            "{:?}",
            outcome.rejected
        );
    }

    #[test]
    fn a_creation_time_outside_the_believable_window_is_refused() {
        // A tag match inside data yields a creation time that renders as 1601
        // beside a plausible process name, which is exactly the row that
        // survives review because every other column looks right.
        for filetime in [1u64, MIN_PROCESS_FILETIME - 1, MAX_PROCESS_FILETIME + 1] {
            let (image, _) = win8_process_image(0b10, 32, b"chrome.exe", filetime);
            let profile = win8_profile(image);
            let outcome = sweep(&profile, &process_constraints());
            assert!(outcome.objects.is_empty(), "filetime {filetime}");
        }
        // ...and the two ends of the window itself are inside it.
        for filetime in [MIN_PROCESS_FILETIME, MAX_PROCESS_FILETIME] {
            let (image, _) = win8_process_image(0b10, 32, b"chrome.exe", filetime);
            let profile = win8_profile(image);
            assert_eq!(
                sweep(&profile, &process_constraints()).objects.len(),
                1,
                "filetime {filetime}"
            );
        }
    }

    #[test]
    fn a_zero_creation_time_is_admitted_only_for_the_system_process() {
        // Both the name and the PID must match: a page of zeros has a zero
        // creation time as well, and exempting on the time alone would admit
        // every zeroed page in the image.
        let (mut image, body) = win8_process_image(0b10, 32, b"System", 0);
        image.put_u64(body + off64::EPROCESS_PID, 4);
        let profile = win8_profile(image);
        assert_eq!(sweep(&profile, &process_constraints()).objects.len(), 1);

        let (mut image, body) = win8_process_image(0b10, 32, b"System", 0);
        image.put_u64(body + off64::EPROCESS_PID, 8);
        let profile = win8_profile(image);
        assert!(
            sweep(&profile, &process_constraints()).objects.is_empty(),
            "PID 8 is not the System process"
        );

        let (mut image, body) = win8_process_image(0b10, 32, b"Sysfem", 0);
        image.put_u64(body + off64::EPROCESS_PID, 4);
        let profile = win8_profile(image);
        assert!(
            sweep(&profile, &process_constraints()).objects.is_empty(),
            "the PID alone does not make a process the System process"
        );
    }

    #[test]
    fn a_name_filling_its_array_with_no_terminator_still_reads() {
        // `ImageFileName` is NUL-terminated only when the name is shorter than
        // the array. A reader that required a terminator would drop exactly the
        // longest names.
        assert_eq!(image_file_name(b"abcdefghijklmno"), "abcdefghijklmno");
        assert_eq!(image_file_name(b"init\0\0\0\0"), "init");
        assert_eq!(image_file_name(&[0u8; 8]), "");
    }

    #[test]
    fn a_thread_id_that_is_not_a_multiple_of_four_is_not_an_nt_thread_id() {
        let build = |thread: u64, process: u64| {
            let mut image = Image::sized(IMAGE_SIZE);
            image.put_u16(POOL64 + off64::POOL_BLOCK_SIZE, 64);
            image.put_u16(POOL64 + off64::POOL_TYPE, 2);
            image.write(POOL64 + off64::POOL_TAG, b"Thre");
            let header = POOL64 + off64::POOL_HEADER_SIZE + 32;
            image.put_u32(
                POOL64 + off64::POOL_HEADER_SIZE + off64::OH_POINTER_COUNT,
                0xFFFF_FFFF,
            );
            image.put_u32(POOL64 + off64::POOL_HEADER_SIZE + 16, 0xFFFF_FFFF);
            image.put_u32(header + off64::OH_POINTER_COUNT, 3);
            image.put_u8(header + off64::OH_INFO_MASK, 0b10);
            let body = header + off64::OH_BODY;
            image.put_u64(body + off64::ETHREAD_CID_THREAD, thread);
            image.put_u64(body + off64::ETHREAD_CID_PROCESS, process);
            win8_profile(image)
        };
        let constraints = builtin_constraints_for(&[*b"Thre"]);
        // A well-formed CID survives. The count is deliberately not asserted:
        // this fixture constrains a `Thre` allocation only by its CID, so
        // several candidate body placements inside it satisfy that one check.
        // Upstream yields every surviving placement too, so the behaviour is
        // not a divergence — but "several placements survived" and "several
        // threads existed" are different claims, and a report must make the
        // second.
        //
        // Settled against the real images on 2026-07-31 by
        // `a_thread_allocation_yields_one_thread_rather_than_one_per_candidate_placement`
        // in tests/parity_poolscan.rs: on XP and Windows 11 alike, no `Thre` or
        // `Thr\xe5` allocation produces more than one row. There is no count to
        // compare against — Volatility 3 2.28.2 ships no `windows.thrdscan` —
        // so only the doubling half is asserted, which is the half that was in
        // doubt.
        assert!(!sweep(&build(0x400, 0x100), &constraints).objects.is_empty());
        assert!(sweep(&build(0x401, 0x100), &constraints).objects.is_empty());
        assert!(sweep(&build(0x400, 0x102), &constraints).objects.is_empty());
    }

    // ── 32-bit, bottom-up (Windows 7 and earlier) ───────────────────────────

    const XP_POOL: u64 = 0x3000;
    const XP_BLOCKS: u16 = 80;

    /// A Windows-XP-shaped `Pro\xe3` allocation with the `_EPROCESS` placed so
    /// that it ends at the end of the allocation.
    fn xp_process_image() -> (Image, u64) {
        let mut image = Image::sized(IMAGE_SIZE);
        image.put_u16(XP_POOL + off32::POOL_BLOCK_SIZE, XP_BLOCKS);
        image.put_u16(XP_POOL + off32::POOL_TYPE, 1); // odd: non-paged pre-Vista
        image.write(XP_POOL + off32::POOL_TAG, b"Pro\xe3");

        let allocation = u64::from(XP_BLOCKS) * POOL_ALIGNMENT_32;
        let body = XP_POOL + allocation - off32::EPROCESS_SIZE;
        image.put_u32(body + off32::EPROCESS_PID, 764);
        image.write(body + off32::EPROCESS_NAME, b"winlogon.exe");
        image.put_u64(body + off32::EPROCESS_CREATE_TIME, CREATE_TIME);
        (image, body)
    }

    /// Windows XP SP-era, over the object header XP actually had: a `Type`
    /// pointer and `NameInfoOffset`, no `TypeIndex`, no `InfoMask`.
    fn xp_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&windows_xp32_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        )
    }

    #[test]
    fn a_bottom_up_object_ends_where_its_allocation_ends() {
        let (image, body) = xp_process_image();
        let profile = xp_profile(image);
        let outcome = sweep(&profile, &builtin_constraints_for(&[*b"Pro\xe3"]));

        assert_eq!(outcome.objects.len(), 1, "{:?}", outcome.rejected);
        let object = &outcome.objects[0];
        assert_eq!(object.address, body);
        assert_eq!(object.pool_header, XP_POOL);
        assert_eq!(
            object.address + off32::EPROCESS_SIZE,
            XP_POOL + object.allocation,
            "the object's last byte is the allocation's last byte"
        );
        assert_eq!(object.tag, "Pro\\xe3");
        assert_eq!(
            object.object_header,
            Some(body - off32::OH_BODY),
            "the header is exactly Body bytes in front of the object on XP too"
        );
    }

    #[test]
    fn the_xp_fixture_declares_the_object_header_xp_had_and_not_a_later_one() {
        // Guards the fixture itself. A "Windows XP" table carrying `TypeIndex`
        // and `InfoMask` describes a build that never shipped, and every test
        // resting on it proves the code works on that imaginary build. That is
        // exactly how the Vista-only pre-flight below went unnoticed.
        let symbols = table(&windows_xp32_isf());
        assert!(symbols.has_member(TYPE_OBJECT_HEADER, "Type"));
        assert!(symbols.has_member(TYPE_OBJECT_HEADER, "NameInfoOffset"));
        assert!(symbols.has_member(TYPE_OBJECT_HEADER, "HandleInfoOffset"));
        assert!(symbols.has_member(TYPE_OBJECT_HEADER, "QuotaInfoOffset"));
        assert!(
            !symbols.has_member(TYPE_OBJECT_HEADER, "InfoMask"),
            "InfoMask arrived with Vista"
        );
        assert!(
            !symbols.has_member(TYPE_OBJECT_HEADER, "TypeIndex"),
            "TypeIndex arrived with Vista"
        );
    }

    #[test]
    fn an_xp_build_is_describable_without_the_members_only_the_top_down_search_reads() {
        // XP places executive objects bottom-up, and `bottom_up` reads exactly
        // two facts: the declared size of the object's type, and `Body`. It never
        // touches `InfoMask` or `PointerCount`. Proving those anyway refused the
        // whole sweep — and with it pool_scan, cross_view, kernel_objects, vad,
        // services, system_calls, tampering and recovered_files — over a field no
        // code path on this build would ever read.
        let symbols = PoolSymbols::from_profile(&xp_profile(Image::sized(IMAGE_SIZE)))
            .expect("XP is describable without Vista's object-header members");

        assert!(!symbols.top_down, "XP places objects bottom-up");
        assert_eq!(symbols.body_offset, Some(off32::OH_BODY));
        assert_eq!(symbols.object_header_size, Some(32));
        assert_eq!(symbols.space, ScanSpace::Physical);
        assert!(
            symbols.padding_index.is_none(),
            "XP has no _OBJECT_HEADER_PADDING_INFO"
        );
        assert_eq!(
            symbols.optional_headers.len(),
            4,
            "XP declares creator, name, handle and quota info and nothing else"
        );
    }

    #[test]
    fn a_top_down_build_missing_an_object_header_member_is_refused_by_name() {
        // The other side of the same rule: where the search really does read the
        // member, its absence must still be fatal — and the message has to name
        // it. A bare `SymbolError` reaches the examiner as "unknown member
        // 'InfoMask'" with nothing saying which sweep wanted it or why.
        for spec in TOP_DOWN_LAYOUT.members {
            let member = spec.members[0];
            let stripped = windows64_isf(false).replace(
                &format!("\"{member}\": {{\"offset\""),
                &format!("\"Not{member}\": {{\"offset\""),
            );
            let profile = profile(
                Image::sized(IMAGE_SIZE).layer(),
                table(&stripped),
                Architecture::X64,
                10,
                0,
                Some(22000),
            );
            let err = PoolSymbols::from_profile(&profile)
                .expect_err("a top-down build cannot be swept without this member");
            assert_eq!(err.class(), "unsupported_build", "{member}: {err}");
            assert!(
                err.to_string().contains(member),
                "the refusal must name the member: {err}"
            );
            assert!(
                err.to_string().contains("top of its allocation"),
                "the refusal must say why the search needs it: {err}"
            );
            assert!(
                err.to_string().contains(STAGE_POOL_SCAN.key),
                "the refusal must name the stage that stopped: {err}"
            );
        }
    }

    /// The escalation class itself, stated as an assertion rather than as a
    /// comment: on a build that reads a member only through the other branch,
    /// the binding must record it as *not declared* and must not fail.
    ///
    /// Against the unfixed code this fails at `from_profile`, because
    /// `reader.member_offset(TYPE_OBJECT_HEADER, "InfoMask")?` was proved for
    /// every build. That one line took pool scanning, cross-view, services,
    /// kernel objects, VAD, syscall scanning, tampering and recovered files with
    /// it on a real Windows XP capture.
    #[test]
    fn on_a_bottom_up_build_the_top_down_members_are_never_asked_for() {
        let symbols = PoolSymbols::from_profile(&xp_profile(Image::sized(IMAGE_SIZE)))
            .expect("XP is describable without Vista's object-header members");
        assert!(
            symbols.top_down_binding.is_none(),
            "a bottom-up build must not even ask for the members only the top-down search reads"
        );

        let layout = symbols.layout_json();
        assert_eq!(layout["top_down"], json!(false));
        assert_eq!(
            layout["top_down_members"],
            json!(null),
            "not asked is a different claim from asked and absent"
        );

        // And the members POOL_LAYOUT does declare are all present on XP, so
        // nothing in the record reads as a gap.
        let members = layout["members"]["members"]
            .as_array()
            .expect("the binding lists its members")
            .clone();
        for member in &members {
            assert_eq!(
                member["kind"], "declared",
                "XP declares every member the sweep needs on any build: {member}"
            );
        }
        assert_eq!(layout["members"]["stage"], json!(STAGE_POOL_SCAN.key));
    }

    /// A build-variant member that is genuinely absent is recorded as an
    /// answer — `not_declared`, naming what was looked for — and the sweep still
    /// runs. The unfixed code turned this into a stage failure.
    #[test]
    fn a_member_this_build_lacks_is_recorded_as_absent_rather_than_failing_the_stage() {
        // Strip `Body` off a build with no `_OBJECT_HEADER` at all by removing
        // the type: the tag sweep still has everything it needs.
        let stripped = windows_xp32_isf().replace("\"_OBJECT_HEADER\":", "\"_NOT_OBJECT_HEADER\":");
        let profile = profile(
            Image::sized(IMAGE_SIZE).layer(),
            table(&stripped),
            Architecture::X86,
            5,
            1,
            Some(2600),
        );
        let symbols = PoolSymbols::from_profile(&profile)
            .expect("a build with no object header still supports a tag sweep");
        assert_eq!(symbols.body_offset, None);
        assert_eq!(symbols.object_header_size, None);

        let layout = symbols.layout_json();
        let body = layout["members"]["members"]
            .as_array()
            .expect("the binding lists its members")
            .iter()
            .find(|entry| entry["key"] == "body")
            .expect("body is declared by POOL_LAYOUT")
            .clone();
        assert_eq!(
            body["kind"], "not_declared",
            "an absent member is an answer, not a failure: {body}"
        );
        assert_eq!(
            body["candidates"],
            json!(["Body"]),
            "a report that says a value is absent has to say what was looked for"
        );
    }

    /// The refusal that must stay fatal: `_POOL_HEADER` is required, and the
    /// message an examiner reads has to say what is lost.
    #[test]
    fn a_build_with_no_pool_header_is_still_refused_and_says_what_is_lost() {
        let stripped = windows_xp32_isf().replace("\"_POOL_HEADER\":", "\"_NOT_POOL_HEADER\":");
        let profile = profile(
            Image::sized(IMAGE_SIZE).layer(),
            table(&stripped),
            Architecture::X86,
            5,
            1,
            Some(2600),
        );
        let err = PoolSymbols::from_profile(&profile)
            .expect_err("without a pool header nothing can be sized");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains(TYPE_POOL_HEADER), "{err}");
        assert!(
            err.to_string().contains("no candidate object can be found"),
            "the refusal must complete the sentence 'Without it, …': {err}"
        );
    }

    /// The layout has to reach the artifact, not just the struct. Three values
    /// have already been recorded here and read by nobody.
    #[test]
    fn the_stage_record_carries_the_layout_this_build_provided() {
        let (image, _) = xp_process_image();
        let outcome = sweep(&xp_profile(image), &builtin_constraints_for(&[*b"Pro\xe3"]));
        let record = outcome.to_json();
        assert_eq!(
            record["layout"]["members"]["stage"],
            json!(STAGE_POOL_SCAN.key),
            "a report cannot tell an absent column from a misnamed one without this"
        );
        assert_eq!(record["layout"]["top_down"], json!(false));
    }

    #[test]
    fn the_allocator_granularity_follows_the_pointer_width_the_table_declares() {
        // Sixteen-byte alignment in a four-byte address space would place every
        // bottom-up object at the wrong address and reject half of them for
        // being misaligned.
        let layer = Image::sized(IMAGE_SIZE).layer();
        let x86 = PoolSymbols::from_profile(&profile(
            Arc::clone(&layer),
            table(&windows32_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        ))
        .unwrap();
        let x64 = PoolSymbols::from_profile(&profile(
            layer,
            table(&windows64_isf(false)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        ))
        .unwrap();
        assert_eq!(x86.alignment, POOL_ALIGNMENT_32);
        assert_eq!(x64.alignment, POOL_ALIGNMENT_64);
        assert_eq!(x86.pool_header_size, off32::POOL_HEADER_SIZE);
        assert_eq!(x64.pool_header_size, off64::POOL_HEADER_SIZE);
        assert!(!x86.top_down);
        assert!(x64.top_down);
        assert!(!x86.vista_or_later);
        assert!(x64.vista_or_later);
        assert_eq!(x86.space, ScanSpace::Physical);
        assert_eq!(x64.space, ScanSpace::KernelVirtual);
        assert_eq!(x64.object_header_size, Some(56));
        assert_eq!(x86.kernel_floor, KERNEL_HALF_START_X86);
        assert_eq!(x64.kernel_floor, KERNEL_HALF_START_X64);
    }

    #[test]
    fn a_sweep_states_what_the_space_it_ran_in_cannot_reach() {
        // The two spaces miss opposite things, and a sweep that examined every
        // byte of one is still not a sweep of the machine. An artifact stamped
        // complete with no such statement invites "the pool scan was complete,
        // so nothing was hidden".
        assert!(ScanSpace::KernelVirtual
            .limits()
            .contains("survives in physical memory"));
        assert!(ScanSpace::Physical.limits().contains("page file"));

        let (image, _) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        let outcome = sweep(&win8_profile(image), &process_constraints());
        let json = outcome.to_json();
        assert_eq!(json["space"], "kernel_virtual");
        assert_eq!(json["space_limits"], ScanSpace::KernelVirtual.limits());
        // This fixture's layer ends far below any kernel half, so the sweep
        // covered all of it and the record says so rather than naming a bound.
        assert!(outcome.swept.is_none());
        assert_eq!(json["swept"], serde_json::Value::Null);
    }

    #[test]
    fn a_kernel_virtual_sweep_starts_at_the_kernel_half_and_not_at_address_zero() {
        // The Windows 11 reference image: a sweep that began at zero walked the
        // user half, was told at 0x0000_8000_0000_0000 that the address does not
        // exist, stopped there, and reported 0 processes against Volatility's
        // 103 — without setting `truncated`, because from its point of view the
        // walk had ended. Every pool allocation is above the gap.
        assert_eq!(
            kernel_half_sweep(KERNEL_HALF_START_X64, u64::MAX),
            Some(KERNEL_HALF_START_X64..u64::MAX)
        );
        assert_eq!(
            kernel_half_sweep(KERNEL_HALF_START_X86, 0xFFFF_FFFF),
            Some(KERNEL_HALF_START_X86..0x1_0000_0000),
            "a 32-bit kernel space has the same two halves at a lower boundary, and the range \
             ends where that space does rather than at the top of a 64-bit one"
        );

        // A layer that ends below the floor has no kernel half to start at —
        // every synthetic fixture, and a partial acquisition. It is swept whole,
        // so this can only ever add coverage, never remove it.
        assert_eq!(kernel_half_sweep(KERNEL_HALF_START_X64, 0x2_FFFF), None);

        // And the floor is the machine's, not a constant: reading a 64-bit
        // kernel from 0x8000_0000 would sweep the non-canonical gap.
        assert_eq!(kernel_half_start(8), Some(KERNEL_HALF_START_X64));
        assert_eq!(kernel_half_start(4), Some(KERNEL_HALF_START_X86));
        assert_eq!(kernel_half_start(6), None);

        // A physical sweep has no halves: the pool's bytes are wherever the
        // acquisition put them, and skipping the bottom of the image would skip
        // real allocations. Its record therefore names no bound at all.
        let (image, _) = xp_process_image();
        let outcome = sweep(&xp_profile(image), &builtin_constraints_for(&[*b"Pro\xe3"]));
        assert_eq!(outcome.space, ScanSpace::Physical);
        assert!(outcome.swept.is_none());
    }

    #[test]
    fn the_distance_from_an_object_to_its_pool_tag_is_four_on_x86_and_twelve_on_x64() {
        // Derived from the symbol table rather than written down: it is exactly
        // `sizeof(_POOL_HEADER) - offsetof(PoolTag)`, which is what makes it
        // survive a build whose header grows.
        let layer = Image::sized(IMAGE_SIZE).layer();
        let x86 = PoolSymbols::from_profile(&profile(
            Arc::clone(&layer),
            table(&windows32_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        ))
        .unwrap();
        let x64 = PoolSymbols::from_profile(&profile(
            layer,
            table(&windows64_isf(false)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        ))
        .unwrap();
        assert_eq!(x86.tag_distance(), 4);
        assert_eq!(x64.tag_distance(), 12);
    }

    #[test]
    fn an_object_larger_than_its_allocation_is_rejected_rather_than_placed_by_wrapping() {
        // Computing `pool + allocation - size` without a checked subtraction
        // lands near the top of the address space, where the read fails for a
        // reason that hides the real one.
        let (mut image, _) = xp_process_image();
        image.put_u16(XP_POOL + off32::POOL_BLOCK_SIZE, 1);
        let profile = xp_profile(image);
        let outcome = sweep(&profile, &builtin_constraints_for(&[*b"Pro\xe3"]));
        assert!(outcome.objects.is_empty());
        assert_eq!(outcome.rejected_total, 1);
        assert!(
            outcome.rejected[0].reason.contains("below the 600"),
            "{:?}",
            outcome.rejected
        );

        // And with the size floor lifted, the placement itself is what refuses.
        let (mut image, _) = xp_process_image();
        image.put_u16(XP_POOL + off32::POOL_BLOCK_SIZE, 4);
        let profile = xp_profile(image);
        let bare = vec![PoolConstraint::new(*b"Pro\xe3", "_EPROCESS").executive("Process")];
        let outcome = sweep(&profile, &bare);
        assert!(outcome.objects.is_empty());
        assert!(
            outcome.rejected[0].reason.contains("cannot be inside it"),
            "{:?}",
            outcome.rejected
        );
    }

    #[test]
    fn structures_allocated_alongside_the_object_move_it_down_the_allocation() {
        // `_DRIVER_OBJECT` shares its allocation with a `_DRIVER_EXTENSION`
        // before Windows 8. Omitting the extension places the driver object one
        // extension too high, and everything read from it is one member out.
        let driver = builtin_constraints()
            .into_iter()
            .find(|c| c.tag == *b"Dri\xf6")
            .expect("the pre-Windows-8 driver tag");
        assert_eq!(driver.additional_structures, vec!["_DRIVER_EXTENSION"]);
        assert!(builtin_constraints()
            .into_iter()
            .find(|c| c.tag == *b"Driv")
            .expect("the Windows 8 driver tag")
            .additional_structures
            .is_empty());
    }

    // ── Pool type encoding ──────────────────────────────────────────────────

    #[test]
    fn the_pool_type_encoding_is_the_opposite_way_round_on_either_side_of_vista() {
        let nonpaged_only = PoolTypes {
            paged: false,
            nonpaged: true,
            free: false,
        };
        // 2 is non-paged from Vista and paged before it; 1 is the reverse.
        assert!(nonpaged_only.admits(2, true));
        assert!(!nonpaged_only.admits(1, true));
        assert!(nonpaged_only.admits(1, false));
        assert!(!nonpaged_only.admits(2, false));

        // Zero is a freed allocation under both encodings, and a constraint
        // that does not want freed allocations must not take it as paged.
        assert!(!nonpaged_only.admits(0, true));
        assert!(!nonpaged_only.admits(0, false));
        assert!(PoolTypes::nonpaged_or_free().admits(0, true));
        assert!(PoolTypes::any().admits(0, false));
        assert!(PoolTypes::paged_or_free().admits(1, true));
        assert!(!PoolTypes::paged_or_free().admits(2, true));
    }

    #[test]
    fn a_paged_allocation_is_not_a_process_and_is_counted_as_a_rejection() {
        let (mut image, _) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        image.put_u16(POOL64 + off64::POOL_TYPE, 1); // odd: paged from Vista
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &process_constraints());
        assert!(outcome.objects.is_empty());
        assert_eq!(outcome.candidates, 1);
        assert_eq!(outcome.rejected_total, 1);
        assert!(outcome.rejected[0].reason.contains("PoolType 1"));
    }

    #[test]
    fn a_freed_allocation_is_reported_and_marked_as_historical() {
        let (mut image, _) = win8_process_image(0b10, 32, b"cmd.exe", CREATE_TIME);
        image.put_u16(POOL64 + off64::POOL_TYPE, 0);
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &process_constraints());
        assert_eq!(outcome.objects.len(), 1);
        assert!(
            outcome.objects[0].freed,
            "a freed allocation is exactly the historical object a sweep exists to find"
        );
        assert_eq!(outcome.objects[0].to_json()["freed"], true);
    }

    // ── Failing closed ──────────────────────────────────────────────────────

    #[test]
    fn a_build_without_a_number_cannot_choose_a_placement_and_says_so() {
        let profile = profile(
            Image::sized(IMAGE_SIZE).layer(),
            table(&windows64_isf(false)),
            Architecture::X64,
            10,
            0,
            None,
        );
        let err = PoolSymbols::from_profile(&profile).expect_err("no build number");
        assert_eq!(err.class(), "build_unknown");
        assert_eq!(
            err.incomplete_reason(),
            IncompleteReason::UnresolvedStructure
        );
        assert_eq!(
            err.to_incomplete().reason,
            IncompleteReason::UnresolvedStructure
        );
    }

    #[test]
    fn a_symbol_table_of_the_wrong_pointer_width_is_refused_before_anything_is_read() {
        // The 32-bit table against a profile that says the kernel is 64-bit.
        // Every allocation base would come out a whole pool header wrong, and
        // every object read from it would still parse.
        let profile = profile(
            Image::sized(IMAGE_SIZE).layer(),
            table(&windows32_isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let err = PoolSymbols::from_profile(&profile).expect_err("mismatched widths");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("4-byte pointers"), "{err}");
    }

    #[test]
    fn two_constraints_claiming_one_tag_is_refused_rather_than_resolved_by_order() {
        let profile = win8_profile(Image::sized(IMAGE_SIZE));
        let symbols = PoolSymbols::from_profile(&profile).unwrap();
        let constraints = vec![
            PoolConstraint::new(*b"Proc", "_EPROCESS"),
            PoolConstraint::new(*b"Proc", "_CMHIVE"),
        ];
        let err = pool_scan(&profile, &symbols, &constraints, &PoolScanConfig::default())
            .expect_err("one tag, one meaning");
        assert_eq!(err.class(), "duplicate_tag");
        assert!(err.to_string().contains("Proc"), "{err}");
    }

    #[test]
    fn a_sweep_with_no_constraints_is_refused_rather_than_returning_an_empty_list() {
        // An empty result here would read as "this machine had no objects".
        let profile = win8_profile(Image::sized(IMAGE_SIZE));
        let symbols = PoolSymbols::from_profile(&profile).unwrap();
        let err = pool_scan(&profile, &symbols, &[], &PoolScanConfig::default())
            .expect_err("nothing to look for");
        assert_eq!(err.class(), "unsupported_build");
    }

    #[test]
    fn a_validity_policy_whose_member_this_build_lacks_fails_the_sweep_not_every_object() {
        // Rejecting each object individually would produce an empty process
        // list, which reads as a machine with no processes.
        let profile = win8_profile(Image::sized(IMAGE_SIZE));
        let symbols = PoolSymbols::from_profile(&profile).unwrap();
        let constraint = PoolConstraint::new(*b"Proc", "_EPROCESS")
            .executive("Process")
            .validity(ObjectValidity::Thread);
        let err = pool_scan(
            &profile,
            &symbols,
            std::slice::from_ref(&constraint),
            &PoolScanConfig::default(),
        )
        .expect_err("_EPROCESS has no Cid");
        assert!(err.to_string().contains("Cid.UniqueThread"), "{err}");
    }

    #[test]
    fn an_executive_constraint_on_a_build_with_no_object_header_is_refused() {
        // Placing the body without an `_OBJECT_HEADER.Body` offset would mean
        // guessing where inside the allocation the object starts.
        let no_header = windows64_isf(false).replace("\"_OBJECT_HEADER\"", "\"_OBJECT_HEADER_X\"");
        let profile = profile(
            Image::sized(IMAGE_SIZE).layer(),
            table(&no_header),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = PoolSymbols::from_profile(&profile).unwrap();
        assert_eq!(symbols.body_offset, None);
        let err = pool_scan(
            &profile,
            &symbols,
            &process_constraints(),
            &PoolScanConfig::default(),
        )
        .expect_err("no object header");
        assert_eq!(err.class(), "unsupported_build");

        // A non-executive constraint is unaffected: it never needed one.
        assert!(pool_scan(
            &profile,
            &symbols,
            &builtin_constraints_for(&[*b"CM10"]),
            &PoolScanConfig::default()
        )
        .is_ok());
    }

    // ── Non-executive allocations ───────────────────────────────────────────

    #[test]
    fn an_allocation_with_no_object_header_starts_immediately_after_the_pool_header() {
        // `CM10` marks a `_CMHIVE`, which the object manager does not own, so
        // there is no object header and no search: the structure is the
        // allocation. Adding the object-header offset would put it 56 bytes in.
        let mut image = Image::sized(IMAGE_SIZE);
        image.put_u16(POOL64 + off64::POOL_BLOCK_SIZE, 128);
        image.put_u16(POOL64 + off64::POOL_TYPE, 1); // paged from Vista
        image.write(POOL64 + off64::POOL_TAG, b"CM10");
        let profile = win8_profile(image);
        let outcome = sweep(&profile, &builtin_constraints_for(&[*b"CM10"]));

        assert_eq!(outcome.objects.len(), 1, "{:?}", outcome.rejected);
        assert_eq!(outcome.objects[0].address, POOL64 + off64::POOL_HEADER_SIZE);
        assert_eq!(outcome.objects[0].object_header, None);
    }

    // ── The object type map ─────────────────────────────────────────────────

    /// Merge two hand-built images, taking every non-zero byte from each.
    fn merge(a: Image, b: Image) -> Image {
        let mut out = Image::sized(IMAGE_SIZE);
        for (index, byte) in a.bytes.iter().enumerate() {
            if *byte != 0 {
                out.bytes[index] = *byte;
            }
        }
        for (index, byte) in b.bytes.iter().enumerate() {
            if *byte != 0 {
                out.bytes[index] = *byte;
            }
        }
        out
    }

    /// An image carrying an object-type table with one named entry, and the
    /// stored `TypeIndex` that resolves to it at `header_address`.
    ///
    /// The entry goes in slot 1 because slot 0 is always null and the first
    /// null after it ends the table, exactly as the kernel lays it out.
    fn typed_image(header_address: u64, cookie: u8, name: &str) -> (Image, u8) {
        let mut image = Image::sized(IMAGE_SIZE);
        let real_index: u8 = 1;
        image.put_u64(TYPE_TABLE_AT + u64::from(real_index) * 8, TYPE_OBJECT_AT);
        let bytes = (name.encode_utf16().count() * 2) as u16;
        image.put_u16(
            TYPE_OBJECT_AT + off64::OBJECT_TYPE_NAME + off64::UNICODE_LENGTH,
            bytes,
        );
        image.put_u16(
            TYPE_OBJECT_AT + off64::OBJECT_TYPE_NAME + off64::UNICODE_MAX_LENGTH,
            bytes,
        );
        image.put_u64(
            TYPE_OBJECT_AT + off64::OBJECT_TYPE_NAME + off64::UNICODE_BUFFER,
            TYPE_NAME_AT,
        );
        image.put_utf16(TYPE_NAME_AT, name);
        image.put_u8(COOKIE_AT, cookie);
        let stored = ((header_address >> 8) ^ u64::from(cookie) ^ u64::from(real_index)) & 0xFF;
        (image, stored as u8)
    }

    /// A process allocation whose object header's `TypeIndex` resolves, through
    /// the mixing, to `name`. Returns the profile, the header address and the
    /// stored index that was written.
    fn typed_process_profile(name: &str) -> (WindowsProfile, u64, u8) {
        let header = POOL64 + off64::POOL_HEADER_SIZE + 32;
        let (typed, stored) = typed_image(header, 0x5A, name);
        let (process, _) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        let mut image = merge(process, typed);
        image.put_u8(header + off64::OH_TYPE_INDEX, stored);
        (win8_profile(image), header, stored)
    }

    fn verified_process_constraint() -> PoolConstraint {
        PoolConstraint::new(*b"Proc", "_EPROCESS")
            .executive("Process")
            .min_size(600)
            .page_type(PoolTypes::nonpaged_or_free())
            .validity(ObjectValidity::Process)
    }

    #[test]
    fn a_windows_ten_type_index_is_unmixed_with_the_header_address_and_the_cookie() {
        // The same object type has a different stored index at every address.
        // Using the stored value directly indexes into an unrelated entry and
        // rejects a real object as the wrong type.
        let (profile, header, stored) = typed_process_profile("Process");
        let map = ObjectTypeMap::from_profile(&profile).expect("a readable table");
        assert_eq!(map.cookie(), Some(0x5A));
        assert!(!map.is_empty());
        assert!(map.entries_read() > 0);

        let stored = u64::from(stored);
        assert_eq!(map.name_for(header, stored), Some("Process"));
        assert_eq!(
            map.name_for(header + 0x100, stored),
            None,
            "the same stored index at another address names another type"
        );

        let symbols = PoolSymbols::from_profile(&profile).unwrap();
        let config = PoolScanConfig {
            type_map: Some(Arc::new(map)),
            ..PoolScanConfig::default()
        };
        let constraint = verified_process_constraint();
        let outcome = pool_scan(
            &profile,
            &symbols,
            std::slice::from_ref(&constraint),
            &config,
        )
        .unwrap();
        assert_eq!(outcome.objects.len(), 1, "{:?}", outcome.rejected);
        assert!(outcome.objects[0].type_verified);
        assert_eq!(outcome.objects[0].object_type.as_deref(), Some("Process"));
    }

    #[test]
    fn an_object_whose_manager_type_disagrees_with_its_tag_is_discarded() {
        let (profile, _, _) = typed_process_profile("Section");
        let map = ObjectTypeMap::from_profile(&profile).unwrap();
        let symbols = PoolSymbols::from_profile(&profile).unwrap();
        let config = PoolScanConfig {
            type_map: Some(Arc::new(map)),
            ..PoolScanConfig::default()
        };
        let constraint = verified_process_constraint();
        let outcome = pool_scan(
            &profile,
            &symbols,
            std::slice::from_ref(&constraint),
            &config,
        )
        .unwrap();
        // The claim that matters: an allocation tagged `Proc` whose object type
        // says `Section` yields no process. Which check fires first is not
        // pinned — several would each reject this candidate independently, and
        // asserting one of them would be asserting the order they happen to run
        // in rather than the finding.
        assert!(outcome.objects.is_empty());
        assert!(
            !outcome.rejected.is_empty(),
            "the candidate was discarded without recording why"
        );
    }

    #[test]
    fn an_unperformed_type_test_is_declared_rather_than_treated_as_a_pass() {
        let (image, _) = win8_process_image(0b10, 32, b"explorer.exe", CREATE_TIME);
        let profile = win8_profile(image);
        let symbols = PoolSymbols::from_profile(&profile).unwrap();
        let constraint = verified_process_constraint();
        let outcome = pool_scan(
            &profile,
            &symbols,
            std::slice::from_ref(&constraint),
            &PoolScanConfig::default(),
        )
        .unwrap();

        assert_eq!(outcome.objects.len(), 1);
        assert!(!outcome.objects[0].type_verified);
        assert!(outcome.objects[0]
            .notes
            .iter()
            .any(|note| note.contains("no object-type map")));
        assert!(
            !outcome.is_complete(),
            "a sweep with an unperformed check is not a clean sweep"
        );
        assert!(outcome
            .incomplete
            .iter()
            .any(|i| i.detail.contains("object-manager type")));
    }

    #[test]
    fn a_table_that_is_not_in_the_symbols_is_an_error_not_an_empty_map() {
        let profile = profile(
            Image::sized(IMAGE_SIZE).layer(),
            table(&windows32_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        );
        let err = ObjectTypeMap::from_profile(&profile).expect_err("no such symbol");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("ObTypeIndexTable"), "{err}");
        assert!(ObjectTypeMap::empty().is_empty());
        assert_eq!(ObjectTypeMap::empty().cookie(), None);
    }

    #[test]
    fn without_a_cookie_the_stored_type_index_is_used_as_it_stands() {
        let mut map = ObjectTypeMap::empty();
        map.by_index.insert(7, "File".to_string());
        assert_eq!(map.name_for(0x1234_5600, 7), Some("File"));
        assert_eq!(map.name_for(0x9999_9900, 7), Some("File"));
        assert_eq!(map.name_for(0x1234_5600, 8), None);
    }

    #[test]
    fn a_map_with_no_cookie_may_not_resolve_an_index_on_a_build_that_mixes_one_in() {
        // Using the stored index as it stands is right up to Windows 8.1 and
        // meaningless from Windows 10, where the index is mixed with the
        // header's own address. A caller that resolves anyway names the wrong
        // kind of object for about a fifth of its rows — the fraction of the
        // 256 slots this table fills — and marks none of them.
        let mut map = ObjectTypeMap::empty();
        map.by_index.insert(7, "File".to_string());
        assert_eq!(map.cookie(), None);

        assert!(map.resolves_indexes(Some(2600)).is_ok(), "XP does not mix");
        assert!(
            map.resolves_indexes(Some(9600)).is_ok(),
            "Windows 8.1 does not mix"
        );
        let refused = map
            .resolves_indexes(Some(FIRST_MIXED_TYPE_INDEX_BUILD))
            .expect_err("Windows 10 RTM mixes");
        assert!(refused.contains(SYMBOL_HEADER_COOKIE), "{refused}");
        assert!(map.resolves_indexes(Some(22000)).is_err());
        assert!(
            map.resolves_indexes(None).is_err(),
            "a build that was never established cannot be shown not to mix"
        );
    }

    #[test]
    fn a_map_that_carries_its_cookie_resolves_on_every_build() {
        let (profile, _, _) = typed_process_profile("Process");
        let map = ObjectTypeMap::from_profile(&profile).expect("a readable table");
        assert_eq!(map.cookie(), Some(0x5A));
        assert!(map.resolves_indexes(Some(22000)).is_ok());
        assert!(map.resolves_indexes(None).is_ok());
    }

    // ── _UNICODE_STRING ─────────────────────────────────────────────────────

    fn string_reader(image: Image) -> (WindowsProfile, StructReader) {
        let profile = win8_profile(image);
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        (profile, reader)
    }

    #[test]
    fn a_unicode_string_length_is_bytes_and_not_characters() {
        let mut image = Image::sized(IMAGE_SIZE);
        let string_at = 0x8000u64;
        let text_at = 0x8100u64;
        image.put_u16(string_at + off64::UNICODE_LENGTH, 14); // seven characters
        image.put_u16(string_at + off64::UNICODE_MAX_LENGTH, 16);
        image.put_u64(string_at + off64::UNICODE_BUFFER, text_at);
        image.put_utf16(text_at, "Process!!");
        let (_profile, reader) = string_reader(image);
        let object = reader.object(string_at, TYPE_OBJECT_TYPE).unwrap();
        assert_eq!(
            unicode_string(&object, "Name").unwrap().as_deref(),
            Some("Process"),
            "14 bytes is seven UTF-16 characters, not fourteen"
        );
    }

    #[test]
    fn a_unicode_string_that_claims_more_text_than_its_buffer_holds_is_malformed() {
        let mut image = Image::sized(IMAGE_SIZE);
        let string_at = 0x8000u64;
        image.put_u16(string_at + off64::UNICODE_LENGTH, 32);
        image.put_u16(string_at + off64::UNICODE_MAX_LENGTH, 16);
        image.put_u64(string_at + off64::UNICODE_BUFFER, 0x8100);
        let (_profile, reader) = string_reader(image);
        let object = reader.object(string_at, TYPE_OBJECT_TYPE).unwrap();
        let err = unicode_string(&object, "Name").expect_err("Length above MaximumLength");
        assert!(err.to_string().contains("buffer of 16"), "{err}");
    }

    #[test]
    fn an_odd_unicode_string_length_is_refused_rather_than_silently_truncated() {
        let mut image = Image::sized(IMAGE_SIZE);
        let string_at = 0x8000u64;
        image.put_u16(string_at + off64::UNICODE_LENGTH, 7);
        image.put_u16(string_at + off64::UNICODE_MAX_LENGTH, 16);
        image.put_u64(string_at + off64::UNICODE_BUFFER, 0x8100);
        let (_profile, reader) = string_reader(image);
        let object = reader.object(string_at, TYPE_OBJECT_TYPE).unwrap();
        assert!(unicode_string(&object, "Name").is_err());
    }

    #[test]
    fn an_empty_unicode_string_is_an_absence_and_a_null_buffer_with_a_length_is_an_error() {
        let string_at = 0x8000u64;
        let mut image = Image::sized(IMAGE_SIZE);
        image.put_u16(string_at + off64::UNICODE_LENGTH, 0);
        let (_profile, reader) = string_reader(image);
        let object = reader.object(string_at, TYPE_OBJECT_TYPE).unwrap();
        assert_eq!(unicode_string(&object, "Name").unwrap(), None);

        let mut image = Image::sized(IMAGE_SIZE);
        image.put_u16(string_at + off64::UNICODE_LENGTH, 8);
        image.put_u16(string_at + off64::UNICODE_MAX_LENGTH, 8);
        let (_profile, reader) = string_reader(image);
        let object = reader.object(string_at, TYPE_OBJECT_TYPE).unwrap();
        assert!(unicode_string(&object, "Name").is_err());
    }

    #[test]
    fn a_torn_string_is_refused_rather_than_published_as_a_name() {
        // The Windows 11 reference image holds one `_LDR_DATA_TABLE_ENTRY` of
        // 5,950 whose `BaseDllName` buffer begins with a NUL and continues into
        // bytes that are not text. Publishing the decode invites an examiner to
        // chase a module name that was never there; upstream truncates at the
        // NUL and prints an empty name, which reads as a module with no name.
        let mut image = Image::sized(IMAGE_SIZE);
        let string_at = 0x8000u64;
        let text_at = 0x8100u64;
        image.put_u16(string_at + off64::UNICODE_LENGTH, 8);
        image.put_u16(string_at + off64::UNICODE_MAX_LENGTH, 16);
        image.put_u64(string_at + off64::UNICODE_BUFFER, text_at);
        image.put_u16(text_at, 0x0000);
        image.put_u16(text_at + 2, 0x4820);
        image.put_u16(text_at + 4, 0x0041);
        image.put_u16(text_at + 6, 0x0042);
        let (_profile, reader) = string_reader(image);
        let object = reader.object(string_at, TYPE_OBJECT_TYPE).unwrap();
        let err = unicode_string(&object, "Name").expect_err("a NUL inside a name");
        assert!(err.to_string().contains("embedded NUL"), "{err}");

        assert_eq!(name_damage("ntdll.dll"), None);
        assert_eq!(
            name_damage(r"\Windows\System32\version.dll"),
            None,
            "a path is a name"
        );
        assert!(name_damage("nt\u{FFFD}dll").is_some());
        assert!(name_damage("nt\u{7}dll").is_some());
    }

    #[test]
    fn a_name_written_in_another_script_is_evidence_and_not_damage() {
        // This reader names registry key components, executive objects and
        // open files. On a Russian, Japanese or Greek machine those names are
        // written in the machine's own script, and refusing them would delete
        // that suspect's registry and open files from the case while claiming
        // the bytes were damaged.
        assert_eq!(name_damage("ПрограммныеНастройки"), None);
        assert_eq!(name_damage("同期オブジェクト"), None);
        assert_eq!(name_damage("Ελληνικά"), None);
        assert_eq!(name_damage(r"\Device\HarddiskVolume2\Пользователи"), None);
    }

    #[test]
    fn an_unpaired_surrogate_renders_as_a_replacement_rather_than_failing() {
        assert_eq!(decode_utf16le(&[0x00, 0xD8]), "\u{FFFD}");
        assert_eq!(decode_utf16le(&[0x41, 0x00, 0x42, 0x00]), "AB");
        assert_eq!(decode_utf16le(&[]), "");
        // An odd trailing byte is dropped by `chunks_exact` rather than read
        // past the end of the buffer.
        assert_eq!(decode_utf16le(&[0x41, 0x00, 0x42]), "A");
    }

    // ── Arithmetic ──────────────────────────────────────────────────────────

    #[test]
    fn rounding_up_to_the_allocator_granularity_is_exact_and_refuses_to_wrap() {
        assert_eq!(round_up(0, 16), Some(0));
        assert_eq!(round_up(1, 16), Some(16));
        assert_eq!(round_up(16, 16), Some(16));
        assert_eq!(round_up(17, 16), Some(32));
        assert_eq!(round_up(608, 8), Some(608));
        assert_eq!(round_up(609, 8), Some(616));
        assert_eq!(round_up(5, 1), Some(5));
        assert_eq!(round_up(5, 0), Some(5));
        assert_eq!(round_up(u64::MAX, 16), None);
    }

    #[test]
    fn a_tag_keeps_every_byte_when_it_is_rendered() {
        assert_eq!(render_tag(b"Proc"), "Proc");
        assert_eq!(render_tag(b"Pro\xe3"), "Pro\\xe3");
        assert_eq!(render_tag(&[0, 1, 2, 3]), "\\x00\\x01\\x02\\x03");
    }

    #[test]
    fn the_builtin_constraints_claim_each_tag_exactly_once() {
        let constraints = builtin_constraints();
        let mut tags: Vec<[u8; 4]> = constraints.iter().map(|c| c.tag).collect();
        tags.sort_unstable();
        let before = tags.len();
        tags.dedup();
        assert_eq!(before, tags.len(), "a tag may only mean one thing");
        assert!(constraints
            .iter()
            .any(|c| c.tag == *b"Pro\xe3" && c.object_type.as_deref() == Some("Process")));
        assert!(constraints
            .iter()
            .any(|c| c.tag == *b"MmLd" && c.object_type.is_none()));
        assert_eq!(builtin_constraints_for(&[*b"MmLd"]).len(), 1);
        assert!(builtin_constraints_for(&[*b"ZzZz"]).is_empty());
    }
}
