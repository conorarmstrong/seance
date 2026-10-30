//! Virtual Address Descriptors: what each range of a process's memory *was*.
//!
//! A process's page tables say which pages are resident. They do not say what
//! any of them are *for*. The VAD tree does: one node per reserved or committed
//! range, recording where the range starts and ends, what protection it was
//! created with, whether it is private or shared, and — for a range backed by a
//! file — which file was mapped into it.
//!
//! That is the difference between "there is executable memory at
//! 0x7ff6`12340000" and "there is executable, private, `PAGE_EXECUTE_READWRITE`
//! memory at 0x7ff6`12340000 that is backed by no file at all", which is the
//! signature of injected code and the basis of every `malfind`-style finding.
//! Every such finding is a claim about *which* VAD an address fell in, so the
//! range arithmetic in this module is load-bearing: an off-by-one page puts a
//! finding in the neighbouring allocation, which may be an innocent one.
//!
//! # The tree, and why the walk here is iterative
//!
//! The VADs form a balanced binary tree hanging off `_EPROCESS.VadRoot`. Its
//! shape has changed three times:
//!
//! | Build | `VadRoot` is | The root node |
//! |---|---|---|
//! | XP, 2003 | a pointer to `_MMVAD` | the pointee |
//! | Vista – 8 | an `_MM_AVL_TABLE` | `BalancedRoot`, a sentinel with no tag |
//! | 8.1 – 11 | an `_RTL_AVL_TREE` | `Root`, a real node |
//!
//! Upstream walks it with recursion and a depth limit that *raises* when it is
//! exceeded. Recursion over pointers taken from an image is a stack overflow
//! waiting for a crafted or corrupt tree, and an exception is not a finding. The
//! walk here is iterative over an explicit stack, cycle-safe through a visited
//! set, bounded by [`MAX_VAD_NODES`] and [`MAX_VAD_DEPTH`], and every node it
//! declines to follow is recorded with the reason on [`VadTree::skipped`]. A
//! tree that was not fully walked is not a short tree; it is a wrong one until
//! the report says otherwise.
//!
//! # Start and end are page numbers, and the end is inclusive
//!
//! A VAD stores *virtual page numbers*, not addresses. The address of the first
//! byte is `StartingVpn × 4096`. The address of the **last** byte is
//! `(EndingVpn + 1) × 4096 − 1`: `EndingVpn` names the last page in the range,
//! so the range runs to the end of that page. Three ways to get this wrong, all
//! of which produce a plausible answer:
//!
//! * forgetting the `+ 1` — the range loses its final page, and a finding in
//!   that page is attributed to the next VAD or to nothing;
//! * forgetting the `− 1` — the range gains a byte and overlaps its neighbour,
//!   so an address can be "in" two VADs;
//! * treating the end as exclusive when reporting it — every rendered range is
//!   one page too long.
//!
//! [`Vad::end`] is the **last accessible byte**, and [`Vad::size`] is
//! `end − start + 1`, which is always a whole number of pages.
//!
//! On 64-bit Windows 8.1 and later the page number does not fit in the 32-bit
//! `StartingVpn`, so a second member, `StartingVpnHigh`, carries the top bits.
//! Upstream composes those as `(Vpn << 12) | (VpnHigh << 44)`. This module
//! composes the *page number* first — `Vpn | (VpnHigh << 32)` — and multiplies
//! once, which is the same result everywhere the two agree and is additionally
//! right in the case where `EndingVpn + 1` carries into bit 32, where the
//! upstream form silently ORs the carry into the high field.
//!
//! # The tag lives in front of the node
//!
//! A VAD is a pool allocation, so its four-byte tag sits at
//! `node − (sizeof(_POOL_HEADER) − offsetof(PoolTag))`: four bytes back on x86
//! and twelve on x64. Both numbers come out of the symbol table via
//! [`crate::poolscan::PoolSymbols::tag_distance`] rather than being written
//! down. The tag says which structure the node is: `VadS` and `VadF` are the
//! short form with no file mapping, and every other `Vad…` tag is the long form
//! that can name a mapped file.

use std::collections::HashSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{Obj, ObjError, StructReader};
use seance_memory::Incomplete;
use seance_symbols::SymbolError;

use crate::poolscan::{unicode_string, PoolError, PoolSymbols};
use crate::profile::WindowsProfile;

/// The short VAD, present at the start of every node whatever its tag.
pub const TYPE_MMVAD_SHORT: &str = "_MMVAD_SHORT";

/// The long VAD, which additionally reaches a mapped file.
pub const TYPE_MMVAD: &str = "_MMVAD";

/// The process structure the tree hangs off.
pub const TYPE_EPROCESS: &str = "_EPROCESS";

/// The file object a mapped VAD's control area points at.
pub const TYPE_FILE_OBJECT: &str = "_FILE_OBJECT";

/// Symbol naming the kernel's table of protection constants.
pub const SYMBOL_PROTECT_TO_VALUE: &str = "MmProtectToValue";

/// Page size, in bytes, on every architecture Windows runs a VAD tree on.
///
/// A virtual page number times this is an address. x86, x64 and ARM64 Windows
/// all use 4 KiB pages for user address space; large pages are a property of
/// the mapping, not of the page-number encoding a VAD uses.
pub const PAGE_SIZE: u64 = 4096;

/// How far the high half of a split page number is shifted.
///
/// `StartingVpnHigh` carries the bits above the 32 that `StartingVpn` holds, so
/// it is shifted by 32 **in page-number space**. Shifting by 44 in address
/// space, as upstream does, is the same thing once the page number is
/// multiplied by [`PAGE_SIZE`].
pub const VPN_HIGH_SHIFT: u32 = 32;

/// Ceiling on nodes one tree walk will visit.
///
/// A process with a hundred thousand distinct allocations does not exist;
/// reaching this means the links are wrong, and it is reported as a cap rather
/// than as the end of the tree.
pub const MAX_VAD_NODES: usize = 262_144;

/// Ceiling on tree depth.
///
/// A balanced tree of [`MAX_VAD_NODES`] nodes is about eighteen deep, and even
/// a badly unbalanced one does not approach this. Reaching it means the walk is
/// following a chain rather than descending a tree.
pub const MAX_VAD_DEPTH: u32 = 128;

/// Ceiling on individually recorded skipped nodes. The *count* stays exact.
pub const MAX_RECORDED_SKIPS: usize = 256;

/// How many protection constants `MmProtectToValue` holds.
pub const PROTECT_VALUE_COUNT: u64 = 32;

/// The WinNT page-protection bits, and the names an examiner reads.
///
/// These are Win32 API constants rather than structure offsets: they are fixed
/// by the published API and have never moved. What *is* build-specific is the
/// mapping from a VAD's five-bit `Protection` index to one of these masks, and
/// that is read from the kernel's own `MmProtectToValue` table rather than
/// assumed.
pub const WINNT_PROTECTIONS: [(&str, u32); 12] = [
    ("PAGE_NOACCESS", 0x01),
    ("PAGE_READONLY", 0x02),
    ("PAGE_READWRITE", 0x04),
    ("PAGE_WRITECOPY", 0x08),
    ("PAGE_EXECUTE", 0x10),
    ("PAGE_EXECUTE_READ", 0x20),
    ("PAGE_EXECUTE_READWRITE", 0x40),
    ("PAGE_EXECUTE_WRITECOPY", 0x80),
    ("PAGE_GUARD", 0x100),
    ("PAGE_NOCACHE", 0x200),
    ("PAGE_WRITECOMBINE", 0x400),
    ("PAGE_TARGETS_INVALID", 0x4000_0000),
];

/// The names that *qualify* a protection rather than being one.
///
/// `MmProtectToValue` combines these with an access protection instead of
/// replacing it — the table's upper half is the lower half again with a guard,
/// cache or write-combine attribute added — so a mask can set two bits and
/// still name exactly one access protection.
pub const WINNT_PROTECTION_MODIFIERS: [&str; 4] = [
    "PAGE_GUARD",
    "PAGE_NOCACHE",
    "PAGE_WRITECOMBINE",
    "PAGE_TARGETS_INVALID",
];

/// The access protection inside a string [`protection_names`] rendered.
///
/// `None` when the mask set only qualifier bits and named no access at all,
/// which is a fact about an unreadable table entry rather than a protection —
/// a caller must report it as undetermined, never compare it to an expected
/// value. The empty string is that same fact: [`ProtectionTable::names_for`]
/// filters it out today, but this must not hand back `Some("")` for it, or the
/// one caller that stops filtering gets a mismatch against a protection nobody
/// read.
///
/// This exists because comparing the whole rendered string to one constant is
/// wrong: `PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE` is a mapped image on a
/// non-cached range, and a string comparison calls it a mismatch.
pub fn base_protection(names: &str) -> Option<&str> {
    names
        .split('|')
        .find(|part| !part.is_empty() && !WINNT_PROTECTION_MODIFIERS.contains(part))
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a VAD walk before it can produce a tree worth reading.
///
/// Note what is *not* here: a node the walk declined to follow. That is a fact
/// about one pointer, and it lands in [`VadTree::skipped`] where an examiner can
/// count it.
#[derive(Debug, thiserror::Error)]
pub enum VadError {
    /// This build's VAD tree cannot be walked with what is available, and no
    /// partial answer would be honest. The message names what is missing.
    #[error("the VAD tree cannot be walked on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// A typed read failed for a reason that invalidates the whole walk rather
    /// than one node.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the walk depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// The pool layout, which the tag in front of each node is read through,
    /// could not be established.
    #[error(transparent)]
    Pool(#[from] PoolError),
}

impl VadError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            VadError::Unsupported { .. } => "unsupported_build",
            VadError::Object(err) => err.class(),
            VadError::Symbols(_) => "symbols",
            VadError::Pool(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            VadError::Object(err) => err.incomplete_reason(),
            VadError::Pool(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be walked" refusal.
    pub fn unsupported(detail: impl Into<String>) -> VadError {
        VadError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Resolve the first of `candidates` that this build's `type_name` actually has.
///
/// The member that holds a VAD's left child is called `LeftChild` on XP, `Left`
/// on Windows 7 and `VadNode.Left` on Windows 10. Picking by build number means
/// a build nobody has catalogued reads the wrong member; asking the symbol table
/// which one exists means it reads the right one or fails naming all the
/// candidates it tried.
///
/// This module used to carry its own copy, which returned a bare `Option` built
/// from `member_offset(..).is_ok()`. That collapsed "the symbol table could not
/// answer" into "this build has no such member" — opposite claims, the second
/// being a statement about the suspect's machine. The shared helper keeps them
/// apart, and there is one definition of it so the two cannot drift.
use seance_memory::binding::first_member;

/// Where the tree hangs off `_EPROCESS`, which differs by build.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VadRootShape {
    /// XP and 2003: `VadRoot` is a pointer to the root `_MMVAD`.
    Pointer,
    /// Windows 8.1 and later: `VadRoot` is an `_RTL_AVL_TREE` whose `Root`
    /// member points at the root node.
    AvlTreeRoot,
    /// Vista through Windows 8: `VadRoot` is an `_MM_AVL_TABLE` whose
    /// `BalancedRoot` is an embedded sentinel node carrying no tag. The real
    /// tree hangs off the sentinel's children.
    BalancedRootSentinel,
}

impl VadRootShape {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            VadRootShape::Pointer => "pointer",
            VadRootShape::AvlTreeRoot => "avl_tree_root",
            VadRootShape::BalancedRootSentinel => "balanced_root_sentinel",
        }
    }
}

/// The member paths this build's VAD nodes are read through.
///
/// Resolved once per image and checked once, so a build whose layout is unknown
/// fails here naming the members that were tried rather than at node three
/// thousand having already emitted ranges read at the wrong offsets.
///
/// Everything the walk reads is read through `_MMVAD_SHORT`, which is the
/// structure at the start of *every* VAD node whatever its tag: on Windows 8 and
/// later `_MMVAD` begins with a `Core` member that is exactly an
/// `_MMVAD_SHORT`, and on earlier builds the two share their leading members.
/// Only the mapped-file lookup needs the long form.
#[derive(Debug, Clone)]
pub struct VadSymbols {
    /// Path to the left-child pointer inside `_MMVAD_SHORT`.
    pub left: String,
    /// Path to the right-child pointer.
    pub right: String,
    /// Path to the low half of the starting page number.
    pub start_vpn: String,
    /// Path to the high half, on builds that split it.
    pub start_vpn_high: Option<String>,
    /// Path to the low half of the ending page number.
    pub end_vpn: String,
    /// Path to the high half, on builds that split it.
    pub end_vpn_high: Option<String>,
    /// Path to the parent link, and whether its low bits carry balance
    /// information that must be masked off.
    pub parent: Option<(String, bool)>,
    /// Path to the commit charge.
    pub commit_charge: Option<String>,
    /// Path to the private-memory flag.
    pub private_memory: Option<String>,
    /// Path to the protection index.
    pub protection: Option<String>,
    /// How the tree hangs off `_EPROCESS`.
    pub root_shape: VadRootShape,
    /// Whether this build declares the long `_MMVAD` at all.
    pub has_long_vad: bool,
    /// Distance from a node to the pool tag in front of it.
    pub tag_distance: u64,
    /// Mask that strips an `_EX_FAST_REF`'s reference count from a pointer.
    pub fast_ref_mask: u64,
}

impl VadSymbols {
    /// Resolve every layout fact a VAD walk of this image needs.
    ///
    /// # Errors
    ///
    /// [`VadError::Unsupported`] naming the members that were tried, when this
    /// build declares none of them. An absent *optional* member — the commit
    /// charge, the protection index — is not an error: it becomes `None` and
    /// the corresponding column is absent rather than zero.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, VadError> {
        let pool = PoolSymbols::from_profile(profile)?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        if !profile.symbols.has_type(TYPE_MMVAD_SHORT) {
            return Err(VadError::unsupported(format!(
                "the symbol table has no '{TYPE_MMVAD_SHORT}', so a process's memory ranges \
                 cannot be read"
            )));
        }

        // `Core.`-prefixed candidates are last: they only apply if a caller ever
        // resolves against the long `_MMVAD`, and putting them first would make
        // a build that has both resolve through the wrong one.
        const LEFT: [&str; 6] = [
            "LeftChild",
            "Left",
            "VadNode.LeftChild",
            "VadNode.Left",
            "Core.VadNode.LeftChild",
            "Core.VadNode.Left",
        ];
        const RIGHT: [&str; 6] = [
            "RightChild",
            "Right",
            "VadNode.RightChild",
            "VadNode.Right",
            "Core.VadNode.RightChild",
            "Core.VadNode.Right",
        ];

        let left = first_member(&reader, TYPE_MMVAD_SHORT, &LEFT)?
            .ok_or_else(|| {
                VadError::unsupported(format!(
                    "'{TYPE_MMVAD_SHORT}' has none of {LEFT:?}, so the tree's left branch cannot \
                     be followed"
                ))
            })?
            .to_string();
        let right = first_member(&reader, TYPE_MMVAD_SHORT, &RIGHT)?
            .ok_or_else(|| {
                VadError::unsupported(format!(
                    "'{TYPE_MMVAD_SHORT}' has none of {RIGHT:?}, so the tree's right branch cannot \
                     be followed"
                ))
            })?
            .to_string();

        let start_vpn = first_member(
            &reader,
            TYPE_MMVAD_SHORT,
            &["StartingVpn", "Core.StartingVpn"],
        )?
        .ok_or_else(|| {
            VadError::unsupported(format!(
                "'{TYPE_MMVAD_SHORT}' has no StartingVpn, so where a range begins is unknown"
            ))
        })?
        .to_string();
        let end_vpn = first_member(&reader, TYPE_MMVAD_SHORT, &["EndingVpn", "Core.EndingVpn"])?
            .ok_or_else(|| {
                VadError::unsupported(format!(
                    "'{TYPE_MMVAD_SHORT}' has no EndingVpn, so where a range ends is unknown"
                ))
            })?
            .to_string();
        let start_vpn_high = first_member(
            &reader,
            TYPE_MMVAD_SHORT,
            &["StartingVpnHigh", "Core.StartingVpnHigh"],
        )?
        .map(str::to_string);
        let end_vpn_high = first_member(
            &reader,
            TYPE_MMVAD_SHORT,
            &["EndingVpnHigh", "Core.EndingVpnHigh"],
        )?
        .map(str::to_string);
        // A build that splits one page number splits both. Half a split would
        // put one end of every range 16 TiB away from the other.
        if start_vpn_high.is_some() != end_vpn_high.is_some() {
            return Err(VadError::unsupported(format!(
                "'{TYPE_MMVAD_SHORT}' declares one of StartingVpnHigh and EndingVpnHigh but not \
                 the other, so a range's two ends would be composed differently"
            )));
        }

        // XP stores the parent pointer plainly; every later build packs two bits
        // of tree balance into the bottom of it, and dereferencing an unmasked
        // one lands three bytes into the parent node.
        let parent = match first_member(&reader, TYPE_MMVAD_SHORT, &["Parent"])? {
            Some(path) => Some((path.to_string(), false)),
            None => first_member(
                &reader,
                TYPE_MMVAD_SHORT,
                &[
                    "u1.Parent",
                    "VadNode.u1.Parent",
                    "VadNode.ParentValue",
                    "Core.VadNode.u1.Parent",
                    "Core.VadNode.ParentValue",
                ],
            )?
            .map(|path| (path.to_string(), true)),
        };

        let commit_charge = first_member(
            &reader,
            TYPE_MMVAD_SHORT,
            &[
                "CommitCharge",
                "u1.VadFlags1.CommitCharge",
                "u.VadFlags.CommitCharge",
                "Core.CommitCharge",
                "Core.u1.VadFlags1.CommitCharge",
            ],
        )?
        .map(str::to_string);
        let private_memory = first_member(
            &reader,
            TYPE_MMVAD_SHORT,
            &[
                "u1.VadFlags1.PrivateMemory",
                "u.VadFlags.PrivateMemory",
                "Core.u1.VadFlags1.PrivateMemory",
                "Core.u.VadFlags.PrivateMemory",
            ],
        )?
        .map(str::to_string);
        let protection = first_member(
            &reader,
            TYPE_MMVAD_SHORT,
            &[
                "u.VadFlags.Protection",
                "Core.u.VadFlags.Protection",
                "u.VadFlags.ProtectionMask",
            ],
        )?
        .map(str::to_string);

        let root_shape = if reader.member_offset(TYPE_EPROCESS, "VadRoot.Root").is_ok() {
            VadRootShape::AvlTreeRoot
        } else if reader
            .member_offset(TYPE_EPROCESS, "VadRoot.BalancedRoot")
            .is_ok()
        {
            VadRootShape::BalancedRootSentinel
        } else if reader.member_offset(TYPE_EPROCESS, "VadRoot").is_ok() {
            VadRootShape::Pointer
        } else {
            return Err(VadError::unsupported(format!(
                "'{TYPE_EPROCESS}' has no VadRoot, so a process's memory ranges cannot be reached"
            )));
        };

        let pointer_size = u64::from(reader.pointer_size()?);
        Ok(Self {
            left,
            right,
            start_vpn,
            start_vpn_high,
            end_vpn,
            end_vpn_high,
            parent,
            commit_charge,
            private_memory,
            protection,
            root_shape,
            has_long_vad: profile.symbols.has_type(TYPE_MMVAD),
            tag_distance: pool.tag_distance(),
            // An `_EX_FAST_REF` packs a reference count into the bits below the
            // pointer's alignment: three on x86, four on x64. The mask is
            // therefore `2 × pointer_size − 1`, which is 7 and 15.
            fast_ref_mask: pointer_size.saturating_mul(2).saturating_sub(1),
        })
    }
}

// ── Protection ──────────────────────────────────────────────────────────────

/// The kernel's own table mapping a VAD's protection index to a WinNT mask.
///
/// The mapping is not fixed by the API and has changed between builds, so it is
/// read out of the image's `MmProtectToValue` rather than written down. A wrong
/// mapping renames every region: a read-only mapping rendered as
/// `PAGE_EXECUTE_READWRITE` is the difference between an ordinary process and a
/// reported code injection.
#[derive(Debug, Clone, Default)]
pub struct ProtectionTable {
    values: Vec<u32>,
}

impl ProtectionTable {
    /// Read the table from the running kernel's data.
    ///
    /// # Errors
    ///
    /// [`VadError::Unsupported`] when `MmProtectToValue` is not in the symbol
    /// table. A caller that gets this back must render the protection as
    /// *unknown*, never as `PAGE_NOACCESS`, which is a claim about the memory.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, VadError> {
        let rva = profile
            .symbols
            .symbol_address(SYMBOL_PROTECT_TO_VALUE)
            .map_err(|_| {
                VadError::unsupported(format!(
                    "the symbol table has no '{SYMBOL_PROTECT_TO_VALUE}', so a VAD's protection \
                     index cannot be turned into the protection it names"
                ))
            })?;
        let base = profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
            VadError::unsupported(
                "the protection table's address does not fit in the 64-bit address space",
            )
        })?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        // Four bytes per entry, little-endian: `MmProtectToValue` is an array of
        // `ULONG`, and every architecture Windows runs on is little-endian.
        let bytes = reader.read_bytes(base, PROTECT_VALUE_COUNT.saturating_mul(4))?;
        let values = bytes
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes([word[0], word[1], word[2], word[3]]))
            .collect();
        Ok(Self { values })
    }

    /// A table built from known values, for a caller that already has them.
    pub fn from_values(values: Vec<u32>) -> Self {
        Self { values }
    }

    /// Whether the table carries any entry.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The WinNT mask a protection index names.
    ///
    /// `None` for an index the table does not have, which is a fact rather than
    /// a zero: upstream substitutes 0 there, and 0 renders as no protection
    /// flags at all, which reads as `PAGE_NOACCESS`-adjacent nothing.
    pub fn mask_for(&self, index: u64) -> Option<u32> {
        usize::try_from(index)
            .ok()
            .and_then(|index| self.values.get(index))
            .copied()
    }

    /// The protection an index names, as an examiner reads it.
    ///
    /// `None` covers both ways the answer can be unavailable: an index past the
    /// end of this kernel's table, and an entry whose mask sets no bit any
    /// WinNT protection constant defines. The second is not "no protections" —
    /// a real `MmProtectToValue` never stores a bare zero, index 0 being
    /// `PAGE_NOACCESS` (`0x01`) — so rendering it would put an empty protection
    /// column in a report that reads exactly like a successful parse.
    pub fn names_for(&self, index: u64) -> Option<String> {
        let names = protection_names(self.mask_for(index)?);
        if names.is_empty() {
            None
        } else {
            Some(names)
        }
    }
}

/// The WinNT protection names a mask sets, joined with `|`.
///
/// An empty string for a mask with no known bits: the mask really did name
/// nothing this table knows, which is different from the flags being absent.
pub fn protection_names(mask: u32) -> String {
    WINNT_PROTECTIONS
        .iter()
        .filter(|(_, bit)| mask & bit != 0)
        .map(|(name, _)| *name)
        .collect::<Vec<_>>()
        .join("|")
}

// ── Results ─────────────────────────────────────────────────────────────────

/// Which form of VAD a node is, as its pool tag says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VadKind {
    /// `VadS` or `VadF`: the short form, which never maps a file.
    Short,
    /// Any other `Vad…` tag: the long form, which can name a mapped file.
    Long,
}

impl VadKind {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            VadKind::Short => "short",
            VadKind::Long => "long",
        }
    }
}

/// The file a VAD maps, or the reason there is not one to report.
///
/// Four outcomes and not two, because "this range maps no file" and "this range
/// maps a file whose name we could not read" support opposite conclusions: the
/// first is the signature of injected code, and reporting the second as the
/// first manufactures a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MappedFile {
    /// A short VAD, which cannot map a file by construction.
    NotApplicable,
    /// A long VAD that maps no file: private memory.
    None,
    /// The mapped file's name.
    Name(String),
    /// A file is mapped and its name could not be read.
    Unavailable(String),
}

impl MappedFile {
    /// The name, when there is one.
    pub fn name(&self) -> Option<&str> {
        match self {
            MappedFile::Name(name) => Some(name),
            _ => None,
        }
    }

    /// Whether this range is definitely backed by no file, which is what makes
    /// executable private memory suspicious.
    pub fn is_definitely_unbacked(&self) -> bool {
        matches!(self, MappedFile::NotApplicable | MappedFile::None)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            MappedFile::NotApplicable => serde_json::json!({"kind": "not_applicable"}),
            MappedFile::None => serde_json::json!({"kind": "no_mapped_file"}),
            MappedFile::Name(name) => serde_json::json!({"kind": "name", "name": name}),
            MappedFile::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
        }
    }
}

/// One virtual address descriptor.
#[derive(Debug, Clone)]
pub struct Vad {
    /// Where the node is, in the kernel address space.
    pub address: u64,
    /// How deep in the tree it was found.
    pub depth: u32,
    /// The four-byte pool tag in front of the node.
    pub tag: String,
    /// Which form of VAD it is.
    pub kind: VadKind,
    /// Address of the **first** byte of the range.
    pub start: u64,
    /// Address of the **last** byte of the range. Inclusive: the range runs to
    /// the end of the page `EndingVpn` names.
    pub end: u64,
    /// The parent node, with the tree-balance bits masked off.
    pub parent: Option<u64>,
    /// Committed pages, when this build records them.
    pub commit_charge: Option<u64>,
    /// Whether the range is private rather than shared.
    pub private_memory: Option<bool>,
    /// The raw protection index, before the kernel's table is applied.
    pub protection: Option<u64>,
    /// The protection as an examiner reads it, when the kernel's table was
    /// available. `None` means the index could not be interpreted — never
    /// "no protection".
    pub protection_names: Option<String>,
    /// The file mapped into the range.
    pub file: MappedFile,
    /// Everything odd about the node that did not disqualify it.
    pub notes: Vec<String>,
}

impl Vad {
    /// Size of the range in bytes: `end − start + 1`, always a whole number of
    /// pages.
    pub fn size(&self) -> u64 {
        self.end.saturating_sub(self.start).saturating_add(1)
    }

    /// Whether an address falls inside the range, with the end inclusive.
    ///
    /// This is the question every "which allocation is this finding in"
    /// answer reduces to, which is why the end being inclusive matters.
    pub fn contains(&self, address: u64) -> bool {
        self.start <= address && address <= self.end
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            // Exact beside the number: a `_MMVAD` is a kernel address above
            // 2^53 and JSON numbers are IEEE doubles, so the numeric form can
            // reach a client rounded by up to a kilobyte — and an address that
            // is off by a kilobyte names a different allocation.
            "address_hex": format!("{:#x}", self.address),
            "depth": self.depth,
            "tag": self.tag,
            "kind": self.kind.as_str(),
            "start": self.start,
            "start_hex": format!("{:#x}", self.start),
            "end": self.end,
            "end_hex": format!("{:#x}", self.end),
            "size": self.size(),
            "parent": self.parent,
            "parent_hex": self.parent.map(|parent| format!("{parent:#x}")),
            "commit_charge": self.commit_charge,
            "private_memory": self.private_memory,
            "protection": self.protection,
            "protection_names": self.protection_names,
            "file": self.file.to_json(),
            "notes": self.notes,
        })
    }
}

/// A node the walk declined to follow, and why.
#[derive(Debug, Clone)]
pub struct SkippedNode {
    /// The node's address.
    pub address: u64,
    /// How deep it was.
    pub depth: u32,
    /// Why it was not reported, in the examiner's terms.
    pub reason: String,
    /// Whether the walk still descended into its children.
    pub descended: bool,
}

/// Why a walk ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VadStop {
    /// Every reachable node was visited.
    Exhausted,
    /// The node cap fired. The walk stopped; the tree did not end.
    CapReached {
        /// The cap that fired.
        cap: usize,
    },
}

impl VadStop {
    /// Whether the tree was fully walked.
    pub fn is_complete(&self) -> bool {
        matches!(self, VadStop::Exhausted)
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            VadStop::Exhausted => "exhausted",
            VadStop::CapReached { .. } => "cap_reached",
        }
    }
}

/// One process's VAD tree, and everything the walk could not do.
#[derive(Debug, Clone)]
pub struct VadTree {
    /// The `_EPROCESS` the tree belongs to.
    pub process: u64,
    /// Where the root node is, or 0 when the process has no tree at all.
    pub root: u64,
    /// How the root was reached.
    pub root_shape: VadRootShape,
    /// The descriptors, in pre-order: each node before its left subtree and its
    /// left subtree before its right.
    pub vads: Vec<Vad>,
    /// Nodes the walk declined to follow, capped by
    /// [`VadWalkConfig::max_recorded_skips`].
    pub skipped: Vec<SkippedNode>,
    /// How many nodes were skipped in total. Exact even when the list above was
    /// capped.
    pub skipped_total: usize,
    /// How many nodes were visited.
    pub visited: usize,
    /// The deepest node reached.
    pub max_depth: u32,
    /// Why the walk ended.
    pub stop: VadStop,
}

impl VadTree {
    /// Whether the whole tree was walked and nothing was skipped.
    ///
    /// The question a report must ask before writing "this process had no such
    /// region": a walk that stopped early says nothing about what it did not
    /// reach.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete() && self.skipped_total == 0
    }

    /// The VAD an address falls in, if any.
    ///
    /// The ranges of a well-formed tree do not overlap, so there is at most one;
    /// the first match is returned rather than asserting uniqueness, because a
    /// corrupt tree is a finding and not a panic.
    pub fn containing(&self, address: u64) -> Option<&Vad> {
        self.vads.iter().find(|vad| vad.contains(address))
    }

    /// Everything a report must declare about this tree.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let VadStop::CapReached { cap } = self.stop {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the VAD walk of {:#x} stopped at its cap of {cap} node(s); the tree \
                     continues",
                    self.process
                ),
            ));
        }
        if self.skipped_total > 0 {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "{} node(s) of {:#x}'s VAD tree could not be followed, so ranges below them \
                     are not listed",
                    self.skipped_total, self.process
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "root": self.root,
            "root_shape": self.root_shape.as_str(),
            "vads": self.vads.iter().map(Vad::to_json).collect::<Vec<_>>(),
            "vad_count": self.vads.len(),
            "visited": self.visited,
            "max_depth": self.max_depth,
            "skipped_total": self.skipped_total,
            "skipped": self
                .skipped
                .iter()
                .map(|s| serde_json::json!({
                    "address": s.address,
                    "depth": s.depth,
                    "reason": s.reason,
                    "descended": s.descended,
                }))
                .collect::<Vec<_>>(),
            "stop": self.stop.as_str(),
            "complete": self.is_complete(),
        })
    }
}

/// Caps for one tree walk.
#[derive(Debug, Clone)]
pub struct VadWalkConfig {
    /// Ceiling on nodes visited.
    pub max_nodes: usize,
    /// Ceiling on tree depth.
    pub max_depth: u32,
    /// Ceiling on individually recorded skipped nodes.
    pub max_recorded_skips: usize,
    /// The kernel's protection table, when it could be read. `None` renders
    /// every protection as unknown rather than as no protection.
    pub protections: Option<Arc<ProtectionTable>>,
}

impl Default for VadWalkConfig {
    fn default() -> Self {
        Self {
            max_nodes: MAX_VAD_NODES,
            max_depth: MAX_VAD_DEPTH,
            max_recorded_skips: MAX_RECORDED_SKIPS,
            protections: None,
        }
    }
}

impl VadWalkConfig {
    /// The config a stage should walk `profile` with: the shipped caps, and the
    /// kernel's own protection table when it can be read.
    ///
    /// **[`Default`] cannot do this** — it is handed no profile, so its
    /// `protections` is `None` — and that is exactly how every caller that
    /// built the default shipped a tree in which no allocation's protection
    /// could be named. Worse, the note each one carried blamed the image:
    /// "this kernel's `MmProtectToValue` was not available", of a table that
    /// was published by the symbols and that nobody had asked for. The
    /// protection-dependent checks downstream — an image mapped at other than
    /// `PAGE_EXECUTE_WRITECOPY`, and private memory that is writable and
    /// executable at once — then reported themselves *not checked* for every
    /// process on the machine.
    ///
    /// A table that genuinely cannot be read still leaves `None` here, and the
    /// note is then true.
    pub fn for_profile(profile: &WindowsProfile) -> Self {
        Self {
            protections: ProtectionTable::from_profile(profile).ok().map(Arc::new),
            ..Self::default()
        }
    }
}

// ── The walk ────────────────────────────────────────────────────────────────

/// Walk one process's VAD tree.
///
/// `process` is the address of an `_EPROCESS` in the **kernel** address space.
/// The ranges the walk reports are addresses in that process's *user* address
/// space; reading their contents is a separate step through the process's own
/// directory table base, and is deliberately not done here.
///
/// # Errors
///
/// Only for failures that make the whole walk meaningless: a build whose VAD
/// layout the symbols cannot describe, or an `_EPROCESS` whose `VadRoot` cannot
/// be read at all. A node the walk declined to follow is not an error — it is
/// counted in [`VadTree::skipped`].
pub fn list_vads(
    profile: &WindowsProfile,
    symbols: &VadSymbols,
    process: u64,
    config: &VadWalkConfig,
) -> Result<VadTree, VadError> {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let eprocess = reader.object(process, TYPE_EPROCESS)?;
    let root = root_node(&eprocess, symbols)?;

    let mut tree = VadTree {
        process,
        root,
        root_shape: symbols.root_shape.clone(),
        vads: Vec::new(),
        skipped: Vec::new(),
        skipped_total: 0,
        visited: 0,
        max_depth: 0,
        stop: VadStop::Exhausted,
    };
    if root == 0 {
        // A process genuinely without a tree: one that has exited, or the
        // System process on some builds. Distinguishable from a walk that
        // failed because `stop` is `Exhausted` and nothing was skipped.
        return Ok(tree);
    }

    // The explicit stack is the point: a recursive walk over pointers taken
    // from an image overflows the host's stack on a crafted or corrupt tree,
    // and a crash is not a finding.
    let mut stack: Vec<(u64, u32)> = vec![(root, 0)];
    let mut visited: HashSet<u64> = HashSet::new();

    while let Some((address, depth)) = stack.pop() {
        if tree.visited >= config.max_nodes {
            tree.stop = VadStop::CapReached {
                cap: config.max_nodes,
            };
            break;
        }
        if depth > config.max_depth {
            record_skip(
                &mut tree,
                config,
                address,
                depth,
                format!(
                    "the tree is more than {} level(s) deep here, which is a chain rather than a \
                     tree",
                    config.max_depth
                ),
                false,
            );
            continue;
        }
        // Cycle safety: a node seen twice means the tree does not terminate,
        // and continuing would either loop forever or report the same range
        // repeatedly.
        if !visited.insert(address) {
            record_skip(
                &mut tree,
                config,
                address,
                depth,
                "this node was already visited, so the tree contains a cycle".to_string(),
                false,
            );
            continue;
        }
        tree.visited += 1;
        tree.max_depth = tree.max_depth.max(depth);

        let node = reader.object(address, TYPE_MMVAD_SHORT)?;
        let (kind, tag, descend) = classify(&reader, symbols, address, depth);
        match kind {
            Some(kind) => {
                let tag = tag.clone().unwrap_or_default();
                match describe(&reader, symbols, config, &node, address, depth, kind, tag) {
                    Ok(vad) => tree.vads.push(vad),
                    Err(reason) => {
                        record_skip(&mut tree, config, address, depth, reason, true);
                    }
                }
            }
            None => {
                if !descend {
                    record_skip(
                        &mut tree,
                        config,
                        address,
                        depth,
                        match &tag {
                            Some(tag) => format!(
                                "the pool tag in front of this node is {tag:?}, which is not a VAD \
                                 tag, so the pointer that reached it is not a tree link"
                            ),
                            None => {
                                "the pool tag in front of this node could not be read".to_string()
                            }
                        },
                        false,
                    );
                    continue;
                }
                record_skip(
                    &mut tree,
                    config,
                    address,
                    depth,
                    match &tag {
                        Some(tag) => format!(
                            "the root carries the tag {tag:?} rather than a VAD tag, so it is a \
                             sentinel and only its children are ranges"
                        ),
                        None => "the pool tag in front of this node could not be read, so the \
                                 node itself is not reported, but its children are still followed"
                            .to_string(),
                    },
                    true,
                );
            }
        }

        // Pre-order, left before right: push right first so left comes off the
        // stack next. The order is the tree's own, which is ascending by
        // address for a well-formed VAD tree.
        let Some(next_depth) = depth.checked_add(1) else {
            continue;
        };
        for path in [&symbols.right, &symbols.left] {
            match node.pointer(path) {
                Ok(0) => {}
                Ok(child) => stack.push((child, next_depth)),
                Err(err) => record_skip(
                    &mut tree,
                    config,
                    address,
                    depth,
                    format!("'{path}' could not be read, so that branch is not followed: {err}"),
                    false,
                ),
            }
        }
    }

    Ok(tree)
}

/// Record a node the walk declined to follow, keeping the list bounded without
/// losing the count.
fn record_skip(
    tree: &mut VadTree,
    config: &VadWalkConfig,
    address: u64,
    depth: u32,
    reason: String,
    descended: bool,
) {
    tree.skipped_total += 1;
    if tree.skipped.len() < config.max_recorded_skips {
        tree.skipped.push(SkippedNode {
            address,
            depth,
            reason,
            descended,
        });
    }
}

/// Where the tree's first node is, for this build's `VadRoot` shape.
fn root_node(eprocess: &Obj, symbols: &VadSymbols) -> Result<u64, VadError> {
    match symbols.root_shape {
        VadRootShape::AvlTreeRoot => Ok(eprocess.pointer("VadRoot.Root")?),
        // The sentinel is *embedded* in the `_EPROCESS`, so its address is the
        // member's address rather than a value read out of it. Following it as
        // a pointer would read the sentinel's own first member as a node
        // address and walk somewhere else entirely.
        VadRootShape::BalancedRootSentinel => Ok(eprocess.member_address("VadRoot.BalancedRoot")?),
        VadRootShape::Pointer => Ok(eprocess.pointer("VadRoot")?),
    }
}

/// What the pool tag in front of a node says it is.
///
/// Returns the kind (`None` when the node is not a VAD), the tag when it was
/// readable, and whether the walk should still descend into the node's
/// children.
///
/// The descend decision is the interesting one:
///
/// * A tag that **read cleanly and is not a VAD tag** means the pointer that
///   reached this node was not a tree link. Its "children" are whatever bytes
///   happen to lie at those offsets, so the subtree is pruned.
/// * A tag that **could not be read** is a gap in the evidence, not proof that
///   the node is not a VAD. Pruning there would silently lose every range below
///   an unacquired page, so the walk descends anyway and says it did. The
///   visited set and the depth and node caps keep that bounded.
/// * At the **root**, a node with no recognisable tag is the `BalancedRoot`
///   sentinel that Vista through Windows 8 put there. It is not a range, but
///   the whole tree hangs off it.
fn classify(
    reader: &StructReader,
    symbols: &VadSymbols,
    address: u64,
    depth: u32,
) -> (Option<VadKind>, Option<String>, bool) {
    let Some(tag_address) = address.checked_sub(symbols.tag_distance) else {
        return (None, None, depth == 0);
    };
    let Ok(bytes) = reader.read_bytes(tag_address, 4) else {
        // Unreadable: descend anyway rather than lose the subtree.
        return (None, None, true);
    };
    let tag: String = bytes
        .iter()
        .map(|&byte| {
            if (0x20..0x7F).contains(&byte) {
                byte as char
            } else {
                '.'
            }
        })
        .collect();
    let kind = if tag == "VadS" || tag == "VadF" {
        Some(VadKind::Short)
    } else if tag.starts_with("Vad") && symbols.has_long_vad {
        Some(VadKind::Long)
    } else if tag.starts_with("Vad") {
        // The build's symbols have no `_MMVAD`, so the long form cannot be
        // read; the range itself still comes from the short form in front of it.
        Some(VadKind::Short)
    } else {
        None
    };
    // A root with no VAD tag is the sentinel; a deeper one is not a tree link.
    let descend = kind.is_some() || depth == 0;
    (kind, Some(tag), descend)
}

/// Read one node's range and attributes.
#[allow(clippy::too_many_arguments)]
fn describe(
    reader: &StructReader,
    symbols: &VadSymbols,
    config: &VadWalkConfig,
    node: &Obj,
    address: u64,
    depth: u32,
    kind: VadKind,
    tag: String,
) -> Result<Vad, String> {
    let mut notes = Vec::new();

    let start_page = page_number(node, &symbols.start_vpn, symbols.start_vpn_high.as_deref())
        .map_err(|err| format!("the starting page number could not be read: {err}"))?;
    let end_page = page_number(node, &symbols.end_vpn, symbols.end_vpn_high.as_deref())
        .map_err(|err| format!("the ending page number could not be read: {err}"))?;
    if end_page < start_page {
        return Err(format!(
            "the range ends at page {end_page:#x} and begins at page {start_page:#x}, so it runs \
             backwards and is not an allocation"
        ));
    }

    // The first byte of the first page...
    let start = start_page.checked_mul(PAGE_SIZE).ok_or_else(|| {
        format!("page {start_page:#x} lies past the end of the 64-bit address space")
    })?;
    // ...and the last byte of the last page. `EndingVpn` names the last page in
    // the range, so the range runs to the end of it: `(end + 1) × 4096 − 1`.
    // The `+1` and the `−1` are both load-bearing; dropping either misplaces a
    // whole page of every range in the process.
    let end = end_page
        .checked_add(1)
        .and_then(|page| page.checked_mul(PAGE_SIZE))
        .and_then(|byte| byte.checked_sub(1))
        .ok_or_else(|| {
            format!("page {end_page:#x} lies past the end of the 64-bit address space")
        })?;

    let parent = match &symbols.parent {
        Some((path, masked)) => match node.int(path) {
            Ok(value) => value.as_u64().map(|value| {
                if *masked {
                    // The bottom two bits hold the node's balance factor. A
                    // parent address dereferenced without masking them lands
                    // three bytes into the parent structure, and every member
                    // read from it is shifted.
                    value & !0b11
                } else {
                    value
                }
            }),
            Err(err) => {
                notes.push(format!("'{path}' could not be read: {err}"));
                None
            }
        },
        None => None,
    };

    let commit_charge = optional_unsigned(node, symbols.commit_charge.as_deref(), &mut notes);
    let private_memory =
        optional_unsigned(node, symbols.private_memory.as_deref(), &mut notes).map(|v| v != 0);
    let protection = optional_unsigned(node, symbols.protection.as_deref(), &mut notes);
    let protection_names = match (protection, config.protections.as_deref()) {
        (Some(index), Some(table)) if !table.is_empty() => {
            let names = table.names_for(index);
            if names.is_none() {
                notes.push(if index >= PROTECT_VALUE_COUNT {
                    format!(
                        "the protection index {index} is past the end of this kernel's \
                         {SYMBOL_PROTECT_TO_VALUE}, so it names no protection"
                    )
                } else {
                    format!(
                        "this kernel's {SYMBOL_PROTECT_TO_VALUE}[{index}] sets no known \
                         protection bit, so it names no protection an examiner can rely on"
                    )
                });
            }
            names
        }
        (Some(_), _) => {
            notes.push(format!(
                "the protection index was not interpreted: this image's \
                 {SYMBOL_PROTECT_TO_VALUE} was not available"
            ));
            None
        }
        (None, _) => None,
    };

    let file = match kind {
        VadKind::Short => MappedFile::NotApplicable,
        VadKind::Long => mapped_file(reader, symbols, address),
    };

    Ok(Vad {
        address,
        depth,
        tag,
        kind,
        start,
        end,
        parent,
        commit_charge,
        private_memory,
        protection,
        protection_names,
        file,
        notes,
    })
}

/// A page number composed from its low half and, where the build splits it, its
/// high half.
///
/// The two halves are combined **as page numbers** and multiplied by the page
/// size once. Upstream shifts each half into address space separately and ORs
/// them, which is the same answer except when `EndingVpn + 1` carries out of
/// the low half — where the carry lands on top of the high field instead of
/// adding to it.
fn page_number(node: &Obj, low: &str, high: Option<&str>) -> Result<u64, ObjError> {
    let low_value = node.int(low)?.as_u64().ok_or_else(|| {
        SymbolError::malformed(format!("'{low}' is negative, which is not a page number"))
    })?;
    let Some(high) = high else {
        return Ok(low_value);
    };
    let high_value = node.int(high)?.as_u64().ok_or_else(|| {
        SymbolError::malformed(format!("'{high}' is negative, which is not a page number"))
    })?;
    // The low half is declared 32 bits wide on every build that splits it. One
    // wider than that would overlap the high half, and the two would silently
    // merge into a page number belonging to neither.
    if low_value > u64::from(u32::MAX) {
        return Err(SymbolError::malformed(format!(
            "'{low}' holds {low_value:#x}, which does not fit in the low half of a split page \
             number, so it cannot be combined with '{high}'"
        ))
        .into());
    }
    let shifted = high_value.checked_shl(VPN_HIGH_SHIFT).ok_or_else(|| {
        SymbolError::malformed(format!(
            "'{high}' cannot be shifted into a 64-bit page number"
        ))
    })?;
    if shifted >> VPN_HIGH_SHIFT != high_value {
        return Err(SymbolError::malformed(format!(
            "'{high}' holds {high_value:#x}, which does not fit in the high half of a page number"
        ))
        .into());
    }
    Ok(low_value | shifted)
}

/// Read an optional unsigned member, recording rather than swallowing a failure.
fn optional_unsigned(node: &Obj, path: Option<&str>, notes: &mut Vec<String>) -> Option<u64> {
    let path = path?;
    match node.int(path) {
        Ok(value) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                notes.push(format!("'{path}' is negative, which is not a count"));
                None
            }
        },
        Err(err) => {
            notes.push(format!("'{path}' could not be read: {err}"));
            None
        }
    }
}

/// The file mapped into a long VAD's range.
///
/// Two routes, both handled: XP and 2003 hang a `_CONTROL_AREA` straight off the
/// VAD, while Vista and later reach it through a `_SUBSECTION`. On the later
/// route the control area's `FilePointer` is an `_EX_FAST_REF`, whose bottom
/// bits hold a reference count that must be masked off before it is a pointer.
fn mapped_file(reader: &StructReader, symbols: &VadSymbols, address: u64) -> MappedFile {
    if !symbols.has_long_vad {
        return MappedFile::Unavailable(format!(
            "this build's symbols have no '{TYPE_MMVAD}', so a mapped file cannot be named"
        ));
    }
    let vad = match reader.object(address, TYPE_MMVAD) {
        Ok(vad) => vad,
        Err(err) => return MappedFile::Unavailable(err.to_string()),
    };

    // XP and 2003 first: a build that has both members is the earlier shape.
    let control_area = if vad.has_member("ControlArea") {
        match vad.pointer("ControlArea") {
            Ok(0) => return MappedFile::None,
            Ok(value) => value,
            Err(err) => return MappedFile::Unavailable(err.to_string()),
        }
    } else if vad.has_member("Subsection") {
        let subsection = match vad.follow("Subsection") {
            Ok(Some(subsection)) => subsection,
            Ok(None) => return MappedFile::None,
            Err(err) => return MappedFile::Unavailable(err.to_string()),
        };
        match subsection.pointer("ControlArea") {
            Ok(0) => return MappedFile::None,
            Ok(value) => value,
            Err(err) => return MappedFile::Unavailable(err.to_string()),
        }
    } else {
        return MappedFile::Unavailable(format!(
            "'{TYPE_MMVAD}' has neither ControlArea nor Subsection on this build"
        ));
    };

    let control = match reader.object(control_area, "_CONTROL_AREA") {
        Ok(control) => control,
        Err(err) => return MappedFile::Unavailable(err.to_string()),
    };
    // `FilePointer` is a plain pointer on XP and an `_EX_FAST_REF` from Vista.
    // The reference count in the low bits is not part of the address, and a
    // `_FILE_OBJECT` read at the unmasked value is offset by up to fifteen
    // bytes — every member of it shifted, every name garbage.
    let file_pointer = if control.member_offset("FilePointer.Object").is_ok() {
        match control.int("FilePointer.Object") {
            Ok(value) => match value.as_u64() {
                Some(value) => value & !symbols.fast_ref_mask,
                None => return MappedFile::Unavailable("FilePointer.Object is negative".into()),
            },
            Err(err) => return MappedFile::Unavailable(err.to_string()),
        }
    } else {
        match control.pointer("FilePointer") {
            Ok(value) => value,
            Err(err) => return MappedFile::Unavailable(err.to_string()),
        }
    };
    if file_pointer == 0 {
        return MappedFile::None;
    }

    let file = match reader.object(file_pointer, TYPE_FILE_OBJECT) {
        Ok(file) => file,
        Err(err) => return MappedFile::Unavailable(err.to_string()),
    };
    match unicode_string(&file, "FileName") {
        Ok(Some(name)) => MappedFile::Name(name),
        // A control area with a file object whose name is empty is a mapping
        // without a path, which is a fact rather than a failure.
        Ok(None) => MappedFile::None,
        Err(err) => MappedFile::Unavailable(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image};
    use seance_memory::Architecture;

    // Where the synthetic 64-bit fixture puts things. Every VAD is preceded by
    // a pool header, as a real allocation is.
    const EPROCESS_AT: u64 = 0x1000;
    const VAD_ROOT: u64 = 0x2000;
    const VAD_LEFT: u64 = 0x3000;
    const VAD_RIGHT: u64 = 0x4000;
    const VAD_DEEP: u64 = 0x5000;
    const SUBSECTION_AT: u64 = 0x6000;
    const CONTROL_AREA_AT: u64 = 0x6100;
    const FILE_OBJECT_AT: u64 = 0x6200;
    const FILE_NAME_AT: u64 = 0x6300;
    const PROTECT_TABLE_AT: u64 = 0x7000;

    /// Offsets the synthetic 64-bit VAD ISF declares.
    mod off {
        pub(super) const POOL_HEADER_SIZE: u64 = 16;
        pub(super) const POOL_TAG: u64 = 4;
        /// `POOL_HEADER_SIZE - POOL_TAG`: how far in front of a node its tag is.
        pub(super) const TAG_DISTANCE: u64 = POOL_HEADER_SIZE - POOL_TAG;

        pub(super) const EPROCESS_VAD_ROOT: u64 = 0;

        pub(super) const VAD_LEFT: u64 = 0;
        pub(super) const VAD_RIGHT: u64 = 8;
        pub(super) const VAD_PARENT: u64 = 16;
        pub(super) const VAD_START_VPN: u64 = 24;
        pub(super) const VAD_END_VPN: u64 = 28;
        pub(super) const VAD_START_HIGH: u64 = 32;
        pub(super) const VAD_END_HIGH: u64 = 33;
        pub(super) const VAD_FLAGS: u64 = 36;
        pub(super) const VAD_FLAGS1: u64 = 40;
        pub(super) const VAD_SUBSECTION: u64 = 48;

        pub(super) const CONTROL_AREA_FILE_POINTER: u64 = 0;
        pub(super) const SUBSECTION_CONTROL_AREA: u64 = 0;
        pub(super) const FILE_OBJECT_NAME: u64 = 0;
        pub(super) const UNICODE_LENGTH: u64 = 0;
        pub(super) const UNICODE_MAX_LENGTH: u64 = 2;
        pub(super) const UNICODE_BUFFER: u64 = 8;
    }

    /// A synthetic 64-bit Windows 10 ISF: split page numbers, an `_RTL_AVL_TREE`
    /// root, `VadNode.Left`/`Right`, an `_EX_FAST_REF` file pointer.
    fn win10_vad_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "CC1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
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
    "_UNICODE_STRING": {"size": 16, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_FILE_OBJECT": {"size": 32, "kind": "struct", "fields": {
      "FileName": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_EX_FAST_REF": {"size": 8, "kind": "union", "fields": {
      "Object": {"offset": 0, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_CONTROL_AREA": {"size": 32, "kind": "struct", "fields": {
      "FilePointer": {"offset": 0, "type": {"kind": "union", "name": "_EX_FAST_REF"}}
    }},
    "_SUBSECTION": {"size": 32, "kind": "struct", "fields": {
      "ControlArea": {"offset": 0, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_CONTROL_AREA"}}}
    }},
    "_RTL_BALANCED_NODE": {"size": 24, "kind": "struct", "fields": {
      "Left": {"offset": 0, "type": {"kind": "pointer",
               "subtype": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}},
      "Right": {"offset": 8, "type": {"kind": "pointer",
                "subtype": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}},
      "ParentValue": {"offset": 16, "type": {"kind": "base", "name": "unsigned long long"}}
    }},
    "_RTL_AVL_TREE": {"size": 8, "kind": "struct", "fields": {"Root": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}}},
    "_MMVAD_FLAGS": {"size": 4, "kind": "struct", "fields": {
      "Protection": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 7,
                     "bit_length": 5, "type": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_MMVAD_FLAGS1": {"size": 4, "kind": "struct", "fields": {
      "CommitCharge": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 0,
                       "bit_length": 31, "type": {"kind": "base", "name": "unsigned long"}}},
      "PrivateMemory": {"offset": 0, "type": {"kind": "bitfield", "bit_position": 31,
                        "bit_length": 1, "type": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_MMVAD_SHORT_U": {"size": 4, "kind": "union", "fields": {
      "VadFlags": {"offset": 0, "type": {"kind": "struct", "name": "_MMVAD_FLAGS"}}
    }},
    "_MMVAD_SHORT_U1": {"size": 4, "kind": "union", "fields": {
      "VadFlags1": {"offset": 0, "type": {"kind": "struct", "name": "_MMVAD_FLAGS1"}}
    }},
    "_MMVAD_SHORT": {"size": 48, "kind": "struct", "fields": {
      "VadNode": {"offset": 0, "type": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}},
      "StartingVpn": {"offset": 24, "type": {"kind": "base", "name": "unsigned long"}},
      "EndingVpn": {"offset": 28, "type": {"kind": "base", "name": "unsigned long"}},
      "StartingVpnHigh": {"offset": 32, "type": {"kind": "base", "name": "unsigned char"}},
      "EndingVpnHigh": {"offset": 33, "type": {"kind": "base", "name": "unsigned char"}},
      "u": {"offset": 36, "type": {"kind": "union", "name": "_MMVAD_SHORT_U"}},
      "u1": {"offset": 40, "type": {"kind": "union", "name": "_MMVAD_SHORT_U1"}}
    }},
    "_MMVAD": {"size": 128, "kind": "struct", "fields": {
      "Core": {"offset": 0, "type": {"kind": "struct", "name": "_MMVAD_SHORT"}},
      "Subsection": {"offset": 48, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "_SUBSECTION"}}}
    }},
    "_EPROCESS": {"size": 64, "kind": "struct", "fields": {
      "VadRoot": {"offset": 0, "type": {"kind": "struct", "name": "_RTL_AVL_TREE"}}
    }}
  },
  "enums": {},
  "symbols": {
    "MmProtectToValue": {"address": 28672}
  }
}"#,
        ]
        .concat()
    }

    /// A synthetic 32-bit Windows XP ISF: unsplit page numbers, a pointer
    /// `VadRoot`, `LeftChild`/`RightChild`, a plain `FilePointer`.
    ///
    /// It declares an `_OBJECT_HEADER` even though no VAD walk reads one, and
    /// the XP object header specifically: a `Type` **pointer** with
    /// `NameInfoOffset` beside it, no `TypeIndex` and no `InfoMask`. A real XP
    /// symbol table has one, and [`VadSymbols::from_profile`] builds
    /// [`PoolSymbols`] before it does anything else — so a fixture that omits it
    /// silently skips the whole object-header branch of that construction and
    /// cannot detect a Vista-only member being required there. That is exactly
    /// how a walk this module performs completely on XP came to be refused over
    /// `_OBJECT_HEADER.InfoMask`, with every unit test here still green.
    fn xp_vad_isf() -> String {
        [
            r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "DD1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
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
    "_UNICODE_STRING": {"size": 8, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 4, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_FILE_OBJECT": {"size": 16, "kind": "struct", "fields": {
      "FileName": {"offset": 0, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_CONTROL_AREA": {"size": 16, "kind": "struct", "fields": {
      "FilePointer": {"offset": 0, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_FILE_OBJECT"}}}
    }},
    "_MMVAD_SHORT": {"size": 32, "kind": "struct", "fields": {
      "StartingVpn": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "EndingVpn": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}},
      "Parent": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "struct", "name": "_MMVAD_SHORT"}}},
      "LeftChild": {"offset": 12, "type": {"kind": "pointer",
                    "subtype": {"kind": "struct", "name": "_MMVAD_SHORT"}}},
      "RightChild": {"offset": 16, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "_MMVAD_SHORT"}}}
    }},
    "_MMVAD": {"size": 48, "kind": "struct", "fields": {
      "StartingVpn": {"offset": 0, "type": {"kind": "base", "name": "unsigned long"}},
      "EndingVpn": {"offset": 4, "type": {"kind": "base", "name": "unsigned long"}},
      "Parent": {"offset": 8, "type": {"kind": "pointer",
                 "subtype": {"kind": "struct", "name": "_MMVAD"}}},
      "LeftChild": {"offset": 12, "type": {"kind": "pointer",
                    "subtype": {"kind": "struct", "name": "_MMVAD"}}},
      "RightChild": {"offset": 16, "type": {"kind": "pointer",
                     "subtype": {"kind": "struct", "name": "_MMVAD"}}},
      "ControlArea": {"offset": 24, "type": {"kind": "pointer",
                      "subtype": {"kind": "struct", "name": "_CONTROL_AREA"}}}
    }},
    "_EPROCESS": {"size": 32, "kind": "struct", "fields": {
      "VadRoot": {"offset": 0, "type": {"kind": "pointer",
                  "subtype": {"kind": "struct", "name": "_MMVAD"}}}
    }}
  },
  "enums": {},
  "symbols": {}
}"#,
        ]
        .concat()
    }

    /// The tag four (x86) or twelve (x64) bytes in front of a node.
    fn put_tag(image: &mut Image, node: u64, tag: &[u8; 4], distance: u64) {
        image.write(node - distance, tag);
    }

    /// A Windows 10 node with its page numbers, flags and children.
    #[allow(clippy::too_many_arguments)]
    fn put_win10_vad(
        image: &mut Image,
        at: u64,
        tag: &[u8; 4],
        start_vpn: u32,
        end_vpn: u32,
        left: u64,
        right: u64,
        parent: u64,
    ) {
        put_tag(image, at, tag, off::TAG_DISTANCE);
        image.put_u64(at + off::VAD_LEFT, left);
        image.put_u64(at + off::VAD_RIGHT, right);
        image.put_u64(at + off::VAD_PARENT, parent);
        image.put_u32(at + off::VAD_START_VPN, start_vpn);
        image.put_u32(at + off::VAD_END_VPN, end_vpn);
    }

    /// A protection table whose index 6 is `PAGE_EXECUTE_READWRITE`, as a real
    /// one's is.
    fn put_protect_table(image: &mut Image) {
        let values: [u32; 8] = [
            0x01, // PAGE_NOACCESS
            0x02, // PAGE_READONLY
            0x04, // PAGE_READWRITE
            0x08, // PAGE_WRITECOPY
            0x10, // PAGE_EXECUTE
            0x20, // PAGE_EXECUTE_READ
            0x40, // PAGE_EXECUTE_READWRITE
            0x80, // PAGE_EXECUTE_WRITECOPY
        ];
        for (index, value) in values.iter().enumerate() {
            image.put_u32(PROTECT_TABLE_AT + (index as u64) * 4, *value);
        }
    }

    fn win10_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&win10_vad_isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    fn xp_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&xp_vad_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        )
    }

    /// A three-node Windows 10 tree: a root with a left and a right child.
    fn win10_tree_image() -> Image {
        let mut image = Image::new();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, VAD_ROOT);
        put_win10_vad(
            &mut image, VAD_ROOT, b"VadS", 0x10, 0x12, VAD_LEFT, VAD_RIGHT, 0,
        );
        put_win10_vad(
            &mut image,
            VAD_LEFT,
            b"VadS",
            0x2,
            0x2,
            0,
            0,
            VAD_ROOT | 0b10,
        );
        put_win10_vad(&mut image, VAD_RIGHT, b"VadS", 0x100, 0x1FF, 0, 0, VAD_ROOT);
        put_protect_table(&mut image);
        image
    }

    fn walk(profile: &WindowsProfile) -> VadTree {
        let symbols = VadSymbols::from_profile(profile).expect("a describable build");
        let protections = ProtectionTable::from_profile(profile).ok().map(Arc::new);
        let config = VadWalkConfig {
            protections,
            ..VadWalkConfig::default()
        };
        list_vads(profile, &symbols, EPROCESS_AT, &config).expect("a runnable walk")
    }

    // ── The range arithmetic ────────────────────────────────────────────────

    #[test]
    fn a_range_begins_at_its_first_page_and_ends_at_the_last_byte_of_its_last_page() {
        // Pages 0x10 through 0x12 inclusive: three pages, 0x10000 to 0x12fff.
        // Dropping the +1 would end it at 0x11fff and lose a page; dropping the
        // -1 would end it at 0x13000 and overlap the next allocation.
        let tree = walk(&win10_profile(win10_tree_image()));
        let root = tree
            .vads
            .iter()
            .find(|vad| vad.address == VAD_ROOT)
            .expect("the root is a range");
        assert_eq!(root.start, 0x10 * PAGE_SIZE);
        assert_eq!(root.end, 0x13 * PAGE_SIZE - 1);
        assert_eq!(root.end, 0x12FFF);
        assert_eq!(root.size(), 3 * PAGE_SIZE);
    }

    #[test]
    fn a_single_page_range_is_one_page_long_and_not_zero_or_two() {
        let tree = walk(&win10_profile(win10_tree_image()));
        let single = tree
            .vads
            .iter()
            .find(|vad| vad.address == VAD_LEFT)
            .expect("the left child is a range");
        assert_eq!(single.start, 0x2000);
        assert_eq!(single.end, 0x2FFF);
        assert_eq!(single.size(), PAGE_SIZE);
    }

    #[test]
    fn the_end_of_a_range_is_inclusive_so_its_last_byte_is_inside_it() {
        // Every "which allocation is this finding in" answer rests on this.
        let tree = walk(&win10_profile(win10_tree_image()));
        let vad = tree
            .vads
            .iter()
            .find(|vad| vad.address == VAD_RIGHT)
            .expect("the right child is a range");
        assert_eq!((vad.start, vad.end), (0x10_0000, 0x20_0000 - 1));
        assert!(vad.contains(vad.start));
        assert!(vad.contains(vad.end), "the last byte is inside the range");
        assert!(!vad.contains(vad.end + 1), "and the next byte is not");
        assert!(!vad.contains(vad.start - 1));

        assert_eq!(
            tree.containing(0x1F_FFFF).map(|v| v.address),
            Some(VAD_RIGHT)
        );
        assert_eq!(tree.containing(0x20_0000).map(|v| v.address), None);
    }

    #[test]
    fn adjacent_ranges_touch_without_overlapping() {
        // Pages 0..0 and 1..1 must be 0x0-0xfff and 0x1000-0x1fff: an off-by-one
        // at either end makes an address belong to two allocations or to none.
        let mut image = Image::new();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, VAD_ROOT);
        put_win10_vad(&mut image, VAD_ROOT, b"VadS", 0, 0, VAD_LEFT, 0, 0);
        put_win10_vad(&mut image, VAD_LEFT, b"VadS", 1, 1, 0, 0, VAD_ROOT);
        let tree = walk(&win10_profile(image));
        let first = tree.containing(0xFFF).expect("the first page");
        let second = tree.containing(0x1000).expect("the second page");
        assert_eq!(first.address, VAD_ROOT);
        assert_eq!(second.address, VAD_LEFT);
        assert_eq!(first.end + 1, second.start);
    }

    #[test]
    fn a_split_page_number_puts_the_high_half_above_the_low_one() {
        // Windows 8.1 and later split the page number because a 64-bit user
        // address does not fit in 32 bits of VPN. Ignoring the high half puts
        // every range in the bottom 16 TiB of the address space, where nothing
        // a modern process maps actually is.
        let mut image = win10_tree_image();
        image.put_u8(VAD_ROOT + off::VAD_START_HIGH, 0x7F);
        image.put_u8(VAD_ROOT + off::VAD_END_HIGH, 0x7F);
        let tree = walk(&win10_profile(image));
        let root = tree
            .vads
            .iter()
            .find(|vad| vad.address == VAD_ROOT)
            .expect("the root is a range");
        assert_eq!(root.start, ((0x7Fu64 << 32) | 0x10) * PAGE_SIZE);
        // 0x7F in the high half is bits 44 and up, matching upstream's
        // `(StartingVpn << 12) | (StartingVpnHigh << 44)`.
        assert_eq!(root.start, 0x0007_F000_0001_0000);
        assert_eq!(root.end, (((0x7Fu64 << 32) | 0x13) * PAGE_SIZE) - 1);
        assert_eq!(root.size(), 3 * PAGE_SIZE);
    }

    #[test]
    fn the_ending_page_carrying_out_of_its_low_half_still_adds_rather_than_ors() {
        // EndingVpn = 0xFFFFFFFF, EndingVpnHigh = 1. Composing in address space
        // as upstream does gives ((0xFFFFFFFF+1) << 12) | (1 << 44), which ORs
        // the carry onto the high field and yields 0x1_0000_0000_000 — the same
        // as high = 1 alone, a range ending 16 TiB below where it should.
        let mut image = Image::new();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, VAD_ROOT);
        put_win10_vad(
            &mut image,
            VAD_ROOT,
            b"VadS",
            0xFFFF_FFF0,
            0xFFFF_FFFF,
            0,
            0,
            0,
        );
        image.put_u8(VAD_ROOT + off::VAD_START_HIGH, 1);
        image.put_u8(VAD_ROOT + off::VAD_END_HIGH, 1);
        let tree = walk(&win10_profile(image));
        let root = &tree.vads[0];
        assert_eq!(root.start, ((1u64 << 32) | 0xFFFF_FFF0) * PAGE_SIZE);
        assert_eq!(root.end, (0x2_0000_0000u64) * PAGE_SIZE - 1);
        assert_eq!(root.size(), 16 * PAGE_SIZE);
        assert!(root.end > root.start, "the range must not run backwards");
    }

    #[test]
    fn a_range_whose_end_is_below_its_start_is_not_an_allocation() {
        let mut image = Image::new();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, VAD_ROOT);
        put_win10_vad(&mut image, VAD_ROOT, b"VadS", 0x200, 0x100, 0, 0, 0);
        let tree = walk(&win10_profile(image));
        assert!(tree.vads.is_empty());
        assert_eq!(tree.skipped_total, 1);
        assert!(
            tree.skipped[0].reason.contains("backwards"),
            "{:?}",
            tree.skipped
        );
        assert!(!tree.is_complete());
    }

    #[test]
    fn an_unsplit_build_reads_the_page_number_from_one_member_only() {
        // The XP fixture has no StartingVpnHigh, so a walker that required one
        // would refuse the build, and one that read the byte that happens to
        // follow StartingVpn would place every range 16 TiB too high.
        let mut image = Image::new();
        image.put_u32(EPROCESS_AT, VAD_ROOT as u32);
        put_tag(&mut image, VAD_ROOT, b"VadS", 4);
        image.put_u32(VAD_ROOT, 0x20); // StartingVpn
        image.put_u32(VAD_ROOT + 4, 0x22); // EndingVpn
        let profile = xp_profile(image);
        let symbols = VadSymbols::from_profile(&profile).unwrap();
        assert_eq!(symbols.start_vpn_high, None);
        assert_eq!(symbols.end_vpn_high, None);
        assert_eq!(symbols.tag_distance, 4);
        assert_eq!(symbols.root_shape, VadRootShape::Pointer);

        let tree = list_vads(&profile, &symbols, EPROCESS_AT, &VadWalkConfig::default()).unwrap();
        assert_eq!(tree.vads.len(), 1);
        assert_eq!(tree.vads[0].start, 0x20 * PAGE_SIZE);
        assert_eq!(tree.vads[0].end, 0x23 * PAGE_SIZE - 1);
    }

    // ── The walk ────────────────────────────────────────────────────────────

    #[test]
    fn every_node_of_the_tree_is_reported_once_in_pre_order() {
        let tree = walk(&win10_profile(win10_tree_image()));
        let addresses: Vec<u64> = tree.vads.iter().map(|vad| vad.address).collect();
        assert_eq!(
            addresses,
            vec![VAD_ROOT, VAD_LEFT, VAD_RIGHT],
            "the node, then its left subtree, then its right"
        );
        assert_eq!(tree.visited, 3);
        assert_eq!(tree.max_depth, 1);
        assert_eq!(tree.stop, VadStop::Exhausted);
        assert!(tree.is_complete());
        assert!(tree.incomplete().is_empty());
    }

    #[test]
    fn a_tree_that_points_back_at_itself_stops_at_the_cycle_rather_than_looping() {
        // A tree captured mid-edit, or one a rootkit spliced, closes onto a node
        // it already visited. A recursive walk would loop until the host's stack
        // ran out; this one names the repeat.
        let mut image = win10_tree_image();
        image.put_u64(VAD_LEFT + off::VAD_LEFT, VAD_ROOT);
        let tree = walk(&win10_profile(image));
        assert_eq!(tree.vads.len(), 3, "each node is still reported once");
        assert_eq!(tree.skipped_total, 1);
        assert!(tree.skipped[0].reason.contains("cycle"));
        assert_eq!(tree.skipped[0].address, VAD_ROOT);
        assert!(!tree.is_complete());
    }

    #[test]
    fn a_chain_deeper_than_the_cap_is_stopped_and_says_so_rather_than_overflowing() {
        // Every node points at the next, so the "tree" is a linked list. This is
        // the shape a corrupt right-child pointer produces, and the shape that
        // overflows a recursive walker's stack.
        let mut image = Image::new();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, VAD_ROOT);
        let mut at = VAD_ROOT;
        for index in 0..40u64 {
            let next = VAD_ROOT + (index + 1) * 0x100;
            put_win10_vad(&mut image, at, b"VadS", 0x10, 0x10, 0, next, 0);
            at = next;
        }
        put_win10_vad(&mut image, at, b"VadS", 0x10, 0x10, 0, 0, 0);

        let symbols = VadSymbols::from_profile(&win10_profile(Image::new())).unwrap();
        let profile = win10_profile(image);
        let config = VadWalkConfig {
            max_depth: 8,
            ..VadWalkConfig::default()
        };
        let tree = list_vads(&profile, &symbols, EPROCESS_AT, &config).unwrap();
        assert_eq!(tree.vads.len(), 9, "depths 0 through 8 inclusive");
        assert_eq!(tree.max_depth, 8);
        assert_eq!(tree.skipped_total, 1);
        assert!(tree.skipped[0].reason.contains("chain rather than a tree"));
        assert!(!tree.is_complete());
    }

    #[test]
    fn the_node_cap_stops_the_walk_and_is_never_mistaken_for_the_end_of_the_tree() {
        let profile = win10_profile(win10_tree_image());
        let symbols = VadSymbols::from_profile(&profile).unwrap();
        let config = VadWalkConfig {
            max_nodes: 2,
            ..VadWalkConfig::default()
        };
        let tree = list_vads(&profile, &symbols, EPROCESS_AT, &config).unwrap();
        assert_eq!(
            tree.vads.len(),
            2,
            "the tree has three; the cap allowed two"
        );
        assert_eq!(tree.stop, VadStop::CapReached { cap: 2 });
        assert!(!tree.is_complete());
        let declared = tree.incomplete();
        assert_eq!(declared[0].reason, IncompleteReason::CapReached);
        assert!(declared[0].detail.contains("the tree continues"));
    }

    #[test]
    fn a_node_whose_tag_is_not_a_vad_tag_is_not_a_range_and_its_children_are_not_followed() {
        // The pointer that reached it was not a tree link, so whatever lies at
        // its child offsets is data, not nodes.
        let mut image = win10_tree_image();
        put_tag(&mut image, VAD_LEFT, b"Junk", off::TAG_DISTANCE);
        image.put_u64(VAD_LEFT + off::VAD_LEFT, VAD_DEEP);
        put_win10_vad(&mut image, VAD_DEEP, b"VadS", 0x900, 0x901, 0, 0, 0);
        let tree = walk(&win10_profile(image));

        let addresses: Vec<u64> = tree.vads.iter().map(|vad| vad.address).collect();
        assert_eq!(addresses, vec![VAD_ROOT, VAD_RIGHT]);
        assert!(
            !addresses.contains(&VAD_DEEP),
            "a subtree below a non-VAD node is not walked"
        );
        assert_eq!(tree.skipped_total, 1);
        assert!(tree.skipped[0].reason.contains("Junk"));
        assert!(!tree.skipped[0].descended);
    }

    #[test]
    fn a_root_with_no_vad_tag_is_a_sentinel_whose_children_are_still_the_tree() {
        // Vista through Windows 8 embed a tagless `BalancedRoot` in the
        // `_EPROCESS`. Refusing it would report every process as having no
        // memory at all.
        let mut image = win10_tree_image();
        put_tag(&mut image, VAD_ROOT, b"\0\0\0\0", off::TAG_DISTANCE);
        let tree = walk(&win10_profile(image));
        let addresses: Vec<u64> = tree.vads.iter().map(|vad| vad.address).collect();
        assert_eq!(addresses, vec![VAD_LEFT, VAD_RIGHT]);
        assert_eq!(tree.skipped_total, 1);
        assert!(
            tree.skipped[0].descended,
            "the sentinel's children are ranges"
        );
        assert_eq!(tree.skipped[0].depth, 0);
    }

    #[test]
    fn a_process_with_no_tree_is_distinguishable_from_a_walk_that_failed() {
        // A null root is a process that has no ranges — one that has exited.
        // An empty list with nothing skipped and an exhausted stop says that;
        // an empty list from a failed walk does not.
        let mut image = Image::new();
        image.put_u64(EPROCESS_AT + off::EPROCESS_VAD_ROOT, 0);
        let tree = walk(&win10_profile(image));
        assert_eq!(tree.root, 0);
        assert!(tree.vads.is_empty());
        assert_eq!(tree.skipped_total, 0);
        assert_eq!(tree.stop, VadStop::Exhausted);
        assert!(tree.is_complete());
    }

    #[test]
    fn a_branch_that_cannot_be_read_is_recorded_rather_than_treated_as_absent() {
        // The child pointer lies past the end of the image. Treating the failed
        // read as a null child would report a leaf where the tree continues.
        let mut image = win10_tree_image();
        image.put_u64(VAD_LEFT + off::VAD_LEFT, u64::MAX - 3);
        let tree = walk(&win10_profile(image));
        assert!(tree.skipped_total >= 1);
        assert!(!tree.is_complete());
    }

    // ── Attributes ──────────────────────────────────────────────────────────

    #[test]
    fn the_parent_link_has_its_tree_balance_bits_masked_off() {
        // The bottom two bits of `ParentValue` are the node's balance factor.
        // Dereferencing the unmasked value lands two bytes into the parent, and
        // every member read from it is shifted.
        let tree = walk(&win10_profile(win10_tree_image()));
        let left = tree
            .vads
            .iter()
            .find(|vad| vad.address == VAD_LEFT)
            .expect("the left child");
        assert_eq!(
            left.parent,
            Some(VAD_ROOT),
            "the stored value was {:#x}",
            VAD_ROOT | 0b10
        );
    }

    #[test]
    fn an_xp_parent_pointer_is_used_as_it_stands() {
        // XP stores the parent plainly. Masking it there would be harmless only
        // because the addresses happen to be aligned; the point is that the
        // decision comes from which member the build has.
        let profile = xp_profile(Image::new());
        let symbols = VadSymbols::from_profile(&profile).unwrap();
        assert_eq!(symbols.parent, Some(("Parent".to_string(), false)));

        let profile = win10_profile(Image::new());
        let symbols = VadSymbols::from_profile(&profile).unwrap();
        assert_eq!(
            symbols.parent,
            Some(("VadNode.ParentValue".to_string(), true))
        );
    }

    #[test]
    fn the_protection_index_is_resolved_through_the_kernels_own_table() {
        // The index-to-mask mapping is not fixed by the API. A hardcoded table
        // renames every region, and calling a read-only mapping
        // PAGE_EXECUTE_READWRITE manufactures a code-injection finding.
        let mut image = win10_tree_image();
        // Protection is a five-bit field at bit 7 of the flags word.
        image.put_u32(VAD_ROOT + off::VAD_FLAGS, 6 << 7);
        let tree = walk(&win10_profile(image));
        let root = &tree.vads[0];
        assert_eq!(root.protection, Some(6));
        assert_eq!(
            root.protection_names.as_deref(),
            Some("PAGE_EXECUTE_READWRITE")
        );
    }

    #[test]
    fn a_protection_index_past_the_end_of_the_table_is_unknown_and_not_no_access() {
        // Upstream substitutes 0 for an out-of-range index, and 0 renders as no
        // protection flags at all — which reads as a region with no access
        // rights rather than as a region whose rights are unknown.
        let mut image = win10_tree_image();
        image.put_u32(VAD_ROOT + off::VAD_FLAGS, 31 << 7);
        let tree = walk(&win10_profile(image));
        let root = &tree.vads[0];
        assert_eq!(root.protection, Some(31));
        assert_eq!(root.protection_names, None);
        assert!(root
            .notes
            .iter()
            .any(|note| note.contains("names no protection")));
    }

    #[test]
    fn the_access_protection_is_read_out_from_beside_its_qualifier_bits() {
        // `MmProtectToValue`'s upper half is its lower half with a guard, cache
        // or write-combine attribute added, so one entry can set two bits and
        // still name exactly one access protection. A consumer comparing the
        // rendered string to a constant would call the qualified form a
        // mismatch.
        assert_eq!(
            base_protection("PAGE_EXECUTE_WRITECOPY"),
            Some("PAGE_EXECUTE_WRITECOPY")
        );
        assert_eq!(
            base_protection("PAGE_EXECUTE_WRITECOPY|PAGE_NOCACHE"),
            Some("PAGE_EXECUTE_WRITECOPY")
        );
        assert_eq!(
            base_protection("PAGE_READONLY|PAGE_GUARD|PAGE_WRITECOMBINE"),
            Some("PAGE_READONLY")
        );
        // Qualifiers alone name no access. That is an unreadable table entry,
        // not a protection, and must not be compared to anything.
        assert_eq!(base_protection("PAGE_GUARD|PAGE_NOCACHE"), None);
        // A mask that named nothing at all renders empty. `Some("")` would be a
        // protection an examiner could be shown a mismatch against.
        assert_eq!(base_protection(""), None);
        assert_eq!(base_protection("|PAGE_READONLY"), Some("PAGE_READONLY"));
    }

    #[test]
    fn without_the_kernels_table_the_protection_is_unknown_rather_than_absent() {
        let profile = win10_profile(win10_tree_image());
        let symbols = VadSymbols::from_profile(&profile).unwrap();
        let tree = list_vads(&profile, &symbols, EPROCESS_AT, &VadWalkConfig::default()).unwrap();
        let root = &tree.vads[0];
        assert!(root.protection.is_some());
        assert_eq!(root.protection_names, None);
        assert!(root
            .notes
            .iter()
            .any(|note| note.contains("was not available")));
    }

    #[test]
    fn the_protection_names_of_a_mask_are_every_bit_it_sets() {
        assert_eq!(protection_names(0x40), "PAGE_EXECUTE_READWRITE");
        assert_eq!(
            protection_names(0x40 | 0x100),
            "PAGE_EXECUTE_READWRITE|PAGE_GUARD"
        );
        assert_eq!(protection_names(0), "");
        assert_eq!(protection_names(0x4000_0000), "PAGE_TARGETS_INVALID");
        let table = ProtectionTable::from_values(vec![0x01, 0x02]);
        assert_eq!(table.mask_for(1), Some(0x02));
        assert_eq!(table.mask_for(2), None);
        assert_eq!(table.names_for(2), None);
        assert!(!table.is_empty());
        assert!(ProtectionTable::default().is_empty());
    }

    #[test]
    fn the_commit_charge_and_private_flag_come_from_the_bitfields_the_build_declares() {
        let mut image = win10_tree_image();
        // CommitCharge is bits 0..30 and PrivateMemory is bit 31.
        image.put_u32(VAD_ROOT + off::VAD_FLAGS1, 0x8000_0000 | 42);
        image.put_u32(VAD_LEFT + off::VAD_FLAGS1, 7);
        let tree = walk(&win10_profile(image));
        let root = &tree.vads[0];
        assert_eq!(root.commit_charge, Some(42));
        assert_eq!(root.private_memory, Some(true));
        let left = &tree.vads[1];
        assert_eq!(left.commit_charge, Some(7));
        assert_eq!(left.private_memory, Some(false));
    }

    // ── Mapped files ────────────────────────────────────────────────────────

    #[test]
    fn a_short_vad_can_never_map_a_file_and_says_so_rather_than_saying_none() {
        let tree = walk(&win10_profile(win10_tree_image()));
        assert_eq!(tree.vads[0].file, MappedFile::NotApplicable);
        assert!(tree.vads[0].file.is_definitely_unbacked());
        assert_eq!(tree.vads[0].file.name(), None);
    }

    #[test]
    fn a_long_vad_reaches_its_mapped_file_through_the_subsection_and_the_fast_reference() {
        // The `_EX_FAST_REF` packs a reference count into the low four bits of
        // the file pointer. Reading it unmasked lands up to fifteen bytes into
        // the `_FILE_OBJECT`, and the name read from there is garbage that
        // still renders.
        let mut image = win10_tree_image();
        put_tag(&mut image, VAD_ROOT, b"Vad ", off::TAG_DISTANCE);
        image.put_u64(VAD_ROOT + off::VAD_SUBSECTION, SUBSECTION_AT);
        image.put_u64(
            SUBSECTION_AT + off::SUBSECTION_CONTROL_AREA,
            CONTROL_AREA_AT,
        );
        image.put_u64(
            CONTROL_AREA_AT + off::CONTROL_AREA_FILE_POINTER,
            FILE_OBJECT_AT | 0xF,
        );
        let name = "\\Windows\\System32\\ntdll.dll";
        let bytes = (name.encode_utf16().count() * 2) as u16;
        image.put_u16(
            FILE_OBJECT_AT + off::FILE_OBJECT_NAME + off::UNICODE_LENGTH,
            bytes,
        );
        image.put_u16(
            FILE_OBJECT_AT + off::FILE_OBJECT_NAME + off::UNICODE_MAX_LENGTH,
            bytes,
        );
        image.put_u64(
            FILE_OBJECT_AT + off::FILE_OBJECT_NAME + off::UNICODE_BUFFER,
            FILE_NAME_AT,
        );
        image.put_utf16(FILE_NAME_AT, name);

        let tree = walk(&win10_profile(image));
        let root = &tree.vads[0];
        assert_eq!(root.kind, VadKind::Long);
        assert_eq!(root.file, MappedFile::Name(name.to_string()));
        assert!(!root.file.is_definitely_unbacked());
        assert_eq!(root.file.to_json()["kind"], "name");
    }

    #[test]
    fn every_address_a_vad_row_carries_is_also_exact() {
        // JSON numbers are IEEE doubles. A kernel `_MMVAD` address and a 64-bit
        // range bound both sit above 2^53, so the numeric form reaches a client
        // rounded — by up to a kilobyte, which is several pages. An examiner
        // reading a rounded start address is reading a different allocation, so
        // every address is written exactly beside its number.
        let tree = walk(&win10_profile(win10_tree_image()));
        let vad = tree
            .vads
            .iter()
            .find(|vad| vad.parent.is_some())
            .expect("a child node, so the parent address is exercised too");
        let value = vad.to_json();

        assert_eq!(value["address_hex"], format!("{:#x}", vad.address));
        assert_eq!(value["start_hex"], format!("{:#x}", vad.start));
        assert_eq!(value["end_hex"], format!("{:#x}", vad.end));
        match vad.parent {
            Some(parent) => assert_eq!(value["parent_hex"], format!("{parent:#x}")),
            None => assert!(value["parent_hex"].is_null()),
        }
    }

    #[test]
    fn a_long_vad_with_no_subsection_maps_no_file_and_that_is_a_finding() {
        // Executable private memory backed by no file is the signature of
        // injected code, so "no file" has to be a positive answer rather than a
        // failure to read one.
        let mut image = win10_tree_image();
        put_tag(&mut image, VAD_ROOT, b"Vad ", off::TAG_DISTANCE);
        image.put_u64(VAD_ROOT + off::VAD_SUBSECTION, 0);
        let tree = walk(&win10_profile(image));
        assert_eq!(tree.vads[0].file, MappedFile::None);
        assert!(tree.vads[0].file.is_definitely_unbacked());
    }

    #[test]
    fn a_mapped_file_whose_name_cannot_be_read_is_not_reported_as_no_file() {
        // The two support opposite conclusions, and rendering them the same way
        // manufactures an injection finding out of an unacquired page.
        let mut image = win10_tree_image();
        put_tag(&mut image, VAD_ROOT, b"Vad ", off::TAG_DISTANCE);
        image.put_u64(VAD_ROOT + off::VAD_SUBSECTION, SUBSECTION_AT);
        image.put_u64(
            SUBSECTION_AT + off::SUBSECTION_CONTROL_AREA,
            CONTROL_AREA_AT,
        );
        image.put_u64(
            CONTROL_AREA_AT + off::CONTROL_AREA_FILE_POINTER,
            FILE_OBJECT_AT,
        );
        // A name that declares text and points nowhere.
        image.put_u16(
            FILE_OBJECT_AT + off::FILE_OBJECT_NAME + off::UNICODE_LENGTH,
            32,
        );
        image.put_u16(
            FILE_OBJECT_AT + off::FILE_OBJECT_NAME + off::UNICODE_MAX_LENGTH,
            32,
        );
        image.put_u64(
            FILE_OBJECT_AT + off::FILE_OBJECT_NAME + off::UNICODE_BUFFER,
            0,
        );
        let tree = walk(&win10_profile(image));
        assert!(matches!(tree.vads[0].file, MappedFile::Unavailable(_)));
        assert!(!tree.vads[0].file.is_definitely_unbacked());
        assert_eq!(tree.vads[0].file.to_json()["kind"], "unavailable");
    }

    #[test]
    fn an_xp_control_area_hangs_straight_off_the_vad_with_a_plain_file_pointer() {
        let mut image = Image::new();
        image.put_u32(EPROCESS_AT, VAD_ROOT as u32);
        put_tag(&mut image, VAD_ROOT, b"Vad ", 4);
        image.put_u32(VAD_ROOT, 0x30);
        image.put_u32(VAD_ROOT + 4, 0x30);
        image.put_u32(VAD_ROOT + 24, CONTROL_AREA_AT as u32); // ControlArea
        image.put_u32(CONTROL_AREA_AT, FILE_OBJECT_AT as u32); // FilePointer
        let name = "\\WINDOWS\\system32\\kernel32.dll";
        let bytes = (name.encode_utf16().count() * 2) as u16;
        image.put_u16(FILE_OBJECT_AT, bytes);
        image.put_u16(FILE_OBJECT_AT + 2, bytes);
        image.put_u32(FILE_OBJECT_AT + 4, FILE_NAME_AT as u32);
        image.put_utf16(FILE_NAME_AT, name);

        let profile = xp_profile(image);
        let symbols = VadSymbols::from_profile(&profile).unwrap();
        assert_eq!(symbols.fast_ref_mask, 7, "three bits on a 32-bit kernel");
        let tree = list_vads(&profile, &symbols, EPROCESS_AT, &VadWalkConfig::default()).unwrap();
        assert_eq!(tree.vads.len(), 1);
        assert_eq!(tree.vads[0].kind, VadKind::Long);
        assert_eq!(tree.vads[0].file, MappedFile::Name(name.to_string()));
    }

    // ── Failing closed ──────────────────────────────────────────────────────

    #[test]
    fn an_xp_walk_survives_an_object_header_that_has_no_vista_members() {
        // This module reads `PoolSymbols` for one number — `tag_distance()`, a
        // `_POOL_HEADER` fact. Nothing in a VAD walk touches an object header at
        // all. But `VadSymbols::from_profile` builds `PoolSymbols` first, so a
        // Vista-only member proved during that construction refused every VAD
        // walk on Windows XP.
        //
        // The fixture is the test. `has_type("_OBJECT_HEADER")` gates the branch
        // that did the proving, so a fixture declaring no object header — which
        // is what this one used to be, and which no real XP table is — never
        // reaches it and stays green through the defect.
        let symbols = table(&xp_vad_isf());
        assert!(
            symbols.has_type("_OBJECT_HEADER"),
            "a fixture with no object header cannot reach the branch that broke"
        );
        assert!(
            !symbols.has_member("_OBJECT_HEADER", "InfoMask"),
            "InfoMask arrived with Vista; an XP table declaring one is not an XP table"
        );
        assert!(
            !symbols.has_member("_OBJECT_HEADER", "TypeIndex"),
            "TypeIndex arrived with Vista"
        );

        let pool = PoolSymbols::from_profile(&xp_profile(Image::new()))
            .expect("XP is describable without Vista's object-header members");
        assert!(!pool.top_down, "XP places executive objects bottom-up");

        let vad = VadSymbols::from_profile(&xp_profile(Image::new()))
            .expect("a VAD walk that reads no object header must not be refused over one");
        assert_eq!(vad.tag_distance, 4, "four bytes back on x86");
    }

    #[test]
    fn the_member_paths_are_chosen_by_what_the_build_declares_not_by_its_version() {
        let win10 = VadSymbols::from_profile(&win10_profile(Image::new())).unwrap();
        assert_eq!(win10.left, "VadNode.Left");
        assert_eq!(win10.right, "VadNode.Right");
        assert_eq!(win10.start_vpn_high.as_deref(), Some("StartingVpnHigh"));
        assert_eq!(win10.root_shape, VadRootShape::AvlTreeRoot);
        assert_eq!(win10.tag_distance, 12, "twelve bytes back on x64");
        assert_eq!(win10.fast_ref_mask, 15, "four bits on a 64-bit kernel");
        assert!(win10.has_long_vad);

        let xp = VadSymbols::from_profile(&xp_profile(Image::new())).unwrap();
        assert_eq!(xp.left, "LeftChild");
        assert_eq!(xp.right, "RightChild");
        assert_eq!(xp.start_vpn_high, None);
        assert_eq!(xp.root_shape, VadRootShape::Pointer);
        assert_eq!(xp.tag_distance, 4, "four bytes back on x86");
    }

    #[test]
    fn a_build_with_no_short_vad_type_is_refused_rather_than_walked_as_something_else() {
        // Renamed everywhere, so the table still resolves and the only thing
        // missing is the name this module reads through.
        let broken = win10_vad_isf().replace("_MMVAD_SHORT", "_MMVAD_TINY");
        let profile = profile(
            Image::new().layer(),
            table(&broken),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let err = VadSymbols::from_profile(&profile).expect_err("no _MMVAD_SHORT");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("_MMVAD_SHORT"), "{err}");
        assert_eq!(
            err.to_incomplete().reason,
            IncompleteReason::UnresolvedStructure
        );
    }

    #[test]
    fn a_build_that_declares_half_a_split_page_number_is_refused() {
        // One half without the other would compose the two ends of every range
        // differently, putting them 16 TiB apart.
        let broken = win10_vad_isf().replace("\"EndingVpnHigh\"", "\"EndingVpnHighish\"");
        let profile = profile(
            Image::new().layer(),
            table(&broken),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let err = VadSymbols::from_profile(&profile).expect_err("half a split");
        assert!(err.to_string().contains("but not the other"), "{err}");
    }

    #[test]
    fn a_build_with_no_child_members_is_refused_naming_everything_that_was_tried() {
        let broken = win10_vad_isf()
            .replace("\"Left\":", "\"Larboard\":")
            .replace("\"Right\":", "\"Starboard\":");
        let profile = profile(
            Image::new().layer(),
            table(&broken),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let err = VadSymbols::from_profile(&profile).expect_err("no child members");
        assert!(err.to_string().contains("LeftChild"), "{err}");
        assert!(err.to_string().contains("VadNode.Left"), "{err}");
    }

    #[test]
    fn a_kernel_without_the_protection_table_says_so_rather_than_returning_zeros() {
        let profile = xp_profile(Image::new());
        let err = ProtectionTable::from_profile(&profile).expect_err("no such symbol");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("MmProtectToValue"), "{err}");
    }

    #[test]
    fn the_root_of_a_balanced_root_build_is_the_embedded_sentinel_not_a_pointer_read_from_it() {
        // Following `BalancedRoot` as though it were a pointer would read the
        // sentinel's own first member as a node address and walk somewhere
        // unrelated, which still parses.
        let with_table = win10_vad_isf().replace(
            r#""_RTL_AVL_TREE": {"size": 8, "kind": "struct", "fields": {"Root": {"offset": 0, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}}}"#,
            r#""_RTL_AVL_TREE": {"size": 24, "kind": "struct", "fields": {"BalancedRoot": {"offset": 0, "type": {"kind": "struct", "name": "_RTL_BALANCED_NODE"}}}}"#,
        );
        assert!(
            with_table.contains("BalancedRoot"),
            "the fixture's AVL tree definition must have been replaced"
        );
        let mut image = Image::new();
        // The sentinel is embedded at the `_EPROCESS`'s VadRoot, and the real
        // tree hangs off its right child.
        image.put_u64(EPROCESS_AT + off::VAD_RIGHT, VAD_LEFT);
        put_win10_vad(&mut image, VAD_LEFT, b"VadS", 0x40, 0x41, 0, 0, 0);
        let profile = profile(
            image.layer(),
            table(&with_table),
            Architecture::X64,
            6,
            1,
            Some(7601),
        );
        let symbols = VadSymbols::from_profile(&profile).unwrap();
        assert_eq!(symbols.root_shape, VadRootShape::BalancedRootSentinel);
        let tree = list_vads(&profile, &symbols, EPROCESS_AT, &VadWalkConfig::default()).unwrap();
        assert_eq!(tree.root, EPROCESS_AT, "the sentinel is embedded");
        assert_eq!(
            tree.vads.iter().map(|v| v.address).collect::<Vec<_>>(),
            vec![VAD_LEFT]
        );
        assert_eq!(tree.vads[0].start, 0x40 * PAGE_SIZE);
    }

    #[test]
    fn a_stop_reason_maps_onto_something_the_artifact_can_carry() {
        assert!(VadStop::Exhausted.is_complete());
        assert_eq!(VadStop::Exhausted.as_str(), "exhausted");
        assert!(!VadStop::CapReached { cap: 4 }.is_complete());
        assert_eq!(VadStop::CapReached { cap: 4 }.as_str(), "cap_reached");
        assert_eq!(VadKind::Short.as_str(), "short");
        assert_eq!(VadKind::Long.as_str(), "long");
        assert_eq!(VadRootShape::Pointer.as_str(), "pointer");
        assert_eq!(MappedFile::None.to_json()["kind"], "no_mapped_file");
        assert_eq!(
            MappedFile::NotApplicable.to_json()["kind"],
            "not_applicable"
        );
    }
}
