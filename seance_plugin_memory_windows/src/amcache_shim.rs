//! The AppCompatCache — the Shimcache — read out of live kernel memory.
//!
//! When a program is launched, the application-compatibility engine looks the
//! file up in a cache keyed by path, and records the path, the file's
//! `$STANDARD_INFORMATION` last-modified time and (on most builds) a flag
//! saying the file was actually executed rather than merely examined. The cache
//! is a doubly linked LRU list hanging off an `_RTL_AVL_TABLE`, and it lives in
//! the `.data` section of `ahcache.sys` on Windows 8.1 and later and of the
//! kernel itself before that.
//!
//! On disk the same data is a single `AppCompatCache` registry value that
//! Windows writes **at shutdown**. Everything the machine ran since it last
//! booted is therefore in memory and not on disk, which is the entire reason
//! this stage exists.
//!
//! # Finding it without a symbol for it
//!
//! Neither `ahcache.sys` nor the kernel exports anything naming the cache, and
//! `SHIM_CACHE_ENTRY` is in no public PDB. What is available is the shape of
//! its neighbours, all of which *are* declared:
//!
//! * an `_RTL_AVL_TABLE` whose `BalancedRoot.Parent` points at itself and whose
//!   three routine pointers land inside the host module's `PAGE` section and
//!   are three distinct addresses;
//! * an `_ERESOURCE` immediately before it, whose `SystemResourcesList` is a
//!   well-formed doubly linked list;
//! * the list head immediately *after* it, one `_RTL_AVL_TABLE` further on,
//!   whose `_LIST_ENTRY` is self-consistent.
//!
//! A pointer-aligned sweep of the host module's `.data` section for that
//! signature is what locates the cache. Every one of those checks comes from
//! the symbol table, so a build whose `_RTL_AVL_TABLE` is a different size is
//! measured correctly rather than assumed.
//!
//! # The one thing that cannot come from symbols
//!
//! `SHIM_CACHE_ENTRY`'s own layout. It changed at Server 2003, Vista, 7, 8, 8.1
//! and 10, and no symbol file describes it, so it is catalogued here per build
//! and pointer width in [`entry_layout_for`]. Two consequences, both deliberate:
//!
//! 1. **A build with no catalogued layout is refused.** Applying the nearest
//!    layout would produce a full list of plausible paths and timestamps read
//!    from the wrong offsets — evidence about files that were never on the
//!    machine, with nothing in the output to suggest anything went wrong.
//! 2. **The catalogued layout is cross-checked against the symbol table.**
//!    Every catalogued offset is expressed in terms of `_LIST_ENTRY` and
//!    `_UNICODE_STRING`, whose sizes this build's symbols state; if they
//!    disagree with what the layout assumes, the layout is not for this build
//!    and it is refused. See [`ShimEntryLayout::agrees_with`].
//!
//! # What is deliberately not here
//!
//! **Windows XP.** On XP the cache is not in kernel `.data` at all: it is a
//! user-mode allocation inside `csrss.exe`, found by scanning that process's
//! VAD tree for a region beginning `0xDEADBEEF`. That needs a per-process
//! address space, which is the process tier's work, and it is not done by this
//! stage. An XP image is therefore refused by name — [`ShimSection::status`]
//! says so — rather than returning an empty list that would read as "this
//! machine ran nothing".

use std::collections::HashSet;

use seance_core::io::IncompleteReason;
use seance_memory::object::{ObjError, StructReader};
use seance_memory::Incomplete;

use crate::amcache::{
    flag_field_json, kernel_reader, number_field_json, push_note, text_field_json, time_field_json,
    u16_at, u32_at, u64_at, AmcacheConfig, Field, WinTime,
};
use crate::modules::{list_kernel_modules, ModuleSymbols, ModuleWalkConfig};
use crate::profile::WindowsProfile;

/// The kernel images the Shimcache lives in before Windows 8.1.
///
/// All four names for the same kernel: uniprocessor and multiprocessor, PAE and
/// not. Which one is loaded depends on the machine, so all four are looked for
/// and the first that is on the module list wins.
pub const SHIMCACHE_KERNEL_MODULES: &[&str] = &[
    "ntoskrnl.exe",
    "ntkrnlpa.exe",
    "ntkrnlmp.exe",
    "ntkrpamp.exe",
];

/// The driver the Shimcache moved into at Windows 8.1.
pub const SHIMCACHE_HOST_MODULES: &[&str] = &["ahcache.sys"];

/// The section the cache's anchor structures live in.
pub const DATA_SECTION: &str = ".data";

/// The section the AVL table's routine pointers must land in.
pub const PAGE_SECTION: &str = "PAGE";

/// `_RTL_AVL_TABLE`, the structure the cache hangs off.
pub const TYPE_RTL_AVL_TABLE: &str = "_RTL_AVL_TABLE";

/// `_ERESOURCE`, the lock that sits in front of the AVL table.
pub const TYPE_ERESOURCE: &str = "_ERESOURCE";

/// `_KSEMAPHORE`, which an `_ERESOURCE`'s shared-waiter pointer addresses.
pub const TYPE_KSEMAPHORE: &str = "_KSEMAPHORE";

/// `_LIST_ENTRY`, which links the cache.
pub const TYPE_LIST_ENTRY: &str = "_LIST_ENTRY";

/// `_UNICODE_STRING`, which holds each cached path.
pub const TYPE_UNICODE_STRING: &str = "_UNICODE_STRING";

/// Ceiling on `IMAGE_SECTION_HEADER`s read from one module.
///
/// A PE cannot declare more than 96 sections and still be loadable; a header
/// claiming more has been tampered with or is not a PE at all.
pub const MAX_SECTIONS: u64 = 96;

/// Bytes of a `_UNICODE_STRING` this module will read as a path.
///
/// A Shimcache path is at most `MAX_PATH` in wide characters. Two kilobytes is
/// well past that and far below what a corrupt `USHORT` could ask for at every
/// candidate in a sweep.
pub const MAX_PATH_BYTES: u64 = 2_048;

/// The first build whose Shimcache lives in `ahcache.sys` rather than the
/// kernel. Windows 8.1 is build 9600.
pub const FIRST_AHCACHE_BUILD: u32 = 9_600;

/// The first build using the `SHIM_CACHE_HANDLE` pointer form. Windows 8.0.
pub const FIRST_HANDLE_BUILD: u32 = 9_200;

/// The bit `InsertFlags` carries when the shim engine saw the file execute
/// rather than merely stat it.
pub const INSERT_FLAG_EXECUTED: u64 = 0x2;

// ── Layout ──────────────────────────────────────────────────────────────────

/// How the cache is anchored in the host module's `.data` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShimVariant {
    /// Server 2003 through Windows 7: the `_RTL_AVL_TABLE` is embedded in
    /// `.data` itself and the list head follows it.
    InlineAvlTable,
    /// Windows 8 and later: `.data` holds a *pointer* to a two-pointer
    /// `SHIM_CACHE_HANDLE` — an `_ERESOURCE` and an `_RTL_AVL_TABLE` — and the
    /// list head follows the table.
    HandlePointer,
}

impl ShimVariant {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            ShimVariant::InlineAvlTable => "inline_avl_table",
            ShimVariant::HandlePointer => "handle_pointer",
        }
    }
}

/// Where the fields of one `SHIM_CACHE_ENTRY_DETAIL` are, on builds that have
/// one.
///
/// Windows 8 moved the per-entry timestamp and flags out of the entry into a
/// separately allocated detail record the entry points at. An examiner reading
/// a Windows 8 entry with a Windows 7 layout gets the timestamp from the middle
/// of a pointer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimDetailLayout {
    /// Offset of the `LastModified` FILETIME.
    pub last_modified: u64,
    /// Offset of `InsertFlags`, on builds whose detail record carries it.
    pub insert_flags: Option<u64>,
    /// Offset and width of `BlobSize`.
    pub blob_size: Option<(u64, u64)>,
    /// Offset and width of `BlobBuffer`, the pointer to the shim blob whose
    /// first four bytes are the execution flag on builds with no `InsertFlags`.
    pub blob_buffer: Option<(u64, u64)>,
}

/// Where the fields of one `SHIM_CACHE_ENTRY` are on one build.
///
/// Every offset is a fact about a structure no symbol file declares, which is
/// why each one is written down beside the build it belongs to and why
/// [`ShimEntryLayout::agrees_with`] re-derives what it can from the symbol
/// table before any of it is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShimEntryLayout {
    /// Stable name of the layout, e.g. `"windows-10-x64"`, reported so a
    /// disputed reading can be traced to the table row that produced it.
    pub name: &'static str,
    /// Size of the whole entry, which is how many bytes are read per entry.
    pub size: u64,
    /// Offset of the embedded `_LIST_ENTRY`. Zero on every catalogued build,
    /// but stated rather than assumed because the walk subtracts it.
    pub list_entry: u64,
    /// Offset of the embedded `_UNICODE_STRING` holding the path.
    pub path: u64,
    /// Offset of the `LastModified` FILETIME, on builds that store it inline.
    pub last_modified: Option<u64>,
    /// Offset of `InsertFlags`, on builds that store it inline.
    pub insert_flags: Option<u64>,
    /// Offset and width of `FileSize`, which only Server 2003 records.
    pub file_size: Option<(u64, u64)>,
    /// Offset of the pointer to the detail record, on builds that have one.
    pub detail_pointer: Option<u64>,
    /// The detail record's layout, on builds that have one.
    pub detail: Option<ShimDetailLayout>,
}

impl ShimEntryLayout {
    /// Whether this build's symbols agree with the sizes this layout assumes.
    ///
    /// The layout is catalogued by build number, and a build number is not a
    /// promise. Two structures inside the entry *are* declared by the symbol
    /// table — the `_LIST_ENTRY` it begins with and the `_UNICODE_STRING`
    /// holding the path — so if either is not the size this layout was written
    /// against, the layout is not describing this build and using it would
    /// produce paths read from the wrong offsets.
    ///
    /// Returns the reason it disagrees, so the refusal names the discrepancy.
    pub fn agrees_with(&self, list_entry_size: u64, unicode_size: u64) -> Result<(), String> {
        if self.path < list_entry_size {
            return Err(format!(
                "the '{}' layout puts the path at offset {:#x}, inside the {list_entry_size}-byte \
                 _LIST_ENTRY this build declares at the start of the entry",
                self.name, self.path
            ));
        }
        let path_end = self.path.checked_add(unicode_size).ok_or_else(|| {
            format!(
                "the '{}' layout's path offset {:#x} plus a {unicode_size}-byte _UNICODE_STRING \
                 does not fit in 64 bits",
                self.name, self.path
            )
        })?;
        if path_end > self.size {
            return Err(format!(
                "the '{}' layout is {} byte(s) long and this build's {unicode_size}-byte \
                 _UNICODE_STRING at offset {:#x} would run past its end, so the layout is not \
                 for this build",
                self.name, self.size, self.path
            ));
        }
        if let Some(detail) = self.detail_pointer {
            if detail < path_end {
                return Err(format!(
                    "the '{}' layout puts the detail pointer at offset {detail:#x}, inside the \
                     {unicode_size}-byte _UNICODE_STRING this build declares",
                    self.name
                ));
            }
        }
        Ok(())
    }
}

/// The catalogued `SHIM_CACHE_ENTRY` layout for a build, or `None`.
///
/// `None` means this module has no layout for the build and the caller must
/// refuse rather than approximate. The bands are the Windows releases at which
/// the structure changed:
///
/// | Build | Release | Layout |
/// |---|---|---|
/// | ≥ 10240 | 10, 11 | detail record, no inline `InsertFlags` |
/// | 9200 – 10239 | 8.0, 8.1 | detail record with `InsertFlags` |
/// | 7600 – 9199 | 7, 2008 R2 | inline timestamp, flags and blob |
/// | 6000 – 7599 | Vista, 2008 | inline timestamp and flags, no blob |
/// | 3790 | 2003, XP x64 | inline timestamp and file size, no flags |
pub fn entry_layout_for(build: u32, is_64bit: bool) -> Option<ShimEntryLayout> {
    let layout = match (build, is_64bit) {
        (10_240.., true) => ShimEntryLayout {
            name: "windows-10-x64",
            size: 0x30,
            list_entry: 0,
            path: 0x18,
            last_modified: None,
            insert_flags: None,
            file_size: None,
            detail_pointer: Some(0x28),
            detail: Some(ShimDetailLayout {
                last_modified: 0x08,
                insert_flags: None,
                blob_size: Some((0x10, 4)),
                blob_buffer: Some((0x18, 8)),
            }),
        },
        (10_240.., false) => ShimEntryLayout {
            name: "windows-10-x86",
            size: 0x18,
            list_entry: 0,
            path: 0x0C,
            last_modified: None,
            insert_flags: None,
            file_size: None,
            detail_pointer: Some(0x14),
            detail: Some(ShimDetailLayout {
                last_modified: 0x08,
                insert_flags: Some(0x04),
                blob_size: Some((0x10, 4)),
                blob_buffer: Some((0x14, 4)),
            }),
        },
        (9_200..=10_239, true) => ShimEntryLayout {
            name: "windows-8-x64",
            size: 0x40,
            list_entry: 0,
            path: 0x18,
            last_modified: None,
            insert_flags: None,
            file_size: None,
            detail_pointer: Some(0x38),
            detail: Some(ShimDetailLayout {
                last_modified: 0x00,
                insert_flags: Some(0x08),
                blob_size: Some((0x10, 8)),
                blob_buffer: Some((0x20, 8)),
            }),
        },
        (9_200..=10_239, false) => ShimEntryLayout {
            name: "windows-8-x86",
            size: 0x24,
            list_entry: 0,
            path: 0x10,
            last_modified: None,
            insert_flags: None,
            file_size: None,
            detail_pointer: Some(0x20),
            detail: Some(ShimDetailLayout {
                last_modified: 0x00,
                insert_flags: Some(0x08),
                blob_size: Some((0x10, 4)),
                blob_buffer: Some((0x14, 4)),
            }),
        },
        (7_600..=9_199, true) => ShimEntryLayout {
            name: "windows-7-x64",
            size: 0x40,
            list_entry: 0,
            path: 0x10,
            last_modified: Some(0x20),
            insert_flags: Some(0x28),
            file_size: None,
            detail_pointer: None,
            detail: None,
        },
        (7_600..=9_199, false) => ShimEntryLayout {
            name: "windows-7-x86",
            size: 0x28,
            list_entry: 0,
            path: 0x08,
            last_modified: Some(0x10),
            insert_flags: Some(0x18),
            file_size: None,
            detail_pointer: None,
            detail: None,
        },
        (6_000..=7_599, true) => ShimEntryLayout {
            name: "windows-vista-x64",
            size: 0x30,
            list_entry: 0,
            path: 0x10,
            last_modified: Some(0x20),
            insert_flags: Some(0x28),
            file_size: None,
            detail_pointer: None,
            detail: None,
        },
        (6_000..=7_599, false) => ShimEntryLayout {
            name: "windows-vista-x86",
            size: 0x24,
            list_entry: 0,
            path: 0x08,
            last_modified: Some(0x10),
            insert_flags: Some(0x18),
            file_size: None,
            detail_pointer: None,
            detail: None,
        },
        (3_790, true) => ShimEntryLayout {
            name: "windows-2003-x64",
            size: 0x30,
            list_entry: 0,
            path: 0x10,
            last_modified: Some(0x20),
            insert_flags: None,
            file_size: Some((0x28, 4)),
            detail_pointer: None,
            detail: None,
        },
        (3_790, false) => ShimEntryLayout {
            name: "windows-2003-x86",
            size: 0x24,
            list_entry: 0,
            path: 0x08,
            last_modified: Some(0x10),
            insert_flags: None,
            file_size: Some((0x18, 4)),
            detail_pointer: None,
            detail: None,
        },
        _ => return None,
    };
    Some(layout)
}

/// Which `.data` anchor holds the Shimcache rather than the compatibility
/// database cache that sits beside it.
///
/// Windows 8 and later place **two** `SHIM_CACHE_HANDLE` structures in the host
/// module's `.data`: one for the shim cache and one for the compatibility
/// database. They are indistinguishable structurally — both validate — and only
/// the build says which is which. Windows 8.0 x64 keeps the Shimcache in the
/// first; 8.0 x86, 8.1, 10 and 11 keep it in the second. Reading the wrong one
/// yields a complete, well-formed list of the wrong cache's contents.
///
/// The inline form has a single anchor, so the answer there is always the
/// first.
pub fn preferred_anchor(variant: ShimVariant, build: u32, is_64bit: bool) -> usize {
    match variant {
        ShimVariant::InlineAvlTable => 0,
        ShimVariant::HandlePointer => usize::from(!(build < FIRST_AHCACHE_BUILD && is_64bit)),
    }
}

/// Everything reading the Shimcache on this build needs.
#[derive(Debug, Clone)]
pub struct ShimLayout {
    /// How the cache is anchored.
    pub variant: ShimVariant,
    /// The catalogued entry layout.
    pub entry: ShimEntryLayout,
    /// Module names to look for the anchor in, in preference order.
    pub host_modules: &'static [&'static str],
    /// Which `.data` anchor holds the Shimcache. See [`preferred_anchor`].
    pub preferred_anchor: usize,
    /// Pointer width, in bytes.
    pub pointer_size: u64,
    /// `_LIST_ENTRY.Flink`.
    pub list_flink: u64,
    /// `_LIST_ENTRY.Blink`.
    pub list_blink: u64,
    /// `sizeof(_LIST_ENTRY)`.
    pub list_entry_size: u64,
    /// `sizeof(_UNICODE_STRING)`.
    pub unicode_size: u64,
    /// `sizeof(_RTL_AVL_TABLE)`, which is the distance from the table to the
    /// list head that follows it.
    pub avl_table_size: u64,
    /// `_RTL_AVL_TABLE.BalancedRoot`, whose *address* a valid table's parent
    /// pointer holds.
    pub avl_balanced_root: u64,
    /// `_RTL_AVL_TABLE.BalancedRoot.Parent`, as a whole-path offset from the
    /// start of the table rather than from the balanced root.
    ///
    /// Stated that way deliberately: adding a whole-path offset to an address
    /// that already includes the containing member's offset lands one member
    /// further on, and the resulting pointer comparison would fail on every
    /// real table while passing on some random ones.
    pub avl_parent: u64,
    /// `_RTL_AVL_TABLE.CompareRoutine`.
    pub avl_compare: u64,
    /// `_RTL_AVL_TABLE.AllocateRoutine`.
    pub avl_allocate: u64,
    /// `_RTL_AVL_TABLE.FreeRoutine`.
    pub avl_free: u64,
    /// `sizeof(_ERESOURCE)`.
    pub eresource_size: u64,
    /// The allocation alignment an `_ERESOURCE` is placed on: 0x20 on 64-bit
    /// Windows and 0x10 on 32-bit. Used to find the lock in front of an inline
    /// AVL table.
    pub eresource_alignment: u64,
    /// `_ERESOURCE.SystemResourcesList`.
    pub eresource_system_list: u64,
    /// `_ERESOURCE.SharedWaiters`.
    pub eresource_shared_waiters: u64,
    /// `_ERESOURCE.NumberOfSharedWaiters`.
    ///
    /// Resolved so that a build whose `_ERESOURCE` does not declare the member
    /// is refused here rather than validated without it. The value itself is
    /// read back through the symbol table, at whatever width this build
    /// declares, because the member is a `USHORT` on some builds and a `ULONG`
    /// on others and reading four bytes where two belong picks up the field
    /// after it.
    pub eresource_shared_waiter_count: u64,
    /// `sizeof(_KSEMAPHORE)`, which a non-null `SharedWaiters` must address.
    pub ksemaphore_size: u64,
    /// How the loaded-module list is read, to find the host module.
    pub modules: ModuleSymbols,
}

impl ShimLayout {
    /// Resolve everything the Shimcache needs, or say why it cannot be read.
    ///
    /// `Err` carries a sentence for the examiner rather than an error type: the
    /// caller records it beside the Amcache hive's reason instead of raising
    /// it, because a build with no catalogued Shimcache layout may still have a
    /// readable Amcache hive.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, String> {
        let Some(build) = profile.build.build else {
            return Err(
                "the kernel build number was never established, and the Shimcache entry layout \
                 changed at almost every Windows release, so no layout can be selected"
                    .to_string(),
            );
        };
        let is_64bit = profile.is_64bit();
        let Some(entry) = entry_layout_for(build, is_64bit) else {
            return Err(format!(
                "build {build} has no catalogued SHIM_CACHE_ENTRY layout for a {}-bit kernel; \
                 Windows XP keeps its cache in a csrss.exe allocation rather than in kernel \
                 .data and is not read by this stage",
                if is_64bit { 64 } else { 32 }
            ));
        };

        // Both closures name the type *and* what its absence costs. Neither is
        // the build-variant class: `_LIST_ENTRY`, `_UNICODE_STRING` and
        // `_RTL_AVL_TABLE` are on every Windows kernel from XP onward, so a
        // table that cannot size one is a table this analysis could not read
        // rather than a build that never had it — and the catalogued entry
        // layout is cross-checked against these two widths, so accepting a
        // guess would slide every field of every Shimcache row.
        //
        // Failing here also does not kill the stage: the caller keeps this
        // message as `shim_unavailable` and still reads the Amcache hive, so
        // the examiner is told which half was lost and why rather than being
        // shown a short list with no explanation.
        let reader = kernel_reader(profile);
        let size_of = |type_name: &str| -> Result<u64, String> {
            reader.size_of(type_name).map(|s| s.bytes()).map_err(|err| {
                format!(
                    "the symbol table cannot size '{type_name}', which the Shimcache entry layout \
                     is cross-checked against, so no Shimcache row could be read at a defensible \
                     offset: {err}"
                )
            })
        };
        let member = |type_name: &str, path: &str| -> Result<u64, String> {
            reader
                .member_offset(type_name, path)
                .map(|o| o.bytes())
                .map_err(|err| {
                    format!(
                    "the symbol table has no '{type_name}.{path}', which the Shimcache sweep reads \
                     to find and thread the cache, so no executed program could be recovered from \
                     it: {err}"
                )
                })
        };

        let list_entry_size = size_of(TYPE_LIST_ENTRY)?;
        let unicode_size = size_of(TYPE_UNICODE_STRING)?;
        entry.agrees_with(list_entry_size, unicode_size)?;

        let pointer_size = u64::from(
            reader
                .pointer_size()
                .map_err(|err| format!("the symbol table declares no pointer size: {err}"))?,
        );

        let variant = if build >= FIRST_HANDLE_BUILD {
            ShimVariant::HandlePointer
        } else {
            ShimVariant::InlineAvlTable
        };
        Ok(Self {
            variant,
            entry,
            host_modules: if build >= FIRST_AHCACHE_BUILD {
                SHIMCACHE_HOST_MODULES
            } else {
                SHIMCACHE_KERNEL_MODULES
            },
            preferred_anchor: preferred_anchor(variant, build, is_64bit),
            pointer_size,
            list_flink: member(TYPE_LIST_ENTRY, "Flink")?,
            list_blink: member(TYPE_LIST_ENTRY, "Blink")?,
            list_entry_size,
            unicode_size,
            avl_table_size: size_of(TYPE_RTL_AVL_TABLE)?,
            avl_balanced_root: member(TYPE_RTL_AVL_TABLE, "BalancedRoot")?,
            avl_parent: member(TYPE_RTL_AVL_TABLE, "BalancedRoot.Parent")?,
            avl_compare: member(TYPE_RTL_AVL_TABLE, "CompareRoutine")?,
            avl_allocate: member(TYPE_RTL_AVL_TABLE, "AllocateRoutine")?,
            avl_free: member(TYPE_RTL_AVL_TABLE, "FreeRoutine")?,
            eresource_size: size_of(TYPE_ERESOURCE)?,
            eresource_alignment: if is_64bit { 0x20 } else { 0x10 },
            eresource_system_list: member(TYPE_ERESOURCE, "SystemResourcesList")?,
            eresource_shared_waiters: member(TYPE_ERESOURCE, "SharedWaiters")?,
            eresource_shared_waiter_count: member(TYPE_ERESOURCE, "NumberOfSharedWaiters")?,
            ksemaphore_size: size_of(TYPE_KSEMAPHORE)?,
            modules: ModuleSymbols::from_profile(profile).map_err(|err| {
                format!("the loaded-module list, which the Shimcache's host module is found on, cannot be walked: {err}")
            })?,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "variant": self.variant.as_str(),
            "entry_layout": self.entry.name,
            "entry_size": self.entry.size,
            "host_modules": self.host_modules,
            "preferred_anchor": self.preferred_anchor,
            "avl_table_size": self.avl_table_size,
            "eresource_size": self.eresource_size,
        })
    }
}

// ── Entries ─────────────────────────────────────────────────────────────────

/// One cached executable.
#[derive(Debug, Clone)]
pub struct ShimEntry {
    /// Where the entry is, in the kernel address space.
    pub address: u64,
    /// Position in the LRU list, zero being the most recently inserted.
    ///
    /// Evidence in its own right: the cache is ordered by use, so an entry near
    /// the head was touched more recently than one near the tail even where
    /// neither carries a usable timestamp.
    pub order: usize,
    /// The path, as `\??\C:\...` or a device path exactly as the kernel held
    /// it. Never normalised, because a rewritten path is not what was cached.
    pub path: Field<String>,
    /// The file's `$STANDARD_INFORMATION` last-modified time, as the shim
    /// engine read it when it cached the file.
    pub last_modified: Field<WinTime>,
    /// Whether the shim engine saw the file *execute* rather than merely be
    /// examined.
    ///
    /// [`Field::NotApplicable`] on Server 2003, whose entries carry no such
    /// flag at all — which must never be rendered as "it did not execute".
    pub executed: Field<bool>,
    /// The file's size, which only Server 2003 entries record.
    pub file_size: Field<u64>,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl ShimEntry {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "order": self.order,
            "path": text_field_json(&self.path),
            "last_modified": time_field_json(&self.last_modified),
            "executed": flag_field_json(&self.executed),
            "file_size": number_field_json(&self.file_size),
            "notes": self.notes,
        })
    }
}

/// Whether the Shimcache was found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShimStatus {
    /// The anchor was found and the list walked.
    Read,
    /// The host module's `.data` section was swept and held no valid anchor.
    NotFound {
        /// Whether the sweep covered the whole section. `false` means part of
        /// `.data` was not acquired or the probe cap fired, so the anchor may
        /// have been in the part that was not looked at.
        search_complete: bool,
    },
    /// The Shimcache could not be looked for at all, and here is why.
    Unavailable(String),
}

impl ShimStatus {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            ShimStatus::Read => "read",
            ShimStatus::NotFound { .. } => "not_found",
            ShimStatus::Unavailable(_) => "unavailable",
        }
    }
}

/// The Shimcache, and everything the sweep and the walk could not do.
#[derive(Debug, Clone)]
pub struct ShimSection {
    /// Whether the cache was found.
    pub status: ShimStatus,
    /// The entries, most recently inserted first.
    pub entries: Vec<ShimEntry>,
    /// How many entries the walk reached.
    ///
    /// A **floor** rather than a total whenever [`ShimSection::truncated`] is
    /// set: the walk stops at the cap rather than counting on past it, because
    /// counting on would mean following an attacker-shaped list for as long as
    /// it cared to run. A report that quotes this number without consulting
    /// `truncated` states a count the evidence does not support.
    pub entries_total: usize,
    /// Whether the entry cap fired. The walk stopped; the list did not end.
    pub truncated: bool,
    /// Which catalogued layout was used, so a disputed reading can be traced.
    pub layout: Option<&'static str>,
    /// Address of the list head.
    pub head: Option<u64>,
    /// The module the anchor was found in.
    pub host_module: Option<String>,
    /// How many pointer-aligned candidates were examined.
    pub probes: usize,
    /// Notes, capped by [`AmcacheConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total.
    pub notes_total: usize,
}

impl ShimSection {
    /// A result for an image whose Shimcache could not be looked for.
    pub fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            status: ShimStatus::Unavailable(detail.into()),
            entries: Vec::new(),
            entries_total: 0,
            truncated: false,
            layout: None,
            head: None,
            host_module: None,
            probes: 0,
            notes: Vec::new(),
            notes_total: 0,
        }
    }

    /// Whether the cache was read in full.
    ///
    /// A cache that was not found is **not** complete, whether or not the sweep
    /// was exhaustive: the flag answers "may a report say this machine did not
    /// run that program?", and without the cache in hand the answer is no. A
    /// note is likewise disqualifying, because every note this stage records is
    /// an entry it could not read or a list it could not follow to the end.
    pub fn is_complete(&self) -> bool {
        matches!(self.status, ShimStatus::Read) && !self.truncated && self.notes_total == 0
    }

    /// Everything a report must declare about this cache.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        match &self.status {
            ShimStatus::Read => {}
            ShimStatus::NotFound { search_complete } => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                if *search_complete {
                    "no Shimcache was found in the host module's .data section, so no in-memory \
                     record of recently executed files could be read"
                        .to_string()
                } else {
                    "no Shimcache was found, and part of the host module's .data section could \
                     not be examined, so the cache may have been in the part that was missed"
                        .to_string()
                },
            )),
            ShimStatus::Unavailable(detail) => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!("the Shimcache could not be read: {detail}"),
            )),
        }
        if self.truncated {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the Shimcache list held {} entries and the walk stopped at its cap; the list \
                     continues",
                    self.entries_total
                ),
            ));
        }
        for note in &self.notes {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                note.clone(),
            ));
        }
        if self.notes_total > self.notes.len() {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "{} further note(s) about the Shimcache were not recorded individually",
                    self.notes_total.saturating_sub(self.notes.len())
                ),
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "status": self.status.as_str(),
            "status_detail": match &self.status {
                ShimStatus::Unavailable(detail) => Some(detail.clone()),
                _ => None,
            },
            "layout": self.layout,
            "head": self.head,
            "host_module": self.host_module,
            "probes": self.probes,
            "entries": self.entries.iter().map(ShimEntry::to_json).collect::<Vec<_>>(),
            "entries_total": self.entries_total,
            "truncated": self.truncated,
            "complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── PE sections ─────────────────────────────────────────────────────────────

/// One loaded PE section, in the address space the image is mapped into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SectionRange {
    /// Virtual address of the section's first byte.
    pub start: u64,
    /// Virtual address one past its last byte.
    pub end: u64,
}

impl SectionRange {
    /// Whether `address` falls inside the section.
    pub fn contains(&self, address: u64) -> bool {
        self.start <= address && address < self.end
    }

    /// The section's length in bytes.
    pub fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Whether the section is empty, which a loadable image's `.data` never is.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Locate a named section of the PE loaded at `base`.
///
/// Reads the DOS and NT headers and walks the section table, bounds-checking
/// every field. A section header that is not there, or a header that is not a
/// PE, is `Ok(None)`: the module is loaded and its headers are paged out or it
/// has no such section, which is not the same as a read failure.
///
/// # Errors
///
/// [`ObjError`] when the headers could not be read at all, which is a fact
/// about the acquisition rather than about the image.
pub fn section_range(
    reader: &StructReader,
    base: u64,
    wanted: &str,
) -> Result<Option<SectionRange>, ObjError> {
    let dos = reader.read_bytes(base, 0x40)?;
    if dos.get(..2) != Some(b"MZ".as_slice()) {
        return Ok(None);
    }
    let Some(lfanew) = u32_at(&dos, 0x3C).map(u64::from) else {
        return Ok(None);
    };
    // A PE's NT headers sit within the first page in every real image; a wild
    // e_lfanew is a header that is not one.
    if !(0x40..0x1000).contains(&lfanew) {
        return Ok(None);
    }
    let Some(nt_base) = base.checked_add(lfanew) else {
        return Ok(None);
    };
    let nt = reader.read_bytes(nt_base, 0x18)?;
    if nt.get(..4) != Some(b"PE\0\0".as_slice()) {
        return Ok(None);
    }
    let Some(section_count) = u16_at(&nt, 0x06).map(u64::from) else {
        return Ok(None);
    };
    let Some(optional_size) = u16_at(&nt, 0x14).map(u64::from) else {
        return Ok(None);
    };
    if section_count == 0 || section_count > MAX_SECTIONS {
        return Ok(None);
    }
    let Some(table) = nt_base
        .checked_add(0x18)
        .and_then(|at| at.checked_add(optional_size))
    else {
        return Ok(None);
    };
    let Some(table_bytes) = section_count.checked_mul(0x28) else {
        return Ok(None);
    };
    let headers = reader.read_bytes(table, table_bytes)?;

    for index in 0..section_count as usize {
        let at = index.saturating_mul(0x28);
        let Some(raw_name) = headers.get(at..at.saturating_add(8)) else {
            break;
        };
        let end = raw_name.iter().position(|b| *b == 0).unwrap_or(8);
        let name = String::from_utf8_lossy(&raw_name[..end]);
        if !name.eq_ignore_ascii_case(wanted) {
            continue;
        }
        let (Some(virtual_size), Some(virtual_address)) =
            (u32_at(&headers, at + 8), u32_at(&headers, at + 12))
        else {
            break;
        };
        let Some(start) = base.checked_add(u64::from(virtual_address)) else {
            break;
        };
        let Some(section_end) = start.checked_add(u64::from(virtual_size)) else {
            break;
        };
        return Ok(Some(SectionRange {
            start,
            end: section_end,
        }));
    }
    Ok(None)
}

// ── The sweep ───────────────────────────────────────────────────────────────

/// Find the Shimcache in kernel memory and read every entry in it.
///
/// Never returns an error: a host module that is not loaded, a `.data` section
/// with no anchor in it, and a list that will not walk are all findings about
/// the image, and each lands on [`ShimSection::status`] with its reason.
pub fn read_shimcache(
    profile: &WindowsProfile,
    layout: &ShimLayout,
    config: &AmcacheConfig,
) -> ShimSection {
    let mut section = ShimSection {
        status: ShimStatus::NotFound {
            search_complete: true,
        },
        entries: Vec::new(),
        entries_total: 0,
        truncated: false,
        layout: Some(layout.entry.name),
        head: None,
        host_module: None,
        probes: 0,
        notes: Vec::new(),
        notes_total: 0,
    };
    let reader = kernel_reader(profile);
    // Every refusal below keeps the layout name, because "we could not look"
    // and "we looked with the wrong ruler" are different things to have to
    // explain, and only the recorded layout separates them.
    let unavailable = |detail: String| ShimSection {
        layout: Some(layout.entry.name),
        ..ShimSection::unavailable(detail)
    };

    let modules = match list_kernel_modules(profile, &layout.modules, &ModuleWalkConfig::default())
    {
        Ok(modules) => modules,
        Err(err) => {
            return unavailable(format!(
                "the kernel's loaded-module list could not be walked, so the Shimcache's host \
                 module could not be located: {err}"
            ))
        }
    };
    let host = layout.host_modules.iter().find_map(|wanted| {
        modules.modules.iter().find_map(|module| {
            let name = module.base_name.name()?;
            if name.eq_ignore_ascii_case(wanted) {
                module.base.map(|base| ((*wanted).to_string(), base))
            } else {
                None
            }
        })
    });
    let Some((host_name, host_base)) = host else {
        return unavailable(format!(
            "none of {:?} is on the kernel's loaded-module list with a readable base address, so \
             the Shimcache's .data section cannot be located{}",
            layout.host_modules,
            if modules.is_complete() {
                ""
            } else {
                "; the module list itself could not be walked in full, so the module may be loaded \
                 and missed"
            }
        ));
    };
    section.host_module = Some(host_name.clone());

    let data = match section_range(&reader, host_base, DATA_SECTION) {
        Ok(Some(range)) if !range.is_empty() => range,
        Ok(_) => {
            return unavailable(format!(
                "'{host_name}' at {host_base:#x} declares no readable '{DATA_SECTION}' section, \
                 so there is nowhere to look for the Shimcache anchor"
            ))
        }
        Err(err) => {
            return unavailable(format!(
                "the PE headers of '{host_name}' at {host_base:#x} could not be read: {err}"
            ))
        }
    };
    let page = match section_range(&reader, host_base, PAGE_SECTION) {
        Ok(Some(range)) if !range.is_empty() => range,
        Ok(_) => {
            return unavailable(format!(
                "'{host_name}' declares no '{PAGE_SECTION}' section, and the AVL table's routine \
                 pointers can only be validated against it"
            ))
        }
        Err(err) => {
            return unavailable(format!(
                "the '{PAGE_SECTION}' section of '{host_name}' could not be read: {err}"
            ))
        }
    };

    let sweep = sweep_for_anchor(&reader, layout, config, data, page);
    section.probes = sweep.probes;
    for note in sweep.notes {
        push_note(
            &mut section.notes,
            &mut section.notes_total,
            config.max_recorded_notes,
            note,
        );
    }

    let Some(head) = sweep.head else {
        section.status = ShimStatus::NotFound {
            search_complete: sweep.search_complete,
        };
        return section;
    };
    section.head = Some(head);
    section.status = ShimStatus::Read;
    walk_list(&reader, layout, config, head, &mut section);
    section
}

/// What one `.data` sweep found.
struct Sweep {
    /// The chosen list head, when one was found.
    head: Option<u64>,
    /// How many pointer-aligned candidates were examined.
    probes: usize,
    /// Whether the whole section was examined.
    search_complete: bool,
    /// Anything the sweep needs to say.
    notes: Vec<String>,
}

/// Sweep a `.data` section for the Shimcache anchor.
fn sweep_for_anchor(
    reader: &StructReader,
    layout: &ShimLayout,
    config: &AmcacheConfig,
    data: SectionRange,
    page: SectionRange,
) -> Sweep {
    let mut sweep = Sweep {
        head: None,
        probes: 0,
        search_complete: true,
        notes: Vec::new(),
    };
    let mut heads: Vec<u64> = Vec::new();
    let mut address = data.start;

    while address < data.end {
        if sweep.probes >= config.max_shim_probes {
            sweep.search_complete = false;
            sweep.notes.push(format!(
                "the .data sweep stopped at its cap of {} probe(s) with {:#x} byte(s) of the \
                 section unexamined",
                config.max_shim_probes,
                data.end.saturating_sub(address)
            ));
            break;
        }
        sweep.probes = sweep.probes.saturating_add(1);

        let candidate = match layout.variant {
            // The pointer form: `.data` holds a pointer to the handle.
            ShimVariant::HandlePointer => match reader.read_pointer_at(address) {
                Ok(0) => None,
                Ok(pointer) => handle_head(reader, layout, page, pointer),
                Err(_) => {
                    // A hole inside `.data` is a gap in the acquisition, not a
                    // failure: it is recorded and the sweep continues past it.
                    sweep.search_complete = false;
                    None
                }
            },
            // The inline form: the table is at the candidate address itself.
            ShimVariant::InlineAvlTable => inline_head(reader, layout, page, address),
        };
        if let Some(head) = candidate {
            if !heads.contains(&head) {
                heads.push(head);
            }
            if heads.len() > layout.preferred_anchor {
                break;
            }
        }

        let Some(next) = address.checked_add(layout.pointer_size) else {
            break;
        };
        address = next;
    }

    // The inline form has exactly one anchor, so the first hit is it. The
    // pointer form has two — the Shimcache and the compatibility-database cache
    // beside it — and which one is which depends on the build.
    sweep.head = match layout.variant {
        ShimVariant::InlineAvlTable => heads.first().copied(),
        ShimVariant::HandlePointer => match heads.get(layout.preferred_anchor) {
            Some(head) => Some(*head),
            None => {
                if !heads.is_empty() {
                    sweep.notes.push(format!(
                        "only {} of the 2 expected SHIM_CACHE_HANDLE structures were found in \
                         .data, and this build keeps the Shimcache in number {}; reporting the \
                         other cache's contents as the Shimcache would be wrong, so neither is \
                         reported",
                        heads.len(),
                        layout.preferred_anchor.saturating_add(1)
                    ));
                }
                None
            }
        },
    };
    sweep
}

/// Validate a `SHIM_CACHE_HANDLE` at `handle` and return its list head.
fn handle_head(
    reader: &StructReader,
    layout: &ShimLayout,
    page: SectionRange,
    handle: u64,
) -> Option<u64> {
    let eresource = reader.read_pointer_at(handle).ok()?;
    let table = reader
        .read_pointer_at(handle.checked_add(layout.pointer_size)?)
        .ok()?;
    if eresource == 0 || table == 0 {
        return None;
    }
    if !eresource_is_valid(reader, layout, eresource) {
        return None;
    }
    if !avl_table_is_valid(reader, layout, page, table) {
        return None;
    }
    let head = table.checked_add(layout.avl_table_size)?;
    if list_head_is_valid(reader, layout, head) {
        Some(head)
    } else {
        None
    }
}

/// Validate an inline `_RTL_AVL_TABLE` at `table` and return its list head.
fn inline_head(
    reader: &StructReader,
    layout: &ShimLayout,
    page: SectionRange,
    table: u64,
) -> Option<u64> {
    if !avl_table_is_valid(reader, layout, page, table) {
        return None;
    }
    // The lock sits immediately in front of the table, rounded down to the
    // allocation alignment. Computed rather than searched for, because a lock
    // found somewhere else in `.data` would validate a table that is not the
    // one it protects.
    let back = layout
        .eresource_size
        .checked_add(table.checked_sub(layout.eresource_size)? % layout.eresource_alignment)?;
    let eresource = table.checked_sub(back)?;
    if !eresource_is_valid(reader, layout, eresource) {
        return None;
    }
    let head = table.checked_add(layout.avl_table_size)?;
    if list_head_is_valid(reader, layout, head) {
        Some(head)
    } else {
        None
    }
}

/// Whether the `_RTL_AVL_TABLE` at `table` is one.
///
/// Four checks, each of which a random eight bytes of `.data` fails:
/// the balanced root's parent points at itself; the three routine pointers land
/// inside the host module's `PAGE` section; and they are three distinct
/// addresses, because a real table has three different routines.
fn avl_table_is_valid(
    reader: &StructReader,
    layout: &ShimLayout,
    page: SectionRange,
    table: u64,
) -> bool {
    let Some(root) = table.checked_add(layout.avl_balanced_root) else {
        return false;
    };
    let Some(parent_at) = table.checked_add(layout.avl_parent) else {
        return false;
    };
    match reader.read_pointer_at(parent_at) {
        Ok(parent) if parent == root => {}
        _ => return false,
    }
    let mut routines = [0u64; 3];
    for (slot, offset) in [layout.avl_compare, layout.avl_allocate, layout.avl_free]
        .into_iter()
        .enumerate()
    {
        let Some(at) = table.checked_add(offset) else {
            return false;
        };
        match reader.read_pointer_at(at) {
            Ok(routine) if page.contains(routine) => routines[slot] = routine,
            _ => return false,
        }
    }
    routines[0] != routines[1] && routines[0] != routines[2] && routines[1] != routines[2]
}

/// Whether the `_ERESOURCE` at `address` is one.
///
/// Mirrors the kernel's own invariants: the resource is on the system resource
/// list with both links pointing back at it, there are no shared waiters, and
/// any shared-waiter semaphore it does name is readable.
fn eresource_is_valid(reader: &StructReader, layout: &ShimLayout, address: u64) -> bool {
    let Some(list) = address.checked_add(layout.eresource_system_list) else {
        return false;
    };
    let (Some(flink_at), Some(blink_at)) = (
        list.checked_add(layout.list_flink),
        list.checked_add(layout.list_blink),
    ) else {
        return false;
    };
    let (Ok(flink), Ok(blink)) = (
        reader.read_pointer_at(flink_at),
        reader.read_pointer_at(blink_at),
    ) else {
        return false;
    };
    if flink == 0 || blink == 0 || flink == blink {
        return false;
    }
    // Both neighbours must point back at this entry, which is what makes it a
    // member of the list rather than eight bytes that look like a pointer.
    let (Some(forward_back), Some(backward_forward)) = (
        flink.checked_add(layout.list_blink),
        blink.checked_add(layout.list_flink),
    ) else {
        return false;
    };
    match (
        reader.read_pointer_at(forward_back),
        reader.read_pointer_at(backward_forward),
    ) {
        (Ok(a), Ok(b)) if a == list && b == list => {}
        _ => return false,
    }

    // A resource protecting a `.data`-resident cache is never held shared at
    // the instant an image is taken with waiters queued on it, and a random
    // sixteen bytes of `.data` almost never reads as zero here.
    let Ok(resource) = reader.object(address, TYPE_ERESOURCE) else {
        return false;
    };
    match resource
        .int("NumberOfSharedWaiters")
        .ok()
        .and_then(|value| value.as_u64())
    {
        Some(0) => {}
        _ => return false,
    }
    let Some(waiters_at) = address.checked_add(layout.eresource_shared_waiters) else {
        return false;
    };
    match reader.read_pointer_at(waiters_at) {
        Ok(0) => true,
        // A non-null shared-waiter pointer must address a readable semaphore.
        Ok(waiters) => reader.read_bytes(waiters, layout.ksemaphore_size).is_ok(),
        Err(_) => false,
    }
}

/// Whether the list head at `head` is a self-consistent `_LIST_ENTRY`.
fn list_head_is_valid(reader: &StructReader, layout: &ShimLayout, head: u64) -> bool {
    let Some(list) = head.checked_add(layout.entry.list_entry) else {
        return false;
    };
    let (Some(flink_at), Some(blink_at)) = (
        list.checked_add(layout.list_flink),
        list.checked_add(layout.list_blink),
    ) else {
        return false;
    };
    let (Ok(flink), Ok(blink)) = (
        reader.read_pointer_at(flink_at),
        reader.read_pointer_at(blink_at),
    ) else {
        return false;
    };
    if flink == 0 || blink == 0 {
        return false;
    }
    // An empty cache links the head to itself, which is a valid head with no
    // entries; a populated one links to a first entry that links back.
    if flink == list && blink == list {
        return true;
    }
    let Some(first_back) = flink.checked_add(layout.list_blink) else {
        return false;
    };
    matches!(reader.read_pointer_at(first_back), Ok(back) if back == list)
}

// ── The walk ────────────────────────────────────────────────────────────────

/// Walk the LRU list from `head`, decoding each entry.
fn walk_list(
    reader: &StructReader,
    layout: &ShimLayout,
    config: &AmcacheConfig,
    head: u64,
    section: &mut ShimSection,
) {
    let Some(head_list) = head.checked_add(layout.entry.list_entry) else {
        push_note(
            &mut section.notes,
            &mut section.notes_total,
            config.max_recorded_notes,
            format!(
                "the Shimcache list head at {head:#x} plus the entry's link offset leaves the \
                 address space, so no entry was read"
            ),
        );
        return;
    };
    let Some(first_at) = head_list.checked_add(layout.list_flink) else {
        push_note(
            &mut section.notes,
            &mut section.notes_total,
            config.max_recorded_notes,
            format!(
                "the forward link of the Shimcache list head at {head:#x} lies past the end of \
                 the address space, so no entry was read"
            ),
        );
        return;
    };
    let mut seen: HashSet<u64> = HashSet::new();
    let mut current = match reader.read_pointer_at(first_at) {
        Ok(first) => first,
        Err(err) => {
            push_note(
                &mut section.notes,
                &mut section.notes_total,
                config.max_recorded_notes,
                format!("the Shimcache list head at {head:#x} could not be followed: {err}"),
            );
            return;
        }
    };

    while current != head_list && current != 0 {
        if !seen.insert(current) {
            push_note(
                &mut section.notes,
                &mut section.notes_total,
                config.max_recorded_notes,
                format!(
                    "the Shimcache list returns to {current:#x}, so it contains a cycle and the \
                     walk stopped there"
                ),
            );
            return;
        }
        section.entries_total = section.entries_total.saturating_add(1);
        if section.entries.len() >= config.max_shim_entries {
            section.truncated = true;
            return;
        }
        // Container arithmetic: the list threads through the entry's own
        // `_LIST_ENTRY`, so the entry starts that member's offset earlier. A
        // link too close to zero to subtract it from is a broken list, not the
        // end of one.
        let Some(entry_address) = current.checked_sub(layout.entry.list_entry) else {
            push_note(
                &mut section.notes,
                &mut section.notes_total,
                config.max_recorded_notes,
                format!(
                    "the Shimcache list link at {current:#x} lies below the entry's own link \
                     offset, so the entry holding it could not be located and the walk stopped \
                     there"
                ),
            );
            return;
        };
        match decode_entry(reader, layout, entry_address, section.entries.len()) {
            Ok(entry) => section.entries.push(entry),
            Err(err) => push_note(
                &mut section.notes,
                &mut section.notes_total,
                config.max_recorded_notes,
                format!("the Shimcache entry at {entry_address:#x} could not be read: {err}"),
            ),
        }

        let Some(next_at) = current.checked_add(layout.list_flink) else {
            push_note(
                &mut section.notes,
                &mut section.notes_total,
                config.max_recorded_notes,
                format!(
                    "the forward link of the Shimcache entry at {current:#x} lies past the end of \
                     the address space, so entries after it are not listed"
                ),
            );
            return;
        };
        match reader.read_pointer_at(next_at) {
            Ok(next) => current = next,
            Err(err) => {
                push_note(
                    &mut section.notes,
                    &mut section.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "the Shimcache list could not be followed past {current:#x}, so entries \
                         after it are not listed: {err}"
                    ),
                );
                return;
            }
        }
    }

    // A `_LIST_ENTRY` list is circular: it ends by arriving back at its head.
    // Arriving at a null link instead means the chain was broken — by smear, or
    // by an entry being unlinked — and the entries beyond the break were never
    // reached. Leaving that unsaid would let the cache read as fully enumerated.
    if current == 0 {
        push_note(
            &mut section.notes,
            &mut section.notes_total,
            config.max_recorded_notes,
            format!(
                "the Shimcache list from {head:#x} reached a null forward link instead of \
                 returning to its head, so it does not close and any entry past the break is not \
                 listed"
            ),
        );
    }
}

/// Decode one `SHIM_CACHE_ENTRY`.
///
/// Public so a test can drive it against a hand-built entry at a known address
/// and prove that each build's layout reads the fields it claims to.
///
/// # Errors
///
/// [`ObjError`] when the entry's own bytes could not be read, which disqualifies
/// the whole entry. A *field* that could not be read is not an error: it becomes
/// a [`Field::Unreadable`] and the rest of the entry still reaches the report.
pub fn decode_entry(
    reader: &StructReader,
    layout: &ShimLayout,
    address: u64,
    order: usize,
) -> Result<ShimEntry, ObjError> {
    let raw = reader.read_bytes(address, layout.entry.size)?;
    let mut entry = ShimEntry {
        address,
        order,
        path: Field::Absent,
        last_modified: Field::NotApplicable,
        executed: Field::NotApplicable,
        file_size: Field::NotApplicable,
        notes: Vec::new(),
    };

    entry.path = match address.checked_add(layout.entry.path) {
        Some(at) => read_path(reader, at),
        None => Field::Unparsable("the entry's path offset does not fit in 64 bits".into()),
    };

    if let Some(offset) = layout.entry.last_modified {
        entry.last_modified = filetime_field(&raw, offset, "LastModified");
    }
    if let Some(offset) = layout.entry.insert_flags {
        entry.executed = insert_flag_field(&raw, offset);
    }
    if let Some((offset, width)) = layout.entry.file_size {
        entry.file_size = match width {
            4 => match u32_at(&raw, offset as usize) {
                Some(size) => Field::Present(u64::from(size)),
                None => Field::Unreadable("the entry is shorter than its FileSize field".into()),
            },
            8 => match u64_at(&raw, offset as usize) {
                Some(size) => Field::Present(size),
                None => Field::Unreadable("the entry is shorter than its FileSize field".into()),
            },
            other => Field::Unparsable(format!("a FileSize of {other} byte(s) is not a size")),
        };
    }

    if let (Some(pointer_offset), Some(detail_layout)) =
        (layout.entry.detail_pointer, layout.entry.detail)
    {
        decode_detail(
            reader,
            layout,
            &detail_layout,
            &raw,
            pointer_offset,
            &mut entry,
        );
    }
    Ok(entry)
}

/// Read the fields that live in a separately allocated detail record.
fn decode_detail(
    reader: &StructReader,
    layout: &ShimLayout,
    detail: &ShimDetailLayout,
    raw: &[u8],
    pointer_offset: u64,
    entry: &mut ShimEntry,
) {
    let Some(pointer) =
        crate::amcache::pointer_at(raw, pointer_offset as usize, layout.pointer_size)
    else {
        entry.last_modified =
            Field::Unreadable("the entry is shorter than its detail pointer".into());
        return;
    };
    if pointer == 0 {
        entry.last_modified = Field::Absent;
        entry.executed = Field::Absent;
        entry
            .notes
            .push("the entry names no detail record, so it carries no timestamp".to_string());
        return;
    }
    // The largest offset the detail record is read at, plus its width, is how
    // many bytes have to be present.
    let span = [
        Some(detail.last_modified.saturating_add(8)),
        detail.insert_flags.map(|off| off.saturating_add(4)),
        detail
            .blob_size
            .map(|(off, width)| off.saturating_add(width)),
        detail
            .blob_buffer
            .map(|(off, width)| off.saturating_add(width)),
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(8);

    let bytes = match reader.read_bytes(pointer, span) {
        Ok(bytes) => bytes,
        Err(err) => {
            let detail_reason = format!("the detail record at {pointer:#x} is not readable: {err}");
            entry.last_modified = Field::Unreadable(detail_reason.clone());
            entry.executed = Field::Unreadable(detail_reason);
            return;
        }
    };

    entry.last_modified = filetime_field(&bytes, detail.last_modified, "LastModified");

    entry.executed = match detail.insert_flags {
        Some(offset) => insert_flag_field(&bytes, offset),
        // Windows 10 x64 dropped `InsertFlags` and moved the execution flag
        // into the first four bytes of the shim blob. A blob that is shorter
        // than four bytes says nothing about execution and must not be read as
        // "it did not execute".
        None => match (detail.blob_size, detail.blob_buffer) {
            (Some((size_offset, size_width)), Some((buffer_offset, buffer_width))) => {
                execution_from_blob(
                    reader,
                    &bytes,
                    size_offset,
                    size_width,
                    buffer_offset,
                    buffer_width,
                )
            }
            _ => Field::NotApplicable,
        },
    };
}

/// Read the execution flag out of the shim blob a detail record points at.
fn execution_from_blob(
    reader: &StructReader,
    bytes: &[u8],
    size_offset: u64,
    size_width: u64,
    buffer_offset: u64,
    buffer_width: u64,
) -> Field<bool> {
    let size = match size_width {
        4 => u32_at(bytes, size_offset as usize).map(u64::from),
        8 => u64_at(bytes, size_offset as usize),
        _ => None,
    };
    let Some(size) = size else {
        return Field::Unreadable("the detail record is shorter than its BlobSize field".into());
    };
    let Some(buffer) = crate::amcache::pointer_at(bytes, buffer_offset as usize, buffer_width)
    else {
        return Field::Unreadable("the detail record is shorter than its BlobBuffer field".into());
    };
    if buffer == 0 || size == 0 {
        return Field::Absent;
    }
    if size < 4 {
        return Field::Unparsable(format!(
            "the shim blob is {size} byte(s) long and the execution flag is a 4-byte value"
        ));
    }
    match reader.read_bytes(buffer, 4) {
        Ok(blob) => match u32_at(&blob, 0) {
            Some(flag) => Field::Present(flag != 0),
            None => Field::Unreadable("the shim blob's first 4 bytes were not returned".into()),
        },
        Err(err) => Field::Unreadable(format!(
            "the shim blob at {buffer:#x} is not readable: {err}"
        )),
    }
}

/// Read a FILETIME out of an already-read buffer.
fn filetime_field(bytes: &[u8], offset: u64, what: &str) -> Field<WinTime> {
    let Some(raw) = u64_at(bytes, offset as usize) else {
        return Field::Unreadable(format!(
            "the structure is shorter than its {what} field at offset {offset:#x}"
        ));
    };
    match WinTime::from_filetime(raw) {
        Some(time) => Field::Present(time),
        None if raw == 0 => Field::Unset,
        None => Field::Unparsable(format!(
            "{what} holds the FILETIME {raw}, which is before 1970 and so is not a time this \
             machine recorded"
        )),
    }
}

/// Read the execution bit out of an `InsertFlags` field.
fn insert_flag_field(bytes: &[u8], offset: u64) -> Field<bool> {
    match u32_at(bytes, offset as usize) {
        Some(flags) => {
            Field::Present(u64::from(flags) & INSERT_FLAG_EXECUTED == INSERT_FLAG_EXECUTED)
        }
        None => Field::Unreadable(format!(
            "the structure is shorter than its InsertFlags field at offset {offset:#x}"
        )),
    }
}

/// Read a `_UNICODE_STRING` at `address` as a path.
///
/// The four rules a naive reader gets wrong, each of which has produced a wrong
/// answer in a real tool: `Length` is a byte count and not a character count;
/// the length is capped before anything is allocated; `MaximumLength` below
/// `Length` means the structure is not a string; and no NUL termination is
/// assumed.
fn read_path(reader: &StructReader, address: u64) -> Field<String> {
    let object = match reader.object(address, TYPE_UNICODE_STRING) {
        Ok(object) => object,
        Err(err) => return Field::Unreadable(format!("the path structure is unreadable: {err}")),
    };
    let length = match object.int("Length").ok().and_then(|value| value.as_u64()) {
        Some(length) => length,
        None => return Field::Unreadable("the path's Length could not be read".into()),
    };
    if length == 0 {
        return Field::Unset;
    }
    if length % 2 != 0 {
        return Field::Unparsable(format!(
            "the path declares {length} byte(s) of UTF-16, which is not a whole number of units"
        ));
    }
    if length > MAX_PATH_BYTES {
        return Field::Unparsable(format!(
            "the path declares {length} byte(s), more than the {MAX_PATH_BYTES} a cached path can \
             hold, so the structure is not a path"
        ));
    }
    if let Some(maximum) = object
        .int("MaximumLength")
        .ok()
        .and_then(|value| value.as_u64())
    {
        if maximum < length {
            return Field::Unparsable(format!(
                "the path declares {length} byte(s) of text in a buffer of {maximum}"
            ));
        }
    }
    let buffer = match object.pointer("Buffer") {
        Ok(0) => {
            return Field::Unparsable(format!(
                "the path declares {length} byte(s) of text and a null buffer"
            ))
        }
        Ok(buffer) => buffer,
        Err(err) => {
            return Field::Unreadable(format!("the path's Buffer could not be read: {err}"))
        }
    };
    match reader.read_bytes(buffer, length) {
        Ok(bytes) => {
            let text = crate::poolscan::decode_utf16le(&bytes);
            // A cached path is a file path, and no file path contains a NUL, an
            // unpaired surrogate or a control character. Text that does is a
            // torn or reused entry, and publishing the decode would put a path
            // in the report that an examiner would go looking for on the disk.
            // The same rule the `_UNICODE_STRING` reader applies — this reader
            // walks the same two members by hand.
            match crate::poolscan::name_damage(&text) {
                None => Field::Present(text),
                Some(damage) => Field::Unparsable(format!(
                    "the path's {length} byte(s) at {buffer:#x} decode to text in which {damage}, \
                     so these bytes are not the path they were read as"
                )),
            }
        }
        Err(err) => Field::Unreadable(format!(
            "the path's {length} byte(s) at {buffer:#x} could not be read: {err}"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::amcache::test_support::{
        inline_shim_fixture, shim_fixture, shim_profile_with_type_renamed, ShimFixture,
    };
    use crate::registry::test_support::xp_profile;

    #[test]
    fn every_catalogued_build_band_selects_a_distinct_layout() {
        let names: Vec<&str> = [
            (22_000u32, true),
            (19_041, false),
            (9_600, true),
            (9_200, false),
            (7_601, true),
            (7_600, false),
            (6_002, true),
            (6_000, false),
            (3_790, true),
            (3_790, false),
        ]
        .into_iter()
        .map(|(build, wide)| {
            entry_layout_for(build, wide)
                .unwrap_or_else(|| panic!("build {build} must have a layout"))
                .name
        })
        .collect();
        let mut unique = names.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), names.len(), "{names:?}");
    }

    #[test]
    fn windows_xp_is_refused_by_name_rather_than_read_with_the_nearest_layout() {
        // XP x86 is build 2600. Reading it with the 2003 layout would produce a
        // full list of paths from the wrong offsets.
        assert!(entry_layout_for(2_600, false).is_none());
        assert!(entry_layout_for(2_600, true).is_none());
        // A build below every catalogued release is refused too.
        assert!(entry_layout_for(1, false).is_none());
        // And Server 2003, which *is* catalogued, is not.
        assert!(entry_layout_for(3_790, false).is_some());
    }

    #[test]
    fn a_layout_that_disagrees_with_this_builds_structures_is_refused() {
        let layout = entry_layout_for(19_041, true).expect("Windows 10 x64 is catalogued");
        // The sizes it was written against: a 16-byte _LIST_ENTRY and a
        // 16-byte _UNICODE_STRING.
        assert!(layout.agrees_with(16, 16).is_ok());
        // A build whose _UNICODE_STRING is bigger would put the detail pointer
        // inside the string, so the layout is not describing it.
        let err = layout
            .agrees_with(16, 24)
            .expect_err("a 24-byte _UNICODE_STRING must be refused");
        assert!(err.contains("detail pointer"), "{err}");
        // A 32-bit _LIST_ENTRY under a 64-bit layout leaves the path inside it
        // only if the path offset is small; the size check catches the rest.
        let x86 = entry_layout_for(19_041, false).expect("Windows 10 x86 is catalogued");
        let err = x86
            .agrees_with(8, 16)
            .expect_err("a 16-byte _UNICODE_STRING does not fit the x86 entry");
        assert!(err.contains("not for this build"), "{err}");
    }

    #[test]
    fn the_build_that_keeps_its_cache_in_the_first_handle_is_the_only_one_that_does() {
        // Windows 8.0 x64 (build 9200) is the exception; 8.0 x86, 8.1 and 10
        // all use the second handle.
        assert_eq!(preferred_anchor(ShimVariant::HandlePointer, 9_200, true), 0);
        assert_eq!(
            preferred_anchor(ShimVariant::HandlePointer, 9_200, false),
            1
        );
        assert_eq!(preferred_anchor(ShimVariant::HandlePointer, 9_600, true), 1);
        assert_eq!(
            preferred_anchor(ShimVariant::HandlePointer, 19_041, true),
            1
        );
        // The inline form has one anchor, so the answer is always the first —
        // including on the 64-bit builds where the pointer form would say zero
        // for a different reason.
        assert_eq!(
            preferred_anchor(ShimVariant::InlineAvlTable, 7_601, true),
            0
        );
        assert_eq!(
            preferred_anchor(ShimVariant::InlineAvlTable, 7_601, false),
            0
        );
    }

    /// Every size this layout takes goes through one closure, so proving the
    /// sentence once proves it for `_LIST_ENTRY` and `_UNICODE_STRING` too —
    /// and `_RTL_AVL_TABLE` is the one of the three that nothing in the fixture
    /// embeds by value, so it can be taken away without making the fixture
    /// describe a kernel that could not exist.
    ///
    /// Fatal is right: these types are on every Windows kernel from XP onward,
    /// so a table that cannot size one is a table this analysis could not read,
    /// and the catalogued entry layout is cross-checked against those widths.
    /// The sentence has to say that, because the caller keeps it as the reason
    /// the Shimcache half is missing from a report that still lists the Amcache
    /// half.
    #[test]
    fn a_type_the_sweep_measures_against_is_refused_saying_what_could_not_be_read() {
        let profile = shim_profile_with_type_renamed("_RTL_AVL_TABLE");
        let err = ShimLayout::from_profile(&profile)
            .expect_err("a table that cannot size the AVL table cannot place the cache");
        assert!(err.contains("_RTL_AVL_TABLE"), "{err}");
        assert!(
            err.contains("no Shimcache row could be read at a defensible offset"),
            "the refusal must say what it cost: {err}"
        );
    }

    #[test]
    fn windows_xp_is_refused_at_layout_resolution_with_a_reason_an_examiner_can_act_on() {
        // The registry fixture's profile carries build 2600, which is XP.
        let profile = xp_profile();
        let err = ShimLayout::from_profile(&profile)
            .expect_err("Windows XP has no kernel-mode Shimcache this stage reads");
        assert!(err.contains("csrss"), "{err}");
    }

    #[test]
    fn the_whole_sweep_finds_the_cache_and_reads_every_entry_in_order() {
        let ShimFixture {
            profile,
            expected_paths,
            ..
        } = shim_fixture();
        let layout = ShimLayout::from_profile(&profile).expect("the fixture is a catalogued build");
        let section = read_shimcache(&profile, &layout, &AmcacheConfig::default());

        assert_eq!(section.status, ShimStatus::Read, "{:?}", section.notes);
        assert_eq!(section.host_module.as_deref(), Some("ahcache.sys"));
        assert_eq!(section.entries_total, expected_paths.len());
        let paths: Vec<String> = section
            .entries
            .iter()
            .map(|entry| entry.path.value().cloned().unwrap_or_default())
            .collect();
        assert_eq!(paths, expected_paths);
        // The LRU order is evidence, so it is preserved and numbered.
        for (index, entry) in section.entries.iter().enumerate() {
            assert_eq!(entry.order, index);
        }
        assert!(section.is_complete(), "{:?}", section.incomplete());
    }

    #[test]
    fn the_pre_windows_eight_anchor_is_found_by_computing_where_its_lock_must_be() {
        // Windows 7 keeps the table inline in the kernel's own `.data` with the
        // `_ERESOURCE` at a *computed* offset in front of it, which is a
        // different discovery path from the Windows 8 handle pointer and would
        // otherwise never be run.
        let ShimFixture {
            profile,
            expected_paths,
            expected_modified,
            ..
        } = inline_shim_fixture();
        let layout = ShimLayout::from_profile(&profile).expect("Windows 7 x64 is catalogued");
        assert_eq!(layout.variant, ShimVariant::InlineAvlTable);
        assert_eq!(layout.entry.name, "windows-7-x64");
        assert_eq!(layout.host_modules, SHIMCACHE_KERNEL_MODULES);

        let section = read_shimcache(&profile, &layout, &AmcacheConfig::default());
        assert_eq!(section.status, ShimStatus::Read, "{:?}", section.notes);
        assert_eq!(section.host_module.as_deref(), Some("ntoskrnl.exe"));
        let paths: Vec<String> = section
            .entries
            .iter()
            .map(|entry| entry.path.value().cloned().unwrap_or_default())
            .collect();
        assert_eq!(paths, expected_paths);
        // This build stores the timestamp and the flags inline, so a reader
        // that went looking for a detail record would find a pointer that is
        // really the top half of a FILETIME.
        assert_eq!(
            section.entries[0].last_modified.value().map(|t| t.filetime),
            Some(expected_modified)
        );
        assert_eq!(section.entries[0].executed, Field::Present(true));
        assert_eq!(section.entries[1].executed, Field::Present(false));
        assert!(section.is_complete(), "{:?}", section.incomplete());
    }

    #[test]
    fn an_entry_that_executed_is_distinguished_from_one_that_only_was_examined() {
        let ShimFixture { profile, .. } = shim_fixture();
        let layout = ShimLayout::from_profile(&profile).expect("a catalogued build");
        let section = read_shimcache(&profile, &layout, &AmcacheConfig::default());

        let executed: Vec<Option<bool>> = section
            .entries
            .iter()
            .map(|entry| entry.executed.value().copied())
            .collect();
        assert_eq!(executed, vec![Some(true), Some(false), None]);
        // The third entry's blob was not readable, which must not read as
        // "the file did not execute".
        assert_eq!(section.entries[2].executed.status(), "unreadable");
        assert!(!section.entries[2].executed.absence_is_a_fact());
    }

    #[test]
    fn a_timestamp_is_read_from_the_detail_record_and_not_from_the_entry() {
        let ShimFixture {
            profile,
            expected_modified,
            ..
        } = shim_fixture();
        let layout = ShimLayout::from_profile(&profile).expect("a catalogued build");
        let section = read_shimcache(&profile, &layout, &AmcacheConfig::default());
        assert_eq!(
            section.entries[0]
                .last_modified
                .value()
                .map(|time| time.filetime),
            Some(expected_modified)
        );
        // Server 2003 records no execution flag at all, and Windows 10 records
        // no file size; neither may render as zero.
        assert_eq!(section.entries[0].file_size, Field::NotApplicable);
    }

    #[test]
    fn the_entry_cap_stops_the_walk_and_says_the_list_continues() {
        let ShimFixture { profile, .. } = shim_fixture();
        let layout = ShimLayout::from_profile(&profile).expect("a catalogued build");
        let config = AmcacheConfig {
            max_shim_entries: 1,
            ..AmcacheConfig::default()
        };
        let section = read_shimcache(&profile, &layout, &config);
        assert_eq!(section.entries.len(), 1);
        assert!(section.truncated);
        assert!(!section.is_complete());
        assert!(section
            .incomplete()
            .iter()
            .any(|item| item.detail.contains("the list continues")));
    }

    #[test]
    fn a_probe_cap_makes_the_absence_of_a_cache_inconclusive() {
        let ShimFixture { profile, .. } = shim_fixture();
        let layout = ShimLayout::from_profile(&profile).expect("a catalogued build");
        let config = AmcacheConfig {
            max_shim_probes: 1,
            ..AmcacheConfig::default()
        };
        let section = read_shimcache(&profile, &layout, &config);
        assert_eq!(
            section.status,
            ShimStatus::NotFound {
                search_complete: false
            }
        );
        assert!(!section.is_complete());
        assert!(section.incomplete().iter().any(|item| item
            .detail
            .contains("may have been in the part that was missed")));
    }

    #[test]
    fn a_pe_section_table_is_walked_with_every_field_bounds_checked() {
        let ShimFixture {
            profile,
            module_base,
            data_section,
            page_section,
            ..
        } = shim_fixture();
        let reader = kernel_reader(&profile);
        assert_eq!(
            section_range(&reader, module_base, DATA_SECTION).expect("headers are readable"),
            Some(data_section)
        );
        assert_eq!(
            section_range(&reader, module_base, PAGE_SECTION).expect("headers are readable"),
            Some(page_section)
        );
        // A section this image does not have is absent, not an error.
        assert_eq!(
            section_range(&reader, module_base, ".nosuch").expect("headers are readable"),
            None
        );
        // An address that is not a PE at all is absent, not an error.
        assert_eq!(
            section_range(&reader, 0x100, DATA_SECTION).expect("the bytes are readable"),
            None
        );
    }

    #[test]
    fn a_section_range_answers_containment_without_including_its_end() {
        let range = SectionRange {
            start: 0x1000,
            end: 0x2000,
        };
        assert!(range.contains(0x1000));
        assert!(range.contains(0x1FFF));
        assert!(!range.contains(0x2000));
        assert_eq!(range.len(), 0x1000);
        assert!(!range.is_empty());
        assert!(SectionRange {
            start: 0x1000,
            end: 0x1000
        }
        .is_empty());
    }

    /// A `_LIST_ENTRY` list closes by returning to its head. A walk that ends
    /// at a null forward link has hit a break, and the entries past the break
    /// were never reached.
    ///
    /// Ending the walk silently there lets the section report as fully
    /// enumerated, and a report is then entitled to write "this machine has no
    /// record of that program having run" on the strength of a list that was
    /// cut in half.
    #[test]
    fn a_shimcache_list_that_ends_at_a_null_link_says_it_did_not_close() {
        let fixture = shim_fixture();
        let layout = ShimLayout::from_profile(&fixture.profile).expect("the build is catalogued");
        let reader = kernel_reader(&fixture.profile);
        let mut section = ShimSection::unavailable("replaced by the walk below");

        // A head in zeroed memory: its forward link reads as null, which is a
        // broken chain rather than the end of a circular one.
        walk_list(
            &reader,
            &layout,
            &AmcacheConfig::default(),
            0x0500,
            &mut section,
        );

        assert!(section.entries.is_empty());
        assert!(
            section
                .notes
                .iter()
                .any(|note| note.contains("null forward link")),
            "a broken list must say so: {:?}",
            section.notes
        );
        assert_eq!(section.notes_total, 1);
    }

    /// The same rule for a chain whose next link cannot be located at all.
    #[test]
    fn a_shimcache_head_whose_link_leaves_the_address_space_is_not_silent() {
        let fixture = shim_fixture();
        let mut layout =
            ShimLayout::from_profile(&fixture.profile).expect("the build is catalogued");
        // A link offset that no address can be added to without wrapping.
        layout.entry.list_entry = u64::MAX;
        let reader = kernel_reader(&fixture.profile);
        let mut section = ShimSection::unavailable("replaced by the walk below");

        walk_list(
            &reader,
            &layout,
            &AmcacheConfig::default(),
            0x0500,
            &mut section,
        );

        assert!(section.entries.is_empty());
        assert_eq!(
            section.notes_total, 1,
            "a walk that could not start must record why: {:?}",
            section.notes
        );
        assert!(
            section.notes[0].contains("leaves the address space"),
            "{:?}",
            section.notes
        );
    }
}
