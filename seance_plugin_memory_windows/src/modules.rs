//! Loaded DLLs and kernel drivers: what code was mapped into a process, and
//! what code the kernel itself had loaded.
//!
//! Three questions, three walks, one structure underneath all of them.
//!
//! * **`dlllist`** — for one process: `_EPROCESS.Peb` → `_PEB.Ldr` →
//!   `_PEB_LDR_DATA.InLoadOrderModuleList`, a circular `_LIST_ENTRY` chain of
//!   `_LDR_DATA_TABLE_ENTRY`. Each entry names a mapped image: its base, its
//!   size, its full path and its base name. This is the loader's own record of
//!   what it loaded, and it is read through the **process's** address space,
//!   because a PEB address means nothing in the kernel's.
//! * **`ldrmodules`** — the same three lists the loader keeps, cross-referenced
//!   against the VAD tree. The loader unlinks nothing; a rootkit does. A module
//!   that has a VAD but is missing from one or more of the PEB lists has been
//!   **unlinked**, and finding that is the whole reason this stage exists.
//! * **`modules`** — the kernel's own list, from the `PsLoadedModuleList`
//!   symbol, the same `_LDR_DATA_TABLE_ENTRY` shape, in kernel space. Drivers.
//!
//! # The three lists are three *different* members
//!
//! `_PEB_LDR_DATA` holds three heads — `InLoadOrderModuleList`,
//! `InMemoryOrderModuleList` and `InInitializationOrderModuleList` — and each
//! one threads through a **different** `_LIST_ENTRY` inside
//! `_LDR_DATA_TABLE_ENTRY`: `InLoadOrderLinks` at the top of the structure,
//! `InMemoryOrderLinks` one link further in, `InInitializationOrderLinks` one
//! further still. The `CONTAINING_RECORD` subtraction is therefore a different
//! constant for each list.
//!
//! Reusing one link member for all three walks does not fail loudly. Two of the
//! three would start from the right head, subtract the wrong offset, and land
//! on addresses that are not entries at all — or, on the shape most tools get
//! wrong, would simply walk the load-order chain three times and report every
//! module as present in every list. Either way the `InInit` and `InMem` columns
//! become decoration, an unlinked module reads as perfectly linked, and the one
//! finding this stage is for is silently destroyed. [`LdrListLayout`] pairs
//! each head with its own link member so the two cannot drift apart, and
//! [`ModuleSymbols::from_profile`] resolves all three from the symbol table.
//!
//! # Absence has to be earned
//!
//! "This module is not in the initialisation-order list" is an accusation. It
//! is only true if that list was walked *to its end* and every entry's
//! `DllBase` was readable. A walk that hit a cycle, a cap or an unacquired page
//! cannot support it, and neither can a list whose entries were partly
//! unreadable. [`LdrListWalk::contains`] returns `Option<bool>`: `None` is
//! "this image cannot say", and it never renders as "missing".
//!
//! # Paths are `_UNICODE_STRING`
//!
//! `Length` counts **bytes** of UTF-16LE, the buffer is not NUL terminated, and
//! the length came out of the image so it is capped before anything is
//! allocated. All of that lives in [`crate::poolscan::unicode_string`] and is
//! used here rather than re-derived.

// `Wow64Loader::Walked` carries the walked lists and is much larger than
// `NotWow64`. Boxing it would put an allocation on the common path of a
// per-process walk to save stack on a value that is moved once, and would
// change every match site in this module and its callers. The size is
// deliberate, not an oversight.
#![allow(clippy::large_enum_variant)]

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::object::{ListSpec, ListStop, Obj, ObjError, StructReader};
use seance_memory::translate::{
    PagingMode, PagingSpec, PteSemantics, TableCache, TranslateError, TranslationPolicy,
    VirtualLayer,
};
use seance_memory::{Architecture, Incomplete, MemoryLayer};
use seance_symbols::SymbolError;

use crate::poolscan::unicode_string;
use crate::process::{PageBacking, PageProvenance, SpaceProvenance};
use crate::profile::WindowsProfile;
use crate::vad::{MappedFile, VadTree};

// ── Names this stage reads through ──────────────────────────────────────────

/// The process structure a PEB hangs off.
pub const TYPE_EPROCESS: &str = "_EPROCESS";

/// The user-mode process environment block.
pub const TYPE_PEB: &str = "_PEB";

/// The loader's own record inside the PEB.
pub const TYPE_PEB_LDR_DATA: &str = "_PEB_LDR_DATA";

/// One loaded image, in a process or in the kernel.
pub const TYPE_LDR_DATA_TABLE_ENTRY: &str = "_LDR_DATA_TABLE_ENTRY";

/// The structure `_EPROCESS.WoW64Process` points at from Windows 10 1511.
///
/// On earlier builds that member points straight at the 32-bit PEB. Which of
/// the two a build uses decides where the 32-bit loader is, and getting it
/// wrong reads a page that is not a PEB.
pub const TYPE_EWOW64PROCESS: &str = "_EWOW64PROCESS";

/// The kernel-only form of the loader entry, present from Windows 10.
///
/// Same leading members as [`TYPE_LDR_DATA_TABLE_ENTRY`]; preferred for the
/// kernel's list when the build declares it, as upstream does.
pub const TYPE_KLDR_DATA_TABLE_ENTRY: &str = "_KLDR_DATA_TABLE_ENTRY";

/// The doubly-linked list link every one of these lists is built from.
pub const TYPE_LIST_ENTRY: &str = "_LIST_ENTRY";

/// The forward-link member of a `_LIST_ENTRY`.
pub const LIST_FORWARD: &str = "Flink";

/// Symbol naming the head of the kernel's loaded-module list.
pub const SYMBOL_PS_LOADED_MODULE_LIST: &str = "PsLoadedModuleList";

/// `MZ`, the first two bytes of every PE image.
///
/// A memory range whose first page does not begin with this is not a mapped
/// image, so it is not a module and its absence from the loader's lists says
/// nothing at all.
pub const DOS_SIGNATURE: [u8; 2] = *b"MZ";

/// Ceiling on entries one module-list walk will return.
///
/// A busy Windows 11 machine has about 160 kernel modules and rarely more than
/// 300 DLLs in any one process. Reaching this means the link chain is wrong,
/// and it is reported as a cap rather than as the end of the list.
pub const MAX_MODULES: usize = 8_192;

/// Ceiling on individually recorded notes. The *count* stays exact.
pub const MAX_RECORDED_NOTES: usize = 256;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops a module walk before it can produce a list worth
/// reading.
///
/// Note what is *not* here: a process whose PEB is paged out, an entry whose
/// name could not be read, a list that ended in a cycle. Those are facts about
/// one process or one entry, and they land in [`LoaderData`], [`NameField`] and
/// [`LdrListWalk::stop`] where an examiner can see them.
#[derive(Debug, thiserror::Error)]
pub enum ModulesError {
    /// This build cannot be walked with what is available, and no partial
    /// answer would be honest. The message names what is missing.
    #[error("the loaded-module lists cannot be walked on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// A VAD tree belonging to a different process was supplied.
    ///
    /// Cross-referencing one process's loader lists against another process's
    /// memory ranges would report every module as unlinked, which is the worst
    /// wrong answer this stage can give.
    #[error(
        "the VAD tree supplied belongs to the process at {supplied:#x}, not to the process at \
         {process:#x}, so its ranges cannot be cross-referenced against this loader"
    )]
    WrongProcess {
        /// The process being analysed.
        process: u64,
        /// The process the supplied tree belongs to.
        supplied: u64,
    },

    /// A typed read failed for a reason that invalidates the whole walk rather
    /// than one entry.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question the walk depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// The process's own address space could not be built from its directory
    /// table base.
    #[error("the process's address space could not be built: {0}")]
    Space(#[from] TranslateError),
}

impl ModulesError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            ModulesError::Unsupported { .. } => "unsupported_build",
            ModulesError::WrongProcess { .. } => "wrong_process",
            ModulesError::Object(err) => err.class(),
            ModulesError::Symbols(_) => "symbols",
            ModulesError::Space(_) => "address_space",
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            ModulesError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be walked" refusal.
    pub fn unsupported(detail: impl Into<String>) -> ModulesError {
        ModulesError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Resolve the first of `candidates` that this build's `type_name` actually has.
///
/// This module used to carry its own copy, which returned a bare `Option` built
/// from `member_offset(..).is_ok()` and so reported "the symbol table could not
/// answer" as "this build has no such member". Those are opposite claims and the
/// shared helper keeps them apart; there is one definition of it so the two
/// cannot drift.
use seance_memory::binding::first_member;

/// As [`first_member`], but a build that has none of them is a refusal naming
/// every candidate that was tried.
fn require_member(
    reader: &StructReader,
    type_name: &str,
    candidates: &[&str],
    what: &str,
) -> Result<String, ModulesError> {
    Ok(first_member(reader, type_name, candidates)?
        .ok_or_else(|| {
            ModulesError::unsupported(format!(
                "'{type_name}' has none of {candidates:?}, so {what} cannot be read"
            ))
        })?
        .to_string())
}

/// One of the loader's three lists: where its head is, and which link inside an
/// entry it threads through.
///
/// The pairing is the point. A head without its matching link member is not
/// half an answer, it is a walk that lands on addresses which are not entries;
/// keeping the two together means they cannot be mismatched by a caller that
/// copies one line and forgets the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LdrListLayout {
    /// The `_PEB_LDR_DATA` member holding this list's head. The head is
    /// *embedded*, so its address is the member's address and not a value read
    /// out of it.
    pub head: String,
    /// The `_LDR_DATA_TABLE_ENTRY` member this list is linked through.
    /// **Different for each of the three lists.**
    pub links: String,
}

/// Everything the user-mode side of this stage needs, when the build has it.
#[derive(Debug, Clone)]
pub struct PebLayout {
    /// `_EPROCESS` member holding the pointer to the process environment block.
    pub peb: String,
    /// `_PEB` member holding the pointer to the loader's data.
    pub ldr: String,
    /// The load-order list. Required: without it there is no DLL list.
    pub load: LdrListLayout,
    /// The memory-order list, when this build declares both its head and its
    /// link member.
    pub memory: Option<LdrListLayout>,
    /// The initialisation-order list, likewise.
    pub init: Option<LdrListLayout>,
}

/// The member paths and addresses this build's module lists are read through.
///
/// Resolved once per image, so a build whose layout the symbols cannot describe
/// fails here naming the members that were tried, rather than at entry three
/// hundred having already emitted rows read at the wrong offsets.
#[derive(Debug, Clone)]
pub struct ModuleSymbols {
    /// The loader entry type used for a process's own lists. Always
    /// [`TYPE_LDR_DATA_TABLE_ENTRY`]: the kernel-only form never appears in a
    /// PEB.
    pub user_entry_type: String,
    /// The loader entry type used for the kernel's list:
    /// [`TYPE_KLDR_DATA_TABLE_ENTRY`] when this build declares it with the
    /// members this stage reads, and [`TYPE_LDR_DATA_TABLE_ENTRY`] otherwise.
    pub kernel_entry_type: String,
    /// Entry member holding the image's base address.
    pub base: String,
    /// Entry member holding the image's size.
    pub size_of_image: String,
    /// Entry member holding the full path.
    pub full_name: String,
    /// Entry member holding the base name.
    pub base_name: String,
    /// The link member the kernel's `PsLoadedModuleList` threads through.
    pub kernel_links: String,
    /// Where the kernel's loaded-module list head is, in kernel virtual space.
    /// `None` when this build's symbols do not name it.
    pub ps_loaded_module_list: Option<u64>,
    /// Path from `_EPROCESS` to the directory table base, and whether that
    /// member is an array. 32-bit Windows declares it as a two-element array
    /// whose first element is the base and whose second is the hyperspace PTE;
    /// 64-bit declares a single value. Reading the array as one wide integer
    /// takes the hyperspace PTE into the high half.
    pub directory_table_base: Option<(String, bool)>,
    /// The user-mode side, when this build declares a PEB at all.
    pub peb: Option<PebLayout>,
    /// Why [`ModuleSymbols::peb`] is absent, when it is. Carried so the refusal
    /// an examiner sees names the missing member rather than saying "no DLLs".
    pub peb_unavailable: Option<String>,
    /// `_EPROCESS` member holding the WOW64 block, spelled `Wow64Process` on
    /// Windows 7 and `WoW64Process` on Windows 10. `None` on a build that
    /// declares neither, which is a 32-bit kernel that cannot host a WOW64
    /// process at all.
    pub wow64: Option<String>,
    /// `_EWOW64PROCESS` member holding the 32-bit PEB, on the builds where the
    /// WOW64 member points at that structure rather than straight at the PEB.
    ///
    /// Windows 10 1511 introduced `_EWOW64PROCESS`; before it, the pointer in
    /// `_EPROCESS` *is* the 32-bit PEB. Reading one as the other lands on the
    /// wrong page and produces a module list that is entirely fiction.
    pub ewow64_peb: Option<String>,
}

impl ModuleSymbols {
    /// Resolve every layout fact the module walks of this image need.
    ///
    /// # Errors
    ///
    /// [`ModulesError::Unsupported`] naming the members that were tried, when
    /// this build declares no loader entry type or no link member. The
    /// *user-mode* side failing is not an error here: it becomes
    /// [`ModuleSymbols::peb_unavailable`] and only the stages that need it
    /// refuse, so an image whose `_PEB` is missing can still list drivers.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, ModulesError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );

        if !profile.symbols.has_type(TYPE_LDR_DATA_TABLE_ENTRY) {
            return Err(ModulesError::unsupported(format!(
                "the symbol table has no '{TYPE_LDR_DATA_TABLE_ENTRY}', so no loaded module can \
                 be described"
            )));
        }
        let user_entry_type = TYPE_LDR_DATA_TABLE_ENTRY.to_string();

        let base = require_member(
            &reader,
            &user_entry_type,
            &["DllBase"],
            "where a loaded image begins",
        )?;
        let size_of_image = require_member(
            &reader,
            &user_entry_type,
            &["SizeOfImage"],
            "how large a loaded image is",
        )?;
        let full_name = require_member(
            &reader,
            &user_entry_type,
            &["FullDllName"],
            "a loaded image's path",
        )?;
        let base_name = require_member(
            &reader,
            &user_entry_type,
            &["BaseDllName"],
            "a loaded image's name",
        )?;
        let load_links = require_member(
            &reader,
            &user_entry_type,
            &["InLoadOrderLinks"],
            "the load-order chain",
        )?;

        // The kernel's list prefers `_KLDR_DATA_TABLE_ENTRY` where the build has
        // one, but only if it really carries the members read below. A type that
        // exists but does not describe them would otherwise turn every driver
        // row into an error.
        let kernel_entry_type = if profile.symbols.has_type(TYPE_KLDR_DATA_TABLE_ENTRY)
            && [
                base.as_str(),
                size_of_image.as_str(),
                full_name.as_str(),
                base_name.as_str(),
                load_links.as_str(),
            ]
            .iter()
            .all(|member| {
                reader
                    .member_offset(TYPE_KLDR_DATA_TABLE_ENTRY, member)
                    .is_ok()
            }) {
            TYPE_KLDR_DATA_TABLE_ENTRY.to_string()
        } else {
            user_entry_type.clone()
        };

        let ps_loaded_module_list = profile
            .symbols
            .symbol_address(SYMBOL_PS_LOADED_MODULE_LIST)
            .ok()
            .and_then(|rva| profile.kernel_base.value.checked_add(rva));

        let directory_table_base = first_member(
            &reader,
            TYPE_EPROCESS,
            &["Pcb.DirectoryTableBase", "DirectoryTableBase"],
        )?
        .map(|path| {
            // No memory is read to answer this: an object at address zero
            // resolves its members entirely through the symbol table, and only
            // the declared *kind* of the member is being asked about.
            let is_array = reader
                .object(0, TYPE_EPROCESS)
                .ok()
                .and_then(|probe| probe.array_len(path).ok())
                .is_some();
            (path.to_string(), is_array)
        });

        let (peb, peb_unavailable) = match resolve_peb(&reader, profile, &user_entry_type) {
            Ok(layout) => (Some(layout), None),
            Err(detail) => (None, Some(detail)),
        };

        // Both spellings occur and neither is a typo: the member was renamed
        // between builds. Asking the table which one exists means a build
        // nobody catalogued still reads the right member or reports that it
        // read none.
        let wow64 = first_member(&reader, TYPE_EPROCESS, &["WoW64Process", "Wow64Process"])?
            .map(str::to_string);
        let ewow64_peb = if profile.symbols.has_type(TYPE_EWOW64PROCESS) {
            first_member(&reader, TYPE_EWOW64PROCESS, &["Peb"])?.map(str::to_string)
        } else {
            None
        };

        Ok(Self {
            user_entry_type,
            kernel_entry_type,
            base,
            size_of_image,
            full_name,
            base_name,
            kernel_links: load_links,
            ps_loaded_module_list,
            directory_table_base,
            peb,
            peb_unavailable,
            wow64,
            ewow64_peb,
        })
    }

    /// The three list layouts this build has, in load, memory, initialisation
    /// order.
    ///
    /// `None` for a list the build does not declare. Exposed so a caller — and
    /// a test — can see that the three link members really are three different
    /// members.
    pub fn peb_lists(&self) -> [Option<&LdrListLayout>; 3] {
        match &self.peb {
            Some(peb) => [Some(&peb.load), peb.memory.as_ref(), peb.init.as_ref()],
            None => [None, None, None],
        }
    }

    /// The user-mode side, or a refusal naming what this build is missing.
    fn require_peb(&self) -> Result<&PebLayout, ModulesError> {
        self.peb.as_ref().ok_or_else(|| {
            ModulesError::unsupported(
                self.peb_unavailable
                    .clone()
                    .unwrap_or_else(|| "this build declares no process environment block".into()),
            )
        })
    }
}

/// Resolve the user-mode side, or say in one sentence why it cannot be.
fn resolve_peb(
    reader: &StructReader,
    profile: &WindowsProfile,
    entry_type: &str,
) -> Result<PebLayout, String> {
    for required in [TYPE_PEB, TYPE_PEB_LDR_DATA] {
        if !profile.symbols.has_type(required) {
            return Err(format!(
                "the symbol table has no '{required}', so a process's own list of loaded DLLs \
                 cannot be reached"
            ));
        }
    }
    // A symbol table that cannot answer is reported as its own sentence, not as
    // "this build has no Peb": the first says the evidence about layout is
    // damaged and the second is a claim about the suspect's machine.
    let peb = first_member(reader, TYPE_EPROCESS, &["Peb"])
        .map_err(|err| {
            format!("the symbol table could not say whether '{TYPE_EPROCESS}' declares Peb: {err}")
        })?
        .ok_or_else(|| {
            format!(
                "'{TYPE_EPROCESS}' has no Peb, so a process's user-mode loader cannot be reached"
            )
        })?
        .to_string();
    let ldr = first_member(reader, TYPE_PEB, &["Ldr"])
        .map_err(|err| {
            format!("the symbol table could not say whether '{TYPE_PEB}' declares Ldr: {err}")
        })?
        .ok_or_else(|| {
            format!("'{TYPE_PEB}' has no Ldr, so the loader's own records cannot be reached")
        })?
        .to_string();

    let list = |head: &str, links: &str| -> Result<Option<LdrListLayout>, String> {
        let describe = |err: ObjError| format!("the symbol table could not be read: {err}");
        // Owned inside each `match`: the candidate slice is a temporary built
        // from a runtime name, so the borrowed answer does not outlive the
        // statement that produced it.
        let head = match first_member(reader, TYPE_PEB_LDR_DATA, &[head]).map_err(describe)? {
            Some(path) => path.to_string(),
            None => return Ok(None),
        };
        let links = match first_member(reader, entry_type, &[links]).map_err(describe)? {
            Some(path) => path.to_string(),
            None => return Ok(None),
        };
        Ok(Some(LdrListLayout { head, links }))
    };

    let load = list("InLoadOrderModuleList", "InLoadOrderLinks")?.ok_or_else(|| {
        format!(
            "'{TYPE_PEB_LDR_DATA}' has no InLoadOrderModuleList, or '{entry_type}' has no \
             InLoadOrderLinks, so the loaded-DLL chain cannot be followed"
        )
    })?;
    Ok(PebLayout {
        peb,
        ldr,
        load,
        memory: list("InMemoryOrderModuleList", "InMemoryOrderLinks")?,
        init: list(
            "InInitializationOrderModuleList",
            "InInitializationOrderLinks",
        )?,
    })
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps and address-space settings for one module walk.
#[derive(Debug, Clone)]
pub struct ModuleWalkConfig {
    /// Ceiling on entries one list walk will return.
    pub max_modules: usize,
    /// Ceiling on individually recorded notes.
    pub max_recorded_notes: usize,
    /// Paging mode for a process address space built by
    /// [`ProcessSpace::build`]. `None` takes it from the kernel space this
    /// profile was discovered with, which is the only place it is recorded.
    pub paging_mode: Option<PagingMode>,
    /// Translation policy for a process address space.
    pub translation: TranslationPolicy,
    /// Page-table entry memo, shared across every process in a case. Entries
    /// are keyed by physical address and mean the same thing in every address
    /// space, so one cache for four hundred processes is right and four hundred
    /// caches is waste.
    pub page_table_cache: Option<Arc<TableCache>>,
}

impl Default for ModuleWalkConfig {
    fn default() -> Self {
        Self {
            max_modules: MAX_MODULES,
            max_recorded_notes: MAX_RECORDED_NOTES,
            paging_mode: None,
            translation: TranslationPolicy::default(),
            page_table_cache: None,
        }
    }
}

/// One process's own user-mode address space.
///
/// A named type rather than a bare layer because handing these functions the
/// **kernel** space instead does not fail: a PEB address read through the
/// kernel's page tables lands on whatever the kernel has mapped there, and the
/// bytes parse. Every row would be wrong and none would be marked as such. A
/// caller either builds one with [`ProcessSpace::build`], which derives it from
/// the process's own directory table base, or states plainly with
/// [`ProcessSpace::supplied`] that it is asserting the layer is that process's.
#[derive(Clone)]
pub struct ProcessSpace {
    layer: Arc<dyn MemoryLayer>,
    dtb: u64,
    /// The same layer with its concrete type kept, when this crate built it.
    ///
    /// `Arc<dyn MemoryLayer>` is everything a reader needs to fetch bytes, and
    /// it is deliberately what [`ProcessSpace::layer`] hands out. It is also
    /// where the provenance stops: the translation-refusal counter and the path
    /// each translation took are on [`VirtualLayer`], not on the trait, and a
    /// stage that has erased the type can no longer say how many pages the
    /// walker declined to give it. `None` for a
    /// [`ProcessSpace::supplied`] layer, where there is no such counter to read
    /// — which is reported as an absent answer, never as zero.
    virt: Option<Arc<VirtualLayer>>,
}

impl std::fmt::Debug for ProcessSpace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProcessSpace")
            .field("dtb", &format_args!("{:#x}", self.dtb))
            .finish_non_exhaustive()
    }
}

impl ProcessSpace {
    /// Build the address space of the process whose `_EPROCESS` is at
    /// `process`, from its own directory table base.
    ///
    /// # Errors
    ///
    /// [`ModulesError::Unsupported`] when this build's `_EPROCESS` does not
    /// declare a directory table base, when the value read is zero — a process
    /// with no address space at all — or when the paging mode cannot be
    /// established. [`ModulesError::Space`] when the base cannot name a page
    /// table hierarchy.
    pub fn build(
        profile: &WindowsProfile,
        symbols: &ModuleSymbols,
        process: u64,
        config: &ModuleWalkConfig,
    ) -> Result<Self, ModulesError> {
        let (path, is_array) = symbols.directory_table_base.as_ref().ok_or_else(|| {
            ModulesError::unsupported(format!(
                "'{TYPE_EPROCESS}' declares no DirectoryTableBase, so a process's own address \
                 space cannot be built"
            ))
        })?;
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let eprocess = reader.object(process, TYPE_EPROCESS)?;
        // 32-bit Windows declares this as `[2] unsigned long`, whose first
        // element is the directory table base and whose second is the
        // hyperspace PTE. Reading the pair as one wide integer takes the second
        // into the high half and translates from an address the machine never
        // used.
        let value = if *is_array {
            eprocess.element_int(path, 0)?
        } else {
            eprocess.int(path)?
        };
        let dtb = value.as_u64().ok_or_else(|| {
            ModulesError::unsupported(format!(
                "'{TYPE_EPROCESS}.{path}' is negative, which is not a directory table base"
            ))
        })?;
        if dtb == 0 {
            return Err(ModulesError::unsupported(format!(
                "the process at {process:#x} has a null directory table base, so it has no \
                 address space to read"
            )));
        }

        let spec = paging_spec(profile, config)?;
        let cache = config
            .page_table_cache
            .clone()
            .unwrap_or_else(|| Arc::new(TableCache::new()));
        let space = VirtualLayer::with_cache(
            Arc::clone(&profile.physical),
            dtb,
            spec,
            config.translation,
            cache,
        )?
        // Most swapped pages are a process's, not the kernel's, so this is where
        // an attached pagefile earns its keep. Empty unless the examiner named
        // one — and without it the layout selected above names a pagefile no
        // layer on this path holds, so every swapped PEB, loader and heap page
        // stays a hole for the module, DLL and services walks while the feature
        // reads as enabled.
        .with_swap(profile.pagefiles.clone());
        let virt = Arc::new(space);
        // `virt.clone()` rather than `Arc::clone(&virt)`: the latter infers its
        // type parameter from the annotation and so asks for `&Arc<dyn MemoryLayer>`,
        // which is not what we hold. Method syntax clones the concrete Arc and
        // then unsize-coerces at the binding.
        let layer: Arc<dyn MemoryLayer> = virt.clone();
        Ok(Self {
            layer,
            dtb,
            virt: Some(virt),
        })
    }

    /// A space the caller asserts is this process's own, with the directory
    /// table base it was built from.
    ///
    /// For a caller that already holds the layer, and for fixtures, where the
    /// image is mapped one to one. Nothing checks the assertion, which is why
    /// it has to be made explicitly.
    pub fn supplied(layer: Arc<dyn MemoryLayer>, dtb: u64) -> Self {
        Self {
            layer,
            dtb,
            // Nothing is known about how a supplied layer translates, so
            // nothing is claimed. See [`ProcessSpace::provenance`].
            virt: None,
        }
    }

    /// The layer user-mode addresses are read through.
    pub fn layer(&self) -> &Arc<dyn MemoryLayer> {
        &self.layer
    }

    /// The directory table base this space is rooted at.
    pub fn dtb(&self) -> u64 {
        self.dtb
    }

    /// How many translations this space has refused under the uniform-table
    /// heuristic so far.
    ///
    /// `None` when the layer was not built here, so the counter cannot be
    /// reached. Never zero in that case: zero is the measured statement that
    /// the heuristic never fired, and an unmeasured zero is how "no page was
    /// hidden from you" gets asserted by a stage that never asked.
    ///
    /// The number rises as the space is read, so it is taken **after** a walk,
    /// not before.
    pub fn uniform_tables_suppressed(&self) -> Option<u64> {
        self.virt
            .as_ref()
            .map(|layer| layer.uniform_tables_suppressed())
    }

    /// What this space reported, naming the pages that carried the evidence.
    ///
    /// `pages` is `(what the page held, its virtual address in this space)`.
    /// Each is translated so the record can say whether bytes quoted from it
    /// are shared — see [`crate::process::PageBacking`], and in particular why
    /// the ordinary page-table answer is **not** a finding that a page is
    /// private.
    ///
    /// A supplied layer yields [`SpaceProvenance::not_built`]: no page is
    /// examined and no count is claimed, because neither could be established.
    ///
    /// The counter is read **before** the page translations below, and the
    /// field order is what does it: the number is meant to be the refusals the
    /// stage's own reads provoked, not those of the probes made to describe
    /// them.
    pub fn provenance(&self, pages: &[(&'static str, u64)]) -> SpaceProvenance {
        let Some(layer) = self.virt.as_ref() else {
            return SpaceProvenance::not_built();
        };
        SpaceProvenance {
            uniform_tables_suppressed: self.uniform_tables_suppressed(),
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
}

/// The paging mode a process address space must be built with.
///
/// Taken from the kernel space discovery already proved out, because that is
/// the only place the answer is recorded: a 32-bit image is PAE or it is not,
/// and the two walk different structures. Guessing from the architecture would
/// pick non-PAE for every 32-bit image, and a PAE image walked as non-PAE
/// translates nothing at all — or worse, translates a few addresses to frames
/// that are not theirs.
/// The paging specification this image's address spaces are read under.
///
/// Extracted so that every walker over this image — the per-process layer
/// above, and the downward enumeration the `strings_map` stage drives — asks
/// the same spec the same questions. Two specs built from the same profile by
/// two call sites is how one of them comes to read a pagefile index the other
/// declines to name.
///
/// # Errors
///
/// [`ModulesError::Unsupported`] where the paging mode cannot be established.
pub(crate) fn paging_spec(
    profile: &WindowsProfile,
    config: &ModuleWalkConfig,
) -> Result<PagingSpec, ModulesError> {
    let mode = resolve_paging_mode(profile, config)?;
    // State which `MMPTE_SOFTWARE.PageFileLow` layout this build uses, so a
    // swapped-out page names the right pagefile. `is_win8_or_later` returns
    // `Option<bool>` precisely so "the build was never established" cannot be
    // mistaken for "not Windows 8"; when it is `None` the spec is left unset
    // and declines to name a pagefile at all.
    Ok(match profile.build.is_win8_or_later() {
        Some(win8) => PagingSpec::new(mode, PteSemantics::Windows).with_win8_pagefile_layout(win8),
        None => PagingSpec::new(mode, PteSemantics::Windows),
    })
}

fn resolve_paging_mode(
    profile: &WindowsProfile,
    config: &ModuleWalkConfig,
) -> Result<PagingMode, ModulesError> {
    if let Some(mode) = config.paging_mode {
        return Ok(mode);
    }
    let recorded = profile
        .kernel_space
        .layer_meta()
        .note("paging_mode")
        .and_then(|value| value.as_str())
        .and_then(|name| match name {
            "intel32" => Some(PagingMode::Intel32),
            "intel_pae" => Some(PagingMode::IntelPae),
            "intel32e" => Some(PagingMode::Intel32e),
            _ => None,
        });
    if let Some(mode) = recorded {
        return Ok(mode);
    }
    match profile.architecture {
        Architecture::X64 => Ok(PagingMode::Intel32e),
        Architecture::X86 => Err(ModulesError::unsupported(
            "this image's kernel space does not record its paging mode, and a 32-bit image is \
             PAE or non-PAE with no way to tell the two apart from the architecture alone",
        )),
        other => Err(ModulesError::unsupported(format!(
            "this image's kernel space does not record its paging mode, and there is no paging \
             specification for {other:?}"
        ))),
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// A name read from a `_UNICODE_STRING`, or the reason there is not one.
///
/// Three outcomes and not two, because "this entry has no path" and "this
/// entry's path was paged out" support different conclusions, and rendering the
/// second as the first puts a nameless module in a report that reads exactly
/// like a successful parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NameField {
    /// The name, decoded from UTF-16LE.
    Name(String),
    /// The string is genuinely zero-length.
    Empty,
    /// The string could not be read, for the reason given.
    Unavailable(String),
}

impl NameField {
    /// The name, when there is one.
    pub fn name(&self) -> Option<&str> {
        match self {
            NameField::Name(name) => Some(name),
            _ => None,
        }
    }

    /// Whether the name is known — including known to be empty.
    pub fn is_known(&self) -> bool {
        !matches!(self, NameField::Unavailable(_))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            NameField::Name(name) => serde_json::json!({"kind": "name", "name": name}),
            NameField::Empty => serde_json::json!({"kind": "empty"}),
            NameField::Unavailable(detail) => {
                serde_json::json!({"kind": "unavailable", "detail": detail})
            }
        }
    }
}

/// Read a `_UNICODE_STRING` member of a **loader entry** into a [`NameField`].
///
/// A decoded string is not automatically a name. A loader entry sitting in
/// reallocated pool decodes to valid UTF-16 that is not the name it was read
/// as, and publishing it puts mojibake in a module list — worse than an absent
/// row, because an examiner searching that list for a malicious DLL can act on
/// "unreadable" and cannot act on garbage. The 32-bit path already made this
/// check; the native path did not, which is how two such rows reached the
/// Windows 11 parity corpus.
///
/// Every reader of a `_LDR_DATA_TABLE_ENTRY` name must come through here, and
/// that includes the pool *sweep* in `crate::kernel_hooks::drivers`, which by
/// construction recovers freed and reallocated entries the loader list no
/// longer holds — the case this rule exists for. `crate::kernel_hooks::name_field`
/// is the reader for everything that is not a loader entry, and deliberately
/// does not apply it.
pub(crate) fn loader_name_field(entry: &Obj, path: &str) -> NameField {
    match unicode_string(entry, path) {
        Ok(Some(name)) => match loader_string_damage(&name) {
            None => NameField::Name(name),
            Some(damage) => {
                NameField::Unavailable(format!("the string at '{path}' was read, but {damage}"))
            }
        },
        Ok(None) => NameField::Empty,
        Err(err) => NameField::Unavailable(err.to_string()),
    }
}

/// Why decoded text cannot be the name or path a loader entry claimed, if it
/// cannot.
///
/// Everything `crate::poolscan::name_damage` refuses, plus one rule that can
/// only be stated about a *loader* string and is stated nowhere else.
///
/// Reallocated pool decodes as perfectly valid UTF-16. An embedded NUL, an
/// unpaired surrogate or a control character catches a torn entry only when the
/// damage happens to land on one; the Windows 11 parity image holds loader
/// entries whose `BaseDllName` decodes cleanly to runs of CJK and Hangul, and
/// Volatility publishes those verbatim as module names.
///
/// What a `_LDR_DATA_TABLE_ENTRY` holds is the name of a PE file the loader
/// mapped, and such a name carries ASCII structure: an extension (`.dll`,
/// `.exe`, `.sys`, `.ocx`, `.drv`), or, in `FullDllName`, path separators. Text
/// that is mostly outside ASCII *and* carries neither is not a file name that
/// was ever written there — it is the damage, rendered.
///
/// Both halves are required on purpose. Judging on script alone would refuse
/// `C:\Users\Ли\Рабочий стол\отчёт.dll`, an ordinary module path on a Russian
/// machine, and hiding a loaded module from an examiner is the worse error;
/// judging on structure alone would admit any mojibake that happened to contain
/// a dot.
fn loader_string_damage(text: &str) -> Option<&'static str> {
    if let Some(damage) = crate::poolscan::name_damage(text) {
        return Some(damage);
    }
    let total = text.chars().count();
    if total < 4 {
        return None;
    }
    let non_ascii = text.chars().filter(|c| !c.is_ascii()).count();
    if non_ascii * 2 <= total {
        return None;
    }
    if has_file_name_structure(text) {
        return None;
    }
    Some(
        "most of the text is outside ASCII and it carries neither a file extension nor a path \
         separator, which the name of a mapped PE file does, so these bytes are not the name they \
         were read as",
    )
}

/// Whether text carries the ASCII structure of a Windows file name: a path
/// separator, or a trailing extension of ASCII alphanumerics.
///
/// The extension is bounded and required to be ASCII alphanumeric because the
/// point is to recognise the `.dll` on the end of a name, not to let a lone `.`
/// inside a run of reallocated pool stand as proof that the run is a file name.
fn has_file_name_structure(text: &str) -> bool {
    if text.contains('\\') || text.contains('/') {
        return true;
    }
    match text.rsplit_once('.') {
        Some((_, extension)) => {
            !extension.is_empty()
                && extension.len() <= 8
                && extension.chars().all(|c| c.is_ascii_alphanumeric())
        }
        None => false,
    }
}

/// One loaded image, as a loader entry describes it.
///
/// Used for both a process's DLLs and the kernel's drivers: it is the same
/// structure, and the only difference is which address space it was read in.
#[derive(Debug, Clone)]
pub struct LoadedModule {
    /// Where the loader entry is.
    pub entry: u64,
    /// Where the image is mapped. `None` when `DllBase` could not be read,
    /// which upstream drops the row for; here the row survives and says so,
    /// because an entry that exists is evidence even when one member of it was
    /// never acquired.
    pub base: Option<u64>,
    /// The image's size in bytes, as the loader recorded it.
    pub size_of_image: Option<u64>,
    /// The full path the image was loaded from.
    pub full_path: NameField,
    /// The image's file name.
    pub base_name: NameField,
    /// Position in the list this entry was walked from, counting from zero. For
    /// the load-order list this is the order the images were loaded in.
    pub load_order: usize,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl LoadedModule {
    /// Last byte of the mapped image, when both base and size are known.
    ///
    /// Inclusive, and `None` rather than a guess: a range with an assumed size
    /// would attribute an address to an image that may not hold it.
    pub fn end(&self) -> Option<u64> {
        let base = self.base?;
        let size = self.size_of_image?;
        if size == 0 {
            return None;
        }
        base.checked_add(size)?.checked_sub(1)
    }

    /// Serializable form for artifact metadata.
    ///
    /// Addresses appear twice: as a JSON number, which is what every existing
    /// consumer reads, and as a `_hex` string, which is what a report may
    /// quote. JSON numbers are IEEE doubles and a mapped image can sit above
    /// 2^53, so the numeric form can reach a client rounded; the string form
    /// carries the bits that were actually read.
    ///
    /// `name` and `full_dll_name` are the flat forms of `base_name` and
    /// `full_path`, present only when the string was read. The structured forms
    /// stay beside them because they alone distinguish a name that was empty
    /// from one that could not be read, and a consumer that shows the flat form
    /// must not present the second as the first.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "entry": self.entry,
            "entry_hex": format!("{:#x}", self.entry),
            "base": self.base,
            "base_hex": self.base.map(|base| format!("{base:#x}")),
            "size_of_image": self.size_of_image,
            "end": self.end(),
            "end_hex": self.end().map(|end| format!("{end:#x}")),
            "full_path": self.full_path.to_json(),
            "base_name": self.base_name.to_json(),
            "name": self.base_name.name(),
            "full_dll_name": self.full_path.name(),
            "load_order": self.load_order,
            "notes": self.notes,
        })
    }
}

/// Whether a process's loader data could be reached, and if not, why not.
///
/// The distinction this type exists for: an empty DLL list and a DLL list that
/// could not be read must never render the same. The first says the process had
/// no DLLs, which for `System` is true and for `explorer.exe` would be an
/// extraordinary claim; the second says this image cannot tell you.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LoaderData {
    /// The loader's data was reached, at these addresses.
    At {
        /// The process environment block.
        peb: u64,
        /// The loader data inside it.
        ldr: u64,
    },
    /// `_EPROCESS.Peb` is null: the process has no user-mode address space. An
    /// empty module list is then a fact about the process.
    NoPeb,
    /// `_PEB.Ldr` is null: the process has a PEB, but the loader had recorded
    /// nothing in it. Also a fact, and a different one.
    NoLdr {
        /// The process environment block.
        peb: u64,
    },
    /// The PEB or the loader data could not be read — paged out, or in a range
    /// this image never captured. **Not** an empty module list.
    Unavailable {
        /// The process environment block, when its address was at least known.
        peb: Option<u64>,
        /// What failed, in the examiner's terms.
        detail: String,
    },
}

impl LoaderData {
    /// Whether the loader's lists can be walked.
    pub fn is_available(&self) -> bool {
        matches!(self, LoaderData::At { .. })
    }

    /// Whether an empty module list here is a fact rather than a gap.
    ///
    /// True for a process that genuinely has no loader data. False for one
    /// whose loader data could not be read, where "no modules" would be a claim
    /// this image does not support.
    pub fn empty_is_a_fact(&self) -> bool {
        matches!(self, LoaderData::NoPeb | LoaderData::NoLdr { .. })
    }

    /// The loader data's address, when it was reached.
    pub fn ldr(&self) -> Option<u64> {
        match self {
            LoaderData::At { ldr, .. } => Some(*ldr),
            _ => None,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            LoaderData::At { .. } => "read",
            LoaderData::NoPeb => "no_peb",
            LoaderData::NoLdr { .. } => "no_ldr",
            LoaderData::Unavailable { .. } => "unavailable",
        }
    }

    /// What a report must declare about this process, or `None` when there is
    /// nothing to declare.
    pub fn incomplete(&self, process: u64) -> Option<Incomplete> {
        match self {
            LoaderData::At { .. } | LoaderData::NoPeb | LoaderData::NoLdr { .. } => None,
            LoaderData::Unavailable { detail, .. } => Some(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the loader data of the process at {process:#x} could not be read, so its \
                     loaded modules are unknown rather than absent: {detail}"
                ),
            )),
        }
    }

    /// Serializable form for artifact metadata.
    ///
    /// The PEB and the loader-data address carry `_hex` siblings for the same
    /// reason every other address in this file does: JSON numbers are IEEE
    /// doubles, a user-mode PEB on x64 sits above 2^53, and a pointer quoted in
    /// a report has to be the pointer that was read.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            LoaderData::At { peb, ldr } => serde_json::json!({
                "kind": "read",
                "peb": peb,
                "peb_hex": format!("{peb:#x}"),
                "ldr": ldr,
                "ldr_hex": format!("{ldr:#x}"),
            }),
            LoaderData::NoPeb => serde_json::json!({"kind": "no_peb"}),
            LoaderData::NoLdr { peb } => serde_json::json!({
                "kind": "no_ldr",
                "peb": peb,
                "peb_hex": format!("{peb:#x}"),
            }),
            LoaderData::Unavailable { peb, detail } => serde_json::json!({
                "kind": "unavailable",
                "peb": peb,
                "peb_hex": peb.map(|peb| format!("{peb:#x}")),
                "detail": detail,
            }),
        }
    }
}

/// One process's loaded DLLs, and everything the walk could not do.
#[derive(Debug, Clone)]
pub struct DllList {
    /// The `_EPROCESS` the list belongs to.
    pub process: u64,
    /// The directory table base the process's address space was read through.
    pub dtb: u64,
    /// Whether the loader data was reachable, and why not when it was not.
    pub loader: LoaderData,
    /// Where the load-order list's head is, when it was reached.
    pub head: Option<u64>,
    /// The loaded images, in load order.
    pub modules: Vec<LoadedModule>,
    /// The 32-bit loader, for a WOW64 process.
    ///
    /// A 32-bit program's own DLLs are all here and none of them are in
    /// [`DllList::modules`], which for such a process holds only the native
    /// `ntdll.dll` and the WOW64 thunking layer. A list that showed the native
    /// half alone would read as a program that had loaded four DLLs.
    pub wow64: Wow64Loader,
    /// Why the walk ended. `None` when the list was never walked.
    pub stop: Option<ListStop>,
    /// Notes, capped by [`ModuleWalkConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total. Exact even when the list was capped.
    pub notes_total: usize,
}

impl DllList {
    /// Whether the whole list was established.
    ///
    /// The question a report must ask before writing "this process had loaded
    /// only these DLLs". A process with no loader data at all is complete: the
    /// absence is established. One whose loader data could not be read is not.
    pub fn is_complete(&self) -> bool {
        let native = match &self.stop {
            Some(stop) => stop.is_complete(),
            None => self.loader.empty_is_a_fact(),
        };
        // A WOW64 process whose 32-bit list could not be read has a DLL list
        // that is missing every DLL the program itself loaded. That is not a
        // complete list by any reading.
        native && self.wow64.establishes_absence()
    }

    /// Everything a report must declare about this list.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(declaration) = self.loader.incomplete(self.process) {
            out.push(declaration);
        }
        if let Some(stop) = &self.stop {
            if let Some(declaration) = stop.incomplete() {
                out.push(declaration);
            }
        }
        if let Some(declaration) = self.wow64.incomplete(self.process) {
            out.push(declaration);
        }
        out
    }

    /// Every image the loader admits to, from both of a WOW64 process's lists.
    pub fn all_modules(&self) -> impl Iterator<Item = &LoadedModule> {
        self.modules.iter().chain(self.wow64.modules().iter())
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process": self.process,
            "process_hex": format!("{:#x}", self.process),
            "dtb": self.dtb,
            "dtb_hex": format!("{:#x}", self.dtb),
            "loader": self.loader.to_json(),
            "head": self.head,
            "head_hex": self.head.map(|head| format!("{head:#x}")),
            "modules": self.modules.iter().map(LoadedModule::to_json).collect::<Vec<_>>(),
            "module_count": self.modules.len(),
            "wow64": self.wow64.to_json(),
            "wow64_module_count": self.wow64.modules().len(),
            "stop": self.stop.as_ref().map(ListStop::as_str),
            "complete": self.is_complete(),
            "notes": self.notes,
            "notes_total": self.notes_total,
        })
    }
}

// ── Shared walking ──────────────────────────────────────────────────────────

/// Record a note, keeping the list bounded without losing the count.
fn push_note(notes: &mut Vec<String>, total: &mut usize, cap: usize, note: String) {
    *total = total.saturating_add(1);
    if notes.len() < cap {
        notes.push(note);
    }
}

/// Read one loader entry.
///
/// Nothing here is fatal: a member that could not be read becomes `None` with a
/// note naming it, because the entry's existence and the members that *did*
/// read are evidence.
fn read_entry(symbols: &ModuleSymbols, entry: &Obj, load_order: usize) -> LoadedModule {
    let mut notes = Vec::new();

    let base = match entry.pointer(&symbols.base) {
        Ok(value) => Some(value),
        Err(err) => {
            notes.push(format!("'{}' could not be read: {err}", symbols.base));
            None
        }
    };
    let size_of_image = match entry.int(&symbols.size_of_image) {
        Ok(value) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                notes.push(format!(
                    "'{}' is negative, which is not a size",
                    symbols.size_of_image
                ));
                None
            }
        },
        Err(err) => {
            notes.push(format!(
                "'{}' could not be read: {err}",
                symbols.size_of_image
            ));
            None
        }
    };

    LoadedModule {
        entry: entry.address(),
        base,
        size_of_image,
        full_path: loader_name_field(entry, &symbols.full_name),
        base_name: loader_name_field(entry, &symbols.base_name),
        load_order,
        notes,
    }
}

/// Walk a chain of loader entries from `head`.
///
/// The head is the address of a `_LIST_ENTRY`; every link in the chain points
/// at the *next entry's embedded link*, and the container arithmetic that
/// recovers the entry is [`ListSpec::in_container`]'s, with the offset taken
/// from the symbol table rather than written down.
fn entry_walk(
    reader: &StructReader,
    head: u64,
    entry_type: &str,
    links: &str,
    max_entries: usize,
) -> Result<(Vec<Obj>, ListStop), ObjError> {
    let spec = ListSpec::new(TYPE_LIST_ENTRY, LIST_FORWARD)
        .in_container(entry_type, links)
        .with_max_entries(max_entries);
    Ok(reader.walk_list(head, &spec)?.walk_to_end())
}

/// The loader data of one process, opened once for however many lists are
/// walked from it.
struct Loader {
    status: LoaderData,
    reader: StructReader,
    ldr: Option<Obj>,
}

/// Reach a process's loader data through its own address space.
///
/// Every failure between the `_EPROCESS` and the `_PEB_LDR_DATA` becomes a
/// [`LoaderData`] rather than an error, because each one is a fact about that
/// process that the case record should hold.
///
/// The load-order head's forward link is read as a probe before any list is
/// walked. Without it, loader data whose page was never acquired would surface
/// as a walk that produced nothing, which in a table is indistinguishable from
/// a process that had no DLLs.
fn open_loader(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    process: u64,
    space: &ProcessSpace,
) -> Result<Loader, ModulesError> {
    let peb_layout = symbols.require_peb()?;
    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let reader = StructReader::new(Arc::clone(space.layer()), Arc::clone(&profile.symbols));

    let unavailable = |status: LoaderData| Loader {
        status,
        reader: reader.clone(),
        ldr: None,
    };

    // The `_EPROCESS` is a kernel structure; the PEB address inside it is a
    // user-mode address, and reading through it in the kernel's space would
    // land on whatever the kernel mapped there.
    let eprocess = kernel.object(process, TYPE_EPROCESS)?;
    let peb = match eprocess.pointer(&peb_layout.peb) {
        Ok(peb) => peb,
        Err(err) => {
            return Ok(unavailable(LoaderData::Unavailable {
                peb: None,
                detail: format!(
                    "'{TYPE_EPROCESS}.{}' could not be read: {err}",
                    peb_layout.peb
                ),
            }))
        }
    };
    if peb == 0 {
        return Ok(unavailable(LoaderData::NoPeb));
    }

    let peb_object = reader.object(peb, TYPE_PEB)?;
    let ldr_address = match peb_object.pointer(&peb_layout.ldr) {
        Ok(value) => value,
        Err(err) => {
            return Ok(unavailable(LoaderData::Unavailable {
                peb: Some(peb),
                detail: format!("'{TYPE_PEB}.{}' could not be read: {err}", peb_layout.ldr),
            }))
        }
    };
    if ldr_address == 0 {
        return Ok(unavailable(LoaderData::NoLdr { peb }));
    }

    let ldr = reader.object(ldr_address, TYPE_PEB_LDR_DATA)?;
    let head = match ldr.member_address(&peb_layout.load.head) {
        Ok(head) => head,
        Err(err) => {
            return Ok(unavailable(LoaderData::Unavailable {
                peb: Some(peb),
                detail: err.to_string(),
            }))
        }
    };
    if let Err(err) = reader.read_pointer_at(head) {
        return Ok(unavailable(LoaderData::Unavailable {
            peb: Some(peb),
            detail: format!(
                "'{TYPE_PEB_LDR_DATA}.{}' at {head:#x} could not be read: {err}",
                peb_layout.load.head
            ),
        }));
    }

    Ok(Loader {
        status: LoaderData::At {
            peb,
            ldr: ldr_address,
        },
        reader: reader.clone(),
        ldr: Some(ldr),
    })
}

// ── dlllist ─────────────────────────────────────────────────────────────────

/// List the DLLs one process has loaded, in the order the loader loaded them.
///
/// `process` is the address of an `_EPROCESS` in the **kernel** address space;
/// `space` is that same process's **own** address space, which is where every
/// address in its PEB is meaningful. Handing this the kernel space instead
/// produces a full table of confident nonsense, which is why the space is a
/// [`ProcessSpace`] and not a bare layer.
///
/// # What an examiner learns
///
/// Which images were mapped into the process and from where. A system DLL
/// loaded from outside `System32`, a module with no path at all, or a base name
/// that does not match the directory it came from are each the start of a
/// finding. An **empty** list from a process that plainly ran code is only
/// meaningful when [`DllList::is_complete`] is true and
/// [`LoaderData::empty_is_a_fact`] holds; otherwise the list is unknown, not
/// empty, and reporting it as empty would clear a process that was never
/// examined.
///
/// # Errors
///
/// Only for failures that make the whole walk meaningless: a build whose PEB
/// layout the symbols cannot describe, or an `_EPROCESS` that cannot be typed.
/// A process whose PEB or loader data is paged out is not an error — it is
/// [`LoaderData::Unavailable`] on the returned list.
pub fn list_dlls(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    process: u64,
    space: &ProcessSpace,
    config: &ModuleWalkConfig,
) -> Result<DllList, ModulesError> {
    let peb_layout = symbols.require_peb()?;
    let loader = open_loader(profile, symbols, process, space)?;

    let mut list = DllList {
        process,
        dtb: space.dtb(),
        loader: loader.status,
        head: None,
        modules: Vec::new(),
        wow64: wow64_loader(profile, symbols, process, space, config),
        stop: None,
        notes: Vec::new(),
        notes_total: 0,
    };
    let Some(ldr) = loader.ldr else {
        return Ok(list);
    };

    let head = ldr.member_address(&peb_layout.load.head)?;
    list.head = Some(head);
    let (entries, stop) = entry_walk(
        &loader.reader,
        head,
        &symbols.user_entry_type,
        &peb_layout.load.links,
        config.max_modules,
    )?;
    for (order, entry) in entries.iter().enumerate() {
        let module = read_entry(symbols, entry, order);
        for note in &module.notes {
            push_note(
                &mut list.notes,
                &mut list.notes_total,
                config.max_recorded_notes,
                format!("the entry at {:#x}: {note}", entry.address()),
            );
        }
        list.modules.push(module);
    }
    list.stop = Some(stop);
    Ok(list)
}

// ── ldrmodules ──────────────────────────────────────────────────────────────

/// One walk of one of the loader's three lists.
///
/// Carries enough to answer "was this image in this list?" *honestly*: the
/// members the walk was built from, what it found, and whether it finished.
#[derive(Debug, Clone)]
pub struct LdrListWalk {
    /// The `_PEB_LDR_DATA` member the head was taken from. `None` when this
    /// build does not declare the list.
    pub head_member: Option<String>,
    /// The `_LDR_DATA_TABLE_ENTRY` member this list threads through. Distinct
    /// from the other two lists' members on every build that has all three.
    pub links_member: Option<String>,
    /// Where the head is, when the list was reachable.
    pub head: Option<u64>,
    /// `(DllBase, entry address)` for every entry whose base was readable.
    pub members: Vec<(u64, u64)>,
    /// Entries whose `DllBase` could not be read. While this is above zero the
    /// walk cannot say any image is *absent*, because one of these might be it.
    pub unreadable_bases: usize,
    /// Why the walk ended. `None` when the list was never walked.
    pub stop: Option<ListStop>,
}

impl LdrListWalk {
    /// A list this build does not declare, or one that was never reached.
    fn absent() -> Self {
        Self {
            head_member: None,
            links_member: None,
            head: None,
            members: Vec::new(),
            unreadable_bases: 0,
            stop: None,
        }
    }

    /// Whether the walk ran, reached the end of the list, and read every base.
    pub fn is_complete(&self) -> bool {
        self.stop.as_ref().is_some_and(ListStop::is_complete) && self.unreadable_bases == 0
    }

    /// Whether an image at `base` was in this list.
    ///
    /// `Some(true)` when it was found. `Some(false)` only when the list was
    /// walked to its end with every base readable, so absence is established.
    /// `None` when this image cannot say — the list was not walked, or it
    /// stopped at a cycle, a cap or an unacquired page, or an entry's base was
    /// unreadable and might have been this one.
    ///
    /// A wrong answer here is the whole cost of the plugin: `Some(false)` where
    /// the truth is `None` accuses a legitimate DLL of having been unlinked by
    /// a rootkit.
    pub fn contains(&self, base: u64) -> Option<bool> {
        if self.members.iter().any(|(found, _)| *found == base) {
            return Some(true);
        }
        if self.is_complete() {
            Some(false)
        } else {
            None
        }
    }

    /// The entry address of the image at `base`, when this list held it.
    pub fn entry_of(&self, base: u64) -> Option<u64> {
        self.members
            .iter()
            .find(|(found, _)| *found == base)
            .map(|(_, entry)| *entry)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "head_member": self.head_member,
            "links_member": self.links_member,
            "head": self.head,
            "head_hex": self.head.map(|head| format!("{head:#x}")),
            "entries": self.members.len(),
            "unreadable_bases": self.unreadable_bases,
            "stop": self.stop.as_ref().map(ListStop::as_str),
            "complete": self.is_complete(),
        })
    }
}

/// One mapped image, and which of the loader's lists still admit to it.
#[derive(Debug, Clone)]
pub struct LdrModule {
    /// Where the image is mapped, from the VAD that holds it.
    pub base: u64,
    /// The VAD node the range came from.
    pub vad: u64,
    /// Whether the image was in `InLoadOrderModuleList`.
    pub in_load: Option<bool>,
    /// Whether it was in `InInitializationOrderModuleList`.
    pub in_init: Option<bool>,
    /// Whether it was in `InMemoryOrderModuleList`.
    pub in_mem: Option<bool>,
    /// The loader entry describing it, from whichever list held it. `None` when
    /// no list did — which is the finding.
    pub entry: Option<u64>,
    /// The file the VAD says is mapped into the range.
    pub mapped_file: MappedFile,
    /// Everything odd about this image that did not disqualify it.
    pub notes: Vec<String>,
}

impl LdrModule {
    /// Whether the image is mapped but missing from at least one loader list.
    ///
    /// This is what the stage exists to find. `ntdll.dll` legitimately appears
    /// in all three; an image absent from one has had its entry unlinked, and
    /// an image absent from all three is mapped, running, and invisible to
    /// every API that asks the loader what is loaded.
    ///
    /// Only established absences count: a list this image could not read
    /// contributes nothing, because [`LdrListWalk::contains`] returned `None`.
    pub fn is_unlinked(&self) -> bool {
        [self.in_load, self.in_init, self.in_mem].contains(&Some(false))
    }

    /// Whether all three lists were read and all three still hold the module.
    pub fn is_fully_linked(&self) -> bool {
        [self.in_load, self.in_init, self.in_mem]
            .iter()
            .all(|answer| *answer == Some(true))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base": self.base,
            "base_hex": format!("{:#x}", self.base),
            "vad": self.vad,
            "vad_hex": format!("{:#x}", self.vad),
            "in_load": self.in_load,
            "in_init": self.in_init,
            "in_mem": self.in_mem,
            "entry": self.entry,
            "entry_hex": self.entry.map(|entry| format!("{entry:#x}")),
            "mapped_file": self.mapped_file.to_json(),
            "unlinked": self.is_unlinked(),
            "notes": self.notes,
        })
    }
}

/// One process's mapped images cross-referenced against its loader lists.
#[derive(Debug, Clone)]
pub struct LdrModules {
    /// The `_EPROCESS` the analysis belongs to.
    pub process: u64,
    /// Whether the loader data was reachable.
    pub loader: LoaderData,
    /// The load-order walk.
    pub load: LdrListWalk,
    /// The memory-order walk.
    pub memory: LdrListWalk,
    /// The initialisation-order walk.
    pub init: LdrListWalk,
    /// The 32-bit loader, for a WOW64 process. A 32-bit program's DLLs are in
    /// this one and in none of the three above, so an image scored against the
    /// native lists alone is scored against the wrong lists.
    pub wow64: Wow64Loader,
    /// One row per mapped image, in ascending base order.
    pub modules: Vec<LdrModule>,
    /// Memory ranges whose first page could not be read, so it is unknown
    /// whether they held an image. An unlinked module could be in any of them.
    pub unreadable_ranges: usize,
    /// Whether the VAD tree this was cross-referenced against was itself
    /// complete. A partial tree cannot support "there are no other modules".
    pub vad_complete: bool,
    /// Notes, capped by [`ModuleWalkConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total.
    pub notes_total: usize,
}

impl LdrModules {
    /// The images missing from at least one loader list.
    pub fn unlinked(&self) -> impl Iterator<Item = &LdrModule> {
        self.modules.iter().filter(|module| module.is_unlinked())
    }

    /// Whether every input to the cross-reference was complete.
    ///
    /// Only when this is true can the analysis support "these are all the
    /// images this process had mapped, and these are the only unlinked ones".
    pub fn is_complete(&self) -> bool {
        self.loader.is_available()
            && self.load.is_complete()
            && self.memory.is_complete()
            && self.init.is_complete()
            && self.wow64.establishes_absence()
            && self.vad_complete
            && self.unreadable_ranges == 0
    }

    /// Everything a report must declare about this analysis.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(declaration) = self.loader.incomplete(self.process) {
            out.push(declaration);
        }
        if self.loader.is_available() {
            for (name, walk) in [
                ("load-order", &self.load),
                ("memory-order", &self.memory),
                ("initialisation-order", &self.init),
            ] {
                if walk.head_member.is_none() {
                    out.push(Incomplete::new(
                        IncompleteReason::UnresolvedStructure,
                        format!(
                            "this build declares no {name} module list, so no module can be shown \
                             to be missing from it"
                        ),
                    ));
                    continue;
                }
                if walk.is_complete() {
                    continue;
                }
                let detail = match &walk.stop {
                    Some(stop) => stop
                        .incomplete()
                        .map(|incomplete| incomplete.detail)
                        .unwrap_or_else(|| {
                            format!("{} entr(ies) had no readable base", walk.unreadable_bases)
                        }),
                    None => "the list was never walked".to_string(),
                };
                out.push(Incomplete::new(
                    IncompleteReason::UnresolvedStructure,
                    format!(
                        "the {name} list of the process at {:#x} was not fully read, so no module \
                         can be shown to be missing from it: {detail}",
                        self.process
                    ),
                ));
            }
        }
        if let Some(declaration) = self.wow64.incomplete(self.process) {
            out.push(declaration);
        }
        if !self.vad_complete {
            out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the VAD tree of the process at {:#x} was not fully walked, so a mapped image \
                     it did not reach would not appear here at all",
                    self.process
                ),
            ));
        }
        if self.unreadable_ranges > 0 {
            out.push(Incomplete::new(
                IncompleteReason::ShortRead,
                format!(
                    "{} memory range(s) of the process at {:#x} begin in unacquired memory, so \
                     whether they hold a mapped image is unknown",
                    self.unreadable_ranges, self.process
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
            "loader": self.loader.to_json(),
            "load": self.load.to_json(),
            "memory": self.memory.to_json(),
            "init": self.init.to_json(),
            "wow64": self.wow64.to_json(),
            "modules": self.modules.iter().map(LdrModule::to_json).collect::<Vec<_>>(),
            "module_count": self.modules.len(),
            "unlinked_count": self.unlinked().count(),
            "unreadable_ranges": self.unreadable_ranges,
            "vad_complete": self.vad_complete,
            "complete": self.is_complete(),
            "notes": self.notes,
            "notes_total": self.notes_total,
        })
    }
}

/// Whether the two bytes at `address` are a DOS header's `MZ`.
fn has_dos_header(reader: &StructReader, address: u64) -> Result<bool, ObjError> {
    let bytes = reader.read_bytes(address, DOS_SIGNATURE.len() as u64)?;
    Ok(bytes == DOS_SIGNATURE)
}

/// Whether an image at `base` is in one of the loader's lists, over **both**
/// loaders a process may have.
///
/// The rule, in the only order it can safely be written:
///
/// * Found in either the native or the 32-bit list — `Some(true)`.
/// * Established absent from both — `Some(false)`. For a process with no 32-bit
///   loader, "both" is the native list alone.
/// * Anything else — `None`, which never renders as unlinked.
///
/// A WOW64 process whose 32-bit lists could not be read therefore yields `None`
/// rather than `Some(false)`, because every ordinary 32-bit DLL it loaded is
/// absent from the 64-bit lists by design and calling that unlinked would
/// accuse a legitimate module.
fn membership(
    native: &LdrListWalk,
    wow64: &Wow64Loader,
    kind: LdrListKind,
    base: u64,
) -> Option<bool> {
    let thirty_two = wow64.walk(kind).and_then(|walk| walk.contains(base));
    if native.contains(base) == Some(true) || thirty_two == Some(true) {
        return Some(true);
    }
    if native.contains(base) == Some(false) && wow64.establishes_absence() {
        // For a WOW64 process the 32-bit walk must also have established the
        // absence; `establishes_absence` is only true when all three of its
        // lists were walked to their end, so `thirty_two` here is `Some(false)`
        // for a list this build declares and `None` only for a list it does
        // not — and a list that does not exist cannot hide a module.
        if thirty_two != Some(true) {
            return Some(false);
        }
    }
    None
}

/// Walk one of the loader's three lists, keeping enough to answer membership
/// honestly.
fn ldr_list_walk(
    reader: &StructReader,
    ldr: &Obj,
    entry_type: &str,
    base_member: &str,
    layout: Option<&LdrListLayout>,
    max_entries: usize,
) -> Result<LdrListWalk, ModulesError> {
    let Some(layout) = layout else {
        return Ok(LdrListWalk::absent());
    };
    let mut walk = LdrListWalk {
        head_member: Some(layout.head.clone()),
        links_member: Some(layout.links.clone()),
        head: None,
        members: Vec::new(),
        unreadable_bases: 0,
        stop: None,
    };
    let head = ldr.member_address(&layout.head)?;
    walk.head = Some(head);
    let (entries, stop) = entry_walk(reader, head, entry_type, &layout.links, max_entries)?;
    for entry in &entries {
        match entry.pointer(base_member) {
            Ok(base) => walk.members.push((base, entry.address())),
            // Not merely a skipped entry: an entry whose base is unknown is
            // exactly the entry that might be the module about to be called
            // missing, so it suppresses every claim of absence from this list.
            Err(_) => walk.unreadable_bases = walk.unreadable_bases.saturating_add(1),
        }
    }
    walk.stop = Some(stop);
    Ok(walk)
}

/// Cross-reference a process's mapped images against the loader's three lists.
///
/// `vads` must be the VAD tree of the same process — [`crate::vad::list_vads`]
/// produces it, and this refuses a tree belonging to anything else rather than
/// reporting every module as unlinked.
///
/// # What an examiner learns
///
/// Every range of the process's memory that begins with a PE image, and which
/// of the loader's three lists still names it. Windows keeps all three in step;
/// nothing legitimate removes an entry from one and leaves it in the others. A
/// row with `in_load = Some(false)` is a module something took deliberate steps
/// to hide from `EnumProcessModules` and every tool built on it, and a row with
/// all three false is a running image the loader denies having loaded.
///
/// A wrong answer in either direction is serious: a false `Some(false)` accuses
/// an innocent DLL, and a false `Some(true)` clears a malicious one. That is
/// why each list is walked through its **own** link member, and why an
/// incomplete walk yields `None` rather than `Some(false)`.
///
/// # Errors
///
/// [`ModulesError::WrongProcess`] for a tree belonging to another process, and
/// the same whole-walk failures as [`list_dlls`]. A list this build does not
/// declare is not an error: its column is `None` throughout and
/// [`LdrModules::incomplete`] says so.
pub fn ldr_modules(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    process: u64,
    space: &ProcessSpace,
    vads: &VadTree,
    config: &ModuleWalkConfig,
) -> Result<LdrModules, ModulesError> {
    if vads.process != process {
        return Err(ModulesError::WrongProcess {
            process,
            supplied: vads.process,
        });
    }
    let peb_layout = symbols.require_peb()?;
    let loader = open_loader(profile, symbols, process, space)?;

    let mut out = LdrModules {
        process,
        loader: loader.status,
        load: LdrListWalk::absent(),
        memory: LdrListWalk::absent(),
        init: LdrListWalk::absent(),
        wow64: wow64_loader(profile, symbols, process, space, config),
        modules: Vec::new(),
        unreadable_ranges: 0,
        vad_complete: vads.is_complete(),
        notes: Vec::new(),
        notes_total: 0,
    };

    if let Some(ldr) = &loader.ldr {
        // Three walks, three container members. Sharing one member here would
        // make every module appear in every list and quietly delete the only
        // finding this function produces.
        out.load = ldr_list_walk(
            &loader.reader,
            ldr,
            &symbols.user_entry_type,
            &symbols.base,
            Some(&peb_layout.load),
            config.max_modules,
        )?;
        out.memory = ldr_list_walk(
            &loader.reader,
            ldr,
            &symbols.user_entry_type,
            &symbols.base,
            peb_layout.memory.as_ref(),
            config.max_modules,
        )?;
        out.init = ldr_list_walk(
            &loader.reader,
            ldr,
            &symbols.user_entry_type,
            &symbols.base,
            peb_layout.init.as_ref(),
            config.max_modules,
        )?;
    }

    for vad in &vads.vads {
        match has_dos_header(&loader.reader, vad.start) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(err) => {
                out.unreadable_ranges = out.unreadable_ranges.saturating_add(1);
                push_note(
                    &mut out.notes,
                    &mut out.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "the range at {:#x} could not be read, so whether it holds a mapped image \
                         is unknown: {err}",
                        vad.start
                    ),
                );
                continue;
            }
        }
        let base = vad.start;
        let mut notes = Vec::new();
        if !out.wow64.establishes_absence() && !matches!(out.wow64, Wow64Loader::NotWow64) {
            notes.push(
                "this process has a 32-bit loader whose lists could not be established, so this \
                 image's absence from the 64-bit lists is not evidence that it was unlinked"
                    .to_string(),
            );
        }
        out.modules.push(LdrModule {
            base,
            vad: vad.address,
            in_load: membership(&out.load, &out.wow64, LdrListKind::Load, base),
            in_init: membership(&out.init, &out.wow64, LdrListKind::Init, base),
            in_mem: membership(&out.memory, &out.wow64, LdrListKind::Memory, base),
            entry: out
                .load
                .entry_of(base)
                .or_else(|| out.memory.entry_of(base))
                .or_else(|| out.init.entry_of(base))
                .or_else(|| {
                    out.wow64
                        .walk(LdrListKind::Load)
                        .and_then(|walk| walk.entry_of(base))
                }),
            mapped_file: vad.file.clone(),
            notes,
        });
    }
    out.modules.sort_by_key(|module| module.base);
    Ok(out)
}

// ── WOW64: the 32-bit loader inside a 64-bit process ────────────────────────

/// Offsets inside the 32-bit loader structures a WOW64 process keeps.
///
/// Written down rather than resolved from the symbol table because the kernel's
/// PDB does not describe them: `_PEB`, `_PEB_LDR_DATA` and
/// `_LDR_DATA_TABLE_ENTRY` in a kernel ISF are the **64-bit** forms, and a
/// WOW64 process has both. The 32-bit forms are part of the frozen Win32 ABI —
/// unchanged from NT 3.51 to Windows 11, because every 32-bit binary ever
/// compiled reads them — which is what makes constants safe here and nowhere
/// else in this crate.
///
/// Every value read through them is nonetheless treated as unverified: see
/// [`Wow64Loader`], where a walk that does not look like a 32-bit loader
/// suppresses claims rather than making them.
mod wow64_layout {
    /// `_PEB32.Ldr`.
    pub(super) const PEB_LDR: u64 = 0x0C;
    /// `_PEB_LDR_DATA32.InLoadOrderModuleList`.
    pub(super) const LDR_LOAD_HEAD: u64 = 0x0C;
    /// `_PEB_LDR_DATA32.InMemoryOrderModuleList`.
    pub(super) const LDR_MEMORY_HEAD: u64 = 0x14;
    /// `_PEB_LDR_DATA32.InInitializationOrderModuleList`.
    pub(super) const LDR_INIT_HEAD: u64 = 0x1C;
    /// `_LDR_DATA_TABLE_ENTRY32.InLoadOrderLinks`.
    pub(super) const ENTRY_LOAD_LINKS: u64 = 0x00;
    /// `_LDR_DATA_TABLE_ENTRY32.InMemoryOrderLinks`.
    pub(super) const ENTRY_MEMORY_LINKS: u64 = 0x08;
    /// `_LDR_DATA_TABLE_ENTRY32.InInitializationOrderLinks`.
    pub(super) const ENTRY_INIT_LINKS: u64 = 0x10;
    /// `_LDR_DATA_TABLE_ENTRY32.DllBase`.
    pub(super) const ENTRY_DLL_BASE: u64 = 0x18;
    /// `_LDR_DATA_TABLE_ENTRY32.SizeOfImage`.
    pub(super) const ENTRY_SIZE_OF_IMAGE: u64 = 0x20;
    /// `_LDR_DATA_TABLE_ENTRY32.FullDllName`, a 32-bit `_UNICODE_STRING`.
    pub(super) const ENTRY_FULL_NAME: u64 = 0x24;
    /// `_LDR_DATA_TABLE_ENTRY32.BaseDllName`.
    pub(super) const ENTRY_BASE_NAME: u64 = 0x2C;
}

/// One byte past the top of a 32-bit address space.
///
/// Every pointer in a WOW64 process's 32-bit structures is below this. A value
/// at or above it is not a 32-bit pointer, which is how a walk started at the
/// wrong offset is caught before it produces rows.
const WOW64_ADDRESS_CEILING: u64 = 1 << 32;

/// Which of the loader's three lists a walk belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LdrListKind {
    /// `InLoadOrderModuleList`.
    Load,
    /// `InMemoryOrderModuleList`.
    Memory,
    /// `InInitializationOrderModuleList`.
    Init,
}

/// The 32-bit loader of a WOW64 process, or the reason there is not one.
///
/// # Why this type exists
///
/// A 32-bit process on a 64-bit kernel has **two** loaders. The 64-bit `_PEB`
/// the kernel points at lists only the native images — `ntdll.dll` and the
/// `wow64*.dll` thunking layer — while every DLL the program actually loaded is
/// in a separate 32-bit `_PEB` reachable only through `_EPROCESS.WoW64Process`.
///
/// Scoring a WOW64 process's mapped images against the 64-bit lists alone
/// therefore finds every one of its ordinary 32-bit DLLs missing from all three
/// and reports them **unlinked**: a rootkit finding, on every 32-bit program on
/// the machine, generated by the tool. That is the worst class of wrong answer
/// this crate can produce, so when the 32-bit side cannot be read the claim is
/// withdrawn rather than made — [`Wow64Loader::establishes_absence`] is false
/// for every variant except [`Wow64Loader::NotWow64`] and a complete
/// [`Wow64Loader::Walked`].
#[derive(Debug, Clone)]
pub enum Wow64Loader {
    /// Not a 32-bit process on a 64-bit kernel: the native lists are the whole
    /// answer, and absence in them is absence.
    NotWow64,
    /// The 32-bit loader was reached and its lists walked.
    Walked {
        /// The 32-bit process environment block.
        peb32: u64,
        /// The 32-bit loader data inside it.
        ldr32: u64,
        /// The 32-bit load-order walk.
        load: LdrListWalk,
        /// The 32-bit memory-order walk.
        memory: LdrListWalk,
        /// The 32-bit initialisation-order walk.
        init: LdrListWalk,
        /// The images on the 32-bit load-order list — the DLL inventory that
        /// the native list of a WOW64 process does not contain.
        modules: Vec<LoadedModule>,
    },
    /// This is a WOW64 process and its 32-bit loader could not be read.
    Unavailable {
        /// The 32-bit PEB, when its address was at least known.
        peb32: Option<u64>,
        /// What failed, in the examiner's terms.
        detail: String,
    },
    /// Whether the process is WOW64 at all could not be established.
    Unknown {
        /// What failed, in the examiner's terms.
        detail: String,
    },
}

impl Wow64Loader {
    /// One of the three 32-bit walks, when they were made.
    pub fn walk(&self, kind: LdrListKind) -> Option<&LdrListWalk> {
        match self {
            Wow64Loader::Walked {
                load, memory, init, ..
            } => Some(match kind {
                LdrListKind::Load => load,
                LdrListKind::Memory => memory,
                LdrListKind::Init => init,
            }),
            _ => None,
        }
    }

    /// The images on the 32-bit load-order list.
    pub fn modules(&self) -> &[LoadedModule] {
        match self {
            Wow64Loader::Walked { modules, .. } => modules,
            _ => &[],
        }
    }

    /// Whether this process's native lists alone can establish that an image is
    /// absent from the loader's records.
    ///
    /// True only when there is no 32-bit loader to miss, or when there is one
    /// and all three of its lists were walked to their end. Anything else and
    /// an image missing from the native lists may simply be in the 32-bit ones.
    pub fn establishes_absence(&self) -> bool {
        match self {
            Wow64Loader::NotWow64 => true,
            Wow64Loader::Walked {
                load, memory, init, ..
            } => load.is_complete() && memory.is_complete() && init.is_complete(),
            Wow64Loader::Unavailable { .. } | Wow64Loader::Unknown { .. } => false,
        }
    }

    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Wow64Loader::NotWow64 => "not_wow64",
            Wow64Loader::Walked { .. } => "walked",
            Wow64Loader::Unavailable { .. } => "unavailable",
            Wow64Loader::Unknown { .. } => "unknown",
        }
    }

    /// What a report must declare about the 32-bit side of this process.
    pub fn incomplete(&self, process: u64) -> Option<Incomplete> {
        match self {
            Wow64Loader::NotWow64 => None,
            Wow64Loader::Walked { .. } if self.establishes_absence() => None,
            Wow64Loader::Walked { .. } => Some(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the 32-bit loader lists of the WOW64 process at {process:#x} were not walked \
                     to their end, so no image of it can be shown to be missing from the loader's \
                     records"
                ),
            )),
            Wow64Loader::Unavailable { detail, .. } => Some(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the process at {process:#x} is a 32-bit process on a 64-bit kernel and its \
                     32-bit module list could not be read, so its 32-bit DLLs are unknown rather \
                     than absent and none of them can be called unlinked: {detail}"
                ),
            )),
            Wow64Loader::Unknown { detail } => Some(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "whether the process at {process:#x} is a 32-bit process on a 64-bit kernel \
                     could not be established, so a second module list may exist and no image of \
                     it can be called unlinked: {detail}"
                ),
            )),
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Wow64Loader::NotWow64 => serde_json::json!({"kind": "not_wow64"}),
            Wow64Loader::Walked {
                peb32,
                ldr32,
                load,
                memory,
                init,
                modules,
            } => serde_json::json!({
                "kind": "walked",
                "peb32": peb32,
                "peb32_hex": format!("{peb32:#x}"),
                "ldr32": ldr32,
                "ldr32_hex": format!("{ldr32:#x}"),
                "load": load.to_json(),
                "memory": memory.to_json(),
                "init": init.to_json(),
                "modules": modules.iter().map(LoadedModule::to_json).collect::<Vec<_>>(),
                "module_count": modules.len(),
                "establishes_absence": self.establishes_absence(),
            }),
            Wow64Loader::Unavailable { peb32, detail } => serde_json::json!({
                "kind": "unavailable",
                "peb32": peb32,
                // The same sibling the `walked` arm carries. A consumer that
                // reads `peb32_hex` must find it on every arm that has a
                // `peb32`, or it silently falls back to the rounded number on
                // exactly the rows where something already went wrong.
                "peb32_hex": peb32.map(|peb32| format!("{peb32:#x}")),
                "detail": detail,
                "establishes_absence": false,
            }),
            Wow64Loader::Unknown { detail } => serde_json::json!({
                "kind": "unknown",
                "detail": detail,
                "establishes_absence": false,
            }),
        }
    }
}

/// Read a little-endian `u32` out of a process's own address space.
fn read_u32(reader: &StructReader, address: u64) -> Result<u32, ObjError> {
    let mut buf = [0u8; 4];
    reader.read_into(address, &mut buf)?;
    Ok(u32::from_le_bytes(buf))
}

/// Read a 32-bit `_UNICODE_STRING` at `address`.
///
/// Same rules as the 64-bit reader in [`crate::poolscan::unicode_string`]:
/// `Length` counts bytes, the length is capped before anything is allocated,
/// and no NUL terminator is assumed. Only the pointer width differs.
fn wow64_unicode_string(reader: &StructReader, address: u64) -> NameField {
    let mut header = [0u8; 8];
    if let Err(err) = reader.read_into(address, &mut header) {
        return NameField::Unavailable(err.to_string());
    }
    let length = u16::from_le_bytes([header[0], header[1]]) as u64;
    let maximum = u16::from_le_bytes([header[2], header[3]]) as u64;
    let buffer = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as u64;
    if length == 0 {
        return NameField::Empty;
    }
    if !length.is_multiple_of(2)
        || length > crate::poolscan::MAX_UNICODE_STRING_BYTES
        || maximum < length
    {
        return NameField::Unavailable(format!(
            "the 32-bit string at {address:#x} declares {length} byte(s) of text in a buffer of \
             {maximum}, which is not a _UNICODE_STRING"
        ));
    }
    if buffer == 0 {
        return NameField::Unavailable(format!(
            "the 32-bit string at {address:#x} declares {length} byte(s) of text and a null buffer"
        ));
    }
    match reader.read_bytes(buffer, length) {
        Ok(bytes) => {
            let text = crate::poolscan::decode_utf16le(&bytes);
            match loader_string_damage(&text) {
                None => NameField::Name(text),
                Some(damage) => NameField::Unavailable(format!(
                    "the 32-bit string at {address:#x} points at {buffer:#x}, where {damage}, so \
                     these bytes are not the name they were read as"
                )),
            }
        }
        Err(err) => NameField::Unavailable(err.to_string()),
    }
}

/// Walk one 32-bit loader list, returning the address of every entry.
///
/// The 32-bit lists cannot go through [`entry_walk`]: that resolves
/// `_LIST_ENTRY` and the container offset from the symbol table, and the symbol
/// table describes the 64-bit forms. The walk is otherwise identical, including
/// the two things that matter — a visited set, so a corrupt list cannot spin,
/// and a [`ListStop`] that distinguishes "reached the end" from "stopped".
fn wow64_list_walk(
    reader: &StructReader,
    head: u64,
    links_offset: u64,
    max_entries: usize,
) -> (Vec<u64>, ListStop) {
    let mut entries = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut link = match read_u32(reader, head) {
        Ok(value) => value as u64,
        Err(err) => {
            return (
                entries,
                ListStop::Failed {
                    detail: format!("the 32-bit list head at {head:#x} could not be read: {err}"),
                    reason: err.incomplete_reason(),
                },
            )
        }
    };

    loop {
        if link == head {
            return (entries, ListStop::Wrapped);
        }
        if link == 0 {
            return (entries, ListStop::NullLink { at: head });
        }
        if link >= WOW64_ADDRESS_CEILING {
            return (
                entries,
                ListStop::Failed {
                    detail: format!(
                        "the 32-bit list link {link:#x} is above the top of a 32-bit address \
                         space, so this is not a 32-bit loader list"
                    ),
                    reason: IncompleteReason::UnresolvedStructure,
                },
            );
        }
        if !seen.insert(link) {
            return (entries, ListStop::Cycle { address: link });
        }
        if entries.len() >= max_entries {
            return (entries, ListStop::CapReached { cap: max_entries });
        }
        let Some(entry) = link.checked_sub(links_offset) else {
            return (
                entries,
                ListStop::Failed {
                    detail: format!(
                        "the 32-bit list link {link:#x} is below the offset of the link member it \
                         is supposed to sit at, so it does not name an entry"
                    ),
                    reason: IncompleteReason::UnresolvedStructure,
                },
            );
        };
        entries.push(entry);
        link = match read_u32(reader, link) {
            Ok(value) => value as u64,
            Err(err) => {
                return (
                    entries,
                    ListStop::Failed {
                        detail: format!(
                            "the 32-bit forward link at {link:#x} could not be read: {err}"
                        ),
                        reason: err.incomplete_reason(),
                    },
                )
            }
        };
    }
}

/// Walk one 32-bit loader list into the same shape the native walks produce.
fn wow64_membership_walk(
    reader: &StructReader,
    ldr32: u64,
    head_offset: u64,
    head_member: &str,
    links_offset: u64,
    links_member: &str,
    max_entries: usize,
) -> LdrListWalk {
    let head = ldr32.saturating_add(head_offset);
    let mut walk = LdrListWalk {
        head_member: Some(head_member.to_string()),
        links_member: Some(links_member.to_string()),
        head: Some(head),
        members: Vec::new(),
        unreadable_bases: 0,
        stop: None,
    };
    let (entries, stop) = wow64_list_walk(reader, head, links_offset, max_entries);
    for entry in entries {
        match read_u32(reader, entry.saturating_add(wow64_layout::ENTRY_DLL_BASE)) {
            Ok(base) => walk.members.push((base as u64, entry)),
            // An entry whose base is unknown is exactly the entry that might be
            // the image about to be called missing, so it suppresses every
            // claim of absence from this list.
            Err(_) => walk.unreadable_bases = walk.unreadable_bases.saturating_add(1),
        }
    }
    walk.stop = Some(stop);
    walk
}

/// Read one 32-bit loader entry into the shape the native walk produces.
fn wow64_read_entry(reader: &StructReader, entry: u64, load_order: usize) -> LoadedModule {
    let mut notes = Vec::new();
    let base = match read_u32(reader, entry.saturating_add(wow64_layout::ENTRY_DLL_BASE)) {
        Ok(value) => Some(value as u64),
        Err(err) => {
            notes.push(format!("the 32-bit 'DllBase' could not be read: {err}"));
            None
        }
    };
    let size = entry.saturating_add(wow64_layout::ENTRY_SIZE_OF_IMAGE);
    let size_of_image = match read_u32(reader, size) {
        Ok(value) => Some(value as u64),
        Err(err) => {
            notes.push(format!("the 32-bit 'SizeOfImage' could not be read: {err}"));
            None
        }
    };
    let full = entry.saturating_add(wow64_layout::ENTRY_FULL_NAME);
    let name = entry.saturating_add(wow64_layout::ENTRY_BASE_NAME);
    LoadedModule {
        entry,
        base,
        size_of_image,
        full_path: wow64_unicode_string(reader, full),
        base_name: wow64_unicode_string(reader, name),
        load_order,
        notes,
    }
}

/// Reach and walk the 32-bit loader of a WOW64 process.
///
/// # What an examiner learns
///
/// The DLLs a 32-bit program actually loaded, which do not appear in the
/// process's 64-bit loader lists at all — and, just as importantly, that those
/// DLLs are legitimately linked. Without this walk every one of them is missing
/// from all three native lists, which is the signature of a module unlinked by
/// a rootkit.
///
/// # What a wrong answer looks like
///
/// [`Wow64Loader::Unavailable`] where the truth is `Walked` costs the 32-bit
/// inventory and leaves the unlinked question unanswered — an honest gap. The
/// opposite, a walk of the wrong structure reported as a walk, would clear
/// images nothing examined, so every pointer read here is checked against the
/// top of a 32-bit address space before it is followed.
fn wow64_loader(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    process: u64,
    space: &ProcessSpace,
    config: &ModuleWalkConfig,
) -> Wow64Loader {
    let Some(wow64_member) = &symbols.wow64 else {
        // A build whose `_EPROCESS` has no WOW64 member is a 32-bit kernel,
        // which cannot host a WOW64 process. Not a gap: an answer.
        return Wow64Loader::NotWow64;
    };
    let kernel = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let eprocess = match kernel.object(process, TYPE_EPROCESS) {
        Ok(object) => object,
        Err(err) => {
            return Wow64Loader::Unknown {
                detail: format!("'{TYPE_EPROCESS}' at {process:#x} could not be typed: {err}"),
            }
        }
    };
    let block = match eprocess.pointer(wow64_member) {
        Ok(value) => value,
        Err(err) => {
            return Wow64Loader::Unknown {
                detail: format!("'{TYPE_EPROCESS}.{wow64_member}' could not be read: {err}"),
            }
        }
    };
    if block == 0 {
        return Wow64Loader::NotWow64;
    }

    // From Windows 10 1511 the member points at an `_EWOW64PROCESS` whose first
    // pointer is the 32-bit PEB; before it, the member is the PEB itself.
    let peb32 = match &symbols.ewow64_peb {
        None => block,
        Some(member) => match kernel.object(block, TYPE_EWOW64PROCESS) {
            Ok(object) => match object.pointer(member) {
                Ok(value) => value,
                Err(err) => {
                    return Wow64Loader::Unavailable {
                        peb32: None,
                        detail: format!(
                            "'{TYPE_EWOW64PROCESS}.{member}' at {block:#x} could not be read: {err}"
                        ),
                    }
                }
            },
            Err(err) => {
                return Wow64Loader::Unavailable {
                    peb32: None,
                    detail: format!(
                        "'{TYPE_EWOW64PROCESS}' at {block:#x} could not be typed: {err}"
                    ),
                }
            }
        },
    };
    if peb32 == 0 || peb32 >= WOW64_ADDRESS_CEILING {
        return Wow64Loader::Unavailable {
            peb32: Some(peb32),
            detail: format!(
                "the WOW64 block names {peb32:#x} as the 32-bit process environment block, which \
                 is not an address in a 32-bit address space"
            ),
        };
    }

    let reader = StructReader::new(Arc::clone(space.layer()), Arc::clone(&profile.symbols));
    let ldr32 = match read_u32(&reader, peb32.saturating_add(wow64_layout::PEB_LDR)) {
        Ok(value) => value as u64,
        Err(err) => {
            return Wow64Loader::Unavailable {
                peb32: Some(peb32),
                detail: format!("the 32-bit '_PEB.Ldr' at {peb32:#x} could not be read: {err}"),
            }
        }
    };
    if ldr32 == 0 {
        return Wow64Loader::Unavailable {
            peb32: Some(peb32),
            detail: "the 32-bit process environment block records no loader data, so the 32-bit \
                     module list cannot be reached"
                .to_string(),
        };
    }

    let load = wow64_membership_walk(
        &reader,
        ldr32,
        wow64_layout::LDR_LOAD_HEAD,
        "InLoadOrderModuleList (32-bit)",
        wow64_layout::ENTRY_LOAD_LINKS,
        "InLoadOrderLinks (32-bit)",
        config.max_modules,
    );
    let memory = wow64_membership_walk(
        &reader,
        ldr32,
        wow64_layout::LDR_MEMORY_HEAD,
        "InMemoryOrderModuleList (32-bit)",
        wow64_layout::ENTRY_MEMORY_LINKS,
        "InMemoryOrderLinks (32-bit)",
        config.max_modules,
    );
    let init = wow64_membership_walk(
        &reader,
        ldr32,
        wow64_layout::LDR_INIT_HEAD,
        "InInitializationOrderModuleList (32-bit)",
        wow64_layout::ENTRY_INIT_LINKS,
        "InInitializationOrderLinks (32-bit)",
        config.max_modules,
    );

    // A load-order walk that produced nothing at all is not a 32-bit loader:
    // every WOW64 process has at least its own image and the 32-bit ntdll on
    // that list. Reporting it as walked would let the absence of every 32-bit
    // DLL from it be treated as established.
    if load.members.is_empty() && load.unreadable_bases == 0 {
        return Wow64Loader::Unavailable {
            peb32: Some(peb32),
            detail: format!(
                "the 32-bit load-order list at {ldr32:#x} yielded no entry, and a running 32-bit \
                 process always has at least its own image on it, so this is not a readable \
                 32-bit loader"
            ),
        };
    }

    let modules = load
        .members
        .iter()
        .enumerate()
        .map(|(order, (_, entry))| wow64_read_entry(&reader, *entry, order))
        .collect();

    Wow64Loader::Walked {
        peb32,
        ldr32,
        load,
        memory,
        init,
        modules,
    }
}

// ── Kernel modules ──────────────────────────────────────────────────────────

/// The kernel's own loaded modules: drivers.
#[derive(Debug, Clone)]
pub struct KernelModules {
    /// Where `PsLoadedModuleList` is, in kernel virtual space.
    pub head: u64,
    /// The loader entry type the list was read through.
    pub entry_type: String,
    /// The drivers, in the order the list holds them.
    pub modules: Vec<LoadedModule>,
    /// Why the walk ended.
    pub stop: ListStop,
    /// Notes, capped by [`ModuleWalkConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total.
    pub notes_total: usize,
}

impl KernelModules {
    /// Whether the whole list was walked.
    pub fn is_complete(&self) -> bool {
        self.stop.is_complete()
    }

    /// Everything a report must declare about this list.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        self.stop.incomplete().into_iter().collect()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "head": self.head,
            "head_hex": format!("{:#x}", self.head),
            "entry_type": self.entry_type,
            "modules": self.modules.iter().map(LoadedModule::to_json).collect::<Vec<_>>(),
            "module_count": self.modules.len(),
            "stop": self.stop.as_str(),
            "complete": self.is_complete(),
            "notes": self.notes,
            "notes_total": self.notes_total,
        })
    }
}

/// List the kernel's loaded modules, from `PsLoadedModuleList`.
///
/// Read entirely in the kernel address space: a driver's loader entry and
/// everything it points at are kernel addresses.
///
/// # What an examiner learns
///
/// Every driver the kernel admits to having loaded, with its base, its size and
/// the path it came from. This is the *linked* view, which is precisely what a
/// rootkit that unlinks its own entry removes itself from — so a driver found
/// by a pool scan of `MmLd` allocations but absent here has been hidden, and
/// comparing the two lists is the reason to run both.
///
/// # Errors
///
/// [`ModulesError::Unsupported`] when this build's symbols do not name
/// `PsLoadedModuleList`. Returning an empty list there would be a claim that
/// the machine had no drivers loaded, which is never true.
pub fn list_kernel_modules(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    config: &ModuleWalkConfig,
) -> Result<KernelModules, ModulesError> {
    let head = symbols.ps_loaded_module_list.ok_or_else(|| {
        ModulesError::unsupported(format!(
            "the symbol table has no '{SYMBOL_PS_LOADED_MODULE_LIST}', so the kernel's own \
             loaded-module list cannot be found"
        ))
    })?;
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let (entries, stop) = entry_walk(
        &reader,
        head,
        &symbols.kernel_entry_type,
        &symbols.kernel_links,
        config.max_modules,
    )?;

    let mut out = KernelModules {
        head,
        entry_type: symbols.kernel_entry_type.clone(),
        modules: Vec::new(),
        stop,
        notes: Vec::new(),
        notes_total: 0,
    };
    for (order, entry) in entries.iter().enumerate() {
        let module = read_entry(symbols, entry, order);
        for note in &module.notes {
            push_note(
                &mut out.notes,
                &mut out.notes_total,
                config.max_recorded_notes,
                format!("the entry at {:#x}: {note}", entry.address()),
            );
        }
        out.modules.push(module);
    }
    Ok(out)
}

// ── The orchestrated stage ──────────────────────────────────────────────────

/// One process's user-mode modules: the loader's own list and the unlinked-module
/// cross-reference, together.
///
/// The two answer different questions and neither replaces the other.
/// [`list_dlls`] says what the loader admits to having loaded; [`ldr_modules`]
/// says what is actually mapped and which of the loader's three lists still name
/// it. A report holding only the first cannot see a module that was unlinked,
/// which is the finding the stage exists for.
#[derive(Debug, Clone)]
pub struct ProcessModules {
    /// The `_EPROCESS` this belongs to.
    pub process: u64,
    /// The process id, when the list could read one.
    pub pid: Option<u64>,
    /// The image name, when the list could read one.
    pub name: Option<String>,
    /// The directory table base the process's own space was built from.
    pub dtb: u64,
    /// The loader's load-order list.
    pub dlls: DllList,
    /// The three loader lists cross-referenced against the VAD tree.
    pub ldr: Option<LdrModules>,
    /// Why [`ProcessModules::ldr`] is absent, when it is.
    ///
    /// Never an empty cross-reference: "no module was found unlinked" and "the
    /// cross-reference was not made" are opposite findings, and a table showing
    /// the first where the truth is the second clears a process nothing looked
    /// at.
    pub ldr_unavailable: Option<String>,
    /// What this process's own address space reported while both halves above
    /// were walked.
    ///
    /// This stage reads more of a process's address space than any other — the
    /// PEB, three loader lists, and every mapped range the VAD tree names — so
    /// it is where the uniform-table heuristic has the most opportunity to
    /// decline a page. The refusal count belongs beside the module list for
    /// exactly that reason: "no unlinked module was found" is a weaker
    /// statement when the walker declined to translate part of the space, and
    /// nothing in the module rows shows that.
    ///
    /// [`SpaceProvenance::not_built`] when the space was supplied rather than
    /// derived, which is an absent answer and not a clean one.
    pub space: SpaceProvenance,
}

impl ProcessModules {
    /// Whether both halves ran in full.
    pub fn is_complete(&self) -> bool {
        self.dlls.is_complete() && self.ldr.as_ref().is_some_and(LdrModules::is_complete)
    }

    /// The mapped images missing from at least one loader list.
    ///
    /// Empty when the cross-reference could not be made — which is why
    /// [`ProcessModules::is_complete`] has to be read beside it.
    pub fn unlinked(&self) -> Vec<&LdrModule> {
        self.ldr
            .as_ref()
            .map(|ldr| ldr.unlinked().collect())
            .unwrap_or_default()
    }

    /// Everything a report must declare about this process's modules.
    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = self.dlls.incomplete();
        match &self.ldr {
            Some(ldr) => out.extend(ldr.incomplete()),
            None => out.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                self.ldr_unavailable.clone().unwrap_or_else(|| {
                    format!(
                        "the mapped images of the process at {:#x} were not cross-referenced \
                         against its loader lists, and no reason was recorded",
                        self.process
                    )
                }),
            )),
        }
        out
    }

    /// One row per image this process had mapped, whatever named it.
    ///
    /// The union of three sources, because any one of them alone hides the
    /// finding the stage exists for: the loader's own 64-bit list, the 32-bit
    /// list a WOW64 process keeps, and the mapped images that no loader list
    /// admits to. That last group is exactly the set an examiner is looking
    /// for, and a DLL table built from the loader's list alone would not
    /// contain a single one of them.
    ///
    /// Each row says which source it came from and whether it is unlinked, so a
    /// renderer that shows only the name and the base still shows the hidden
    /// module as a row rather than omitting it.
    ///
    /// A mapped image whose membership could not be **established** — a WOW64
    /// process whose 32-bit loader would not read, a list that stopped at a
    /// cycle — is a row too, with `unlinked: null` and
    /// `membership_established: false`. Dropping it would take an image that
    /// was demonstrably mapped out of the table entirely, and a table that does
    /// not list it reads as a process that never had it mapped. The row is the
    /// honest answer: this was mapped, and whether the loader still admits to
    /// it is unknown.
    fn module_rows(&self) -> Vec<serde_json::Value> {
        let mut out = Vec::new();
        let mut listed: Vec<u64> = Vec::new();
        for (source, module) in self
            .dlls
            .modules
            .iter()
            .map(|module| ("loader_list_64", module))
            .chain(
                self.dlls
                    .wow64
                    .modules()
                    .iter()
                    .map(|module| ("loader_list_32", module)),
            )
        {
            let mut row = module.to_json();
            if let Some(object) = row.as_object_mut() {
                object.insert("source".into(), serde_json::json!(source));
                object.insert("unlinked".into(), serde_json::json!(false));
            }
            if let Some(base) = module.base {
                listed.push(base);
            }
            out.push(row);
        }
        // Mapped images no loader list named. `is_unlinked` is only true for an
        // *established* absence, so an image whose lists could not be walked is
        // never accused here — it is carried with `unlinked: null` instead,
        // because dropping it would hide an image that was demonstrably mapped.
        for module in self.ldr.iter().flat_map(|ldr| ldr.modules.iter()) {
            if listed.contains(&module.base) {
                continue;
            }
            // Three answers, never two: missing from a list that was walked to
            // its end, present in all three, or not established either way.
            let unlinked = if module.is_unlinked() {
                Some(true)
            } else if module.is_fully_linked() {
                Some(false)
            } else {
                None
            };
            out.push(serde_json::json!({
                "base": module.base,
                "base_hex": format!("{:#x}", module.base),
                "name": module.mapped_file.name(),
                "full_dll_name": module.mapped_file.name(),
                "source": "mapped_image",
                "unlinked": unlinked,
                "membership_established": unlinked.is_some(),
                "in_load": module.in_load,
                "in_init": module.in_init,
                "in_mem": module.in_mem,
                "vad": module.vad,
                "vad_hex": format!("{:#x}", module.vad),
                "notes": module.notes,
            }));
        }
        out
    }

    /// Serializable form for one process's module record.
    ///
    /// Self-contained: it carries the process it belongs to, so a caller may
    /// emit one artifact per process without tagging it afterwards.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process_address": self.process,
            "process_address_hex": format!("{:#x}", self.process),
            "pid": self.pid,
            "process_name": self.name,
            "dtb": self.dtb,
            "dtb_hex": format!("{:#x}", self.dtb),
            "modules": self.module_rows(),
            "dlls": self.dlls.to_json(),
            "ldr_modules": self.ldr.as_ref().map(LdrModules::to_json),
            "ldr_unavailable": self.ldr_unavailable,
            "address_space": self.space.to_json(),
            "unlinked_count": self.unlinked().len(),
            "complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// A process the survey could not examine at all, and why.
#[derive(Debug, Clone)]
pub struct SkippedProcess {
    /// The `_EPROCESS`.
    pub process: u64,
    /// Its process id, when the list could read one.
    pub pid: Option<u64>,
    /// Its image name, when the list could read one.
    pub name: Option<String>,
    /// Why nothing could be read.
    pub reason: String,
}

impl SkippedProcess {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "process_address": self.process,
            "process_address_hex": format!("{:#x}", self.process),
            "pid": self.pid,
            "process_name": self.name,
            "reason": self.reason,
        })
    }
}

/// Caps for a whole-image module survey.
#[derive(Debug, Clone, Default)]
pub struct ModuleSurveyConfig {
    /// Caps and address-space settings for each process's loader walks.
    pub walk: ModuleWalkConfig,
    /// Caps for each process's VAD walk, which the cross-reference rests on.
    pub vad: crate::vad::VadWalkConfig,
}

/// Every process's user-mode modules, and every process that could not be read.
#[derive(Debug, Clone)]
pub struct ModuleSurvey {
    /// One entry per process that was examined, in list order.
    pub processes: Vec<ProcessModules>,
    /// The processes nothing could be read for.
    pub skipped: Vec<SkippedProcess>,
    /// How complete the process list the survey ran over was.
    ///
    /// The same stamp every other process-dependent stage carries: a survey
    /// that read every module of every process it was handed is still a floor
    /// when the list it was handed stopped short.
    pub inventory: crate::process::ProcessInventory,
    /// Why the VAD cross-reference was impossible for the whole image, when it
    /// was — a build whose VAD structures the symbols cannot describe.
    pub vad_symbols_unavailable: Option<String>,
}

impl ModuleSurvey {
    /// Every mapped image found missing from at least one loader list.
    pub fn unlinked(&self) -> Vec<(&ProcessModules, &LdrModule)> {
        self.processes
            .iter()
            .flat_map(|process| {
                process
                    .unlinked()
                    .into_iter()
                    .map(move |module| (process, module))
            })
            .collect()
    }

    /// Whether the survey covered every process on the list, in full.
    ///
    /// The question a report must ask before writing "no module was hidden in
    /// this image".
    pub fn is_complete(&self) -> bool {
        self.inventory.is_complete()
            && self.skipped.is_empty()
            && self.vad_symbols_unavailable.is_none()
            && self.processes.iter().all(ProcessModules::is_complete)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        let mut value = serde_json::json!({
            "processes": self.processes.iter().map(ProcessModules::to_json).collect::<Vec<_>>(),
            "process_count": self.processes.len(),
            "skipped": self.skipped.iter().map(SkippedProcess::to_json).collect::<Vec<_>>(),
            "unlinked_count": self.unlinked().len(),
            "list_complete": self.inventory.is_complete(),
            "vad_symbols_unavailable": self.vad_symbols_unavailable,
            "complete": self.is_complete(),
        });
        self.inventory.stamp(&mut value);
        value
    }
}

/// Examine every process on a list — the whole `dlls` stage.
///
/// This is the entry point an orchestrator calls. It never fails as a whole:
/// a process whose address space cannot be built is recorded in
/// [`ModuleSurvey::skipped`] and the rest still run, because one unreadable
/// process must not cost the other hundred. What it will not do is return an
/// empty survey that reads like a machine with no modules loaded — an empty
/// [`ModuleSurvey::processes`] with a populated `skipped` says plainly that
/// nothing was examined.
///
/// The VAD tree each cross-reference needs is walked here rather than taken from
/// the caller, so that the tree used is provably the one belonging to the
/// process being examined.
///
/// # What an examiner learns
///
/// Every user-mode image mapped anywhere on the machine, and every one of them
/// the loader has been made to forget. [`ModuleSurvey::unlinked`] is the finding
/// list; [`ModuleSurvey::is_complete`] is whether its emptiness means anything.
pub fn survey_process_modules(
    profile: &WindowsProfile,
    symbols: &ModuleSymbols,
    list: &crate::process::ProcessList,
    config: &ModuleSurveyConfig,
) -> ModuleSurvey {
    let (vad_symbols, vad_symbols_unavailable) = match crate::vad::VadSymbols::from_profile(profile)
    {
        Ok(symbols) => (Some(symbols), None),
        Err(err) => (
            None,
            Some(format!(
                "this build's virtual address descriptors cannot be walked, so no mapped image \
                     can be shown to be missing from a loader list: {err}"
            )),
        ),
    };

    let mut survey = ModuleSurvey {
        processes: Vec::new(),
        skipped: Vec::new(),
        inventory: list.inventory(),
        vad_symbols_unavailable,
    };

    // One page-table memo for the whole image. Entries are keyed by physical
    // address and mean the same thing in every process's address space, so one
    // cache for four hundred processes is right and four hundred caches is
    // waste.
    let mut walk = config.walk.clone();
    if walk.page_table_cache.is_none() {
        walk.page_table_cache = Some(Arc::new(TableCache::new()));
    }

    for entry in &list.processes {
        let pid = entry.pid.known().copied();
        let name = entry.image_file_name.known().cloned();
        let space = match ProcessSpace::build(profile, symbols, entry.address, &walk) {
            Ok(space) => space,
            Err(err) => {
                survey.skipped.push(SkippedProcess {
                    process: entry.address,
                    pid,
                    name,
                    reason: format!(
                        "the process's own address space could not be built, so its loaded modules \
                         are unknown rather than absent: {err}"
                    ),
                });
                continue;
            }
        };

        let dlls = match list_dlls(profile, symbols, entry.address, &space, &walk) {
            Ok(dlls) => dlls,
            Err(err) => {
                survey.skipped.push(SkippedProcess {
                    process: entry.address,
                    pid,
                    name,
                    reason: format!("the loader's module list could not be walked: {err}"),
                });
                continue;
            }
        };

        let (ldr, ldr_unavailable) = match &vad_symbols {
            None => (None, survey.vad_symbols_unavailable.clone()),
            Some(vad_symbols) => {
                match crate::vad::list_vads(profile, vad_symbols, entry.address, &config.vad) {
                    Err(err) => (
                        None,
                        Some(format!(
                            "the VAD tree of the process at {:#x} could not be walked, so its \
                             mapped images could not be cross-referenced against its loader lists: \
                             {err}",
                            entry.address
                        )),
                    ),
                    Ok(tree) => {
                        match ldr_modules(profile, symbols, entry.address, &space, &tree, &walk) {
                            Ok(ldr) => (Some(ldr), None),
                            Err(err) => (
                                None,
                                Some(format!(
                                    "the mapped images of the process at {:#x} could not be \
                                     cross-referenced against its loader lists: {err}",
                                    entry.address
                                )),
                            ),
                        }
                    }
                }
            }
        };

        // Taken after both walks, not before: the refusal counter is a running
        // total on the layer, and what an examiner needs to know is how many
        // pages were declined while *this* result was being produced. The
        // loader's own data is named because it is the evidence every row here
        // rests on — a shared PEB or a shared `_PEB_LDR_DATA` would mean the
        // module list is not private to this process.
        let mut pages: Vec<(&'static str, u64)> = Vec::new();
        if let LoaderData::At { peb, ldr } = &dlls.loader {
            pages.push(("the process environment block", *peb));
            pages.push(("the loader's module data", *ldr));
        }
        let provenance = space.provenance(&pages);

        survey.processes.push(ProcessModules {
            process: entry.address,
            pid,
            name,
            dtb: space.dtb(),
            dlls,
            ldr,
            ldr_unavailable,
            space: provenance,
        });
    }

    survey
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::poolscan::test_support::{profile, table, Image};
    use crate::vad::{Vad, VadKind, VadRootShape, VadStop};

    // Where the synthetic 64-bit fixture puts things.
    const EPROCESS_AT: u64 = 0x1000;
    const PEB_AT: u64 = 0x2000;
    const LDR_AT: u64 = 0x3000;
    const ENTRY_A: u64 = 0x4000;
    const ENTRY_B: u64 = 0x5000;
    const FULL_A_AT: u64 = 0x6000;
    const BASE_A_AT: u64 = 0x6100;
    const FULL_B_AT: u64 = 0x6200;
    const BASE_B_AT: u64 = 0x6300;
    const KERNEL_HEAD: u64 = 0x7000;
    const DRIVER_AT: u64 = 0x8000;
    const DRIVER_FULL_AT: u64 = 0x8400;
    const DRIVER_BASE_AT: u64 = 0x8500;
    const PROCESS_DTB: u64 = 0x9000;

    /// The three mapped images, and one range that holds no image at all.
    const MODULE_A: u64 = 0xA000;
    const MODULE_B: u64 = 0xB000;
    const MODULE_C: u64 = 0xC000;
    const PLAIN_RANGE: u64 = 0xD000;

    /// An address no synthetic image covers, so a read of it fails the way a
    /// paged-out page does.
    const NOWHERE: u64 = 0xFFFF_0000;

    /// Offsets the synthetic 64-bit module ISF declares.
    mod off {
        pub(super) const EPROCESS_DTB: u64 = 0;
        pub(super) const EPROCESS_PEB: u64 = 16;
        pub(super) const PEB_LDR: u64 = 8;
        pub(super) const LDR_LOAD_HEAD: u64 = 16;
        pub(super) const LDR_MEMORY_HEAD: u64 = 32;
        pub(super) const LDR_INIT_HEAD: u64 = 48;
        pub(super) const ENTRY_LOAD_LINKS: u64 = 0;
        pub(super) const ENTRY_MEMORY_LINKS: u64 = 16;
        pub(super) const ENTRY_INIT_LINKS: u64 = 32;
        pub(super) const ENTRY_DLL_BASE: u64 = 48;
        pub(super) const ENTRY_SIZE_OF_IMAGE: u64 = 56;
        pub(super) const ENTRY_FULL_NAME: u64 = 64;
        pub(super) const ENTRY_BASE_NAME: u64 = 80;
        pub(super) const UNICODE_LENGTH: u64 = 0;
        pub(super) const UNICODE_MAX_LENGTH: u64 = 2;
        pub(super) const UNICODE_BUFFER: u64 = 8;
    }

    /// Offsets the synthetic 32-bit module ISF declares.
    mod off32 {
        pub(super) const EPROCESS_DTB: u64 = 0;
        pub(super) const EPROCESS_PEB: u64 = 8;
        pub(super) const PEB_LDR: u64 = 4;
        pub(super) const LDR_LOAD_HEAD: u64 = 8;
        pub(super) const LDR_MEMORY_HEAD: u64 = 16;
        pub(super) const LDR_INIT_HEAD: u64 = 24;
        pub(super) const ENTRY_LOAD_LINKS: u64 = 0;
        pub(super) const ENTRY_MEMORY_LINKS: u64 = 8;
        pub(super) const ENTRY_INIT_LINKS: u64 = 16;
        pub(super) const ENTRY_DLL_BASE: u64 = 24;
        pub(super) const ENTRY_SIZE_OF_IMAGE: u64 = 28;
        pub(super) const ENTRY_FULL_NAME: u64 = 32;
        pub(super) const ENTRY_BASE_NAME: u64 = 40;
        pub(super) const UNICODE_LENGTH: u64 = 0;
        pub(super) const UNICODE_MAX_LENGTH: u64 = 2;
        pub(super) const UNICODE_BUFFER: u64 = 4;
    }

    /// A synthetic 64-bit Windows 10 ISF for the loader structures.
    ///
    /// `kernel_entry` adds `_KLDR_DATA_TABLE_ENTRY`, which Windows 10 declares
    /// and earlier builds do not; `ps_loaded_module_list` decides whether the
    /// kernel's list head is nameable at all.
    fn win10_module_isf(kernel_entry: bool, ps_loaded_module_list: bool) -> String {
        let kldr = if kernel_entry {
            r#""_KLDR_DATA_TABLE_ENTRY": {"size": 96, "kind": "struct", "fields": {
      "InLoadOrderLinks": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InMemoryOrderLinks": {"offset": 16, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InInitializationOrderLinks": {"offset": 32, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "DllBase": {"offset": 48, "type": {"kind": "pointer", "subtype": {"kind": "base", "name": "unsigned char"}}},
      "SizeOfImage": {"offset": 56, "type": {"kind": "base", "name": "unsigned long"}},
      "FullDllName": {"offset": 64, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "BaseDllName": {"offset": 80, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},"#
        } else {
            ""
        };
        let symbols = if ps_loaded_module_list {
            r#""PsLoadedModuleList": {"address": 28672}"#
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
  "base_types": {{
    "pointer": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
    "unsigned long long": {{"size": 8, "signed": false, "kind": "int", "endian": "little"}},
    "long long": {{"size": 8, "signed": true, "kind": "int", "endian": "little"}},
    "unsigned long": {{"size": 4, "signed": false, "kind": "int", "endian": "little"}},
    "long": {{"size": 4, "signed": true, "kind": "int", "endian": "little"}},
    "unsigned short": {{"size": 2, "signed": false, "kind": "int", "endian": "little"}},
    "unsigned char": {{"size": 1, "signed": false, "kind": "int", "endian": "little"}}
  }},
  "user_types": {{
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
    "_LDR_DATA_TABLE_ENTRY": {{"size": 96, "kind": "struct", "fields": {{
      "InLoadOrderLinks": {{"offset": 0, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "InMemoryOrderLinks": {{"offset": 16, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "InInitializationOrderLinks": {{"offset": 32, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "DllBase": {{"offset": 48, "type": {{"kind": "pointer",
                  "subtype": {{"kind": "base", "name": "unsigned char"}}}}}},
      "SizeOfImage": {{"offset": 56, "type": {{"kind": "base", "name": "unsigned long"}}}},
      "FullDllName": {{"offset": 64, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}},
      "BaseDllName": {{"offset": 80, "type": {{"kind": "struct", "name": "_UNICODE_STRING"}}}}
    }}}},
    {kldr}
    "_PEB_LDR_DATA": {{"size": 64, "kind": "struct", "fields": {{
      "InLoadOrderModuleList": {{"offset": 16, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "InMemoryOrderModuleList": {{"offset": 32, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}},
      "InInitializationOrderModuleList": {{"offset": 48, "type": {{"kind": "struct", "name": "_LIST_ENTRY"}}}}
    }}}},
    "_PEB": {{"size": 64, "kind": "struct", "fields": {{
      "Ldr": {{"offset": 8, "type": {{"kind": "pointer",
              "subtype": {{"kind": "struct", "name": "_PEB_LDR_DATA"}}}}}}
    }}}},
    "_KPROCESS": {{"size": 16, "kind": "struct", "fields": {{
      "DirectoryTableBase": {{"offset": 0, "type": {{"kind": "base", "name": "unsigned long long"}}}}
    }}}},
    "_EPROCESS": {{"size": 64, "kind": "struct", "fields": {{
      "Pcb": {{"offset": 0, "type": {{"kind": "struct", "name": "_KPROCESS"}}}},
      "Peb": {{"offset": 16, "type": {{"kind": "pointer", "subtype": {{"kind": "struct", "name": "_PEB"}}}}}}
    }}}}
  }},
  "enums": {{}},
  "symbols": {{{symbols}}}
}}"#
        )
    }

    /// A synthetic 32-bit Windows XP ISF: four-byte pointers throughout, and a
    /// directory table base declared as a two-element array.
    fn xp_module_isf() -> String {
        r#"{
  "metadata": {
    "format": "6.2.0",
    "producer": {"name": "seance-test", "version": "1.0.0"},
    "windows": {"pdb": {"GUID": "FF1B2C3D4E5F60718293A4B5C6D7E8F9", "age": 1,
                        "database": "ntkrnlmp.pdb", "machine_type": 332}}
  },
  "base_types": {
    "pointer": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "unsigned long": {"size": 4, "signed": false, "kind": "int", "endian": "little"},
    "long": {"size": 4, "signed": true, "kind": "int", "endian": "little"},
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
    "_UNICODE_STRING": {"size": 8, "kind": "struct", "fields": {
      "Length": {"offset": 0, "type": {"kind": "base", "name": "unsigned short"}},
      "MaximumLength": {"offset": 2, "type": {"kind": "base", "name": "unsigned short"}},
      "Buffer": {"offset": 4, "type": {"kind": "pointer",
                 "subtype": {"kind": "base", "name": "unsigned short"}}}
    }},
    "_LDR_DATA_TABLE_ENTRY": {"size": 48, "kind": "struct", "fields": {
      "InLoadOrderLinks": {"offset": 0, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InMemoryOrderLinks": {"offset": 8, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InInitializationOrderLinks": {"offset": 16, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "DllBase": {"offset": 24, "type": {"kind": "pointer",
                  "subtype": {"kind": "base", "name": "unsigned char"}}},
      "SizeOfImage": {"offset": 28, "type": {"kind": "base", "name": "unsigned long"}},
      "FullDllName": {"offset": 32, "type": {"kind": "struct", "name": "_UNICODE_STRING"}},
      "BaseDllName": {"offset": 40, "type": {"kind": "struct", "name": "_UNICODE_STRING"}}
    }},
    "_PEB_LDR_DATA": {"size": 32, "kind": "struct", "fields": {
      "InLoadOrderModuleList": {"offset": 8, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InMemoryOrderModuleList": {"offset": 16, "type": {"kind": "struct", "name": "_LIST_ENTRY"}},
      "InInitializationOrderModuleList": {"offset": 24, "type": {"kind": "struct", "name": "_LIST_ENTRY"}}
    }},
    "_PEB": {"size": 32, "kind": "struct", "fields": {
      "Ldr": {"offset": 4, "type": {"kind": "pointer",
              "subtype": {"kind": "struct", "name": "_PEB_LDR_DATA"}}}
    }},
    "_KPROCESS": {"size": 8, "kind": "struct", "fields": {
      "DirectoryTableBase": {"offset": 0, "type": {"kind": "array", "count": 2,
                             "subtype": {"kind": "base", "name": "unsigned long"}}}
    }},
    "_EPROCESS": {"size": 32, "kind": "struct", "fields": {
      "Pcb": {"offset": 0, "type": {"kind": "struct", "name": "_KPROCESS"}},
      "Peb": {"offset": 8, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_PEB"}}}
    }}
  },
  "enums": {},
  "symbols": {"PsLoadedModuleList": {"address": 28672}}
}"#
        .to_string()
    }

    /// Write a `_UNICODE_STRING` and the UTF-16LE text it points at.
    ///
    /// `Length` is the text's length in **bytes** and no terminator is written,
    /// which is how the kernel stores these.
    #[allow(clippy::too_many_arguments)]
    fn put_unicode(
        image: &mut Image,
        at: u64,
        buffer_at: u64,
        text: &str,
        length_offset: u64,
        max_offset: u64,
        buffer_offset: u64,
        pointer_size: u64,
    ) {
        let bytes = text.encode_utf16().count() as u64 * 2;
        image.put_u16(at + length_offset, bytes as u16);
        image.put_u16(at + max_offset, (bytes + 2) as u16);
        if pointer_size == 8 {
            image.put_u64(at + buffer_offset, buffer_at);
        } else {
            image.put_u32(at + buffer_offset, buffer_at as u32);
        }
        image.put_utf16(buffer_at, text);
        // Poison immediately past the text: a reader that ran to a NUL rather
        // than honouring `Length` would pick this up, and a reader that walked
        // past the buffer would too.
        image.write(buffer_at + bytes, &[0x41; 8]);
    }

    /// A 64-bit entry: its base, its size and its two names.
    fn put_entry(
        image: &mut Image,
        at: u64,
        base: u64,
        size: u32,
        full: (u64, &str),
        name: (u64, &str),
    ) {
        image.put_u64(at + off::ENTRY_DLL_BASE, base);
        image.put_u32(at + off::ENTRY_SIZE_OF_IMAGE, size);
        put_unicode(
            image,
            at + off::ENTRY_FULL_NAME,
            full.0,
            full.1,
            off::UNICODE_LENGTH,
            off::UNICODE_MAX_LENGTH,
            off::UNICODE_BUFFER,
            8,
        );
        put_unicode(
            image,
            at + off::ENTRY_BASE_NAME,
            name.0,
            name.1,
            off::UNICODE_LENGTH,
            off::UNICODE_MAX_LENGTH,
            off::UNICODE_BUFFER,
            8,
        );
    }

    /// The base 64-bit fixture.
    ///
    /// Two entries. The load-order and memory-order lists hold both; the
    /// initialisation-order list holds only the second, so the first is a
    /// module that has been unlinked from exactly one list. A third image is
    /// mapped with no loader entry at all, and a fourth range holds no image.
    fn win10_image() -> Image {
        let mut image = Image::new();

        image.put_u64(EPROCESS_AT + off::EPROCESS_DTB, PROCESS_DTB);
        image.put_u64(EPROCESS_AT + off::EPROCESS_PEB, PEB_AT);
        image.put_u64(PEB_AT + off::PEB_LDR, LDR_AT);

        // Load order: head → A → B → head.
        image.put_u64(LDR_AT + off::LDR_LOAD_HEAD, ENTRY_A + off::ENTRY_LOAD_LINKS);
        image.put_u64(
            ENTRY_A + off::ENTRY_LOAD_LINKS,
            ENTRY_B + off::ENTRY_LOAD_LINKS,
        );
        image.put_u64(ENTRY_B + off::ENTRY_LOAD_LINKS, LDR_AT + off::LDR_LOAD_HEAD);

        // Memory order: the same two entries, threaded through a *different*
        // link member sixteen bytes further into each entry.
        image.put_u64(
            LDR_AT + off::LDR_MEMORY_HEAD,
            ENTRY_A + off::ENTRY_MEMORY_LINKS,
        );
        image.put_u64(
            ENTRY_A + off::ENTRY_MEMORY_LINKS,
            ENTRY_B + off::ENTRY_MEMORY_LINKS,
        );
        image.put_u64(
            ENTRY_B + off::ENTRY_MEMORY_LINKS,
            LDR_AT + off::LDR_MEMORY_HEAD,
        );

        // Initialisation order: B only. A has been unlinked from this list.
        image.put_u64(LDR_AT + off::LDR_INIT_HEAD, ENTRY_B + off::ENTRY_INIT_LINKS);
        image.put_u64(ENTRY_B + off::ENTRY_INIT_LINKS, LDR_AT + off::LDR_INIT_HEAD);

        put_entry(
            &mut image,
            ENTRY_A,
            MODULE_A,
            0x1000,
            (FULL_A_AT, r"C:\Windows\System32\ntdll.dll"),
            (BASE_A_AT, "ntdll.dll"),
        );
        put_entry(
            &mut image,
            ENTRY_B,
            MODULE_B,
            0x2000,
            (FULL_B_AT, r"C:\Windows\System32\kernel32.dll"),
            (BASE_B_AT, "kernel32.dll"),
        );

        // The kernel's own list: one driver.
        image.put_u64(KERNEL_HEAD, DRIVER_AT + off::ENTRY_LOAD_LINKS);
        image.put_u64(DRIVER_AT + off::ENTRY_LOAD_LINKS, KERNEL_HEAD);
        put_entry(
            &mut image,
            DRIVER_AT,
            0xFFFF_F800_0000_1000,
            0x0050_0000,
            (DRIVER_FULL_AT, r"\SystemRoot\system32\ntoskrnl.exe"),
            (DRIVER_BASE_AT, "ntoskrnl.exe"),
        );

        // Three mapped images and one range that is not an image.
        for base in [MODULE_A, MODULE_B, MODULE_C] {
            image.write(base, &DOS_SIGNATURE);
        }
        image.write(PLAIN_RANGE, b"\x00\x00");
        image
    }

    fn win10_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&win10_module_isf(false, true)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    fn xp_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&xp_module_isf()),
            Architecture::X86,
            5,
            1,
            Some(2600),
        )
    }

    /// The process's own space. The fixture's layer maps one to one, which is
    /// exactly the assertion [`ProcessSpace::supplied`] exists to make explicit.
    fn space(profile: &WindowsProfile) -> ProcessSpace {
        ProcessSpace::supplied(Arc::clone(&profile.kernel_space), PROCESS_DTB)
    }

    fn symbols(profile: &WindowsProfile) -> ModuleSymbols {
        ModuleSymbols::from_profile(profile).expect("a describable build")
    }

    /// One VAD covering `size` bytes from `start`.
    fn vad(address: u64, start: u64, size: u64, file: MappedFile) -> Vad {
        Vad {
            address,
            depth: 0,
            tag: "Vad ".to_string(),
            kind: VadKind::Long,
            start,
            end: start + size - 1,
            parent: None,
            commit_charge: None,
            private_memory: None,
            protection: None,
            protection_names: None,
            file,
            notes: Vec::new(),
        }
    }

    /// A complete VAD tree over the fixture's four ranges.
    fn fixture_tree(process: u64) -> VadTree {
        let vads = vec![
            vad(
                0x1_1000,
                MODULE_A,
                0x1000,
                MappedFile::Name(r"\Windows\System32\ntdll.dll".into()),
            ),
            vad(
                0x1_2000,
                MODULE_B,
                0x2000,
                MappedFile::Name(r"\Windows\System32\kernel32.dll".into()),
            ),
            vad(0x1_3000, MODULE_C, 0x1000, MappedFile::None),
            vad(0x1_4000, PLAIN_RANGE, 0x1000, MappedFile::None),
        ];
        VadTree {
            process,
            root: 0x1_1000,
            root_shape: VadRootShape::AvlTreeRoot,
            vads,
            skipped: Vec::new(),
            skipped_total: 0,
            visited: 4,
            max_depth: 1,
            stop: VadStop::Exhausted,
        }
    }

    // ── The three lists are three different members ─────────────────────────

    #[test]
    fn each_of_the_three_loader_lists_is_walked_through_its_own_container_member() {
        // The failure this guards: reusing one link member for all three walks.
        // Every module then appears in every list, and an unlinked module — the
        // only thing this stage is for — reads as perfectly linked.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let layouts = symbols.peb_lists();

        let links: Vec<&str> = layouts
            .into_iter()
            .map(|layout| {
                layout
                    .expect("this build declares all three lists")
                    .links
                    .as_str()
            })
            .collect();
        assert_eq!(
            links,
            vec![
                "InLoadOrderLinks",
                "InMemoryOrderLinks",
                "InInitializationOrderLinks"
            ]
        );
        let mut distinct = links.clone();
        distinct.sort_unstable();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            3,
            "one member used three times would be a bug"
        );

        let heads: Vec<&str> = layouts
            .into_iter()
            .map(|layout| layout.expect("declared").head.as_str())
            .collect();
        assert_eq!(
            heads,
            vec![
                "InLoadOrderModuleList",
                "InMemoryOrderModuleList",
                "InInitializationOrderModuleList"
            ]
        );
    }

    #[test]
    fn the_memory_order_walk_subtracts_its_own_link_offset_and_lands_on_the_entries() {
        // The memory-order links are sixteen bytes into an entry. A walk that
        // subtracted the load-order offset instead would report entries at
        // ENTRY_A + 16, and every member read off them would come from the
        // wrong place while still parsing.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .expect("a runnable cross-reference");

        assert_eq!(
            out.memory.members,
            vec![(MODULE_A, ENTRY_A), (MODULE_B, ENTRY_B)],
            "the memory-order list must yield the entries themselves"
        );
        assert_eq!(
            out.load.members,
            vec![(MODULE_A, ENTRY_A), (MODULE_B, ENTRY_B)]
        );
        assert_eq!(out.init.members, vec![(MODULE_B, ENTRY_B)]);
        assert_eq!(out.load.links_member.as_deref(), Some("InLoadOrderLinks"));
        assert_eq!(
            out.memory.links_member.as_deref(),
            Some("InMemoryOrderLinks")
        );
        assert_eq!(
            out.init.links_member.as_deref(),
            Some("InInitializationOrderLinks")
        );
    }

    // ── Unlinking ───────────────────────────────────────────────────────────

    #[test]
    fn a_module_missing_from_one_loader_list_is_flagged_as_unlinked() {
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        let first = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_A)
            .expect("the first image is mapped");
        assert_eq!(first.in_load, Some(true));
        assert_eq!(first.in_mem, Some(true));
        assert_eq!(
            first.in_init,
            Some(false),
            "it was removed from the initialisation-order list only"
        );
        assert!(first.is_unlinked());
        assert!(!first.is_fully_linked());
        assert_eq!(first.entry, Some(ENTRY_A));
    }

    #[test]
    fn a_module_in_the_vad_but_in_none_of_the_loader_lists_is_flagged_as_unlinked() {
        // The malfind-adjacent case: a PE image mapped and running that the
        // loader denies all knowledge of.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        let hidden = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_C)
            .expect("the third image is mapped");
        assert_eq!(
            (hidden.in_load, hidden.in_mem, hidden.in_init),
            (Some(false), Some(false), Some(false))
        );
        assert!(hidden.is_unlinked());
        assert_eq!(hidden.entry, None, "no list holds an entry for it");
        assert_eq!(out.unlinked().count(), 2, "the first image and this one");
    }

    #[test]
    fn a_module_present_in_all_three_lists_is_not_flagged() {
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        let linked = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_B)
            .expect("the second image is mapped");
        assert!(linked.is_fully_linked());
        assert!(!linked.is_unlinked());
        assert!(out.is_complete());
        assert!(out.incomplete().is_empty());
    }

    // ── WOW64 ───────────────────────────────────────────────────────────────

    /// Where the synthetic WOW64 fixture puts the 32-bit loader.
    const PEB32_AT: u64 = 0x2_0000;
    const LDR32_AT: u64 = 0x2_1000;
    const ENTRY32_AT: u64 = 0x2_2000;
    const FULL32_AT: u64 = 0x2_3000;
    const BASE32_AT: u64 = 0x2_3100;

    /// The 64-bit ISF with the WOW64 member Windows 10 declares.
    fn win10_wow64_isf() -> String {
        let base = win10_module_isf(false, true);
        let peb = r#""Peb": {"offset": 16, "type": {"kind": "pointer", "subtype": {"kind": "struct", "name": "_PEB"}}}"#;
        let with_wow64 = format!(
            "{peb},\n      \"WoW64Process\": {{\"offset\": 24, \"type\": {{\"kind\": \"pointer\", \
             \"subtype\": {{\"kind\": \"base\", \"name\": \"unsigned char\"}}}}}}"
        );
        let out = base.replace(peb, &with_wow64);
        assert_ne!(
            out, base,
            "the fixture ISF no longer declares Peb as expected"
        );
        out
    }

    /// The 64-bit fixture with a WOW64 block whose 32-bit loader lists the
    /// third mapped image — the one the 64-bit lists do not name.
    fn wow64_image(readable_peb32: bool) -> Image {
        let mut image = win10_image();
        let block = if readable_peb32 { PEB32_AT } else { NOWHERE };
        image.put_u64(EPROCESS_AT + 24, block);
        if !readable_peb32 {
            return image;
        }

        image.put_u32(PEB32_AT + wow64_layout::PEB_LDR, LDR32_AT as u32);
        for (head, links) in [
            (wow64_layout::LDR_LOAD_HEAD, wow64_layout::ENTRY_LOAD_LINKS),
            (
                wow64_layout::LDR_MEMORY_HEAD,
                wow64_layout::ENTRY_MEMORY_LINKS,
            ),
            (wow64_layout::LDR_INIT_HEAD, wow64_layout::ENTRY_INIT_LINKS),
        ] {
            image.put_u32(LDR32_AT + head, (ENTRY32_AT + links) as u32);
            image.put_u32(ENTRY32_AT + links, (LDR32_AT + head) as u32);
        }
        image.put_u32(ENTRY32_AT + wow64_layout::ENTRY_DLL_BASE, MODULE_C as u32);
        image.put_u32(ENTRY32_AT + wow64_layout::ENTRY_SIZE_OF_IMAGE, 0x1000);
        put_unicode(
            &mut image,
            ENTRY32_AT + wow64_layout::ENTRY_FULL_NAME,
            FULL32_AT,
            r"C:\Windows\SysWOW64\ntdll.dll",
            off32::UNICODE_LENGTH,
            off32::UNICODE_MAX_LENGTH,
            off32::UNICODE_BUFFER,
            4,
        );
        put_unicode(
            &mut image,
            ENTRY32_AT + wow64_layout::ENTRY_BASE_NAME,
            BASE32_AT,
            "ntdll.dll",
            off32::UNICODE_LENGTH,
            off32::UNICODE_MAX_LENGTH,
            off32::UNICODE_BUFFER,
            4,
        );
        image
    }

    fn wow64_profile(image: Image) -> WindowsProfile {
        profile(
            image.layer(),
            table(&win10_wow64_isf()),
            Architecture::X64,
            10,
            0,
            Some(22000),
        )
    }

    #[test]
    fn a_thirty_two_bit_dll_of_a_wow64_process_is_not_reported_as_unlinked() {
        // The regression that matters most in this file. A 32-bit process on a
        // 64-bit kernel keeps its DLLs in a second, 32-bit loader; the 64-bit
        // lists the kernel points at hold only ntdll and the thunking layer.
        // Scoring the mapped images against the 64-bit lists alone finds every
        // ordinary 32-bit DLL missing from all three and calls it unlinked —
        // a rootkit finding manufactured by the tool, on every 32-bit program
        // on the machine.
        let profile = wow64_profile(wow64_image(true));
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert!(
            matches!(out.wow64, Wow64Loader::Walked { .. }),
            "{:?}",
            out.wow64
        );
        let thirty_two = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_C)
            .expect("the 32-bit image is mapped");
        assert_eq!(
            (thirty_two.in_load, thirty_two.in_mem, thirty_two.in_init),
            (Some(true), Some(true), Some(true)),
            "the 32-bit loader names this image in all three of its lists"
        );
        assert!(
            !thirty_two.is_unlinked(),
            "a legitimate 32-bit DLL must not be accused of having been unlinked"
        );

        // The genuine finding survives: the first image really is missing from
        // the initialisation-order list of both loaders.
        let unlinked = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_A)
            .expect("the first image is mapped");
        assert_eq!(unlinked.in_init, Some(false));
        assert!(unlinked.is_unlinked());
    }

    #[test]
    fn the_thirty_two_bit_module_list_is_recovered_rather_than_merely_suppressed() {
        // Suppressing the false accusation is only half of it: without the
        // 32-bit walk the DLLs a 32-bit program loaded are missing from the
        // record entirely, and a DLL table showing four native modules for a
        // program that loaded forty is its own wrong answer.
        let profile = wow64_profile(wow64_image(true));
        let symbols = symbols(&profile);
        let space = space(&profile);
        let dlls = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        let thirty_two = dlls.wow64.modules();
        assert_eq!(thirty_two.len(), 1);
        assert_eq!(thirty_two[0].base, Some(MODULE_C));
        assert_eq!(thirty_two[0].base_name.name(), Some("ntdll.dll"));
        assert_eq!(
            thirty_two[0].full_path.name(),
            Some(r"C:\Windows\SysWOW64\ntdll.dll")
        );
        assert_eq!(
            dlls.all_modules().count(),
            3,
            "two native entries and one 32-bit entry"
        );
        assert_eq!(dlls.to_json()["wow64_module_count"], 1);
    }

    #[test]
    fn a_wow64_process_whose_thirty_two_bit_loader_cannot_be_read_makes_no_accusation() {
        // The honest gap. When the 32-bit side cannot be reached, an image
        // missing from the 64-bit lists may simply be in the 32-bit ones, so
        // the answer is "cannot say" and never "unlinked".
        let profile = wow64_profile(wow64_image(false));
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert!(
            matches!(out.wow64, Wow64Loader::Unavailable { .. }),
            "{:?}",
            out.wow64
        );
        for module in &out.modules {
            assert!(
                !module.is_unlinked(),
                "{:#x} was accused with no 32-bit list to check it against",
                module.base
            );
        }
        let unnamed = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_C)
            .expect("the image no 64-bit list names is mapped");
        assert_eq!(
            (unnamed.in_load, unnamed.in_mem, unnamed.in_init),
            (None, None, None),
            "absence from the 64-bit lists cannot be established while a 32-bit list may hold it"
        );
        assert!(
            out.modules
                .iter()
                .any(|module| module.in_load == Some(true)),
            "an image the 64-bit list does name is still established as present"
        );
        assert!(!out.is_complete());
        assert!(out.incomplete().iter().any(|entry| entry
            .detail
            .contains("32-bit module list could not be read")));
    }

    #[test]
    fn a_build_with_no_wow64_member_is_answered_rather_than_left_unknown() {
        // A 32-bit kernel cannot host a WOW64 process, so the native lists are
        // the whole answer and absence in them is absence. Treating this as an
        // unknown would suppress every unlinked-module finding on such a build.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        assert!(symbols.wow64.is_none());
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        assert!(matches!(out.wow64, Wow64Loader::NotWow64));
        assert!(out.wow64.establishes_absence());
        assert_eq!(out.unlinked().count(), 2);
    }

    #[test]
    fn the_flat_module_rows_carry_the_hidden_module_as_well_as_the_listed_ones() {
        // The Process Inspector's DLL table reads the flat `modules` array. An
        // array built from the loader's own list alone would omit the one
        // module the stage exists to find, because being missing from that list
        // is precisely what makes it a finding.
        let listed = LoadedModule {
            entry: ENTRY_A,
            base: Some(MODULE_A),
            size_of_image: Some(0x1000),
            full_path: NameField::Name(r"C:\Windows\System32\ntdll.dll".to_string()),
            base_name: NameField::Name("ntdll.dll".to_string()),
            load_order: 0,
            notes: Vec::new(),
        };
        let hidden = LdrModule {
            base: MODULE_C,
            vad: 0x1_0000,
            in_load: Some(false),
            in_init: Some(false),
            in_mem: Some(false),
            entry: None,
            mapped_file: MappedFile::None,
            notes: Vec::new(),
        };
        let modules = ProcessModules {
            process: EPROCESS_AT,
            pid: Some(1234),
            name: Some("notepad.exe".to_string()),
            dtb: PROCESS_DTB,
            dlls: DllList {
                process: EPROCESS_AT,
                dtb: PROCESS_DTB,
                loader: LoaderData::At {
                    peb: PEB_AT,
                    ldr: LDR_AT,
                },
                head: Some(LDR_AT),
                modules: vec![listed],
                wow64: Wow64Loader::NotWow64,
                stop: Some(ListStop::Wrapped),
                notes: Vec::new(),
                notes_total: 0,
            },
            ldr: Some(LdrModules {
                process: EPROCESS_AT,
                loader: LoaderData::At {
                    peb: PEB_AT,
                    ldr: LDR_AT,
                },
                load: LdrListWalk::absent(),
                memory: LdrListWalk::absent(),
                init: LdrListWalk::absent(),
                wow64: Wow64Loader::NotWow64,
                modules: vec![hidden],
                unreadable_ranges: 0,
                vad_complete: true,
                notes: Vec::new(),
                notes_total: 0,
            }),
            ldr_unavailable: None,
            space: SpaceProvenance::not_built(),
        };

        let body = modules.to_json();
        assert_eq!(body["pid"], 1234);
        // Every per-process module record states what its address space
        // reported. Here the space was supplied rather than derived, so the
        // refusal count is absent — and absent must not read as a measured
        // zero, which would tell an examiner no page was withheld from a walk
        // that never counted.
        assert!(
            body["address_space"]["uniform_tables_suppressed"].is_null(),
            "{body}"
        );
        assert!(
            body["address_space"]["uniform_tables_suppressed_meaning"]
                .as_str()
                .expect("a meaning is stated")
                .contains("not a count of zero"),
            "{body}"
        );
        let rows = body["modules"].as_array().expect("an array");
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(
            rows.iter().any(|row| row["name"] == "ntdll.dll"
                && row["source"] == "loader_list_64"
                && row["unlinked"] == false),
            "{rows:?}"
        );
        let hidden_row = rows
            .iter()
            .find(|row| row["source"] == "mapped_image")
            .expect("the unlinked image is a row of its own");
        assert_eq!(hidden_row["unlinked"], true);
        assert_eq!(hidden_row["membership_established"], true);
        assert_eq!(hidden_row["base_hex"], format!("{MODULE_C:#x}"));
        assert_eq!(hidden_row["vad_hex"], format!("{:#x}", 0x1_0000u64));
        // Every address on the record has an exact string beside the number the
        // JSON encoder rounds.
        assert_eq!(body["process_address_hex"], format!("{EPROCESS_AT:#x}"));
        assert_eq!(body["dlls"]["head_hex"], format!("{LDR_AT:#x}"));
        assert_eq!(body["dlls"]["loader"]["peb_hex"], format!("{PEB_AT:#x}"));
        assert_eq!(body["dlls"]["loader"]["ldr_hex"], format!("{LDR_AT:#x}"));
        assert_eq!(
            body["ldr_modules"]["process_hex"],
            format!("{EPROCESS_AT:#x}")
        );
    }

    #[test]
    fn a_mapped_image_nothing_could_score_is_a_row_saying_so_rather_than_no_row() {
        // The three-way answer the DLL table has to keep. An image whose
        // membership could not be established is not unlinked — but it is also
        // not absent, and leaving it out of the table entirely renders as a
        // process that never had it mapped. That is the same false negative
        // this stage exists to prevent, arrived at from the other side.
        let unknown = LdrModule {
            base: MODULE_C,
            vad: 0x1_0000,
            in_load: None,
            in_init: None,
            in_mem: None,
            entry: None,
            mapped_file: MappedFile::Name(r"C:\Windows\SysWOW64\kernel32.dll".to_string()),
            notes: vec!["the 32-bit loader could not be read".to_string()],
        };
        let modules = ProcessModules {
            process: EPROCESS_AT,
            pid: Some(1234),
            name: Some("notepad.exe".to_string()),
            dtb: PROCESS_DTB,
            dlls: DllList {
                process: EPROCESS_AT,
                dtb: PROCESS_DTB,
                loader: LoaderData::At {
                    peb: PEB_AT,
                    ldr: LDR_AT,
                },
                head: Some(LDR_AT),
                modules: Vec::new(),
                wow64: Wow64Loader::Unavailable {
                    peb32: Some(0x2_0000),
                    detail: "the 32-bit '_PEB.Ldr' could not be read".to_string(),
                },
                stop: Some(ListStop::Wrapped),
                notes: Vec::new(),
                notes_total: 0,
            },
            ldr: Some(LdrModules {
                process: EPROCESS_AT,
                loader: LoaderData::At {
                    peb: PEB_AT,
                    ldr: LDR_AT,
                },
                load: LdrListWalk::absent(),
                memory: LdrListWalk::absent(),
                init: LdrListWalk::absent(),
                wow64: Wow64Loader::Unavailable {
                    peb32: Some(0x2_0000),
                    detail: "the 32-bit '_PEB.Ldr' could not be read".to_string(),
                },
                modules: vec![unknown],
                unreadable_ranges: 0,
                vad_complete: true,
                notes: Vec::new(),
                notes_total: 0,
            }),
            ldr_unavailable: None,
            space: SpaceProvenance::not_built(),
        };

        let body = modules.to_json();
        let rows = body["modules"].as_array().expect("an array");
        assert_eq!(
            rows.len(),
            1,
            "the mapped image must still be a row: {rows:?}"
        );
        assert_eq!(rows[0]["source"], "mapped_image");
        assert_eq!(
            rows[0]["unlinked"],
            serde_json::Value::Null,
            "an unestablished membership must never render as an accusation"
        );
        assert_eq!(rows[0]["membership_established"], false);
        assert_eq!(rows[0]["name"], r"C:\Windows\SysWOW64\kernel32.dll");
        assert!(!modules.is_complete());
    }

    #[test]
    fn a_memory_range_without_a_dos_header_is_not_a_module() {
        // Every process has dozens of heap and stack ranges. Treating them as
        // modules would report every one of them as unlinked.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert_eq!(
            out.modules.iter().map(|m| m.base).collect::<Vec<_>>(),
            vec![MODULE_A, MODULE_B, MODULE_C]
        );
        assert!(out.modules.iter().all(|m| m.base != PLAIN_RANGE));
    }

    #[test]
    fn a_range_whose_first_page_was_never_acquired_is_counted_rather_than_dismissed() {
        // An unlinked module could be in exactly this range, so it cannot be
        // silently dropped the way a range known to hold no image is.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let mut tree = fixture_tree(EPROCESS_AT);
        tree.vads
            .push(vad(0x1_5000, NOWHERE, 0x1000, MappedFile::None));

        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &tree,
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        assert_eq!(out.unreadable_ranges, 1);
        assert!(!out.is_complete());
        assert!(out
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("unacquired memory")));
        assert_eq!(out.notes_total, 1);
    }

    #[test]
    fn a_vad_tree_belonging_to_another_process_is_refused() {
        // Cross-referencing one process's loader against another's ranges would
        // report every module as unlinked.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let err = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT + 0x1000),
            &ModuleWalkConfig::default(),
        )
        .expect_err("a tree from a different process is not this process's memory");
        assert_eq!(err.class(), "wrong_process");
    }

    // ── Unavailable is not empty ────────────────────────────────────────────

    #[test]
    fn a_process_whose_loader_data_is_paged_out_is_unavailable_rather_than_empty() {
        // The distinction the whole type exists for. Rendered as an empty list,
        // this process would read as having loaded no DLLs at all.
        let mut image = win10_image();
        image.put_u64(PEB_AT + off::PEB_LDR, NOWHERE);
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);

        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .expect("an unreadable loader is a finding, not an error");

        assert!(list.modules.is_empty());
        assert!(matches!(list.loader, LoaderData::Unavailable { .. }));
        assert!(!list.loader.empty_is_a_fact());
        assert!(!list.is_complete(), "an unread list is not a complete one");
        assert_eq!(list.stop, None, "the list was never walked");
        let declared = list.incomplete();
        assert_eq!(declared.len(), 1);
        assert!(declared[0].detail.contains("unknown rather than absent"));
    }

    #[test]
    fn a_process_whose_peb_could_not_be_read_names_the_member_that_failed() {
        let mut image = win10_image();
        image.put_u64(EPROCESS_AT + off::EPROCESS_PEB, NOWHERE);
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);

        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        match &list.loader {
            LoaderData::Unavailable { peb, detail } => {
                assert_eq!(*peb, Some(NOWHERE));
                assert!(detail.contains("_PEB.Ldr"), "{detail}");
            }
            other => panic!("expected an unavailable loader, got {other:?}"),
        }
        assert!(!list.is_complete());
    }

    #[test]
    fn a_process_with_a_null_peb_has_an_empty_dll_list_that_is_a_fact() {
        // The System process really does have no user-mode address space. An
        // empty list here is established, and must not be declared incomplete.
        let mut image = win10_image();
        image.put_u64(EPROCESS_AT + off::EPROCESS_PEB, 0);
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);

        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        assert_eq!(list.loader, LoaderData::NoPeb);
        assert!(list.modules.is_empty());
        assert!(list.loader.empty_is_a_fact());
        assert!(list.is_complete());
        assert!(list.incomplete().is_empty());
    }

    #[test]
    fn a_null_loader_pointer_is_a_different_fact_from_a_missing_peb() {
        let mut image = win10_image();
        image.put_u64(PEB_AT + off::PEB_LDR, 0);
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);

        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        assert_eq!(list.loader, LoaderData::NoLdr { peb: PEB_AT });
        assert_ne!(list.loader, LoaderData::NoPeb);
        assert!(list.is_complete());
        assert_eq!(list.loader.as_str(), "no_ldr");
    }

    // ── Bounded walks ───────────────────────────────────────────────────────

    #[test]
    fn a_cyclic_module_list_terminates_and_does_not_claim_to_have_wrapped() {
        // A list a rootkit spliced, or one captured mid-edit, points back into
        // itself. A naive walk loops forever or reports the same DLL a hundred
        // times.
        let mut image = win10_image();
        image.put_u64(
            ENTRY_B + off::ENTRY_LOAD_LINKS,
            ENTRY_A + off::ENTRY_LOAD_LINKS,
        );
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);

        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        assert_eq!(list.modules.len(), 2, "each entry is reported once");
        assert_eq!(list.stop, Some(ListStop::Cycle { address: ENTRY_A }));
        assert!(!list.is_complete());
        assert!(list.incomplete()[0].detail.contains("does not terminate"));
    }

    #[test]
    fn absence_cannot_be_claimed_from_a_list_that_did_not_finish() {
        // The accusation this stage makes has to be earned. A load-order list
        // that ended in a cycle says nothing about what lies past the cycle, so
        // a module not found in it is unknown, not missing.
        let mut image = win10_image();
        image.put_u64(
            ENTRY_B + off::ENTRY_LOAD_LINKS,
            ENTRY_A + off::ENTRY_LOAD_LINKS,
        );
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert!(!out.load.is_complete());
        assert_eq!(
            out.load.contains(MODULE_C),
            None,
            "a module not found in a truncated list must not be reported missing"
        );
        assert_eq!(
            out.load.contains(MODULE_A),
            Some(true),
            "one that was found is still found"
        );
        let hidden = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_C)
            .unwrap();
        assert_eq!(hidden.in_load, None);
        assert_eq!(
            hidden.in_mem,
            Some(false),
            "the lists that did finish still answer"
        );
        assert!(!out.is_complete());
        assert!(out
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("load-order list")));
    }

    #[test]
    fn an_entry_whose_base_is_unreadable_suppresses_every_claim_of_absence_from_that_list() {
        // That one entry might be the very module about to be called missing,
        // so a list holding it can confirm presence but can never establish
        // absence.
        let mut walk = LdrListWalk::absent();
        walk.head_member = Some("InLoadOrderModuleList".into());
        walk.links_member = Some("InLoadOrderLinks".into());
        walk.stop = Some(ListStop::Wrapped);
        walk.members.push((MODULE_B, ENTRY_B));
        walk.unreadable_bases = 1;

        assert!(
            !walk.is_complete(),
            "a list with an unreadable base is not fully read"
        );
        assert_eq!(walk.contains(MODULE_B), Some(true));
        assert_eq!(
            walk.contains(MODULE_C),
            None,
            "not found is not the same as not there"
        );

        // With every base readable, the same list does establish absence.
        walk.unreadable_bases = 0;
        assert!(walk.is_complete());
        assert_eq!(walk.contains(MODULE_C), Some(false));
    }

    #[test]
    fn the_entry_cap_stops_the_walk_and_is_never_mistaken_for_the_end_of_the_list() {
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let config = ModuleWalkConfig {
            max_modules: 1,
            ..ModuleWalkConfig::default()
        };
        let list = list_dlls(&profile, &symbols, EPROCESS_AT, &space, &config).unwrap();
        assert_eq!(
            list.modules.len(),
            1,
            "the list has two; the cap allowed one"
        );
        assert_eq!(list.stop, Some(ListStop::CapReached { cap: 1 }));
        assert!(!list.is_complete());
        assert_eq!(list.incomplete()[0].reason, IncompleteReason::CapReached);
    }

    // ── dlllist rows ────────────────────────────────────────────────────────

    #[test]
    fn the_dll_list_yields_base_size_both_names_and_the_order_they_were_loaded_in() {
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert_eq!(list.process, EPROCESS_AT);
        assert_eq!(list.dtb, PROCESS_DTB);
        assert_eq!(
            list.loader,
            LoaderData::At {
                peb: PEB_AT,
                ldr: LDR_AT
            }
        );
        assert_eq!(list.head, Some(LDR_AT + off::LDR_LOAD_HEAD));
        assert_eq!(list.stop, Some(ListStop::Wrapped));
        assert!(list.is_complete());

        assert_eq!(list.modules.len(), 2);
        let first = &list.modules[0];
        assert_eq!(first.entry, ENTRY_A);
        assert_eq!(first.base, Some(MODULE_A));
        assert_eq!(first.size_of_image, Some(0x1000));
        assert_eq!(first.end(), Some(MODULE_A + 0x1000 - 1));
        assert_eq!(first.load_order, 0);
        assert_eq!(
            first.full_path.name(),
            Some(r"C:\Windows\System32\ntdll.dll")
        );
        assert_eq!(first.base_name.name(), Some("ntdll.dll"));

        let second = &list.modules[1];
        assert_eq!(second.load_order, 1, "the order the loader loaded them in");
        assert_eq!(second.base, Some(MODULE_B));
        assert_eq!(second.base_name.name(), Some("kernel32.dll"));
        assert!(first.notes.is_empty() && second.notes.is_empty());
    }

    #[test]
    fn a_path_is_read_by_its_byte_length_and_not_up_to_a_terminator() {
        // `Length` counts bytes of UTF-16, and the kernel does not NUL
        // terminate these. A reader that ran to a terminator would pick up the
        // bytes that follow the buffer, which the fixture fills with poison.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        let name = list.modules[0].base_name.name().expect("a readable name");
        assert_eq!(name, "ntdll.dll");
        assert!(
            !name.contains('A'),
            "the poison past the buffer was not read"
        );
        assert_eq!(name.len(), 9, "nine characters, from eighteen bytes");
    }

    #[test]
    fn an_unreadable_name_is_distinguishable_from_an_empty_one() {
        // Rendered alike, a DLL whose path was paged out and a DLL with no path
        // become the same row, and only one of them is suspicious.
        let mut image = win10_image();
        // The first entry's path points at memory that was never acquired...
        image.put_u64(
            ENTRY_A + off::ENTRY_FULL_NAME + off::UNICODE_BUFFER,
            NOWHERE,
        );
        // ...and the second entry's is genuinely zero-length.
        image.put_u16(ENTRY_B + off::ENTRY_FULL_NAME + off::UNICODE_LENGTH, 0);
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);
        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert!(matches!(
            list.modules[0].full_path,
            NameField::Unavailable(_)
        ));
        assert!(!list.modules[0].full_path.is_known());
        assert_eq!(list.modules[1].full_path, NameField::Empty);
        assert!(list.modules[1].full_path.is_known());
        assert_ne!(list.modules[0].full_path, list.modules[1].full_path);
        // The rest of both rows survives either way.
        assert_eq!(list.modules[0].base, Some(MODULE_A));
        assert_eq!(list.modules[1].base_name.name(), Some("kernel32.dll"));
    }

    #[test]
    fn an_entry_whose_base_could_not_be_read_keeps_its_row_and_says_so() {
        let mut image = win10_image();
        // Put the entry itself where nothing was acquired, so its members fail.
        image.put_u64(LDR_AT + off::LDR_LOAD_HEAD, NOWHERE + off::ENTRY_LOAD_LINKS);
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let space = space(&profile);
        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert_eq!(
            list.modules.len(),
            1,
            "the link named an entry, so it is a fact"
        );
        let module = &list.modules[0];
        assert_eq!(module.entry, NOWHERE);
        assert_eq!(module.base, None);
        assert_eq!(module.size_of_image, None);
        assert_eq!(module.end(), None);
        assert!(!module.notes.is_empty());
        assert!(module.notes[0].contains("DllBase"), "{:?}", module.notes);
        assert!(list.notes_total >= 1);
        assert!(
            !list.is_complete(),
            "the walk could not follow the chain on"
        );
    }

    // ── Which decoded strings are names ─────────────────────────────────────

    #[test]
    fn reallocated_pool_decoded_as_text_is_not_a_module_name() {
        // Three `BaseDllName` strings and one `FullDllName` from the Windows 11
        // parity image, whose loader entries sit in reallocated pool.
        // Volatility publishes all four verbatim.
        for damaged in [
            "䄐༈䈑\u{f208}ဏᡉ\u{0ff2}䨑쌘쳌",
            "쏀쳌쳌쳌쳌쳌쳌쳌\u{f071}囚韽錜",
            "쾠\u{2}譈⡋蕈瓉䠜玉䠨Ƌ멉녰㙞ἐ몬",
            "䡈쒃䄠彞썞쳌쳌쳌쳌쳌襈\u{245c}圐荈䃬譈䣂\u{f98b}赈颙",
        ] {
            assert!(
                loader_string_damage(damaged).is_some(),
                "published as a module name: {damaged:?}"
            );
        }
    }

    #[test]
    fn a_module_named_in_another_script_is_still_a_module() {
        // Refusing one of these would hide a loaded module from an examiner,
        // which is the error this rule must not make. The last two are mostly
        // outside ASCII, and each carries structure a mapped PE file's name has.
        assert_eq!(loader_string_damage("ntdll.dll"), None);
        assert_eq!(loader_string_damage(r"C:\Windows\System32\ntdll.dll"), None);
        assert_eq!(
            loader_string_damage(r"C:\Users\Ли\Рабочий стол\отчёт.dll"),
            None,
            "a path separator is structure no reallocated pool has"
        );
        assert_eq!(
            loader_string_damage("テストのモジュール.dll"),
            None,
            "an ASCII extension is structure no reallocated pool has"
        );
        // Short strings are exempt: there is not enough text for a majority to
        // mean anything, and refusing on two characters would be a guess.
        assert_eq!(loader_string_damage("日本"), None);
    }

    #[test]
    fn a_lone_dot_in_reallocated_pool_is_not_an_extension() {
        // Structure alone must not admit the damage: an extension has to be
        // ASCII alphanumeric and bounded, or every run of pool holding a full
        // stop would pass as a file name.
        assert!(loader_string_damage("쏀쳌쳌.쳌쳌쳌쳌").is_some());
        assert!(loader_string_damage("囚韽錜.").is_some());
        assert!(loader_string_damage("囚韽錜.쳌").is_some());
    }

    // ── Thirty-two bit ──────────────────────────────────────────────────────

    /// A four-byte forward link, with the backward link set to `0xFFFFFFFF`.
    ///
    /// The poison is what makes the width test bite: read eight bytes instead
    /// of four and the link becomes `0xFFFFFFFF_00004000`, an address in
    /// nobody's process, from which the walk never returns to its head.
    fn put32_link(image: &mut Image, at: u64, target: u64) {
        image.put_u32(at, target as u32);
        image.put_u32(at + 4, 0xFFFF_FFFF);
    }

    /// A 32-bit entry.
    fn put32_entry(
        image: &mut Image,
        at: u64,
        base: u32,
        size: u32,
        full: (u64, &str),
        name: (u64, &str),
    ) {
        image.put_u32(at + off32::ENTRY_DLL_BASE, base);
        image.put_u32(at + off32::ENTRY_SIZE_OF_IMAGE, size);
        put_unicode(
            image,
            at + off32::ENTRY_FULL_NAME,
            full.0,
            full.1,
            off32::UNICODE_LENGTH,
            off32::UNICODE_MAX_LENGTH,
            off32::UNICODE_BUFFER,
            4,
        );
        put_unicode(
            image,
            at + off32::ENTRY_BASE_NAME,
            name.0,
            name.1,
            off32::UNICODE_LENGTH,
            off32::UNICODE_MAX_LENGTH,
            off32::UNICODE_BUFFER,
            4,
        );
    }

    /// The 32-bit fixture: the same two entries, four-byte links throughout,
    /// and a directory table base declared as a two-element array.
    fn xp_image() -> Image {
        let mut image = Image::new();
        image.put_u32(EPROCESS_AT + off32::EPROCESS_DTB, PROCESS_DTB as u32);
        image.put_u32(EPROCESS_AT + off32::EPROCESS_DTB + 4, 0xDEAD_BEEF);
        image.put_u32(EPROCESS_AT + off32::EPROCESS_PEB, PEB_AT as u32);
        image.put_u32(PEB_AT + off32::PEB_LDR, LDR_AT as u32);

        put32_link(
            &mut image,
            LDR_AT + off32::LDR_LOAD_HEAD,
            ENTRY_A + off32::ENTRY_LOAD_LINKS,
        );
        put32_link(
            &mut image,
            ENTRY_A + off32::ENTRY_LOAD_LINKS,
            ENTRY_B + off32::ENTRY_LOAD_LINKS,
        );
        put32_link(
            &mut image,
            ENTRY_B + off32::ENTRY_LOAD_LINKS,
            LDR_AT + off32::LDR_LOAD_HEAD,
        );

        put32_link(
            &mut image,
            LDR_AT + off32::LDR_MEMORY_HEAD,
            ENTRY_A + off32::ENTRY_MEMORY_LINKS,
        );
        put32_link(
            &mut image,
            ENTRY_A + off32::ENTRY_MEMORY_LINKS,
            ENTRY_B + off32::ENTRY_MEMORY_LINKS,
        );
        put32_link(
            &mut image,
            ENTRY_B + off32::ENTRY_MEMORY_LINKS,
            LDR_AT + off32::LDR_MEMORY_HEAD,
        );

        put32_link(
            &mut image,
            LDR_AT + off32::LDR_INIT_HEAD,
            ENTRY_B + off32::ENTRY_INIT_LINKS,
        );
        put32_link(
            &mut image,
            ENTRY_B + off32::ENTRY_INIT_LINKS,
            LDR_AT + off32::LDR_INIT_HEAD,
        );

        put32_entry(
            &mut image,
            ENTRY_A,
            MODULE_A as u32,
            0x1000,
            (FULL_A_AT, r"C:\WINDOWS\system32\ntdll.dll"),
            (BASE_A_AT, "ntdll.dll"),
        );
        put32_entry(
            &mut image,
            ENTRY_B,
            MODULE_B as u32,
            0x2000,
            (FULL_B_AT, r"C:\WINDOWS\system32\kernel32.dll"),
            (BASE_B_AT, "kernel32.dll"),
        );

        put32_link(&mut image, KERNEL_HEAD, DRIVER_AT + off32::ENTRY_LOAD_LINKS);
        put32_link(&mut image, DRIVER_AT + off32::ENTRY_LOAD_LINKS, KERNEL_HEAD);
        put32_entry(
            &mut image,
            DRIVER_AT,
            0x8054_0000,
            0x0020_0000,
            (DRIVER_FULL_AT, r"\WINDOWS\system32\ntoskrnl.exe"),
            (DRIVER_BASE_AT, "ntoskrnl.exe"),
        );

        for base in [MODULE_A, MODULE_B, MODULE_C] {
            image.write(base, &DOS_SIGNATURE);
        }
        image
    }

    #[test]
    fn a_thirty_two_bit_loader_list_is_followed_at_the_width_the_symbol_table_declares() {
        let profile = xp_profile(xp_image());
        let symbols = symbols(&profile);
        let space = ProcessSpace::supplied(Arc::clone(&profile.kernel_space), PROCESS_DTB);
        let list = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert_eq!(
            list.stop,
            Some(ListStop::Wrapped),
            "read at eight bytes the chain never comes back to its head"
        );
        assert_eq!(
            list.modules.iter().map(|m| m.entry).collect::<Vec<_>>(),
            vec![ENTRY_A, ENTRY_B]
        );
        assert_eq!(list.modules[0].base, Some(MODULE_A));
        assert_eq!(list.modules[0].size_of_image, Some(0x1000));
        assert_eq!(list.modules[1].base_name.name(), Some("kernel32.dll"));
    }

    #[test]
    fn a_thirty_two_bit_process_still_gets_three_separate_list_walks() {
        let profile = xp_profile(xp_image());
        let symbols = symbols(&profile);
        let space = ProcessSpace::supplied(Arc::clone(&profile.kernel_space), PROCESS_DTB);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();

        assert_eq!(
            out.load.members,
            vec![(MODULE_A, ENTRY_A), (MODULE_B, ENTRY_B)]
        );
        assert_eq!(
            out.memory.members,
            vec![(MODULE_A, ENTRY_A), (MODULE_B, ENTRY_B)]
        );
        assert_eq!(out.init.members, vec![(MODULE_B, ENTRY_B)]);
        let first = out
            .modules
            .iter()
            .find(|module| module.base == MODULE_A)
            .unwrap();
        assert_eq!(first.in_init, Some(false));
        assert!(first.is_unlinked());
    }

    #[test]
    fn a_split_directory_table_base_is_read_from_its_first_element_only() {
        // 32-bit Windows declares `DirectoryTableBase` as `[2] unsigned long`,
        // whose second element is the hyperspace PTE. Reading the pair as one
        // wide value gives 0xdeadbeef_00009000 and translates nothing.
        let profile = xp_profile(xp_image());
        let symbols = symbols(&profile);
        assert_eq!(
            symbols
                .directory_table_base
                .as_ref()
                .map(|(path, array)| (path.as_str(), *array)),
            Some(("Pcb.DirectoryTableBase", true))
        );
        let config = ModuleWalkConfig {
            paging_mode: Some(PagingMode::Intel32),
            ..ModuleWalkConfig::default()
        };
        let built = ProcessSpace::build(&profile, &symbols, EPROCESS_AT, &config)
            .expect("a usable directory table base");
        assert_eq!(built.dtb(), PROCESS_DTB);
    }

    #[test]
    fn an_unsplit_directory_table_base_is_read_as_one_value() {
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        assert_eq!(
            symbols
                .directory_table_base
                .as_ref()
                .map(|(_, array)| *array),
            Some(false)
        );
        let built = ProcessSpace::build(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ModuleWalkConfig::default(),
        )
        .expect("a usable directory table base");
        assert_eq!(built.dtb(), PROCESS_DTB);
        assert!(!Arc::ptr_eq(built.layer(), &profile.kernel_space));
    }

    /// A virtual address the fixture's identity map does not cover, used for
    /// the one page that is swapped out. Its bytes exist nowhere in the memory
    /// image, so only an attached pagefile can produce them.
    const SWAPPED_VA: u64 = 0x8_0000;

    /// Where [`SWAPPED_VA`]'s page sits in the fixture's pagefile: the second
    /// 4 KiB page, which is what `PageFileHigh` of 1 names.
    const SWAPPED_AT: usize = 0x1000;

    /// The page-table fixture with [`SWAPPED_VA`] paged out to pagefile 0.
    fn image_with_a_swapped_page() -> Image {
        // The leaf table `image_with_process_page_tables` builds; the entry has
        // to be written into that same table to be the one the walk reaches.
        const PT: u64 = 0x1_0000;
        let mut image = image_with_process_page_tables();
        // `MMPTE_SOFTWARE`: Valid, Prototype and Transition all clear,
        // PageFileLow — bits 15:12 on Windows 8 and later, which this fixture's
        // build 22000 selects — naming pagefile 0, and PageFileHigh at bit 32
        // naming page 1.
        image.put_u64(PT + (SWAPPED_VA / 0x1000) * 8, 1u64 << 32);
        image
    }

    #[test]
    fn a_swapped_page_of_a_process_space_reads_from_the_pagefile_the_examiner_attached() {
        use seance_core::data_source::{ByteSliceDataSource, DataSource};
        use seance_memory::translate::SwapFile;
        use seance_memory::{BackingSource, HoleReason};

        // A pagefile whose page 1 holds a recognisable pattern, so bytes read
        // at the wrong offset — or out of the memory image — are visible rather
        // than merely wrong.
        let mut bytes = vec![0u8; SWAPPED_AT + 0x1000];
        for (i, slot) in bytes[SWAPPED_AT..].iter_mut().enumerate() {
            *slot = (i % 251) as u8;
        }
        let pagefile: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));

        // Fail closed first: with nothing attached the page stays a hole, which
        // is the honest answer when the pagefile was never collected.
        let bare = win10_profile(image_with_a_swapped_page());
        let bare_symbols = symbols(&bare);
        let space = ProcessSpace::build(
            &bare,
            &bare_symbols,
            EPROCESS_AT,
            &ModuleWalkConfig::default(),
        )
        .expect("a usable directory table base");
        assert_eq!(
            space
                .layer()
                .mapping(SWAPPED_VA, 0x10)
                .unwrap_err()
                .hole()
                .map(|hole| hole.reason),
            Some(HoleReason::SwappedOut)
        );

        // And with the examiner's pagefile on the profile, the same page reads.
        // `process_virtual_space` already attached it; this path — every
        // per-process module and DLL walk, and services.exe's own space — did
        // not, so a correctly supplied pagefile was inert everywhere a loader
        // was walked while the feature reported itself as on.
        let mut attached = win10_profile(image_with_a_swapped_page());
        attached.pagefiles = vec![SwapFile {
            index: 0,
            label: "pagefile.sys".to_string(),
            source: pagefile,
        }];
        let attached_symbols = symbols(&attached);
        let space = ProcessSpace::build(
            &attached,
            &attached_symbols,
            EPROCESS_AT,
            &ModuleWalkConfig::default(),
        )
        .expect("a usable directory table base");

        let runs = space.layer().mapping(SWAPPED_VA, 0x10).expect("mapped");
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].source, BackingSource::Auxiliary(0));
        // A page recovered from a pagefile was written there before the capture
        // and is not RAM, so the run has to say where the bytes came from.
        assert_eq!(runs[0].via, Some("pagefile"));
        assert_eq!(runs[0].mapped_offset, SWAPPED_AT as u64);
        assert_eq!(space.layer().auxiliary_label(0), Some("pagefile.sys"));

        let mut buf = [0u8; 16];
        assert_eq!(
            space
                .layer()
                .read_at(SWAPPED_VA, &mut buf)
                .expect("the attached pagefile holds this page"),
            16
        );
        assert_eq!(buf, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    }

    #[test]
    fn a_space_this_crate_built_can_say_how_many_pages_the_walker_declined() {
        // The seam this exists for. `VirtualLayer::uniform_tables_suppressed`
        // is the only answer to "could this tool have hidden a page from me",
        // and before this it had no product caller at all: `ProcessSpace` kept
        // the layer as `Arc<dyn MemoryLayer>`, the counter is not on that
        // trait, and the layer was dropped when the stage finished. The number
        // never reached a record.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let built = ProcessSpace::build(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ModuleWalkConfig::default(),
        )
        .expect("a usable directory table base");

        // A measured zero: this space is intact, and the heuristic declined
        // nothing while it was read.
        assert_eq!(built.uniform_tables_suppressed(), Some(0));
        let measured = built.provenance(&[]);
        assert_eq!(measured.uniform_tables_suppressed, Some(0));
        assert_eq!(measured.suppression_occurred(), Some(false));

        // A supplied layer is a different answer, and must not be the same one.
        // Nothing can be read off it, so nothing is claimed — reporting zero
        // here would assert "no page was hidden from you" on behalf of a walk
        // that was never made.
        let asserted = ProcessSpace::supplied(Arc::clone(&profile.kernel_space), PROCESS_DTB);
        assert_eq!(asserted.uniform_tables_suppressed(), None);
        assert_eq!(asserted.provenance(&[]), SpaceProvenance::not_built());
        assert_eq!(asserted.provenance(&[]).suppression_occurred(), None);
        assert_ne!(measured, asserted.provenance(&[]));
    }

    #[test]
    fn a_named_page_reports_how_it_was_resolved_and_never_guesses_that_it_is_private() {
        // The other half of the seam: `Translation.via` was set on every
        // translation and read by nothing. It is read here, and what it can and
        // cannot support is pinned down. The fixture holds no page tables under
        // the process's directory table base, so the PEB does not translate —
        // and the answer is "not established", never a page-table result and
        // certainly never a claim about privacy.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let built = ProcessSpace::build(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ModuleWalkConfig::default(),
        )
        .expect("a usable directory table base");

        let provenance = built.provenance(&[("the process environment block", PEB_AT)]);
        assert_eq!(provenance.pages.len(), 1);
        let page = &provenance.pages[0];
        assert_eq!(page.va, PEB_AT);
        assert!(
            !page.backing.is_shared(),
            "an unresolved address is not evidence of sharing either way"
        );
        assert!(
            matches!(page.backing, PageBacking::NotEstablished(_)),
            "{:?}",
            page.backing
        );
        assert!(provenance.to_json()["pages"][0]["backing"]["shared"].is_null());
        assert_eq!(
            provenance.to_json()["pages"][0]["va_hex"],
            format!("{PEB_AT:#x}")
        );
        assert!(!provenance.any_page_shared());
    }

    #[test]
    fn a_process_with_a_null_directory_table_base_is_refused_rather_than_read_from_zero() {
        let mut image = win10_image();
        image.put_u64(EPROCESS_AT + off::EPROCESS_DTB, 0);
        let profile = win10_profile(image);
        let symbols = symbols(&profile);
        let err = ProcessSpace::build(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ModuleWalkConfig::default(),
        )
        .expect_err("a walk rooted at zero reads the bottom of the image");
        assert_eq!(err.class(), "unsupported_build");
        assert!(
            err.to_string().contains("null directory table base"),
            "{err}"
        );
    }

    #[test]
    fn a_thirty_two_bit_image_that_never_recorded_its_paging_mode_is_refused() {
        // PAE and non-PAE walk different structures, and the architecture alone
        // does not say which this machine used. Picking one would translate a
        // few addresses to frames that are not theirs.
        let profile = xp_profile(xp_image());
        let symbols = symbols(&profile);
        let err = ProcessSpace::build(
            &profile,
            &symbols,
            EPROCESS_AT,
            &ModuleWalkConfig::default(),
        )
        .expect_err("the mode was never established");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains("PAE"), "{err}");
    }

    // ── The kernel's own modules ────────────────────────────────────────────

    #[test]
    fn the_kernel_module_list_is_walked_from_ps_loaded_module_list() {
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        assert_eq!(symbols.ps_loaded_module_list, Some(KERNEL_HEAD));

        let list = list_kernel_modules(&profile, &symbols, &ModuleWalkConfig::default()).unwrap();
        assert_eq!(list.head, KERNEL_HEAD);
        assert_eq!(list.stop, ListStop::Wrapped);
        assert!(list.is_complete());
        assert!(list.incomplete().is_empty());
        assert_eq!(list.modules.len(), 1);

        let driver = &list.modules[0];
        assert_eq!(driver.entry, DRIVER_AT);
        assert_eq!(driver.base, Some(0xFFFF_F800_0000_1000));
        assert_eq!(driver.size_of_image, Some(0x0050_0000));
        assert_eq!(driver.base_name.name(), Some("ntoskrnl.exe"));
        assert_eq!(
            driver.full_path.name(),
            Some(r"\SystemRoot\system32\ntoskrnl.exe")
        );
    }

    #[test]
    fn a_thirty_two_bit_kernel_module_list_is_walked_at_four_byte_links() {
        let profile = xp_profile(xp_image());
        let symbols = symbols(&profile);
        let list = list_kernel_modules(&profile, &symbols, &ModuleWalkConfig::default()).unwrap();
        assert_eq!(list.stop, ListStop::Wrapped);
        assert_eq!(list.modules.len(), 1);
        assert_eq!(list.modules[0].base, Some(0x8054_0000));
        assert_eq!(list.modules[0].base_name.name(), Some("ntoskrnl.exe"));
    }

    #[test]
    fn the_kernel_list_prefers_the_kernel_only_entry_type_when_the_build_declares_it() {
        let with_kldr = profile(
            win10_image().layer(),
            table(&win10_module_isf(true, true)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = ModuleSymbols::from_profile(&with_kldr).unwrap();
        assert_eq!(symbols.kernel_entry_type, TYPE_KLDR_DATA_TABLE_ENTRY);
        assert_eq!(
            symbols.user_entry_type, TYPE_LDR_DATA_TABLE_ENTRY,
            "a PEB never holds the kernel-only form"
        );
        let list = list_kernel_modules(&with_kldr, &symbols, &ModuleWalkConfig::default()).unwrap();
        assert_eq!(list.entry_type, TYPE_KLDR_DATA_TABLE_ENTRY);
        assert_eq!(list.modules[0].base_name.name(), Some("ntoskrnl.exe"));

        // Without it, both walks use the ordinary entry type.
        let without = win10_profile(win10_image());
        let symbols = ModuleSymbols::from_profile(&without).unwrap();
        assert_eq!(symbols.kernel_entry_type, TYPE_LDR_DATA_TABLE_ENTRY);
    }

    #[test]
    fn a_build_that_does_not_name_ps_loaded_module_list_refuses_rather_than_listing_no_drivers() {
        // An empty driver list would be a claim that the machine had no drivers
        // loaded, which is never true of a running Windows system.
        let profile = profile(
            win10_image().layer(),
            table(&win10_module_isf(false, false)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = ModuleSymbols::from_profile(&profile).unwrap();
        assert_eq!(symbols.ps_loaded_module_list, None);
        let err = list_kernel_modules(&profile, &symbols, &ModuleWalkConfig::default())
            .expect_err("no symbol, no list");
        assert_eq!(err.class(), "unsupported_build");
        assert!(
            err.to_string().contains(SYMBOL_PS_LOADED_MODULE_LIST),
            "{err}"
        );
    }

    // ── Builds this stage cannot describe ───────────────────────────────────

    #[test]
    fn a_build_with_no_loader_entry_type_is_refused_naming_it() {
        let profile = profile(
            win10_image().layer(),
            table(&crate::poolscan::test_support::windows64_isf(true)),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let err =
            ModuleSymbols::from_profile(&profile).expect_err("no loader entry type, no modules");
        assert_eq!(err.class(), "unsupported_build");
        assert!(err.to_string().contains(TYPE_LDR_DATA_TABLE_ENTRY), "{err}");
        assert_eq!(
            err.incomplete_reason(),
            IncompleteReason::UnresolvedStructure
        );
        assert!(!err.to_incomplete().detail.is_empty());
    }

    #[test]
    fn a_build_with_no_peb_still_lists_drivers_and_names_what_it_cannot_do() {
        // The two sides are independent: an image whose user-mode structures
        // are undescribable must not cost the examiner the driver list.
        let isf = win10_module_isf(false, true)
            .replace(r#""_PEB": {"size": 64"#, r#""_PEBX": {"size": 64"#)
            .replace(r#""name": "_PEB"}"#, r#""name": "_PEBX"}"#);
        let profile = profile(
            win10_image().layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols =
            ModuleSymbols::from_profile(&profile).expect("the kernel side still resolves");
        assert!(symbols.peb.is_none());
        assert!(symbols
            .peb_unavailable
            .as_deref()
            .expect("a reason")
            .contains("_PEB"));

        let space = ProcessSpace::supplied(Arc::clone(&profile.kernel_space), PROCESS_DTB);
        let err = list_dlls(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &ModuleWalkConfig::default(),
        )
        .expect_err("no PEB, no DLL list");
        assert!(err.to_string().contains("_PEB"), "{err}");

        let list = list_kernel_modules(&profile, &symbols, &ModuleWalkConfig::default()).unwrap();
        assert_eq!(list.modules.len(), 1, "the driver list is unaffected");
    }

    #[test]
    fn a_list_this_build_does_not_declare_yields_unknown_rather_than_missing() {
        // No initialisation-order list means no module can be shown to be
        // missing from it, and the report has to say so rather than print a
        // column of falses.
        let isf = win10_module_isf(false, true).replace(
            r#""InInitializationOrderModuleList": {"offset": 48"#,
            r#""SomeOtherMember": {"offset": 48"#,
        );
        let profile = profile(
            win10_image().layer(),
            table(&isf),
            Architecture::X64,
            10,
            0,
            Some(22000),
        );
        let symbols = ModuleSymbols::from_profile(&profile).unwrap();
        assert!(symbols.peb.as_ref().expect("a PEB").init.is_none());
        assert_eq!(symbols.peb_lists()[2], None);

        let space = ProcessSpace::supplied(Arc::clone(&profile.kernel_space), PROCESS_DTB);
        let out = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &ModuleWalkConfig::default(),
        )
        .unwrap();
        for module in &out.modules {
            assert_eq!(module.in_init, None, "an unread list accuses nobody");
            assert!(!module.is_fully_linked());
        }
        assert!(!out.is_complete());
        assert!(out
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("no initialisation-order module list")));
    }

    // ── Artifact shape ──────────────────────────────────────────────────────

    #[test]
    fn every_result_serialises_with_its_completeness_attached() {
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let space = space(&profile);
        let config = ModuleWalkConfig::default();

        let dlls = list_dlls(&profile, &symbols, EPROCESS_AT, &space, &config).unwrap();
        let json = dlls.to_json();
        assert_eq!(json["complete"], true);
        assert_eq!(json["module_count"], 2);
        assert_eq!(json["loader"]["kind"], "read");
        assert_eq!(json["modules"][0]["base_name"]["name"], "ntdll.dll");

        let ldr = ldr_modules(
            &profile,
            &symbols,
            EPROCESS_AT,
            &space,
            &fixture_tree(EPROCESS_AT),
            &config,
        )
        .unwrap();
        let json = ldr.to_json();
        assert_eq!(json["unlinked_count"], 2);
        assert_eq!(json["load"]["links_member"], "InLoadOrderLinks");
        assert_eq!(json["memory"]["links_member"], "InMemoryOrderLinks");
        assert_eq!(json["init"]["links_member"], "InInitializationOrderLinks");
        assert_eq!(json["modules"][0]["in_init"], false);

        let kernel = list_kernel_modules(&profile, &symbols, &config).unwrap();
        let json = kernel.to_json();
        assert_eq!(json["complete"], true);
        assert_eq!(json["entry_type"], TYPE_LDR_DATA_TABLE_ENTRY);
    }

    // ── The orchestrated stage ──────────────────────────────────────────────

    /// A process-list row for the fixture's `_EPROCESS`.
    ///
    /// Built by hand rather than walked: this fixture's ISF describes the
    /// loader structures, not the active process list, and what is under test
    /// is the survey's orchestration rather than the list walk that feeds it.
    fn record(address: u64, pid: u64, name: &str) -> crate::process::ProcessRecord {
        use crate::process::{Field, ProcessTime, WalkDirection};
        crate::process::ProcessRecord {
            address,
            direction: WalkDirection::Forward,
            pid: Field::Known(pid),
            ppid: Field::Known(4),
            image_file_name: Field::Known(name.to_string()),
            image_name_well_formed: true,
            threads: Field::Known(1),
            handles: Field::Known(1),
            session_id: Field::Known(1),
            wow64: Field::Known(false),
            create_time: ProcessTime::NotRecorded,
            exit_time: ProcessTime::NotRecorded,
            peb: Field::Known(PEB_AT),
            notes: Vec::new(),
        }
    }

    fn list_of(records: Vec<crate::process::ProcessRecord>) -> crate::process::ProcessList {
        crate::process::ProcessList {
            head: 0x100,
            links_offset: 0,
            processes: records,
            forward_stop: ListStop::Wrapped,
            backward_stop: None,
        }
    }

    /// The fixture plus a page-table hierarchy rooted at [`PROCESS_DTB`] that
    /// maps the image one to one.
    ///
    /// The survey builds each process's address space from its own directory
    /// table base — which is the point, since reading a PEB address through the
    /// kernel's tables produces a full table of confident nonsense — so a
    /// fixture that exercises it has to have tables to walk.
    fn image_with_process_page_tables() -> Image {
        // Every table is page aligned: a page-table entry carries the frame in
        // bits 51:12, so a table at a half-page address would be walked from
        // the page below it.
        const PDPT: u64 = 0xE000;
        const PD: u64 = 0xF000;
        const PT: u64 = 0x1_0000;
        let mut image = win10_image();
        image.put_u64(PROCESS_DTB, PDPT | 3);
        image.put_u64(PDPT, PD | 3);
        image.put_u64(PD, PT | 3);
        // Identity for the whole fixture image, whatever its size: virtual
        // 0x3000 is physical 0x3000, which is what makes the loader structures
        // reachable through the process's own tables as well as the kernel's.
        for page in 0..(crate::poolscan::test_support::IMAGE_SIZE as u64 / 0x1000) {
            image.put_u64(PT + page * 8, (page * 0x1000) | 3);
        }
        image
    }

    #[test]
    fn the_survey_walks_each_process_through_its_own_address_space() {
        // The stage this wires exists because the loader walks were implemented
        // and never run. What it must not do is come back empty: a machine with
        // no user-mode modules loaded has never existed, and a survey that
        // returned one would read as exactly that.
        let profile = win10_profile(image_with_process_page_tables());
        let symbols = symbols(&profile);
        let list = list_of(vec![record(EPROCESS_AT, 1234, "notepad.exe")]);

        let survey =
            survey_process_modules(&profile, &symbols, &list, &ModuleSurveyConfig::default());
        assert_eq!(survey.processes.len(), 1);
        assert!(survey.skipped.is_empty(), "{:?}", survey.skipped);

        let modules = &survey.processes[0];
        assert_eq!(modules.pid, Some(1234));
        assert_eq!(modules.name.as_deref(), Some("notepad.exe"));
        assert_eq!(
            modules.dtb, PROCESS_DTB,
            "read through the process's own directory table base"
        );
        assert_eq!(
            modules.dlls.modules.len(),
            2,
            "the loader's own list ran: {:?}",
            modules.dlls.loader
        );

        let json = survey.to_json();
        assert_eq!(json["process_count"], 1);
        assert_eq!(json["processes"][0]["pid"], 1234);
        assert_eq!(json["processes"][0]["dlls"]["module_count"], 2);
    }

    #[test]
    fn a_process_whose_loader_data_was_never_captured_is_reported_as_unknown_not_as_empty() {
        // No page tables under this profile, so the process's own space
        // translates nothing. A row of zero modules that did not say so would
        // read as a process that had loaded no code at all.
        let profile = win10_profile(win10_image());
        let symbols = symbols(&profile);
        let list = list_of(vec![record(EPROCESS_AT, 1234, "notepad.exe")]);

        let survey =
            survey_process_modules(&profile, &symbols, &list, &ModuleSurveyConfig::default());
        let modules = &survey.processes[0];
        assert!(modules.dlls.modules.is_empty());
        assert!(
            !modules.dlls.is_complete(),
            "an unreadable loader is not an empty one"
        );
        assert!(!modules.is_complete());
        assert!(!survey.is_complete());
    }

    #[test]
    fn a_build_whose_vad_tree_cannot_be_walked_loses_the_cross_reference_and_says_so() {
        // The unlinked-module finding rests on the VAD tree. Without it the
        // survey still reports what the loader admits to — and must not let the
        // absent cross-reference read as "no module was unlinked", which would
        // clear a process nothing checked.
        let profile = win10_profile(image_with_process_page_tables());
        let symbols = symbols(&profile);
        let list = list_of(vec![record(EPROCESS_AT, 1234, "notepad.exe")]);

        let survey =
            survey_process_modules(&profile, &symbols, &list, &ModuleSurveyConfig::default());
        let reason = survey
            .vad_symbols_unavailable
            .as_deref()
            .expect("this fixture's ISF describes no VAD structures");
        assert!(reason.contains("missing from a loader list"), "{reason}");

        let modules = &survey.processes[0];
        assert!(modules.ldr.is_none());
        assert!(modules.ldr_unavailable.is_some());
        assert!(modules.unlinked().is_empty());
        assert!(!modules.is_complete());
        assert!(!survey.is_complete());
        assert!(modules
            .incomplete()
            .iter()
            .any(|i| i.detail.contains("missing from a loader list")));
        assert_eq!(
            survey.to_json()["processes"][0]["ldr_modules"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn a_process_whose_address_space_cannot_be_built_is_recorded_rather_than_dropped() {
        // A process silently missing from the survey is indistinguishable from
        // one that had no modules. NOWHERE has no directory table base in the
        // image, so its space cannot be built.
        let profile = win10_profile(image_with_process_page_tables());
        let symbols = symbols(&profile);
        let list = list_of(vec![
            record(EPROCESS_AT, 1234, "notepad.exe"),
            record(NOWHERE, 5678, "hidden.exe"),
        ]);

        let survey =
            survey_process_modules(&profile, &symbols, &list, &ModuleSurveyConfig::default());
        assert_eq!(survey.processes.len(), 1);
        assert_eq!(survey.skipped.len(), 1);
        assert_eq!(survey.skipped[0].pid, Some(5678));
        assert_eq!(survey.skipped[0].process, NOWHERE);
        assert!(!survey.is_complete());
        assert_eq!(survey.to_json()["skipped"][0]["pid"], 5678);
    }

    #[test]
    fn a_survey_over_a_short_process_list_is_not_a_complete_survey() {
        // Every process the survey did reach can be complete while the list it
        // ran over stopped early, and the modules of the processes past the
        // stop are then simply absent.
        let profile = win10_profile(image_with_process_page_tables());
        let symbols = symbols(&profile);
        let mut list = list_of(vec![record(EPROCESS_AT, 1234, "notepad.exe")]);
        list.forward_stop = ListStop::CapReached { cap: 1 };

        let survey =
            survey_process_modules(&profile, &symbols, &list, &ModuleSurveyConfig::default());
        assert!(!survey.inventory.is_complete());
        assert!(!survey.is_complete());
        let body = survey.to_json();
        assert_eq!(body["list_complete"], false);
        // The shared inventory stamp, identical to the one the other
        // process-dependent stages carry.
        assert_eq!(body["process_inventory_incomplete"], true);
        assert_eq!(body["process_inventory"]["count_is_floor"], true);
        assert_eq!(body["content_complete"], false);
    }
}
