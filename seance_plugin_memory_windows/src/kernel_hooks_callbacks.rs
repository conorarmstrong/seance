//! Notification, registry and bugcheck callbacks: who the kernel calls, and
//! from where.
//!
//! Three families, three shapes, one question each time — where does the
//! registered routine live?
//!
//! # Notification routines
//!
//! `PspCreateProcessNotifyRoutine`, `PspCreateThreadNotifyRoutine` and
//! `PspLoadImageNotifyRoutine` are fixed-size arrays of `_EX_FAST_REF` in the
//! kernel's data. Each non-empty slot points at a small block whose second
//! pointer-sized field is the routine. A driver that wants to see every process
//! start registers here; so does every EDR agent, and so does a great deal of
//! malware.
//!
//! Two details are easy to get wrong and both produce plausible rubbish:
//!
//! * an `_EX_FAST_REF` packs a reference count into the bits below the pointer's
//!   alignment — three on x86, four on x64 — and a block read at the unmasked
//!   value is offset by up to fifteen bytes, so the "routine" is whatever bytes
//!   lie fifteen bytes early;
//! * the arrays hold **eight** slots on Windows XP and 2003 and **sixty-four**
//!   for process and thread notifications from Vista onwards. Reading 64 on XP
//!   walks 56 slots of unrelated kernel data; reading 8 on Windows 10 misses
//!   every callback past the eighth, which is exactly where a late-loading
//!   driver's registration lands.
//!
//! # Where the routine sits inside the block
//!
//! The block is `_EX_CALLBACK_ROUTINE_BLOCK`: a rundown reference, then the
//! function pointer, then a context. Its offset is taken from the symbol table
//! in one of three ways, tried in order, and the one that was used travels into
//! the artifact as [`BlockRoute`]:
//!
//! 1. the build declares `_EX_CALLBACK_ROUTINE_BLOCK.Function` — read it;
//! 2. the build declares `_GENERIC_CALLBACK.Callback` — read that;
//! 3. the build declares `_EX_RUNDOWN_REF` — the function follows it, so the
//!    offset is that type's declared size.
//!
//! A build with none of the three is refused, naming all three. Writing the
//! offset down as a constant would be the one thing this crate does not do:
//! every offset comes from the symbols for the build in hand.
//!
//! # Registry callbacks
//!
//! Two shapes, and which one applies is decided by which symbols the build
//! carries rather than by a version number. Windows XP through Vista keep an
//! array of `_EX_FAST_REF` in `CmpCallBackVector` with `CmpCallBackCount`
//! entries; Windows 7 and later keep a linked list at `CallbackListHead` of
//! `_CM_CALLBACK_ENTRY`, each carrying the filter's *altitude* — the string that
//! orders filters against each other and which identifies the product that
//! registered it.
//!
//! # Bugcheck callbacks
//!
//! `KeBugCheckCallbackListHead` and `KeBugCheckReasonCallbackListHead` are
//! linked lists of records that run when the machine crashes. They are a
//! long-standing persistence spot precisely because nothing else looks at them,
//! and each record carries a `Component` string naming the driver that
//! registered it — which, unlike the routine pointer, the registering driver
//! chose, so it is a claim rather than a fact.

use std::sync::Arc;

use seance_memory::binding::{required_size, BindError};
use seance_memory::object::{ListSpec, Obj, StructReader};

use crate::kernel_hooks::{
    push_note, read_u32, symbol_address, KernelHookConfig, KernelHookError, ModuleMap, Ownership,
};
use crate::module::STAGE_KERNEL_HOOKS;
use crate::poolscan::unicode_string;
use crate::profile::WindowsProfile;

/// Symbol naming the process-creation notification array.
pub const SYMBOL_PROCESS_NOTIFY: &str = "PspCreateProcessNotifyRoutine";

/// Symbol naming the thread-creation notification array.
pub const SYMBOL_THREAD_NOTIFY: &str = "PspCreateThreadNotifyRoutine";

/// Symbol naming the image-load notification array.
pub const SYMBOL_IMAGE_NOTIFY: &str = "PspLoadImageNotifyRoutine";

/// Symbol naming the pre-Windows-7 registry callback vector.
pub const SYMBOL_REGISTRY_VECTOR: &str = "CmpCallBackVector";

/// Symbol naming how many registry callbacks are registered.
pub const SYMBOL_REGISTRY_COUNT: &str = "CmpCallBackCount";

/// Symbol naming the Windows 7 and later registry callback list.
pub const SYMBOL_REGISTRY_LIST: &str = "CallbackListHead";

/// Symbol naming the bugcheck callback list.
pub const SYMBOL_BUGCHECK_LIST: &str = "KeBugCheckCallbackListHead";

/// Symbol naming the bugcheck-reason callback list.
pub const SYMBOL_BUGCHECK_REASON_LIST: &str = "KeBugCheckReasonCallbackListHead";

/// The kernel's callback block, which holds the registered routine.
pub const TYPE_CALLBACK_BLOCK: &str = "_EX_CALLBACK_ROUTINE_BLOCK";

/// The stand-in some symbol packs ship for the same block.
pub const TYPE_GENERIC_CALLBACK: &str = "_GENERIC_CALLBACK";

/// The rundown reference at the front of a callback block.
pub const TYPE_RUNDOWN_REF: &str = "_EX_RUNDOWN_REF";

/// One entry of the Windows 7 and later registry callback list.
pub const TYPE_CM_CALLBACK_ENTRY: &str = "_CM_CALLBACK_ENTRY";

/// One bugcheck callback record.
pub const TYPE_BUGCHECK_RECORD: &str = "_KBUGCHECK_CALLBACK_RECORD";

/// One bugcheck-reason callback record.
pub const TYPE_BUGCHECK_REASON_RECORD: &str = "_KBUGCHECK_REASON_CALLBACK_RECORD";

/// The kernel's doubly-linked list link.
pub const TYPE_LIST_ENTRY: &str = "_LIST_ENTRY";

/// The forward link of a `_LIST_ENTRY`.
pub const LIST_FORWARD: &str = "Flink";

/// Slots in a notification array on Windows XP and 2003.
pub const LEGACY_NOTIFY_SLOTS: u64 = 8;

/// Slots in the process and thread notification arrays from Vista onwards.
pub const EXTENDED_NOTIFY_SLOTS: u64 = 64;

/// First Windows major version with the extended notification arrays.
pub const FIRST_EXTENDED_NOTIFY_MAJOR: u32 = 6;

/// Ceiling on registry callbacks one sweep will read.
///
/// A machine has a few dozen registry filters. A count above this came out of
/// the image and is wrong, so it is a cap rather than a very long loop.
pub const MAX_REGISTRY_CALLBACKS: u64 = 1_024;

/// Ceiling on entries one bugcheck list walk will follow.
pub const MAX_BUGCHECK_RECORDS: usize = 1_024;

/// Ceiling on bytes read from a bugcheck record's component string.
pub const MAX_COMPONENT_BYTES: u64 = 64;

// ── Layout ──────────────────────────────────────────────────────────────────

/// How the offset of the routine inside a callback block was established.
///
/// Carried into the artifact because the three routes do not carry equal
/// confidence: a declared member is the build's own statement, while deriving
/// the offset from the size of the rundown reference in front of it rests on the
/// block's shape being what every Windows kernel has had.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockRoute {
    /// The build declares the member outright.
    Declared {
        /// The type it was read from.
        type_name: String,
        /// The member.
        member: String,
    },
    /// The build declares `_EX_RUNDOWN_REF` but not the block, so the routine
    /// sits immediately after the rundown reference.
    RundownRefSize,
}

impl BlockRoute {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            BlockRoute::Declared { .. } => "declared_member",
            BlockRoute::RundownRefSize => "rundown_ref_size",
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            BlockRoute::Declared { type_name, member } => serde_json::json!({
                "kind": "declared_member",
                "type": type_name,
                "member": member,
            }),
            BlockRoute::RundownRefSize => serde_json::json!({"kind": "rundown_ref_size"}),
        }
    }
}

/// Where the registered routine sits inside a callback block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackBlock {
    /// Distance from the block's first byte to the routine pointer.
    pub function_offset: u64,
    /// How that distance was established.
    pub route: BlockRoute,
}

impl CallbackBlock {
    /// Resolve the block layout from whatever this build declares.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] naming all three types that were tried.
    /// Guessing the offset would put a "callback address" one pointer early or
    /// late on every row, and every one of those rows would look exactly like a
    /// correct one.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        for (type_name, member) in [
            (TYPE_CALLBACK_BLOCK, "Function"),
            (TYPE_GENERIC_CALLBACK, "Callback"),
        ] {
            if !profile.symbols.has_type(type_name) {
                continue;
            }
            if let Ok(offset) = reader.member_offset(type_name, member) {
                return Ok(Self {
                    function_offset: offset.bytes(),
                    route: BlockRoute::Declared {
                        type_name: type_name.to_string(),
                        member: member.to_string(),
                    },
                });
            }
        }
        // The last route: the routine follows an `_EX_RUNDOWN_REF`, so the
        // rundown reference's own width is the distance to it.
        //
        // Absence here is not a failure of *this* route, it is the third of
        // three routes coming up empty, and the refusal below names all three.
        // Only a table that could not answer is fatal at this point, and it
        // arrives naming this stage and what was lost rather than as a bare
        // `SymbolError` — which, on a `has_type` guard, would instead have been
        // reported as "this build declares none of the three": a claim about
        // the suspect's machine made from a table this analysis could not read.
        match required_size(
            &profile.symbols,
            STAGE_KERNEL_HOOKS,
            &[TYPE_RUNDOWN_REF],
            "the distance from a callback block to the routine it registers cannot be \
             established, so no notification callback can be attributed to a driver",
        ) {
            Ok(size) => {
                if size == 0 {
                    return Err(KernelHookError::unsupported(format!(
                        "'{TYPE_RUNDOWN_REF}' declares a size of 0, so the routine that follows it \
                         would be read from the front of the block"
                    )));
                }
                return Ok(Self {
                    function_offset: size,
                    route: BlockRoute::RundownRefSize,
                });
            }
            Err(BindError::RequiredNotDeclared { .. }) => {}
            Err(err) => return Err(err.into()),
        }
        Err(KernelHookError::unsupported(format!(
            "this build declares none of '{TYPE_CALLBACK_BLOCK}.Function', \
             '{TYPE_GENERIC_CALLBACK}.Callback' and '{TYPE_RUNDOWN_REF}', so where a registered \
             routine sits inside a callback block cannot be established"
        )))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "function_offset": self.function_offset,
            "route": self.route.to_json(),
        })
    }
}

/// Which family a callback belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallbackKind {
    /// Called when a process is created or exits.
    ProcessNotify,
    /// Called when a thread is created or exits.
    ThreadNotify,
    /// Called when an image is mapped into a process.
    ImageLoadNotify,
    /// Called around registry operations.
    Registry,
    /// Called when the machine bugchecks.
    BugCheck,
    /// Called when the machine bugchecks, with a reason code.
    BugCheckReason,
}

impl CallbackKind {
    /// Stable identifier for artifact metadata.
    pub fn as_str(self) -> &'static str {
        match self {
            CallbackKind::ProcessNotify => "process_notify",
            CallbackKind::ThreadNotify => "thread_notify",
            CallbackKind::ImageLoadNotify => "image_load_notify",
            CallbackKind::Registry => "registry",
            CallbackKind::BugCheck => "bugcheck",
            CallbackKind::BugCheckReason => "bugcheck_reason",
        }
    }
}

/// One notification array in the kernel's data.
#[derive(Debug, Clone)]
pub struct NotifyArray {
    /// The symbol naming it.
    pub symbol: &'static str,
    /// Which family its entries belong to.
    pub kind: CallbackKind,
    /// Where the array is, in kernel virtual space.
    pub address: u64,
    /// How many slots it has on this build.
    pub slots: u64,
}

/// The notification arrays this build has, and how to read a slot.
#[derive(Debug, Clone)]
pub struct NotifySymbols {
    /// The arrays, in the order they are read.
    pub arrays: Vec<NotifyArray>,
    /// Where the routine sits inside a block.
    pub block: CallbackBlock,
    /// Pointer width, which is the stride of a slot.
    pub pointer_size: u64,
    /// Mask that strips an `_EX_FAST_REF`'s reference count from a slot.
    pub fast_ref_mask: u64,
}

impl NotifySymbols {
    /// Resolve the notification arrays this build carries.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] when the block layout cannot be
    /// established, or when the build names none of the three arrays. An empty
    /// result would say the kernel notifies nobody when a process starts, which
    /// is not true of any Windows installation.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let block = CallbackBlock::from_profile(profile)?;
        // The process and thread arrays grew from eight slots to sixty-four in
        // Vista; the image-load array did not.
        let extended = profile.build.major >= FIRST_EXTENDED_NOTIFY_MAJOR;
        let mut arrays = Vec::new();
        let mut missing = Vec::new();
        for (symbol, kind, grows) in [
            (SYMBOL_PROCESS_NOTIFY, CallbackKind::ProcessNotify, true),
            (SYMBOL_THREAD_NOTIFY, CallbackKind::ThreadNotify, true),
            (SYMBOL_IMAGE_NOTIFY, CallbackKind::ImageLoadNotify, false),
        ] {
            match symbol_address(profile, symbol) {
                Ok(address) => arrays.push(NotifyArray {
                    symbol,
                    kind,
                    address,
                    slots: if grows && extended {
                        EXTENDED_NOTIFY_SLOTS
                    } else {
                        LEGACY_NOTIFY_SLOTS
                    },
                }),
                Err(_) => missing.push(symbol),
            }
        }
        if arrays.is_empty() {
            return Err(KernelHookError::unsupported(format!(
                "this build's symbols name none of {missing:?}, so the routines the kernel calls \
                 when a process, thread or image starts cannot be listed"
            )));
        }
        let pointer_size = profile.pointer_size();
        Ok(Self {
            arrays,
            block,
            pointer_size,
            // An `_EX_FAST_REF` packs the reference count into the bits below
            // the pointer's alignment: three on x86, four on x64. The mask is
            // therefore `2 × pointer_size − 1`, which is 7 and 15.
            fast_ref_mask: pointer_size.saturating_mul(2).saturating_sub(1),
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "block": self.block.to_json(),
            "arrays": self
                .arrays
                .iter()
                .map(|array| serde_json::json!({
                    "symbol": array.symbol,
                    "kind": array.kind.as_str(),
                    "address": array.address,
                    "slots": array.slots,
                }))
                .collect::<Vec<_>>(),
        })
    }
}

/// Which of the two registry-callback shapes this build uses.
#[derive(Debug, Clone)]
pub enum RegistryCallbackShape {
    /// XP through Vista: an array of `_EX_FAST_REF` with a separate count.
    Vector {
        /// Where the array is.
        vector: u64,
        /// Where the count is.
        count_at: u64,
        /// Where the routine sits inside a block.
        block: CallbackBlock,
        /// Pointer width, which is the stride of a slot.
        pointer_size: u64,
        /// Mask that strips an `_EX_FAST_REF`'s reference count.
        fast_ref_mask: u64,
    },
    /// Windows 7 and later: a linked list of `_CM_CALLBACK_ENTRY`.
    List {
        /// Where the list head is.
        head: u64,
        /// Where the count is, when the build names it. Used only as a
        /// cross-check against how many entries the walk found.
        count_at: Option<u64>,
        /// The entry type.
        entry_type: String,
        /// The member the list threads through.
        link: String,
        /// The member holding the registered routine.
        function: String,
        /// The member holding the filter's altitude, when the build has it.
        altitude: Option<String>,
    },
}

impl RegistryCallbackShape {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            RegistryCallbackShape::Vector { .. } => "vector",
            RegistryCallbackShape::List { .. } => "list",
        }
    }
}

/// How this build's registry filter callbacks are reached.
#[derive(Debug, Clone)]
pub struct RegistryCallbackSymbols {
    /// The shape in use.
    pub shape: RegistryCallbackShape,
}

impl RegistryCallbackSymbols {
    /// Resolve the registry callback list or vector.
    ///
    /// The shape is chosen by which symbols the build carries, never by a
    /// version number: a build that has both is read through the vector, which
    /// is what the kernel that has both actually maintains.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] naming every symbol that was tried when
    /// neither shape is available.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        let count_at = symbol_address(profile, SYMBOL_REGISTRY_COUNT).ok();

        if let (Ok(vector), Some(count_at)) =
            (symbol_address(profile, SYMBOL_REGISTRY_VECTOR), count_at)
        {
            let block = CallbackBlock::from_profile(profile)?;
            let pointer_size = profile.pointer_size();
            return Ok(Self {
                shape: RegistryCallbackShape::Vector {
                    vector,
                    count_at,
                    block,
                    pointer_size,
                    fast_ref_mask: pointer_size.saturating_mul(2).saturating_sub(1),
                },
            });
        }

        if let Ok(head) = symbol_address(profile, SYMBOL_REGISTRY_LIST) {
            if !profile.symbols.has_type(TYPE_CM_CALLBACK_ENTRY) {
                return Err(KernelHookError::unsupported(format!(
                    "'{SYMBOL_REGISTRY_LIST}' is in this build's symbols but \
                     '{TYPE_CM_CALLBACK_ENTRY}' is not, so the list could be found and not read"
                )));
            }
            let link = reader
                .member_offset(TYPE_CM_CALLBACK_ENTRY, "Link")
                .map(|_| "Link".to_string())
                .map_err(|err| {
                    KernelHookError::unsupported(format!(
                        "'{TYPE_CM_CALLBACK_ENTRY}' has no Link, so the registry callback list \
                         cannot be threaded: {err}"
                    ))
                })?;
            let function = reader
                .member_offset(TYPE_CM_CALLBACK_ENTRY, "Function")
                .map(|_| "Function".to_string())
                .map_err(|err| {
                    KernelHookError::unsupported(format!(
                        "'{TYPE_CM_CALLBACK_ENTRY}' has no Function, so a registry filter's \
                         routine could not be named: {err}"
                    ))
                })?;
            let altitude = reader
                .member_offset(TYPE_CM_CALLBACK_ENTRY, "Altitude")
                .ok()
                .map(|_| "Altitude".to_string());
            return Ok(Self {
                shape: RegistryCallbackShape::List {
                    head,
                    count_at,
                    entry_type: TYPE_CM_CALLBACK_ENTRY.to_string(),
                    link,
                    function,
                    altitude,
                },
            });
        }

        Err(KernelHookError::unsupported(format!(
            "this build's symbols name neither '{SYMBOL_REGISTRY_VECTOR}' with \
             '{SYMBOL_REGISTRY_COUNT}' nor '{SYMBOL_REGISTRY_LIST}', so the drivers filtering \
             registry operations cannot be listed"
        )))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match &self.shape {
            RegistryCallbackShape::Vector {
                vector,
                count_at,
                block,
                ..
            } => serde_json::json!({
                "shape": "vector",
                "vector": vector,
                "count_at": count_at,
                "block": block.to_json(),
            }),
            RegistryCallbackShape::List {
                head,
                count_at,
                entry_type,
                function,
                altitude,
                ..
            } => serde_json::json!({
                "shape": "list",
                "head": head,
                "count_at": count_at,
                "entry_type": entry_type,
                "function": function,
                "altitude": altitude,
            }),
        }
    }
}

/// One bugcheck callback list.
#[derive(Debug, Clone)]
pub struct BugcheckList {
    /// The symbol naming the head.
    pub symbol: &'static str,
    /// Which family its records belong to.
    pub kind: CallbackKind,
    /// Where the head is.
    pub head: u64,
    /// The record type the list threads.
    pub record_type: &'static str,
    /// The member the list threads through.
    pub link: String,
    /// The member holding the registered routine.
    pub routine: String,
    /// The member holding the component name, when the build has it.
    pub component: Option<String>,
}

/// The bugcheck callback lists this build carries.
#[derive(Debug, Clone)]
pub struct BugcheckSymbols {
    /// The lists, in the order they are walked.
    pub lists: Vec<BugcheckList>,
}

impl BugcheckSymbols {
    /// Resolve whichever of the two bugcheck lists this build declares.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] when neither list can be reached,
    /// naming both symbols and both record types.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type(TYPE_LIST_ENTRY) {
            return Err(KernelHookError::unsupported(format!(
                "the symbol table has no '{TYPE_LIST_ENTRY}', so no kernel list can be walked"
            )));
        }
        let mut lists = Vec::new();
        for (symbol, kind, record_type) in [
            (
                SYMBOL_BUGCHECK_LIST,
                CallbackKind::BugCheck,
                TYPE_BUGCHECK_RECORD,
            ),
            (
                SYMBOL_BUGCHECK_REASON_LIST,
                CallbackKind::BugCheckReason,
                TYPE_BUGCHECK_REASON_RECORD,
            ),
        ] {
            let Ok(head) = symbol_address(profile, symbol) else {
                continue;
            };
            if !profile.symbols.has_type(record_type) {
                continue;
            }
            let (Ok(_), Ok(_)) = (
                reader.member_offset(record_type, "Entry"),
                reader.member_offset(record_type, "CallbackRoutine"),
            ) else {
                continue;
            };
            lists.push(BugcheckList {
                symbol,
                kind,
                head,
                record_type,
                link: "Entry".to_string(),
                routine: "CallbackRoutine".to_string(),
                component: reader
                    .member_offset(record_type, "Component")
                    .ok()
                    .map(|_| "Component".to_string()),
            });
        }
        if lists.is_empty() {
            return Err(KernelHookError::unsupported(format!(
                "this build declares neither '{SYMBOL_BUGCHECK_LIST}' with \
                 '{TYPE_BUGCHECK_RECORD}' nor '{SYMBOL_BUGCHECK_REASON_LIST}' with \
                 '{TYPE_BUGCHECK_REASON_RECORD}', so the routines that run when the machine \
                 crashes cannot be listed"
            )));
        }
        Ok(Self { lists })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "lists": self
                .lists
                .iter()
                .map(|list| serde_json::json!({
                    "symbol": list.symbol,
                    "kind": list.kind.as_str(),
                    "head": list.head,
                    "record_type": list.record_type,
                    "component": list.component,
                }))
                .collect::<Vec<_>>(),
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One registered callback, and where its target lives.
#[derive(Debug, Clone)]
pub struct CallbackRecord {
    /// Which family it belongs to.
    pub kind: CallbackKind,
    /// The symbol or list it was found in.
    pub source: String,
    /// The array slot it occupied, for a callback found in an array.
    pub slot: Option<u64>,
    /// Where the block or record describing it is.
    pub record: Option<u64>,
    /// The routine the kernel would call.
    pub routine: u64,
    /// Where that routine lives. A routine in no loaded module is the finding;
    /// a routine the map cannot answer for is not.
    pub ownership: Ownership,
    /// Anything the record itself said about who registered it — a filter's
    /// altitude, a bugcheck record's component. A claim by the registering
    /// driver rather than a fact about memory, so it is never used to attribute.
    pub detail: Option<String>,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl CallbackRecord {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "kind": self.kind.as_str(),
            "source": self.source,
            "slot": self.slot,
            "record": self.record,
            "routine": self.routine,
            "ownership": self.ownership.to_json(),
            "module": self.ownership.module(),
            "outside_any_module": self.ownership.is_outside_any_module(),
            "detail": self.detail,
            "notes": self.notes,
        })
    }
}

/// What one callback group found, and everything it could not do.
#[derive(Debug, Clone, Default)]
pub struct CallbackSweep {
    /// The callbacks.
    pub records: Vec<CallbackRecord>,
    /// Notes about slots and entries that could not be followed, capped by
    /// [`KernelHookConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes were raised in total. Exact even when the list was capped.
    pub notes_total: usize,
    /// Whether a cap fired. The group stopped; the kernel did not run out.
    pub capped: bool,
}

// ── The groups ──────────────────────────────────────────────────────────────

/// Read every process, thread and image-load notification routine.
///
/// # What an examiner learns
///
/// Which routines the kernel calls when a process starts, when a thread starts
/// and when an image is mapped — and, for each, the driver that owns the target.
/// A routine owned by no loaded module is code the loader has no record of.
///
/// # What a wrong answer looks like
///
/// A routine address one pointer out, produced by reading the block at the
/// wrong offset or by failing to mask the `_EX_FAST_REF` reference count. Such
/// an address lands in the middle of an instruction and attributes to whichever
/// module happens to contain it, which is usually the right module and the wrong
/// function — a row that is wrong and looks right.
pub fn list_notify_routines(
    profile: &WindowsProfile,
    symbols: &NotifySymbols,
    modules: &ModuleMap,
    config: &KernelHookConfig,
) -> CallbackSweep {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let mut sweep = CallbackSweep::default();

    for array in &symbols.arrays {
        for slot in 0..array.slots {
            if sweep.records.len() >= config.max_callbacks {
                sweep.capped = true;
                return sweep;
            }
            let Some(at) = slot
                .checked_mul(symbols.pointer_size)
                .and_then(|within| array.address.checked_add(within))
            else {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "slot {slot} of '{}' lies past the end of the address space, so the array \
                         was not read to its end",
                        array.symbol
                    ),
                );
                sweep.capped = true;
                break;
            };
            let raw = match reader.read_pointer_at(at) {
                Ok(raw) => raw,
                Err(err) => {
                    // One unreadable slot means the array's page was not
                    // acquired, so the rest of it is not there either. Stopping
                    // here and saying so beats sixty-three identical notes.
                    push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "'{}' could not be read from slot {slot} onwards, so any callback in \
                             the remaining {} slot(s) is not listed: {err}",
                            array.symbol,
                            array.slots.saturating_sub(slot)
                        ),
                    );
                    // The array is short. Without this the group reports as
                    // having run to completion, and a report would be entitled
                    // to write "nothing was notified when a process started".
                    sweep.capped = true;
                    break;
                }
            };
            // An empty slot is the ordinary case and is not a note.
            if raw == 0 {
                continue;
            }
            let block = raw & !symbols.fast_ref_mask;
            if block == 0 {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "slot {slot} of '{}' holds {raw:#x}, which is a reference count with no \
                         pointer, so no callback block could be reached",
                        array.symbol
                    ),
                );
                continue;
            }
            let Some(function_at) = block.checked_add(symbols.block.function_offset) else {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "the callback block at {block:#x} from slot {slot} of '{}' would place its \
                         routine past the end of the address space",
                        array.symbol
                    ),
                );
                continue;
            };
            let routine = match reader.read_pointer_at(function_at) {
                Ok(routine) => routine,
                Err(err) => {
                    push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "the callback block at {block:#x} from slot {slot} of '{}' is \
                             registered and its routine could not be read: {err}",
                            array.symbol
                        ),
                    );
                    continue;
                }
            };
            if routine == 0 {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "the callback block at {block:#x} from slot {slot} of '{}' holds a null \
                         routine",
                        array.symbol
                    ),
                );
                continue;
            }
            sweep.records.push(CallbackRecord {
                kind: array.kind,
                source: array.symbol.to_string(),
                slot: Some(slot),
                record: Some(block),
                routine,
                ownership: modules.attribute(routine),
                detail: None,
                notes: Vec::new(),
            });
        }
    }
    sweep
}

/// Read every registry filter callback.
///
/// # What an examiner learns
///
/// Which routines see every registry operation on the machine, and — through
/// the altitude string, where the build carries it — which product registered
/// each. A registry filter is how a rootkit hides its own keys from every tool
/// that reads the registry through the API.
pub fn list_registry_callbacks(
    profile: &WindowsProfile,
    symbols: &RegistryCallbackSymbols,
    modules: &ModuleMap,
    config: &KernelHookConfig,
) -> CallbackSweep {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let mut sweep = CallbackSweep::default();

    match &symbols.shape {
        RegistryCallbackShape::Vector {
            vector,
            count_at,
            block,
            pointer_size,
            fast_ref_mask,
        } => {
            let declared = match read_u32(&reader, *count_at) {
                Ok(count) => u64::from(count),
                Err(err) => {
                    push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "'{SYMBOL_REGISTRY_COUNT}' could not be read, so it is not known how \
                             many registry callbacks the vector holds: {err}"
                        ),
                    );
                    sweep.capped = true;
                    return sweep;
                }
            };
            let count = declared.min(MAX_REGISTRY_CALLBACKS);
            if count < declared {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "'{SYMBOL_REGISTRY_COUNT}' declares {declared} callbacks, above the \
                         {MAX_REGISTRY_CALLBACKS} this stage will read, so the vector was not \
                         followed to its declared end"
                    ),
                );
                sweep.capped = true;
            }
            for slot in 0..count {
                if sweep.records.len() >= config.max_callbacks {
                    sweep.capped = true;
                    return sweep;
                }
                let Some(at) = slot
                    .checked_mul(*pointer_size)
                    .and_then(|within| vector.checked_add(within))
                else {
                    // The vector runs off the end of the address space. The
                    // slots after this one were never looked at, so the sweep
                    // is short and has to say so: a registry filter hiding a
                    // key sits in a slot like any other.
                    push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "slot {slot} of '{SYMBOL_REGISTRY_VECTOR}' lies past the end of the \
                             address space, so the vector was not read to its declared end"
                        ),
                    );
                    sweep.capped = true;
                    break;
                };
                let raw = match reader.read_pointer_at(at) {
                    Ok(raw) => raw,
                    Err(err) => {
                        push_note(
                            &mut sweep.notes,
                            &mut sweep.notes_total,
                            config.max_recorded_notes,
                            format!(
                                "'{SYMBOL_REGISTRY_VECTOR}' could not be read from slot {slot} \
                                 onwards, so the remaining {} slot(s) are not listed: {err}",
                                count.saturating_sub(slot)
                            ),
                        );
                        // Without this the group reports as having run to
                        // completion, and a report would be entitled to write
                        // "this machine had no registry filter beyond these".
                        sweep.capped = true;
                        break;
                    }
                };
                if raw == 0 {
                    continue;
                }
                let entry = raw & !*fast_ref_mask;
                let Some(function_at) = entry.checked_add(block.function_offset) else {
                    push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "the registry callback block at {entry:#x} from slot {slot} is \
                             registered and its routine would lie past the end of the address \
                             space, so the routine it names is unknown rather than absent"
                        ),
                    );
                    continue;
                };
                match reader.read_pointer_at(function_at) {
                    // A registered block whose routine pointer is null. The
                    // notification arrays record the same thing, and it must
                    // not be dropped silently here: the slot is occupied, and
                    // an occupied slot naming nothing is itself odd.
                    Ok(0) => push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "the registry callback block at {entry:#x} from slot {slot} holds a \
                             null routine"
                        ),
                    ),
                    Ok(routine) => sweep.records.push(CallbackRecord {
                        kind: CallbackKind::Registry,
                        source: SYMBOL_REGISTRY_VECTOR.to_string(),
                        slot: Some(slot),
                        record: Some(entry),
                        routine,
                        ownership: modules.attribute(routine),
                        detail: None,
                        notes: Vec::new(),
                    }),
                    Err(err) => push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "the registry callback block at {entry:#x} from slot {slot} is \
                             registered and its routine could not be read: {err}"
                        ),
                    ),
                }
            }
        }
        RegistryCallbackShape::List {
            head,
            count_at,
            entry_type,
            link,
            function,
            altitude,
        } => {
            let spec = ListSpec::new(TYPE_LIST_ENTRY, LIST_FORWARD)
                .in_container(entry_type.clone(), link.clone())
                .with_max_entries(config.max_callbacks);
            let walk = match reader.walk_list(*head, &spec) {
                Ok(walk) => walk,
                Err(err) => {
                    push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!("'{SYMBOL_REGISTRY_LIST}' could not be walked: {err}"),
                    );
                    sweep.capped = true;
                    return sweep;
                }
            };
            let (entries, stop) = walk.walk_to_end();
            if !stop.is_complete() {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!(
                        "the registry callback list walk ended at '{}', so any filter past that \
                         point is not listed",
                        stop.as_str()
                    ),
                );
                sweep.capped = true;
            }
            for entry in &entries {
                let mut notes = Vec::new();
                let routine = match address_member(entry, function) {
                    Ok(routine) => routine,
                    Err(detail) => {
                        push_note(
                            &mut sweep.notes,
                            &mut sweep.notes_total,
                            config.max_recorded_notes,
                            format!(
                                "the registry callback entry at {:#x} is registered and its \
                                 routine could not be read: {detail}",
                                entry.address()
                            ),
                        );
                        continue;
                    }
                };
                let detail =
                    altitude
                        .as_deref()
                        .and_then(|member| match unicode_string(entry, member) {
                            Ok(Some(text)) => Some(format!("altitude {text}")),
                            Ok(None) => None,
                            Err(err) => {
                                notes.push(format!("'{member}' could not be read: {err}"));
                                None
                            }
                        });
                sweep.records.push(CallbackRecord {
                    kind: CallbackKind::Registry,
                    source: SYMBOL_REGISTRY_LIST.to_string(),
                    slot: None,
                    record: Some(entry.address()),
                    routine,
                    ownership: modules.attribute(routine),
                    detail,
                    notes,
                });
            }
            // The kernel's own count is a cross-check, not a source of rows: a
            // disagreement means the list was spliced or the walk stopped, and
            // either is worth saying.
            if let Some(count_at) = count_at {
                if let Ok(declared) = read_u32(&reader, *count_at) {
                    if u64::from(declared) != u64::try_from(entries.len()).unwrap_or(u64::MAX) {
                        push_note(
                            &mut sweep.notes,
                            &mut sweep.notes_total,
                            config.max_recorded_notes,
                            format!(
                                "'{SYMBOL_REGISTRY_COUNT}' says {declared} registry callback(s) \
                                 are registered and the list walk found {}",
                                entries.len()
                            ),
                        );
                    }
                }
            }
        }
    }
    sweep
}

/// Read every bugcheck and bugcheck-reason callback.
///
/// # What an examiner learns
///
/// Which routines run when the machine crashes, and which component each record
/// claims to belong to. The component is a string the registering driver chose;
/// the routine's address is not, which is why attribution is done from the
/// address and the component is reported as a claim beside it.
pub fn list_bugcheck_callbacks(
    profile: &WindowsProfile,
    symbols: &BugcheckSymbols,
    modules: &ModuleMap,
    config: &KernelHookConfig,
) -> CallbackSweep {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let mut sweep = CallbackSweep::default();

    for list in &symbols.lists {
        let spec = ListSpec::new(TYPE_LIST_ENTRY, LIST_FORWARD)
            .in_container(list.record_type.to_string(), list.link.clone())
            .with_max_entries(MAX_BUGCHECK_RECORDS.min(config.max_callbacks));
        let walk = match reader.walk_list(list.head, &spec) {
            Ok(walk) => walk,
            Err(err) => {
                push_note(
                    &mut sweep.notes,
                    &mut sweep.notes_total,
                    config.max_recorded_notes,
                    format!("'{}' could not be walked: {err}", list.symbol),
                );
                sweep.capped = true;
                continue;
            }
        };
        let (entries, stop) = walk.walk_to_end();
        if !stop.is_complete() {
            push_note(
                &mut sweep.notes,
                &mut sweep.notes_total,
                config.max_recorded_notes,
                format!(
                    "the walk of '{}' ended at '{}', so any callback past that point is not listed",
                    list.symbol,
                    stop.as_str()
                ),
            );
            sweep.capped = true;
        }
        for entry in &entries {
            if sweep.records.len() >= config.max_callbacks {
                sweep.capped = true;
                return sweep;
            }
            let mut notes = Vec::new();
            let routine = match address_member(entry, &list.routine) {
                Ok(routine) => routine,
                Err(detail) => {
                    push_note(
                        &mut sweep.notes,
                        &mut sweep.notes_total,
                        config.max_recorded_notes,
                        format!(
                            "the bugcheck record at {:#x} is registered and its routine could not \
                             be read: {detail}",
                            entry.address()
                        ),
                    );
                    continue;
                }
            };
            if routine == 0 {
                notes.push("the record holds a null routine".to_string());
            }
            let detail = list.component.as_deref().and_then(|member| {
                match component_string(&reader, entry, member) {
                    Ok(text) => text.map(|text| format!("component {text}")),
                    Err(err) => {
                        notes.push(format!("'{member}' could not be read: {err}"));
                        None
                    }
                }
            });
            sweep.records.push(CallbackRecord {
                kind: list.kind,
                source: list.symbol.to_string(),
                slot: None,
                record: Some(entry.address()),
                routine,
                ownership: modules.attribute(routine),
                detail,
                notes,
            });
        }
    }
    sweep
}

// ── Reading ─────────────────────────────────────────────────────────────────

/// Read a member that holds an address, whether the build declares it as a
/// pointer or as an integer.
///
/// A signed declaration is reinterpreted rather than refused: kernel addresses
/// on x64 have the top bit set, and a build that types the field as a signed
/// long is describing the same bits.
fn address_member(object: &Obj, path: &str) -> Result<u64, String> {
    let value = object
        .int(path)
        .map_err(|err| format!("'{path}' could not be read: {err}"))?;
    value
        .as_u64()
        .or_else(|| value.as_i64().map(|signed| signed as u64))
        .ok_or_else(|| format!("'{path}' holds {value}, which is not an address"))
}

/// The NUL-terminated component name a bugcheck record points at.
///
/// `Ok(None)` when the record carries no component pointer, which is ordinary.
/// The string is read from the **native** space because the pointer is a kernel
/// virtual address whatever space the record itself was read from, and it is cut
/// at the first NUL so that a record whose component runs into neighbouring data
/// does not put that data in a report.
fn component_string(
    reader: &StructReader,
    record: &Obj,
    member: &str,
) -> Result<Option<String>, String> {
    let pointer = address_member(record, member)?;
    if pointer == 0 {
        return Ok(None);
    }
    let bytes = reader
        .in_native_space()
        .read_bytes(pointer, MAX_COMPONENT_BYTES)
        .map_err(|err| err.to_string())?;
    let end = bytes.iter().position(|&byte| byte == 0).unwrap_or(0);
    if end == 0 {
        return Ok(None);
    }
    // The component is an ANSI string. Non-ASCII bytes are shown rather than
    // dropped, because the bytes are the evidence.
    Ok(Some(
        bytes[..end]
            .iter()
            .map(|&byte| {
                if (0x20..0x7F).contains(&byte) {
                    byte as char
                } else {
                    '.'
                }
            })
            .collect(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_hooks::test_support::{
        hook_isf, hook_profile, isf_with_registry_vector, off, populated_image,
        BUGCHECK_REASON_ROUTINE, BUGCHECK_ROUTINE, FLT_NAME, FLT_ROUTINE, HIDDEN_ROUTINE,
        NOTIFY_BLOCK_HIDDEN, NOTIFY_BLOCK_NT, NT_NAME, NT_ROUTINE, REGISTRY_ALTITUDE,
        REGISTRY_COUNT_AT,
    };
    use crate::kernel_hooks::ModuleMap;
    use crate::poolscan::test_support::IMAGE_SIZE;

    /// The stage's own view of the fixture: symbols, a module map built from the
    /// fixture's loaded-module list, and the default caps.
    fn sweep_notify(isf: &str) -> CallbackSweep {
        let profile = hook_profile(populated_image(), isf);
        let modules = ModuleMap::from_profile(&profile);
        let symbols = NotifySymbols::from_profile(&profile).expect("a describable build");
        list_notify_routines(&profile, &symbols, &modules, &KernelHookConfig::default())
    }

    // ── Notification routines ───────────────────────────────────────────────

    #[test]
    fn a_registered_process_callback_is_attributed_to_the_module_that_owns_it() {
        let sweep = sweep_notify(&hook_isf());
        let record = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::ProcessNotify)
            .unwrap_or_else(|| panic!("a process callback: {:?}", sweep));
        assert_eq!(record.routine, NT_ROUTINE);
        assert_eq!(record.record, Some(NOTIFY_BLOCK_NT));
        assert_eq!(record.slot, Some(0));
        assert_eq!(record.ownership.module(), Some(NT_NAME));
        assert!(!record.ownership.is_outside_any_module());
    }

    #[test]
    fn a_callback_landing_in_no_loaded_module_is_the_finding_and_is_marked_as_one() {
        let sweep = sweep_notify(&hook_isf());
        let record = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::ThreadNotify)
            .expect("a thread callback");
        assert_eq!(record.routine, HIDDEN_ROUTINE);
        assert!(
            record.ownership.is_outside_any_module(),
            "{:?}",
            record.ownership
        );
        assert_eq!(record.ownership.module(), None);
    }

    #[test]
    fn the_reference_count_in_a_fast_ref_slot_is_masked_off_before_it_is_followed() {
        // The fixture's thread slot holds `block | 3`. Following it unmasked
        // reads the block three bytes late, and every member after that is
        // shifted — a routine address that is wrong and still looks like one.
        let sweep = sweep_notify(&hook_isf());
        let record = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::ThreadNotify)
            .expect("a thread callback");
        assert_eq!(record.record, Some(NOTIFY_BLOCK_HIDDEN));
        assert_eq!(NOTIFY_BLOCK_HIDDEN % 16, 0, "the fixture block is aligned");
    }

    #[test]
    fn an_array_with_no_registration_produces_no_rows_and_no_complaint() {
        // An empty notification array is ordinary. Turning it into notes would
        // bury the arrays that do hold something.
        let sweep = sweep_notify(&hook_isf());
        assert!(
            !sweep
                .records
                .iter()
                .any(|r| r.kind == CallbackKind::ImageLoadNotify),
            "{:?}",
            sweep.records
        );
        assert!(sweep.notes.is_empty(), "{:?}", sweep.notes);
        assert!(!sweep.capped);
    }

    #[test]
    fn the_process_and_thread_arrays_have_sixty_four_slots_from_vista_onwards() {
        // Reading eight on Windows 10 loses every registration past the eighth,
        // which is exactly where a late-loading driver's lands.
        let profile = hook_profile(populated_image(), &hook_isf());
        let symbols = NotifySymbols::from_profile(&profile).expect("a describable build");
        let slots: Vec<(CallbackKind, u64)> = symbols
            .arrays
            .iter()
            .map(|array| (array.kind, array.slots))
            .collect();
        assert_eq!(
            slots,
            vec![
                (CallbackKind::ProcessNotify, EXTENDED_NOTIFY_SLOTS),
                (CallbackKind::ThreadNotify, EXTENDED_NOTIFY_SLOTS),
                (CallbackKind::ImageLoadNotify, LEGACY_NOTIFY_SLOTS),
            ]
        );
    }

    #[test]
    fn an_array_whose_page_was_never_acquired_stops_the_walk_and_says_where() {
        // The alternative is sixty-three identical notes, or worse, silence.
        //
        // The address is computed from `IMAGE_SIZE` rather than written out. It
        // was written out once, and when the fixture image grew from 128 KiB to
        // 192 KiB the address moved *inside* it: every slot then read back as a
        // captured null and the test stopped exercising an unacquired page at
        // all.
        let isf = hook_isf().replace(
            r#""PspLoadImageNotifyRoutine": {"address": 1536}"#,
            &format!(
                r#""PspLoadImageNotifyRoutine": {{"address": {}}}"#,
                IMAGE_SIZE as u64 - 16
            ),
        );
        let sweep = sweep_notify(&isf);
        assert!(
            sweep
                .notes
                .iter()
                .any(|note| note.contains("PspLoadImageNotifyRoutine") && note.contains("onwards")),
            "{:?}",
            sweep.notes
        );
    }

    // ── The callback block layout ───────────────────────────────────────────

    #[test]
    fn the_routines_offset_comes_from_the_declared_member_when_the_build_has_one() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let block = CallbackBlock::from_profile(&profile).expect("a describable build");
        assert_eq!(block.function_offset, off::BLOCK_FUNCTION);
        assert_eq!(block.route.as_str(), "declared_member");
    }

    #[test]
    fn a_build_without_the_block_falls_back_to_the_size_of_the_rundown_reference() {
        // Derived from the symbol table rather than written down, and the route
        // travels into the artifact so an examiner sees which one was used.
        let isf = hook_isf().replace(
            r#""_EX_CALLBACK_ROUTINE_BLOCK": {"size": 24,"#,
            r#""_EX_CALLBACK_ROUTINE_BLOCK_X": {"size": 24,"#,
        );
        let profile = hook_profile(populated_image(), &isf);
        let block = CallbackBlock::from_profile(&profile).expect("the rundown route");
        assert_eq!(block.function_offset, off::BLOCK_FUNCTION);
        assert_eq!(block.route, BlockRoute::RundownRefSize);

        // And the derived offset finds the same routine the declared one does.
        let sweep = sweep_notify(&isf);
        assert!(sweep.records.iter().any(|r| r.routine == NT_ROUTINE));
    }

    #[test]
    fn a_build_with_none_of_the_three_is_refused_naming_all_three() {
        let isf = hook_isf()
            .replace(
                r#""_EX_CALLBACK_ROUTINE_BLOCK""#,
                r#""_EX_CALLBACK_ROUTINE_BLOCK_X""#,
            )
            .replace(r#""_EX_RUNDOWN_REF""#, r#""_EX_RUNDOWN_REF_X""#);
        let profile = hook_profile(populated_image(), &isf);
        let err = CallbackBlock::from_profile(&profile).expect_err("nothing to read through");
        let text = err.to_string();
        assert!(text.contains(TYPE_CALLBACK_BLOCK), "{text}");
        assert!(text.contains(TYPE_GENERIC_CALLBACK), "{text}");
        assert!(text.contains(TYPE_RUNDOWN_REF), "{text}");
    }

    /// A table that cannot answer is not a build that has none of the three.
    ///
    /// `has_type` is `type_id(..).is_ok()`, so the guard that used to stand
    /// here answered `false` for a name declared in two blocks at once — and
    /// the stage then told an examiner this kernel declares none of the three
    /// routes, which is a claim about the suspect's machine made from a symbol
    /// table this analysis could not read.
    #[test]
    fn a_rundown_reference_the_table_cannot_disambiguate_is_not_reported_as_absent() {
        let isf = hook_isf()
            .replace(
                r#""_EX_CALLBACK_ROUTINE_BLOCK": {"size": 24,"#,
                r#""_EX_CALLBACK_ROUTINE_BLOCK_X": {"size": 24,"#,
            )
            .replace(
                r#""pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},"#,
                r#""pointer": {"size": 8, "signed": false, "kind": "int", "endian": "little"},
    "_EX_RUNDOWN_REF": {"size": 8, "signed": false, "kind": "int", "endian": "little"},"#,
            );
        let profile = hook_profile(populated_image(), &isf);
        let err =
            CallbackBlock::from_profile(&profile).expect_err("the table cannot say which layout");
        assert_eq!(
            err.class(),
            "required_unresolved",
            "a shadowed name is a table this analysis could not read, not an absent type"
        );
        let text = err.to_string();
        assert!(text.contains(TYPE_RUNDOWN_REF), "{text}");
        assert!(text.contains(STAGE_KERNEL_HOOKS.key), "{text}");
        // The whole negative clause, not just "attributed to a driver": the
        // shorter substring is also present in a message claiming every callback
        // WAS attributed, so it would pass on the exact inversion this test
        // exists to catch.
        assert!(
            text.contains("no notification callback can be attributed to a driver"),
            "the refusal must say what it cost: {text}"
        );
    }

    // ── Registry callbacks ──────────────────────────────────────────────────

    #[test]
    fn a_registry_filter_is_listed_with_the_altitude_that_identifies_its_product() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let symbols = RegistryCallbackSymbols::from_profile(&profile).expect("the list shape");
        assert_eq!(symbols.shape.as_str(), "list");
        let sweep =
            list_registry_callbacks(&profile, &symbols, &modules, &KernelHookConfig::default());
        assert_eq!(sweep.records.len(), 1, "{:?}", sweep);
        let record = &sweep.records[0];
        assert_eq!(record.kind, CallbackKind::Registry);
        assert_eq!(record.routine, FLT_ROUTINE);
        assert_eq!(record.ownership.module(), Some(FLT_NAME));
        let expected = format!("altitude {REGISTRY_ALTITUDE}");
        assert_eq!(record.detail.as_deref(), Some(expected.as_str()));
        assert!(sweep.notes.is_empty(), "{:?}", sweep.notes);
    }

    #[test]
    fn a_build_that_keeps_a_vector_rather_than_a_list_is_read_through_the_vector() {
        let isf = isf_with_registry_vector();
        let profile = hook_profile(populated_image(), &isf);
        let modules = ModuleMap::from_profile(&profile);
        let symbols = RegistryCallbackSymbols::from_profile(&profile).expect("the vector shape");
        assert_eq!(symbols.shape.as_str(), "vector");
        let sweep =
            list_registry_callbacks(&profile, &symbols, &modules, &KernelHookConfig::default());
        assert_eq!(sweep.records.len(), 1, "{:?}", sweep);
        assert_eq!(sweep.records[0].routine, NT_ROUTINE);
        assert_eq!(sweep.records[0].slot, Some(0));
    }

    #[test]
    fn a_kernel_count_that_disagrees_with_the_walk_is_reported_rather_than_reconciled() {
        // A list shorter than the kernel's own count means it was spliced or
        // the walk stopped. Either is worth an examiner's attention, and
        // neither may be silently smoothed over.
        let mut image = populated_image();
        image.put_u32(REGISTRY_COUNT_AT, 5);
        let profile = hook_profile(image, &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let symbols = RegistryCallbackSymbols::from_profile(&profile).expect("the list shape");
        let sweep =
            list_registry_callbacks(&profile, &symbols, &modules, &KernelHookConfig::default());
        assert_eq!(sweep.records.len(), 1);
        assert!(
            sweep
                .notes
                .iter()
                .any(|note| note.contains("says 5") && note.contains("found 1")),
            "{:?}",
            sweep.notes
        );
    }

    #[test]
    fn a_build_with_neither_registry_shape_is_refused_naming_every_symbol_tried() {
        let isf = hook_isf()
            .replace(r#""CallbackListHead""#, r#""CallbackListHeadX""#)
            .replace(r#""CmpCallBackCount""#, r#""CmpCallBackCountX""#);
        let profile = hook_profile(populated_image(), &isf);
        let err = RegistryCallbackSymbols::from_profile(&profile).expect_err("nothing to read");
        let text = err.to_string();
        assert!(text.contains(SYMBOL_REGISTRY_VECTOR), "{text}");
        assert!(text.contains(SYMBOL_REGISTRY_COUNT), "{text}");
        assert!(text.contains(SYMBOL_REGISTRY_LIST), "{text}");
    }

    // ── Bugcheck callbacks ──────────────────────────────────────────────────

    #[test]
    fn both_bugcheck_lists_are_walked_and_each_records_where_its_routine_lives() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let symbols = BugcheckSymbols::from_profile(&profile).expect("both lists");
        assert_eq!(symbols.lists.len(), 2);
        let sweep =
            list_bugcheck_callbacks(&profile, &symbols, &modules, &KernelHookConfig::default());
        assert_eq!(sweep.records.len(), 2, "{:?}", sweep);

        let ordinary = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::BugCheck)
            .expect("a bugcheck callback");
        assert_eq!(ordinary.routine, BUGCHECK_ROUTINE);
        assert_eq!(ordinary.ownership.module(), Some(NT_NAME));

        let suspicious = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::BugCheckReason)
            .expect("a bugcheck-reason callback");
        assert_eq!(suspicious.routine, BUGCHECK_REASON_ROUTINE);
        assert!(suspicious.ownership.is_outside_any_module());
    }

    #[test]
    fn a_bugcheck_records_component_is_reported_as_the_claim_that_it_is() {
        // The component is a string the registering driver chose. It sits
        // beside the address rather than being used to attribute it.
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let symbols = BugcheckSymbols::from_profile(&profile).expect("both lists");
        let sweep =
            list_bugcheck_callbacks(&profile, &symbols, &modules, &KernelHookConfig::default());
        let ordinary = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::BugCheck)
            .expect("a bugcheck callback");
        assert_eq!(ordinary.detail.as_deref(), Some("component Ntfs"));
    }

    #[test]
    fn a_record_with_no_component_pointer_carries_no_claim_rather_than_an_empty_one() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let symbols = BugcheckSymbols::from_profile(&profile).expect("both lists");
        let sweep =
            list_bugcheck_callbacks(&profile, &symbols, &modules, &KernelHookConfig::default());
        let suspicious = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::BugCheckReason)
            .expect("a bugcheck-reason callback");
        assert_eq!(suspicious.detail, None);
    }

    #[test]
    fn a_build_with_neither_bugcheck_list_is_refused_naming_both() {
        let isf = hook_isf()
            .replace(r#""KeBugCheckCallbackListHead""#, r#""KeBugCheckXa""#)
            .replace(r#""KeBugCheckReasonCallbackListHead""#, r#""KeBugCheckXb""#);
        let profile = hook_profile(populated_image(), &isf);
        let err = BugcheckSymbols::from_profile(&profile).expect_err("nothing to walk");
        let text = err.to_string();
        assert!(text.contains(SYMBOL_BUGCHECK_LIST), "{text}");
        assert!(text.contains(SYMBOL_BUGCHECK_REASON_LIST), "{text}");
    }

    // ── Rendering ───────────────────────────────────────────────────────────

    #[test]
    fn a_callback_row_says_both_where_its_routine_is_and_what_that_means() {
        let sweep = sweep_notify(&hook_isf());
        let record = sweep
            .records
            .iter()
            .find(|r| r.kind == CallbackKind::ThreadNotify)
            .expect("a thread callback");
        let value = record.to_json();
        assert_eq!(value["kind"], "thread_notify");
        assert_eq!(value["routine"], HIDDEN_ROUTINE);
        assert_eq!(value["outside_any_module"], true);
        assert_eq!(value["ownership"]["kind"], "outside_any_module");
        assert!(value["module"].is_null());
    }

    #[test]
    fn an_undetermined_owner_never_renders_as_an_absent_one() {
        // The whole point of the three-way verdict.
        let profile = hook_profile(populated_image(), &hook_isf());
        let unusable = ModuleMap::unavailable("the module list was never walked");
        let symbols = NotifySymbols::from_profile(&profile).expect("a describable build");
        let sweep =
            list_notify_routines(&profile, &symbols, &unusable, &KernelHookConfig::default());
        assert!(!sweep.records.is_empty());
        for record in &sweep.records {
            assert!(
                matches!(record.ownership, Ownership::Undetermined(_)),
                "{:?}",
                record.ownership
            );
            assert_eq!(record.to_json()["outside_any_module"], false);
        }
    }

    /// A notification array whose later slots were never acquired must report
    /// the sweep as short, not merely note it.
    ///
    /// The group's completeness is read from [`CallbackSweep::capped`], and
    /// nothing else. An array read for one slot out of sixty-four, reported as
    /// having run to completion, entitles a report to write "nothing was
    /// notified when a process started on this machine" — which is a statement
    /// about fifty-six slots nobody looked at.
    #[test]
    fn an_array_whose_remaining_slots_were_never_acquired_reports_the_sweep_short() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        // The array is placed so that slot 0 is the last readable pointer in
        // the image and every slot after it falls off the end.
        let last = profile.physical.max_address();
        let symbols = NotifySymbols {
            arrays: vec![NotifyArray {
                symbol: SYMBOL_PROCESS_NOTIFY,
                kind: CallbackKind::ProcessNotify,
                address: last.saturating_sub(7),
                slots: EXTENDED_NOTIFY_SLOTS,
            }],
            block: CallbackBlock {
                function_offset: 8,
                route: BlockRoute::RundownRefSize,
            },
            pointer_size: 8,
            fast_ref_mask: 15,
        };
        let sweep =
            list_notify_routines(&profile, &symbols, &modules, &KernelHookConfig::default());
        assert!(
            sweep.capped,
            "a sweep that stopped part-way must not report as having run to the end: {sweep:?}"
        );
        assert!(
            sweep
                .notes
                .iter()
                .any(|note| note.contains(SYMBOL_PROCESS_NOTIFY)),
            "the reason must name the array: {:?}",
            sweep.notes
        );
    }

    /// The same rule for the pre-Windows-7 registry callback vector.
    #[test]
    fn a_registry_vector_whose_remaining_slots_were_never_acquired_reports_it_short() {
        let mut image = populated_image();
        // Eight registered filters, so the vector has slots past the first.
        image.put_u32(REGISTRY_COUNT_AT, 8);
        let profile = hook_profile(image, &isf_with_registry_vector());
        let modules = ModuleMap::from_profile(&profile);
        let last = profile.physical.max_address();
        let symbols = RegistryCallbackSymbols {
            shape: RegistryCallbackShape::Vector {
                vector: last.saturating_sub(7),
                count_at: REGISTRY_COUNT_AT,
                block: CallbackBlock {
                    function_offset: 8,
                    route: BlockRoute::RundownRefSize,
                },
                pointer_size: 8,
                fast_ref_mask: 15,
            },
        };
        let sweep =
            list_registry_callbacks(&profile, &symbols, &modules, &KernelHookConfig::default());
        assert!(
            sweep.capped,
            "a vector read for one slot out of many must not report as complete: {sweep:?}"
        );
    }
}
