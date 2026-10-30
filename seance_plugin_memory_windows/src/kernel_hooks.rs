//! Kernel-level persistence and hooking: callbacks, the service table, driver
//! dispatch pointers, and the drivers the module list no longer admits to.
//!
//! Everything here reduces to one question asked six ways: **is this function
//! pointer where it ought to be?** Windows is full of places where a driver can
//! legitimately register a routine — a process-creation callback, a registry
//! filter, an IRP dispatch entry — and each of them is also how a rootkit gets
//! itself called. The pointer alone says nothing. What makes it a finding is
//! where it *lands*:
//!
//! * inside a loaded module — ordinary, and the module's name is the answer to
//!   "who registered this";
//! * inside no loaded module at all — code executing from memory the loader has
//!   no record of, which is the classic signature of an unlinked driver or of
//!   shellcode in the kernel pool;
//! * somewhere the module list cannot answer for — which is **not** the second
//!   case, and the distinction is the whole point of [`Ownership`].
//!
//! # This module never calls anything malicious
//!
//! A hooked pointer has legitimate causes. Antivirus products, EDR agents,
//! virtualisation drivers and Windows itself all register callbacks and patch
//! dispatch tables. A driver whose `IRP_MJ_READ` points into a filter driver is
//! the filter working as designed. What is reported here is the *signal* and the
//! *evidence* — which pointer, where it lands, which module owns it and which
//! driver it belongs to — and the conclusion is the examiner's to draw.
//!
//! # Why an unattributable pointer is not an unattributed one
//!
//! Attribution needs a complete list of loaded modules. If the loaded-module
//! walk stopped at a hole, or an entry's base or size could not be read, then a
//! pointer that matched no module might simply have matched a module that is not
//! in the map. [`ModuleMap::is_authoritative`] is what decides whether "not in
//! any module" may be stated at all; when it is false every miss becomes
//! [`Ownership::Undetermined`] with the reason attached. Reporting those as
//! findings would manufacture a rootkit out of an incomplete acquisition.
//!
//! # The six capabilities
//!
//! | Group | Upstream | What it answers |
//! |---|---|---|
//! | notification callbacks | `callbacks.py` | who is told when a process, thread or image starts |
//! | registry callbacks | `callbacks.py` | who filters registry operations |
//! | bugcheck callbacks | `callbacks.py` | who runs when the machine crashes |
//! | service table | `ssdt.py` | whether each system call still enters ntoskrnl |
//! | drivers | `driverscan.py`, `driverirp.py` | every driver object in the pool, and its 28 dispatch pointers |
//! | module scan | `modscan.py` | loader entries in the pool, including unlinked ones |
//!
//! A group whose symbols this build does not carry is **not run**, and says so
//! in [`GroupStatus`]. An empty findings list from a group that never ran and an
//! empty findings list from a group that ran and found nothing are opposite
//! statements, and this module never lets them render the same.

#[path = "kernel_hooks_callbacks.rs"]
pub mod callbacks;
#[path = "kernel_hooks_drivers.rs"]
pub mod drivers;
#[path = "kernel_hooks_ssdt.rs"]
pub mod ssdt;

#[cfg(test)]
#[path = "kernel_hooks_test_support.rs"]
pub(crate) mod test_support;

pub use callbacks::{
    BlockRoute, BugcheckList, BugcheckSymbols, CallbackBlock, CallbackKind, CallbackRecord,
    CallbackSweep, NotifyArray, NotifySymbols, RegistryCallbackShape, RegistryCallbackSymbols,
};
pub use drivers::{
    DriverRecord, DriverSweep, DriverSymbols, IrpEntry, LdrScanSymbols, ModuleScanSweep,
    ScannedModule, IRP_MAJOR_FUNCTIONS,
};
pub use ssdt::{ServiceTableSweep, SsdtEntry, SsdtSymbols};

use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::BindError;
use seance_memory::object::{Obj, ObjError, StructReader};
use seance_memory::Incomplete;
use seance_symbols::SymbolError;

use crate::modules::{
    self, KernelModules, ModuleSymbols, ModuleWalkConfig, ModulesError, NameField,
};
use crate::poolscan::{ObjectTypeMap, PoolError, PoolScanConfig, PoolSymbols};
use crate::profile::WindowsProfile;

/// Group name for the process, thread and image-load notification callbacks.
pub const GROUP_NOTIFY: &str = "notification_callbacks";

/// Group name for the registry filter callbacks.
pub const GROUP_REGISTRY: &str = "registry_callbacks";

/// Group name for the bugcheck and bugcheck-reason callbacks.
pub const GROUP_BUGCHECK: &str = "bugcheck_callbacks";

/// Group name for the system service descriptor table.
pub const GROUP_SSDT: &str = "service_table";

/// Group name for the driver objects and their IRP dispatch pointers.
pub const GROUP_DRIVERS: &str = "drivers";

/// Group name for the pool sweep of loader entries.
pub const GROUP_MODULE_SCAN: &str = "module_scan";

/// Ceiling on individually recorded notes. The *count* stays exact.
pub const MAX_RECORDED_NOTES: usize = 512;

/// Ceiling on callbacks one group will report.
///
/// The notification arrays hold 64 slots each and a machine has a few dozen
/// registry filters. Reaching this means a list is looping rather than that the
/// machine is busy, and it is reported as a cap.
pub const MAX_CALLBACKS: usize = 4_096;

/// Ceiling on driver objects one sweep will report.
pub const MAX_DRIVERS: usize = 16_384;

/// Ceiling on loader entries one sweep will report.
pub const MAX_SCANNED_MODULES: usize = 16_384;

// ── Errors ──────────────────────────────────────────────────────────────────

/// Everything that stops this stage before it can produce a result worth
/// reading.
///
/// Note what is *not* here: a capability this build cannot support. That becomes
/// a [`GroupStatus`] saying the group did not run and why, because a stage that
/// ran four of its six groups still has four groups' worth of evidence.
#[derive(Debug, thiserror::Error)]
pub enum KernelHookError {
    /// Not one of the groups can run on this build, so no partial answer would
    /// be honest. The message names what is missing.
    #[error("kernel hooking cannot be examined on this build: {detail}")]
    Unsupported {
        /// What is missing, in the examiner's terms.
        detail: String,
    },

    /// The pool layout, without which no allocation can be decoded at all.
    #[error(transparent)]
    Pool(#[from] PoolError),

    /// The loaded-module list, which every attribution rests on.
    #[error(transparent)]
    Modules(#[from] ModulesError),

    /// A typed read failed for a reason that invalidates a whole group rather
    /// than one pointer.
    #[error(transparent)]
    Object(#[from] ObjError),

    /// The symbol table could not answer a question a group depends on.
    #[error(transparent)]
    Symbols(#[from] SymbolError),

    /// A layout a group cannot proceed without could not be bound to this
    /// build.
    ///
    /// `#[error(transparent)]` here is deliberate, and it is not the
    /// transparency that made the original defect undiagnosable: a
    /// [`BindError`] states the stage that stopped, every name that was tried
    /// and what stopping cost, where a bare [`SymbolError`] states only that
    /// some type was unknown.
    #[error(transparent)]
    Bind(#[from] BindError),
}

impl KernelHookError {
    /// Stable machine-readable class, for artifact metadata and log lines.
    pub fn class(&self) -> &'static str {
        match self {
            KernelHookError::Unsupported { .. } => "unsupported_build",
            KernelHookError::Pool(err) => err.class(),
            KernelHookError::Modules(err) => err.class(),
            KernelHookError::Object(err) => err.class(),
            KernelHookError::Symbols(_) => "symbols",
            KernelHookError::Bind(err) => err.class(),
        }
    }

    /// How a report should record the gap this failure leaves.
    pub fn incomplete_reason(&self) -> IncompleteReason {
        match self {
            KernelHookError::Pool(err) => err.incomplete_reason(),
            KernelHookError::Modules(err) => err.incomplete_reason(),
            KernelHookError::Object(err) => err.incomplete_reason(),
            _ => IncompleteReason::UnresolvedStructure,
        }
    }

    /// This failure as something an artifact can carry.
    pub fn to_incomplete(&self) -> Incomplete {
        Incomplete::new(self.incomplete_reason(), self.to_string())
    }

    /// Shorthand for the "this build cannot be examined" refusal.
    pub fn unsupported(detail: impl Into<String>) -> KernelHookError {
        KernelHookError::Unsupported {
            detail: detail.into(),
        }
    }
}

// ── Attribution ─────────────────────────────────────────────────────────────

/// One loaded module and the addresses it covers.
#[derive(Debug, Clone)]
pub struct ModuleRange {
    /// Where the image is mapped.
    pub base: u64,
    /// The **last** byte of the image. Inclusive, so an address exactly at the
    /// end of a driver is attributed to that driver and not to nothing.
    pub end: u64,
    /// The image's file name, when the loader entry carried a readable one.
    pub name: Option<String>,
    /// Where the loader entry describing it is.
    pub entry: u64,
}

impl ModuleRange {
    /// Whether an address falls inside this image, end inclusive.
    pub fn contains(&self, address: u64) -> bool {
        self.base <= address && address <= self.end
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "base": self.base,
            "end": self.end,
            "name": self.name,
            "entry": self.entry,
        })
    }
}

/// Where a function pointer landed.
///
/// Three outcomes and not two. [`Ownership::OutsideAnyModule`] is a claim about
/// the machine — code running from memory the loader has no record of — and it
/// may only be made when the module map is complete enough to support it.
/// Everything else that failed to match is [`Ownership::Undetermined`], which is
/// a claim about this image's completeness instead.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ownership {
    /// The pointer lands inside a loaded module.
    InModule {
        /// The module's file name, when it had a readable one.
        name: Option<String>,
        /// Where the module is mapped.
        base: u64,
        /// How far into the module the pointer lands.
        offset: u64,
    },
    /// The pointer lands inside no loaded module, and the module list was
    /// complete enough for that to be a statement about the machine.
    OutsideAnyModule,
    /// The pointer matched no module and the module list cannot support the
    /// claim that none owns it. The string says why.
    Undetermined(String),
}

impl Ownership {
    /// Stable identifier for artifact metadata.
    pub fn as_str(&self) -> &'static str {
        match self {
            Ownership::InModule { .. } => "in_module",
            Ownership::OutsideAnyModule => "outside_any_module",
            Ownership::Undetermined(_) => "undetermined",
        }
    }

    /// The owning module's name, when there is one.
    pub fn module(&self) -> Option<&str> {
        match self {
            Ownership::InModule { name, .. } => name.as_deref(),
            _ => None,
        }
    }

    /// Whether this pointer is a reportable signal: it lands outside every
    /// loaded module, and the map was good enough to say so.
    pub fn is_outside_any_module(&self) -> bool {
        matches!(self, Ownership::OutsideAnyModule)
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            Ownership::InModule { name, base, offset } => serde_json::json!({
                "kind": "in_module",
                "module": name,
                "module_base": base,
                "offset": offset,
            }),
            Ownership::OutsideAnyModule => serde_json::json!({"kind": "outside_any_module"}),
            Ownership::Undetermined(detail) => {
                serde_json::json!({"kind": "undetermined", "detail": detail})
            }
        }
    }
}

/// The loaded modules, as a thing addresses can be looked up in.
///
/// Built once per image and shared by every group, so that two groups can never
/// disagree about which driver owns an address.
#[derive(Debug, Clone, Default)]
pub struct ModuleMap {
    ranges: Vec<ModuleRange>,
    complete: bool,
    unusable: usize,
    head: Option<u64>,
    note: Option<String>,
}

impl ModuleMap {
    /// Walk the kernel's loaded-module list and index what it holds.
    ///
    /// Never fails: a list that cannot be walked yields a map that is not
    /// authoritative and says why, because losing attribution must not cost the
    /// examiner the pointers themselves.
    pub fn from_profile(profile: &WindowsProfile) -> Self {
        let symbols = match ModuleSymbols::from_profile(profile) {
            Ok(symbols) => symbols,
            Err(err) => {
                return Self::unavailable(format!(
                    "the kernel's loaded-module list could not be described on this build, so no \
                     pointer can be attributed to a driver: {err}"
                ))
            }
        };
        let listing =
            match modules::list_kernel_modules(profile, &symbols, &ModuleWalkConfig::default()) {
                Ok(listing) => listing,
                Err(err) => {
                    return Self::unavailable(format!(
                        "the kernel's loaded-module list could not be walked, so no pointer can be \
                         attributed to a driver: {err}"
                    ))
                }
            };
        Self::from_listing(&listing)
    }

    /// Index a listing somebody else already walked.
    ///
    /// For a caller that has run the kernel-modules stage and does not want the
    /// list walked twice — which would also be two chances for the two results
    /// to disagree.
    pub fn from_listing(listing: &KernelModules) -> Self {
        let mut ranges = Vec::with_capacity(listing.modules.len());
        let mut unusable = 0usize;
        for module in &listing.modules {
            match (module.base, module.end()) {
                (Some(base), Some(end)) => ranges.push(ModuleRange {
                    base,
                    end,
                    name: module
                        .base_name
                        .name()
                        .or_else(|| module.full_path.name())
                        .map(str::to_string),
                    entry: module.entry,
                }),
                // A loader entry without a usable base and size covers no
                // addresses, so it cannot own a pointer — and its absence is
                // exactly what stops the map being authoritative.
                _ => unusable = unusable.saturating_add(1),
            }
        }
        ranges.sort_by_key(|range| range.base);
        let note = if listing.is_complete() && unusable == 0 {
            None
        } else if !listing.is_complete() {
            Some(format!(
                "the kernel's loaded-module list walk ended early ({}), so a pointer that matches \
                 no module here may still belong to a module the walk never reached",
                listing.stop.as_str()
            ))
        } else {
            Some(format!(
                "{unusable} loader entr(y/ies) had no readable base and size, so a pointer that \
                 matches no module here may still belong to one of them"
            ))
        };
        Self {
            ranges,
            complete: listing.is_complete(),
            unusable,
            head: Some(listing.head),
            note,
        }
    }

    /// A map that could not be built, carrying the reason.
    pub fn unavailable(reason: impl Into<String>) -> Self {
        Self {
            ranges: Vec::new(),
            complete: false,
            unusable: 0,
            head: None,
            note: Some(reason.into()),
        }
    }

    /// A map built from ranges a caller already has, for tests and for a caller
    /// with its own module knowledge.
    pub fn from_ranges(ranges: Vec<ModuleRange>) -> Self {
        let mut ranges = ranges;
        ranges.sort_by_key(|range| range.base);
        Self {
            ranges,
            complete: true,
            unusable: 0,
            head: None,
            note: None,
        }
    }

    /// The modules, ascending by base address.
    pub fn ranges(&self) -> &[ModuleRange] {
        &self.ranges
    }

    /// How many modules the map holds.
    pub fn len(&self) -> usize {
        self.ranges.len()
    }

    /// Whether the map holds no module at all.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// Why the map is not authoritative, when it is not.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// Whether "this address is in no loaded module" may be stated at all.
    ///
    /// False when the list walk ended early, when any entry lacked a usable
    /// base and size, or when the map holds nothing. Every miss is then
    /// [`Ownership::Undetermined`], because a rootkit finding manufactured out
    /// of an incomplete acquisition is worse than no finding.
    pub fn is_authoritative(&self) -> bool {
        self.complete && self.unusable == 0 && !self.ranges.is_empty()
    }

    /// The module an address falls in, if any.
    ///
    /// Linear because a machine has a few hundred drivers and the ranges of a
    /// well-formed list do not overlap; a binary search would have to fall back
    /// to this anyway for a list that does.
    pub fn owner_of(&self, address: u64) -> Option<&ModuleRange> {
        self.ranges.iter().find(|range| range.contains(address))
    }

    /// Where a pointer landed, refusing to overstate what the map can support.
    pub fn attribute(&self, address: u64) -> Ownership {
        if let Some(range) = self.owner_of(address) {
            return Ownership::InModule {
                name: range.name.clone(),
                base: range.base,
                offset: address.saturating_sub(range.base),
            };
        }
        if self.is_authoritative() {
            return Ownership::OutsideAnyModule;
        }
        Ownership::Undetermined(self.note.clone().unwrap_or_else(|| {
            "the loaded-module list held no usable entry, so nothing can be attributed".to_string()
        }))
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "head": self.head,
            "module_count": self.ranges.len(),
            "unusable_entries": self.unusable,
            "list_complete": self.complete,
            "authoritative": self.is_authoritative(),
            "note": self.note,
            "modules": self.ranges.iter().map(ModuleRange::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// Everything one image's kernel-hook groups are read through.
///
/// Each group is optional and carries the reason it is absent. The struct as a
/// whole exists only if at least one group can run: a stage with nothing to do
/// would emit an empty finding list, and an empty finding list reads as a clean
/// machine.
#[derive(Debug, Clone)]
pub struct KernelHookSymbols {
    /// The pool layout, when it could be established. Needed by the driver and
    /// module sweeps.
    pub pool: Option<PoolSymbols>,
    /// Why [`KernelHookSymbols::pool`] is absent, when it is.
    pub pool_unavailable: Option<String>,
    /// The object manager's type index, which is what rejects an allocation
    /// whose tag matched by accident.
    pub type_map: Option<Arc<ObjectTypeMap>>,
    /// Why [`KernelHookSymbols::type_map`] is absent, when it is. Every driver
    /// admitted without the check says so on its own row.
    pub type_map_unavailable: Option<String>,
    /// The process, thread and image-load notification arrays.
    pub notify: Option<NotifySymbols>,
    /// Why the notification arrays are not read, when they are not.
    pub notify_unavailable: Option<String>,
    /// The registry filter callbacks.
    pub registry: Option<RegistryCallbackSymbols>,
    /// Why the registry callbacks are not read, when they are not.
    pub registry_unavailable: Option<String>,
    /// The bugcheck callback lists.
    pub bugcheck: Option<BugcheckSymbols>,
    /// Why the bugcheck lists are not read, when they are not.
    pub bugcheck_unavailable: Option<String>,
    /// The system service descriptor table.
    pub ssdt: Option<SsdtSymbols>,
    /// Why the service table is not read, when it is not.
    pub ssdt_unavailable: Option<String>,
    /// Driver objects and their dispatch pointers.
    pub driver: Option<DriverSymbols>,
    /// Why drivers are not swept for, when they are not.
    pub driver_unavailable: Option<String>,
    /// Loader entries in the pool.
    pub ldr: Option<LdrScanSymbols>,
    /// Why loader entries are not swept for, when they are not.
    pub ldr_unavailable: Option<String>,
}

impl KernelHookSymbols {
    /// Resolve every layout fact this stage's groups need.
    ///
    /// # What an examiner learns
    ///
    /// Which of the six capabilities this image can be asked about. A group
    /// whose symbols the build does not carry is named, with the symbol or type
    /// that is missing, so that a report can say "the service table was not
    /// read because this build's symbols do not name `KiServiceTable`" rather
    /// than showing an empty table.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] when not one group can run, listing
    /// every group's reason. A stage that returned an empty result there would
    /// be asserting that the kernel has no callbacks, no service table and no
    /// drivers, which no Windows kernel has ever been true of.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let (pool, pool_unavailable) = match PoolSymbols::from_profile(profile) {
            Ok(pool) => (Some(pool), None),
            Err(err) => (
                None,
                Some(format!(
                    "the pool layout could not be established, so nothing can be recovered from \
                     freed or unlinked allocations: {err}"
                )),
            ),
        };

        let (type_map, type_map_unavailable) = match ObjectTypeMap::from_profile(profile) {
            Ok(map) if map.is_empty() => (
                None,
                Some(
                    "the object manager's type table was located but held no readable entry, so a \
                     driver object cannot be checked against the type the kernel believes it has"
                        .to_string(),
                ),
            ),
            Ok(map) => (Some(Arc::new(map)), None),
            Err(err) => (
                None,
                Some(format!(
                    "the object manager's type table could not be read, so a driver object cannot \
                     be checked against the type the kernel believes it has: {err}"
                )),
            ),
        };

        let (notify, notify_unavailable) = split(NotifySymbols::from_profile(profile));
        let (registry, registry_unavailable) =
            split(RegistryCallbackSymbols::from_profile(profile));
        let (bugcheck, bugcheck_unavailable) = split(BugcheckSymbols::from_profile(profile));
        let (ssdt, ssdt_unavailable) = split(SsdtSymbols::from_profile(profile));
        let (driver, driver_unavailable) = match pool.as_ref() {
            Some(_) => split(DriverSymbols::from_profile(profile)),
            None => (None, pool_unavailable.clone()),
        };
        let (ldr, ldr_unavailable) = match pool.as_ref() {
            Some(_) => split(LdrScanSymbols::from_profile(profile)),
            None => (None, pool_unavailable.clone()),
        };

        let symbols = Self {
            pool,
            pool_unavailable,
            type_map,
            type_map_unavailable,
            notify,
            notify_unavailable,
            registry,
            registry_unavailable,
            bugcheck,
            bugcheck_unavailable,
            ssdt,
            ssdt_unavailable,
            driver,
            driver_unavailable,
            ldr,
            ldr_unavailable,
        };
        if !symbols.any_group_available() {
            return Err(KernelHookError::unsupported(format!(
                "not one of this stage's groups can run on this build. Notification callbacks: \
                 {}. Registry callbacks: {}. Bugcheck callbacks: {}. Service table: {}. Drivers: \
                 {}. Loader entries: {}",
                reason(&symbols.notify_unavailable),
                reason(&symbols.registry_unavailable),
                reason(&symbols.bugcheck_unavailable),
                reason(&symbols.ssdt_unavailable),
                reason(&symbols.driver_unavailable),
                reason(&symbols.ldr_unavailable),
            )));
        }
        Ok(symbols)
    }

    /// Whether any group at all can run.
    pub fn any_group_available(&self) -> bool {
        self.notify.is_some()
            || self.registry.is_some()
            || self.bugcheck.is_some()
            || self.ssdt.is_some()
            || self.driver.is_some()
            || self.ldr.is_some()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "pool_available": self.pool.is_some(),
            "pool_unavailable": self.pool_unavailable,
            "type_map_available": self.type_map.is_some(),
            "type_map_unavailable": self.type_map_unavailable,
            "notify_available": self.notify.is_some(),
            "notify_unavailable": self.notify_unavailable,
            "registry_available": self.registry.is_some(),
            "registry_unavailable": self.registry_unavailable,
            "bugcheck_available": self.bugcheck.is_some(),
            "bugcheck_unavailable": self.bugcheck_unavailable,
            "ssdt_available": self.ssdt.is_some(),
            "ssdt_unavailable": self.ssdt_unavailable,
            "driver_available": self.driver.is_some(),
            "driver_unavailable": self.driver_unavailable,
            "ldr_available": self.ldr.is_some(),
            "ldr_unavailable": self.ldr_unavailable,
        })
    }
}

/// Turn a group's resolution into "the symbols" or "the reason there are none".
fn split<T>(result: Result<T, KernelHookError>) -> (Option<T>, Option<String>) {
    match result {
        Ok(value) => (Some(value), None),
        Err(err) => (None, Some(err.to_string())),
    }
}

/// A group's stated reason, or a stand-in when a group succeeded.
fn reason(detail: &Option<String>) -> String {
    detail.clone().unwrap_or_else(|| "available".to_string())
}

// ── Configuration ───────────────────────────────────────────────────────────

/// Caps and shared state for one examination.
#[derive(Debug, Clone)]
pub struct KernelHookConfig {
    /// Geometry and caps for the pool sweeps.
    pub pool: PoolScanConfig,
    /// The loaded modules, when a caller has already indexed them. `None` walks
    /// the list here.
    pub modules: Option<Arc<ModuleMap>>,
    /// Ceiling on callbacks one group will report.
    pub max_callbacks: usize,
    /// Ceiling on driver objects reported.
    pub max_drivers: usize,
    /// Ceiling on loader entries reported.
    pub max_scanned_modules: usize,
    /// Ceiling on individually recorded notes.
    pub max_recorded_notes: usize,
}

impl Default for KernelHookConfig {
    fn default() -> Self {
        Self {
            pool: PoolScanConfig::default(),
            modules: None,
            max_callbacks: MAX_CALLBACKS,
            max_drivers: MAX_DRIVERS,
            max_scanned_modules: MAX_SCANNED_MODULES,
            max_recorded_notes: MAX_RECORDED_NOTES,
        }
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// Whether one group ran, and if not, why not.
#[derive(Debug, Clone)]
pub struct GroupStatus {
    /// The group's stable name.
    pub group: &'static str,
    /// Whether it ran at all.
    pub ran: bool,
    /// Why it did not run, or what went wrong part-way.
    pub detail: Option<String>,
    /// How many rows it produced.
    pub found: usize,
    /// Whether a cap fired inside it.
    pub capped: bool,
}

impl GroupStatus {
    /// A group that did not run, and the reason.
    pub fn did_not_run(group: &'static str, detail: Option<String>) -> Self {
        Self {
            group,
            ran: false,
            detail: Some(detail.unwrap_or_else(|| {
                "this build's symbols do not carry what the group needs, and no reason was \
                 recorded"
                    .to_string()
            })),
            found: 0,
            capped: false,
        }
    }

    /// A group that ran.
    pub fn performed(group: &'static str, found: usize, capped: bool) -> Self {
        Self {
            group,
            ran: true,
            detail: None,
            found,
            capped,
        }
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "group": self.group,
            "ran": self.ran,
            "detail": self.detail,
            "found": self.found,
            "capped": self.capped,
        })
    }
}

/// What one examination found, and everything it could not do.
#[derive(Debug, Clone)]
pub struct KernelHookOutcome {
    /// The loaded modules every attribution was made against.
    pub modules: Arc<ModuleMap>,
    /// Notification, registry and bugcheck callbacks, in the order the groups
    /// ran.
    pub callbacks: Vec<CallbackRecord>,
    /// The system service descriptor table.
    pub services: Vec<SsdtEntry>,
    /// The service limit the kernel declared, when it was read.
    pub service_limit: Option<u64>,
    /// Driver objects recovered from the pool, with their dispatch pointers.
    pub drivers: Vec<DriverRecord>,
    /// Loader entries recovered from the pool.
    pub scanned_modules: Vec<ScannedModule>,
    /// Which groups ran and which did not.
    pub groups: Vec<GroupStatus>,
    /// Notes, capped by [`KernelHookConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes there were in total. Exact even when the list was capped.
    pub notes_total: usize,
    /// Everything a report must declare about this result.
    pub incomplete: Vec<Incomplete>,
}

impl KernelHookOutcome {
    /// Whether every group ran, nothing was capped and every pointer could be
    /// attributed.
    ///
    /// The question a report must ask before writing "this kernel had no hooked
    /// pointers": a group that never ran says nothing about what it did not
    /// look at.
    pub fn is_complete(&self) -> bool {
        self.groups.iter().all(|group| group.ran && !group.capped)
            && self.modules.is_authoritative()
            && self.incomplete.is_empty()
    }

    /// Callbacks whose target lands in no loaded module.
    ///
    /// The signal, not the conclusion: a driver may have been unloaded after
    /// registering, and legitimate products do register from allocations the
    /// loader list does not describe.
    pub fn unattributed_callbacks(&self) -> impl Iterator<Item = &CallbackRecord> {
        self.callbacks
            .iter()
            .filter(|record| record.ownership.is_outside_any_module())
    }

    /// Service table entries that do not land inside the kernel image.
    pub fn services_outside_the_kernel(&self) -> impl Iterator<Item = &SsdtEntry> {
        self.services
            .iter()
            .filter(|entry| entry.in_kernel == Some(false))
    }

    /// Dispatch pointers that do not land inside the driver that owns them.
    pub fn irps_outside_their_driver(&self) -> impl Iterator<Item = (&DriverRecord, &IrpEntry)> {
        self.drivers.iter().flat_map(|driver| {
            driver
                .irps
                .iter()
                .filter(|irp| irp.in_owning_driver == Some(false))
                .map(move |irp| (driver, irp))
        })
    }

    /// Loader entries found in the pool that the kernel's own list does not
    /// hold — the classic unlinked driver.
    pub fn unlinked_modules(&self) -> impl Iterator<Item = &ScannedModule> {
        self.scanned_modules
            .iter()
            .filter(|module| module.in_loaded_list == Some(false))
    }

    /// Every pointer this stage could not attribute to a loaded module, as
    /// `(what, address)` pairs.
    ///
    /// Handed to the tamper stage, which asks of each one whether it falls
    /// inside the range of a driver the kernel has **unloaded**. That is the
    /// possibility [`Self::unattributed_callbacks`] names in as many words —
    /// "a driver may have been unloaded after registering" — and cannot
    /// answer from the loaded-module map alone.
    ///
    /// Only pointers that landed in **no** loaded module are here. A pointer
    /// the map could not answer for is [`Ownership::Undetermined`] and is not
    /// a candidate: cross-referencing it would turn an incomplete acquisition
    /// into a lead.
    ///
    /// Each pair carries a sentence rather than a code, because the sentence
    /// is what a record shows an examiner.
    pub fn unattributed_candidates(&self) -> Vec<(String, u64)> {
        let mut out: Vec<(String, u64)> = Vec::new();
        for callback in self.unattributed_callbacks() {
            out.push((
                format!(
                    "a {} callback registered from {}",
                    callback.kind.as_str(),
                    callback.source
                ),
                callback.routine,
            ));
        }
        // `services_outside_the_kernel` and `irps_outside_their_driver` are
        // the wrong tests here, and the difference is not cosmetic: a service
        // routine outside ntoskrnl but inside another loaded module, or an IRP
        // handler inside a module other than the one publishing it, HAS a
        // current owner. Asking the unloaded table about it would offer an
        // examiner a driver that unloaded as an explanation for a pointer
        // something loaded already accounts for. Only a pointer no loaded
        // module owns is a candidate.
        for entry in self
            .services
            .iter()
            .filter(|entry| entry.ownership.is_outside_any_module())
        {
            out.push((
                format!("system service {}'s routine", entry.index),
                entry.target,
            ));
        }
        for (driver, irp) in self.drivers.iter().flat_map(|driver| {
            driver
                .irps
                .iter()
                .filter(|irp| irp.ownership.is_outside_any_module())
                .map(move |irp| (driver, irp))
        }) {
            out.push((
                format!(
                    "{}'s {} handler",
                    driver.name.name().unwrap_or("an unnamed driver"),
                    irp.name
                ),
                irp.handler,
            ));
        }
        out
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "modules": self.modules.to_json(),
            "callbacks": self.callbacks.iter().map(CallbackRecord::to_json).collect::<Vec<_>>(),
            "callback_count": self.callbacks.len(),
            "callbacks_outside_any_module": self.unattributed_callbacks().count(),
            "services": self.services.iter().map(SsdtEntry::to_json).collect::<Vec<_>>(),
            "service_count": self.services.len(),
            "service_limit": self.service_limit,
            "services_outside_the_kernel": self.services_outside_the_kernel().count(),
            "drivers": self.drivers.iter().map(DriverRecord::to_json).collect::<Vec<_>>(),
            "driver_count": self.drivers.len(),
            "irps_outside_their_driver": self.irps_outside_their_driver().count(),
            "scanned_modules": self
                .scanned_modules
                .iter()
                .map(ScannedModule::to_json)
                .collect::<Vec<_>>(),
            "scanned_module_count": self.scanned_modules.len(),
            "unlinked_module_count": self.unlinked_modules().count(),
            "groups": self.groups.iter().map(GroupStatus::to_json).collect::<Vec<_>>(),
            "notes": self.notes,
            "notes_total": self.notes_total,
            "complete": self.is_complete(),
            "incomplete": self.incomplete.iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

// ── The examination ─────────────────────────────────────────────────────────

/// Examine every kernel-hooking capability this build supports.
///
/// This is the stage entry point: the orchestrator calls it once per image with
/// [`KernelHookSymbols::from_profile`] and a [`KernelHookConfig`].
///
/// # What an examiner learns
///
/// Every notification, registry and bugcheck callback the kernel would call,
/// with the driver that owns each target; every system service table entry and
/// whether it still enters ntoskrnl; every driver object in the pool with its 28
/// IRP dispatch pointers and whether each stays inside the driver that owns it;
/// and every loader entry in the pool, including those the kernel's own list no
/// longer holds.
///
/// # What a wrong answer looks like
///
/// A pointer reported as landing outside every loaded module when in truth the
/// module list was short — a manufactured rootkit finding. That is what
/// [`ModuleMap::is_authoritative`] exists to prevent, and why a miss against an
/// incomplete map is [`Ownership::Undetermined`] rather than a finding.
///
/// # Errors
///
/// Never for a group that could not run: that is recorded in [`GroupStatus`] and
/// the other groups still run. The only failure returned is one that leaves
/// nothing to report, and [`KernelHookSymbols::from_profile`] has already
/// refused in that case.
pub fn examine_kernel_hooks(
    profile: &WindowsProfile,
    symbols: &KernelHookSymbols,
    config: &KernelHookConfig,
) -> Result<KernelHookOutcome, KernelHookError> {
    let modules = match config.modules.clone() {
        Some(map) => map,
        None => Arc::new(ModuleMap::from_profile(profile)),
    };

    // The object-type map the symbols resolved is used unless the caller
    // supplied one of its own. Without it every driver object would be admitted
    // on its tag alone, which is the check that rejects a four-byte coincidence.
    let effective;
    let config = if config.pool.type_map.is_none() && symbols.type_map.is_some() {
        let mut owned = config.clone();
        owned.pool.type_map = symbols.type_map.clone();
        effective = owned;
        &effective
    } else {
        config
    };

    let mut out = KernelHookOutcome {
        modules: Arc::clone(&modules),
        callbacks: Vec::new(),
        services: Vec::new(),
        service_limit: None,
        drivers: Vec::new(),
        scanned_modules: Vec::new(),
        groups: Vec::new(),
        notes: Vec::new(),
        notes_total: 0,
        incomplete: Vec::new(),
    };

    // Callbacks. Each group is independent: a registry callback list that will
    // not walk must not cost the examiner the process-creation callbacks.
    match symbols.notify.as_ref() {
        Some(notify) => {
            let sweep = callbacks::list_notify_routines(profile, notify, modules.as_ref(), config);
            absorb_callbacks(&mut out, config, GROUP_NOTIFY, sweep);
        }
        None => out.groups.push(GroupStatus::did_not_run(
            GROUP_NOTIFY,
            symbols.notify_unavailable.clone(),
        )),
    }

    match symbols.registry.as_ref() {
        Some(registry) => {
            let sweep =
                callbacks::list_registry_callbacks(profile, registry, modules.as_ref(), config);
            absorb_callbacks(&mut out, config, GROUP_REGISTRY, sweep);
        }
        None => out.groups.push(GroupStatus::did_not_run(
            GROUP_REGISTRY,
            symbols.registry_unavailable.clone(),
        )),
    }

    match symbols.bugcheck.as_ref() {
        Some(bugcheck) => {
            let sweep =
                callbacks::list_bugcheck_callbacks(profile, bugcheck, modules.as_ref(), config);
            absorb_callbacks(&mut out, config, GROUP_BUGCHECK, sweep);
        }
        None => out.groups.push(GroupStatus::did_not_run(
            GROUP_BUGCHECK,
            symbols.bugcheck_unavailable.clone(),
        )),
    }

    match symbols.ssdt.as_ref() {
        Some(table) => {
            let sweep = ssdt::read_service_table(profile, table, modules.as_ref(), config);
            out.service_limit = sweep.limit;
            out.groups.push(GroupStatus::performed(
                GROUP_SSDT,
                sweep.entries.len(),
                sweep.capped,
            ));
            out.services = sweep.entries;
            absorb_notes(&mut out, config, sweep.notes, sweep.notes_total);
        }
        None => out.groups.push(GroupStatus::did_not_run(
            GROUP_SSDT,
            symbols.ssdt_unavailable.clone(),
        )),
    }

    match (symbols.driver.as_ref(), symbols.pool.as_ref()) {
        (Some(driver), Some(pool)) => {
            match drivers::scan_drivers(profile, driver, pool, modules.as_ref(), config) {
                Ok(sweep) => {
                    out.groups.push(GroupStatus::performed(
                        GROUP_DRIVERS,
                        sweep.drivers.len(),
                        sweep.capped,
                    ));
                    out.drivers = sweep.drivers;
                    absorb_notes(&mut out, config, sweep.notes, sweep.notes_total);
                }
                Err(err) => out.groups.push(GroupStatus::did_not_run(
                    GROUP_DRIVERS,
                    Some(err.to_string()),
                )),
            }
        }
        _ => out.groups.push(GroupStatus::did_not_run(
            GROUP_DRIVERS,
            symbols
                .driver_unavailable
                .clone()
                .or_else(|| symbols.pool_unavailable.clone()),
        )),
    }

    match (symbols.ldr.as_ref(), symbols.pool.as_ref()) {
        (Some(ldr), Some(pool)) => {
            match drivers::scan_loader_entries(profile, ldr, pool, modules.as_ref(), config) {
                Ok(sweep) => {
                    out.groups.push(GroupStatus::performed(
                        GROUP_MODULE_SCAN,
                        sweep.modules.len(),
                        sweep.capped,
                    ));
                    out.scanned_modules = sweep.modules;
                    absorb_notes(&mut out, config, sweep.notes, sweep.notes_total);
                }
                Err(err) => out.groups.push(GroupStatus::did_not_run(
                    GROUP_MODULE_SCAN,
                    Some(err.to_string()),
                )),
            }
        }
        _ => out.groups.push(GroupStatus::did_not_run(
            GROUP_MODULE_SCAN,
            symbols
                .ldr_unavailable
                .clone()
                .or_else(|| symbols.pool_unavailable.clone()),
        )),
    }

    let incomplete = declare_incomplete(&out);
    out.incomplete = incomplete;
    Ok(out)
}

/// Fold one callback group's result into the outcome.
fn absorb_callbacks(
    out: &mut KernelHookOutcome,
    config: &KernelHookConfig,
    group: &'static str,
    sweep: CallbackSweep,
) {
    out.groups.push(GroupStatus::performed(
        group,
        sweep.records.len(),
        sweep.capped,
    ));
    out.callbacks.extend(sweep.records);
    absorb_notes(out, config, sweep.notes, sweep.notes_total);
}

/// Fold one group's notes into the outcome without losing the count of the ones
/// the group itself had already stopped recording.
fn absorb_notes(
    out: &mut KernelHookOutcome,
    config: &KernelHookConfig,
    notes: Vec<String>,
    total: usize,
) {
    let dropped = total.saturating_sub(notes.len());
    for note in notes {
        push_note(
            &mut out.notes,
            &mut out.notes_total,
            config.max_recorded_notes,
            note,
        );
    }
    out.notes_total = out.notes_total.saturating_add(dropped);
}

/// Everything about this result a report is obliged to state.
fn declare_incomplete(out: &KernelHookOutcome) -> Vec<Incomplete> {
    let mut incomplete = Vec::new();
    for group in &out.groups {
        if !group.ran {
            incomplete.push(Incomplete::new(
                IncompleteReason::UnresolvedStructure,
                format!(
                    "the '{}' group did not run, so this result says nothing about whether the \
                     kernel had any: {}",
                    group.group,
                    group.detail.as_deref().unwrap_or("no reason was recorded")
                ),
            ));
        }
        if group.capped {
            incomplete.push(Incomplete::new(
                IncompleteReason::CapReached,
                format!(
                    "the '{}' group stopped at a cap; the kernel did not run out of entries",
                    group.group
                ),
            ));
        }
    }
    if !out.modules.is_authoritative() {
        incomplete.push(Incomplete::new(
            IncompleteReason::UnresolvedStructure,
            format!(
                "no pointer here may be said to lie outside every loaded module, because {}",
                out.modules
                    .note()
                    .unwrap_or("the loaded-module list held no usable entry")
            ),
        ));
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

// ── Shared helpers ──────────────────────────────────────────────────────────

/// Record a note, keeping the list bounded without losing the count.
pub(crate) fn push_note(notes: &mut Vec<String>, total: &mut usize, cap: usize, note: String) {
    *total = total.saturating_add(1);
    if notes.len() < cap {
        notes.push(note);
    }
}

/// The element count a symbol table declares for an array member.
///
/// Reads no memory: the count is a property of the type, and asking for it
/// through an object at address zero is how the reader exposes it. A count above
/// `cap` is refused rather than silently shortened, because such an array is
/// *wrong* rather than merely large.
pub(crate) fn declared_array_len(
    reader: &StructReader,
    type_name: &str,
    path: &str,
    cap: u64,
) -> Result<u64, ObjError> {
    reader.object(0, type_name)?.array_len_capped(path, cap)
}

/// Read a 32-bit little-endian value the kernel stores as a bare `ULONG`.
///
/// Used for the handful of kernel globals that are counts rather than
/// structures — `KiServiceLimit`, `CmpCallBackCount` — where an ISF records the
/// symbol's address but not its type. The width and byte order are properties of
/// the ABI rather than of a structure, which is why they are not read from the
/// symbol table here.
pub(crate) fn read_u32(reader: &StructReader, address: u64) -> Result<u32, ObjError> {
    let bytes = reader.read_bytes(address, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The kernel-virtual address a symbol names, or an error saying which symbol.
pub(crate) fn symbol_address(
    profile: &WindowsProfile,
    symbol: &str,
) -> Result<u64, KernelHookError> {
    let rva = profile
        .symbols
        .symbol_address(symbol)
        .map_err(|_| KernelHookError::unsupported(format!("the symbol table has no '{symbol}'")))?;
    profile.kernel_base.value.checked_add(rva).ok_or_else(|| {
        KernelHookError::unsupported(format!(
            "the address of '{symbol}' does not fit in the 64-bit address space"
        ))
    })
}

/// A `_UNICODE_STRING` member read into a [`NameField`].
pub(crate) fn name_field(object: &Obj, path: &str) -> NameField {
    match crate::poolscan::unicode_string(object, path) {
        Ok(Some(name)) => NameField::Name(name),
        Ok(None) => NameField::Empty,
        Err(err) => NameField::Unavailable(err.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_hooks::test_support::{hook_isf, hook_profile, populated_image};

    fn range(base: u64, end: u64, name: &str) -> ModuleRange {
        ModuleRange {
            base,
            end,
            name: Some(name.to_string()),
            entry: 0,
        }
    }

    // ── Attribution ─────────────────────────────────────────────────────────

    #[test]
    fn an_address_inside_a_module_is_attributed_to_it_with_its_offset() {
        let map = ModuleMap::from_ranges(vec![range(0x1000, 0x1FFF, "ntoskrnl.exe")]);
        assert_eq!(
            map.attribute(0x1234),
            Ownership::InModule {
                name: Some("ntoskrnl.exe".to_string()),
                base: 0x1000,
                offset: 0x234,
            }
        );
    }

    #[test]
    fn a_modules_last_byte_is_inside_it_and_the_next_byte_is_not() {
        // An off-by-one here attributes a pointer to the neighbouring driver, or
        // to nothing at all, which is the difference between an ordinary row and
        // a reported finding.
        let map = ModuleMap::from_ranges(vec![range(0x1000, 0x1FFF, "ntoskrnl.exe")]);
        assert!(map.owner_of(0x1FFF).is_some());
        assert!(map.owner_of(0x2000).is_none());
        assert_eq!(map.attribute(0x2000), Ownership::OutsideAnyModule);
    }

    #[test]
    fn an_incomplete_module_list_cannot_say_a_pointer_lies_outside_every_module() {
        // The rule that stops an incomplete acquisition being reported as a
        // rootkit.
        let map = ModuleMap::unavailable("the list walk stopped at a hole");
        assert!(!map.is_authoritative());
        match map.attribute(0x2000) {
            Ownership::Undetermined(detail) => assert!(detail.contains("hole"), "{detail}"),
            other => panic!("an unusable map must not accuse: {other:?}"),
        }
    }

    #[test]
    fn an_empty_module_map_is_never_authoritative() {
        // Otherwise every pointer in the image would be reported as landing
        // outside every module, which would be a page of findings from a walk
        // that found nothing.
        let map = ModuleMap::from_ranges(Vec::new());
        assert!(!map.is_authoritative());
        assert!(matches!(map.attribute(1), Ownership::Undetermined(_)));
    }

    #[test]
    fn an_ownership_verdict_renders_differently_for_absent_and_for_unknown() {
        let outside = Ownership::OutsideAnyModule;
        let unknown = Ownership::Undetermined("the list was short".to_string());
        assert_ne!(outside.to_json(), unknown.to_json());
        assert_eq!(outside.as_str(), "outside_any_module");
        assert_eq!(unknown.as_str(), "undetermined");
        assert!(outside.is_outside_any_module());
        assert!(!unknown.is_outside_any_module());
    }

    // ── The stage ───────────────────────────────────────────────────────────

    #[test]
    fn every_group_this_build_supports_runs_and_says_so() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let symbols = KernelHookSymbols::from_profile(&profile).expect("a describable build");
        let outcome = examine_kernel_hooks(&profile, &symbols, &KernelHookConfig::default())
            .expect("a runnable examination");
        let names: Vec<&str> = outcome.groups.iter().map(|g| g.group).collect();
        assert_eq!(
            names,
            vec![
                GROUP_NOTIFY,
                GROUP_REGISTRY,
                GROUP_BUGCHECK,
                GROUP_SSDT,
                GROUP_DRIVERS,
                GROUP_MODULE_SCAN,
            ]
        );
        assert!(
            outcome.groups.iter().all(|group| group.ran),
            "{:?}",
            outcome.groups
        );
    }

    /// **The unattributed pointers are collected for the unloaded-driver
    /// cross-reference**, and only the pointers that landed in no module are.
    ///
    /// An `Undetermined` pointer — one the map could not answer for — must not
    /// become a candidate: cross-referencing it would turn an incomplete
    /// acquisition into a lead against a driver that had nothing to do with
    /// it.
    #[test]
    fn the_unattributed_pointers_are_offered_as_candidates_and_undetermined_ones_are_not() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let symbols = KernelHookSymbols::from_profile(&profile).expect("a describable build");
        let outcome = examine_kernel_hooks(&profile, &symbols, &KernelHookConfig::default())
            .expect("a runnable examination");
        let candidates = outcome.unattributed_candidates();
        // Counted against "outside every module", NOT against
        // `services_outside_the_kernel` / `irps_outside_their_driver`: a
        // service routine in a module that is not ntoskrnl, or an IRP handler
        // in a module other than its own driver, has a current owner and is
        // not a question for the unloaded table.
        let outside = |o: &Ownership| o.is_outside_any_module();
        assert_eq!(
            candidates.len(),
            outcome.unattributed_callbacks().count()
                + outcome
                    .services
                    .iter()
                    .filter(|e| outside(&e.ownership))
                    .count()
                + outcome
                    .drivers
                    .iter()
                    .flat_map(|d| d.irps.iter())
                    .filter(|i| outside(&i.ownership))
                    .count(),
            "every pointer in no loaded module, of all three kinds, and nothing else"
        );
        assert!(!candidates.is_empty(), "this fixture has hooked pointers");
        for (what, address) in &candidates {
            assert!(
                what.len() > 8 && what.chars().any(char::is_alphabetic),
                "a candidate carries the sentence a record will show: {what:?}"
            );
            assert_ne!(*address, 0, "{what} has no address");
            assert!(
                outcome.modules.attribute(*address).is_outside_any_module(),
                "{what} at {address:#x} is not outside every module, so it is not a candidate"
            );
        }
    }

    #[test]
    fn a_group_whose_symbols_are_missing_does_not_run_and_names_what_is_missing() {
        // The incident this whole crate is written against: a group that
        // silently produced nothing would read as a clean kernel.
        let isf = hook_isf().replace(
            r#""KiServiceTable": {"address""#,
            r#""KiServiceTableX": {"address""#,
        );
        let profile = hook_profile(populated_image(), &isf);
        let symbols = KernelHookSymbols::from_profile(&profile).expect("other groups still run");
        assert!(symbols.ssdt.is_none());
        let outcome = examine_kernel_hooks(&profile, &symbols, &KernelHookConfig::default())
            .expect("a runnable examination");
        let ssdt = outcome
            .groups
            .iter()
            .find(|group| group.group == GROUP_SSDT)
            .expect("the service table has a status");
        assert!(!ssdt.ran);
        assert!(ssdt
            .detail
            .as_deref()
            .expect("a stated reason")
            .contains("KiServiceTable"));
        assert!(!outcome.is_complete());
        assert!(outcome
            .incomplete
            .iter()
            .any(|i| i.detail.contains("did not run")));
    }

    #[test]
    fn a_build_supporting_no_group_at_all_is_refused_rather_than_examined() {
        let isf = hook_isf()
            .replace(r#""KiServiceTable""#, r#""KiServiceTableX""#)
            .replace(r#""PspCreateProcessNotifyRoutine""#, r#""PspXa""#)
            .replace(r#""PspCreateThreadNotifyRoutine""#, r#""PspXb""#)
            .replace(r#""PspLoadImageNotifyRoutine""#, r#""PspXc""#)
            .replace(r#""CallbackListHead""#, r#""CallbackListHeadX""#)
            .replace(r#""CmpCallBackCount""#, r#""CmpCallBackCountX""#)
            .replace(r#""KeBugCheckCallbackListHead""#, r#""KeBugCheckXa""#)
            .replace(r#""KeBugCheckReasonCallbackListHead""#, r#""KeBugCheckXb""#)
            .replace(r#""_DRIVER_OBJECT": {"#, r#""_DRIVER_OBJECT_X": {"#)
            .replace(
                r#""_LDR_DATA_TABLE_ENTRY": {"#,
                r#""_LDR_DATA_TABLE_ENTRY_X": {"#,
            );
        let profile = hook_profile(populated_image(), &isf);
        let err = KernelHookSymbols::from_profile(&profile).expect_err("nothing can run");
        assert_eq!(err.class(), "unsupported_build");
        let text = err.to_string();
        assert!(text.contains("Service table"), "{text}");
        assert!(text.contains("Drivers"), "{text}");
    }

    #[test]
    fn the_module_map_the_attributions_were_made_against_reaches_the_artifact() {
        // A report quoting "outside every loaded module" has to be able to show
        // which list that was measured against.
        let profile = hook_profile(populated_image(), &hook_isf());
        let symbols = KernelHookSymbols::from_profile(&profile).expect("a describable build");
        let outcome = examine_kernel_hooks(&profile, &symbols, &KernelHookConfig::default())
            .expect("a runnable examination");
        let value = outcome.to_json();
        assert!(value["modules"]["module_count"].as_u64().expect("a count") >= 2);
        assert_eq!(value["modules"]["authoritative"], true);
        assert!(value["groups"].as_array().expect("six groups").len() == 6);
    }

    #[test]
    fn a_supplied_module_map_is_used_rather_than_the_list_being_walked_again() {
        // Two walks are two chances for the same image to disagree with itself.
        let profile = hook_profile(populated_image(), &hook_isf());
        let symbols = KernelHookSymbols::from_profile(&profile).expect("a describable build");
        let supplied = Arc::new(ModuleMap::from_ranges(vec![range(
            0x10_0000, 0x10_FFFF, "fake.sys",
        )]));
        let config = KernelHookConfig {
            modules: Some(Arc::clone(&supplied)),
            ..KernelHookConfig::default()
        };
        let outcome =
            examine_kernel_hooks(&profile, &symbols, &config).expect("a runnable examination");
        assert_eq!(outcome.modules.len(), 1);
        assert_eq!(
            outcome.modules.ranges()[0].name.as_deref(),
            Some("fake.sys")
        );
    }
}
