//! Driver objects and loader entries recovered from the pool, and the 28
//! dispatch pointers each driver publishes.
//!
//! # Why sweep rather than walk
//!
//! The kernel's `PsLoadedModuleList` is a linked list, and a linked list is
//! something a driver with kernel privileges can unlink itself from in two
//! stores. Every allocation is still there — the allocator has not forgotten it
//! — so a sweep for the `MmLd` tag finds loader entries the list no longer holds,
//! and a sweep for `Dri\xf6`/`Driv` finds driver objects the same way. A module
//! present in the sweep and absent from the walk is the classic unlinked driver,
//! which is why [`ScannedModule::in_loaded_list`] exists and why it is
//! `Option<bool>`: the comparison can only be made against a module list that
//! was itself complete.
//!
//! # The 28 dispatch pointers
//!
//! Every `_DRIVER_OBJECT` carries `MajorFunction`, an array of dispatch routines
//! indexed by IRP major function code. A file-system filter that wants to see
//! every read hooks `IRP_MJ_READ` in the driver below it; so does a rootkit
//! hiding files. The signal reported here is a dispatch pointer that does **not**
//! land inside the driver that publishes it, computed from that driver's own
//! `DriverStart` and `DriverSize` rather than from a module list — because a
//! driver that has unlinked itself is exactly the one whose dispatch table is
//! worth reading, and it will not be in the list.
//!
//! Many rootkits zero `DriverStart` for anti-forensics. That makes the
//! in-driver question unanswerable rather than answerable as "no", so
//! [`IrpEntry::in_owning_driver`] is `None` there and the row still carries the
//! pointer and its module attribution.
//!
//! # Nothing here is a conclusion
//!
//! Windows itself hooks. `IRP_MJ_READ` on a volume pointing into `fltmgr.sys` is
//! the filter manager working exactly as designed, and an antivirus product's
//! entire reason for existing is to be in that path. The finding is the pointer
//! and where it lands; the interpretation is the examiner's.

use std::sync::Arc;

use seance_memory::object::{Obj, StructReader};
use seance_memory::MemoryLayer;

use crate::handles::token::first_member;
use crate::kernel_hooks::{
    declared_array_len, name_field, push_note, KernelHookConfig, KernelHookError, ModuleMap,
    Ownership,
};
use crate::modules::{loader_name_field, NameField};
use crate::poolscan::{
    builtin_constraints_for, pool_scan, PoolObject, PoolScanOutcome, PoolSymbols, ScanSpace,
};
use crate::profile::WindowsProfile;

/// The kernel's driver object.
pub const TYPE_DRIVER_OBJECT: &str = "_DRIVER_OBJECT";

/// The extension allocated alongside a driver object.
pub const TYPE_DRIVER_EXTENSION: &str = "_DRIVER_EXTENSION";

/// The loader entry describing a loaded image.
pub const TYPE_LDR_DATA_TABLE_ENTRY: &str = "_LDR_DATA_TABLE_ENTRY";

/// Pool tag for a protected driver object, as builds before Windows 8 wrote it.
pub const TAG_DRIVER_PROTECTED: [u8; 4] = *b"Dri\xf6";

/// Pool tag for a driver object, as Windows 8 and later write it.
pub const TAG_DRIVER: [u8; 4] = *b"Driv";

/// Pool tag for a loaded kernel module's loader entry.
pub const TAG_MODULE: [u8; 4] = *b"MmLd";

/// The IRP major function codes, in the order `MajorFunction` holds them.
///
/// These are published API constants rather than structure offsets: the codes
/// are fixed by the driver ABI and have not moved since Windows NT. What *is*
/// read from the symbol table is how many entries the array has, because a build
/// that declares a different count would otherwise have its table read past the
/// end.
pub const IRP_MAJOR_FUNCTIONS: [&str; 28] = [
    "IRP_MJ_CREATE",
    "IRP_MJ_CREATE_NAMED_PIPE",
    "IRP_MJ_CLOSE",
    "IRP_MJ_READ",
    "IRP_MJ_WRITE",
    "IRP_MJ_QUERY_INFORMATION",
    "IRP_MJ_SET_INFORMATION",
    "IRP_MJ_QUERY_EA",
    "IRP_MJ_SET_EA",
    "IRP_MJ_FLUSH_BUFFERS",
    "IRP_MJ_QUERY_VOLUME_INFORMATION",
    "IRP_MJ_SET_VOLUME_INFORMATION",
    "IRP_MJ_DIRECTORY_CONTROL",
    "IRP_MJ_FILE_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CONTROL",
    "IRP_MJ_INTERNAL_DEVICE_CONTROL",
    "IRP_MJ_SHUTDOWN",
    "IRP_MJ_LOCK_CONTROL",
    "IRP_MJ_CLEANUP",
    "IRP_MJ_CREATE_MAILSLOT",
    "IRP_MJ_QUERY_SECURITY",
    "IRP_MJ_SET_SECURITY",
    "IRP_MJ_POWER",
    "IRP_MJ_SYSTEM_CONTROL",
    "IRP_MJ_DEVICE_CHANGE",
    "IRP_MJ_QUERY_QUOTA",
    "IRP_MJ_SET_QUOTA",
    "IRP_MJ_PNP",
];

/// The page an image is mapped on, on every Windows there has been.
///
/// 4 KiB on x86, PAE and x64 alike: large pages change how a range is backed,
/// not the granularity a `DllBase` lands on.
const PAGE_SIZE: u64 = 0x1000;

/// Ceiling on the declared length of `MajorFunction`.
///
/// The array has 28 entries on every Windows there has been. A symbol table
/// declaring more than this is describing something else, and iterating it would
/// read a driver object's neighbours as dispatch pointers.
pub const MAX_IRP_FUNCTIONS: u64 = 64;

/// The name an IRP index carries.
///
/// An index past the published codes is named by its number rather than left
/// blank, so a build with a longer array produces rows an examiner can still
/// read.
pub fn irp_name(index: u64) -> String {
    usize::try_from(index)
        .ok()
        .and_then(|index| IRP_MAJOR_FUNCTIONS.get(index))
        .map(|name| (*name).to_string())
        .unwrap_or_else(|| format!("IRP_MJ_{index}"))
}

// ── Layout ──────────────────────────────────────────────────────────────────

/// The members a driver object is read through.
#[derive(Debug, Clone)]
pub struct DriverSymbols {
    /// The dispatch table.
    pub major_function: String,
    /// How many entries this build declares it has.
    pub major_function_count: u64,
    /// Where the driver image begins.
    pub driver_start: Option<String>,
    /// How large the driver image is.
    pub driver_size: Option<String>,
    /// The object-manager path of the driver.
    pub driver_name: Option<String>,
    /// The driver's entry point.
    pub driver_init: Option<String>,
    /// The driver's unload routine.
    pub driver_unload: Option<String>,
    /// The pointer to the extension allocated alongside it.
    pub driver_extension: Option<String>,
    /// The service key name inside that extension.
    pub service_key_name: Option<String>,
}

impl DriverSymbols {
    /// Resolve the members a driver object is read through.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] when this build has no `_DRIVER_OBJECT`
    /// or no `MajorFunction` array. Everything else is optional and becomes an
    /// absent column that says so, because a driver object without a readable
    /// name is still a driver object that was in the pool.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type(TYPE_DRIVER_OBJECT) {
            return Err(KernelHookError::unsupported(format!(
                "the symbol table has no '{TYPE_DRIVER_OBJECT}', so no driver's dispatch table can \
                 be read"
            )));
        }
        let major_function = first_member(&reader, TYPE_DRIVER_OBJECT, &["MajorFunction"])?
            .ok_or_else(|| {
                KernelHookError::unsupported(format!(
                    "'{TYPE_DRIVER_OBJECT}' has no MajorFunction on this build, so the routines a \
                     driver dispatches IRPs to cannot be listed"
                ))
            })?
            .to_string();
        let major_function_count = declared_array_len(
            &reader,
            TYPE_DRIVER_OBJECT,
            &major_function,
            MAX_IRP_FUNCTIONS,
        )
        .map_err(|err| {
            KernelHookError::unsupported(format!(
                "'{TYPE_DRIVER_OBJECT}.{major_function}' does not declare a believable \
                         number of dispatch entries: {err}"
            ))
        })?;

        let driver_extension =
            first_member(&reader, TYPE_DRIVER_OBJECT, &["DriverExtension"])?.map(str::to_string);
        let service_key_name = if profile.symbols.has_type(TYPE_DRIVER_EXTENSION) {
            first_member(&reader, TYPE_DRIVER_EXTENSION, &["ServiceKeyName"])?.map(str::to_string)
        } else {
            None
        };

        Ok(Self {
            major_function,
            major_function_count,
            driver_start: first_member(&reader, TYPE_DRIVER_OBJECT, &["DriverStart"])?
                .map(str::to_string),
            driver_size: first_member(&reader, TYPE_DRIVER_OBJECT, &["DriverSize"])?
                .map(str::to_string),
            driver_name: first_member(&reader, TYPE_DRIVER_OBJECT, &["DriverName"])?
                .map(str::to_string),
            driver_init: first_member(&reader, TYPE_DRIVER_OBJECT, &["DriverInit"])?
                .map(str::to_string),
            driver_unload: first_member(&reader, TYPE_DRIVER_OBJECT, &["DriverUnload"])?
                .map(str::to_string),
            driver_extension,
            service_key_name,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "major_function": self.major_function,
            "major_function_count": self.major_function_count,
            "driver_start": self.driver_start,
            "driver_size": self.driver_size,
            "driver_name": self.driver_name,
            "driver_init": self.driver_init,
            "driver_unload": self.driver_unload,
            "driver_extension": self.driver_extension,
            "service_key_name": self.service_key_name,
        })
    }
}

/// The members a pool-recovered loader entry is read through.
#[derive(Debug, Clone)]
pub struct LdrScanSymbols {
    /// The entry type.
    pub entry_type: String,
    /// Where the image is mapped.
    pub base: String,
    /// How large the mapped image is.
    pub size_of_image: String,
    /// The full path the image came from.
    pub full_name: String,
    /// The image's file name.
    pub base_name: String,
}

impl LdrScanSymbols {
    /// Resolve the members a loader entry is read through.
    ///
    /// # Errors
    ///
    /// [`KernelHookError::Unsupported`] naming the missing type or member. A
    /// sweep that returned entries with no base would be a list of addresses
    /// where a driver might have been.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, KernelHookError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type(TYPE_LDR_DATA_TABLE_ENTRY) {
            return Err(KernelHookError::unsupported(format!(
                "the symbol table has no '{TYPE_LDR_DATA_TABLE_ENTRY}', so loader entries cannot \
                 be recovered from the pool"
            )));
        }
        let require = |member: &str, purpose: &str| -> Result<String, KernelHookError> {
            Ok(first_member(&reader, TYPE_LDR_DATA_TABLE_ENTRY, &[member])?
                .ok_or_else(|| {
                    KernelHookError::unsupported(format!(
                        "'{TYPE_LDR_DATA_TABLE_ENTRY}' has no {member} on this build, so {purpose} \
                         could not be established for a recovered entry"
                    ))
                })?
                .to_string())
        };
        Ok(Self {
            entry_type: TYPE_LDR_DATA_TABLE_ENTRY.to_string(),
            base: require("DllBase", "where the image is mapped")?,
            size_of_image: require("SizeOfImage", "how large the image is")?,
            full_name: require("FullDllName", "the path the image came from")?,
            base_name: require("BaseDllName", "the image's file name")?,
        })
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "entry_type": self.entry_type,
            "base": self.base,
            "size_of_image": self.size_of_image,
            "full_name": self.full_name,
            "base_name": self.base_name,
        })
    }
}

// ── Results ─────────────────────────────────────────────────────────────────

/// One dispatch pointer a driver publishes.
#[derive(Debug, Clone)]
pub struct IrpEntry {
    /// The IRP major function code.
    pub index: u64,
    /// The code's published name.
    pub name: String,
    /// The routine the driver dispatches that IRP to.
    pub handler: u64,
    /// Whether the routine lies inside the driver that publishes it. `None`
    /// means the question could not be answered — most often because the driver
    /// object's `DriverStart` is zero, which rootkits do deliberately — and it
    /// is never rendered as `false`.
    pub in_owning_driver: Option<bool>,
    /// Which loaded module owns the routine.
    pub ownership: Ownership,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl IrpEntry {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "index": self.index,
            "name": self.name,
            "handler": self.handler,
            "in_owning_driver": self.in_owning_driver,
            "ownership": self.ownership.to_json(),
            "module": self.ownership.module(),
            "outside_any_module": self.ownership.is_outside_any_module(),
            "notes": self.notes,
        })
    }
}

/// One driver object recovered from the pool.
#[derive(Debug, Clone)]
pub struct DriverRecord {
    /// Where the `_DRIVER_OBJECT` is, in the space that was swept.
    pub address: u64,
    /// Where its allocation starts.
    pub pool_header: u64,
    /// The tag, rendered so that every byte survives.
    pub tag: String,
    /// Whether the allocation is freed — an unloaded driver, historically.
    pub freed: bool,
    /// Whether the object-manager type was compared against the tag.
    pub type_verified: bool,
    /// The object-manager type the header named, when it was resolved.
    pub object_type: Option<String>,
    /// Where the driver image begins.
    pub start: Option<u64>,
    /// How large the driver image is.
    pub size: Option<u64>,
    /// The object-manager path, e.g. `\Driver\Tcpip`.
    pub name: NameField,
    /// The service key the driver was started from.
    pub service_key: NameField,
    /// The driver's entry point.
    pub init: Option<u64>,
    /// The driver's unload routine.
    pub unload: Option<u64>,
    /// The dispatch table.
    pub irps: Vec<IrpEntry>,
    /// Everything odd about the object that did not disqualify it.
    pub notes: Vec<String>,
}

impl DriverRecord {
    /// The last byte of the driver image, when both start and size are known.
    ///
    /// Inclusive, and `None` rather than a guess: a range with an assumed size
    /// would place a dispatch pointer inside a driver that may not hold it.
    pub fn end(&self) -> Option<u64> {
        let start = self.start?;
        let size = self.size?;
        if size == 0 {
            return None;
        }
        start.checked_add(size)?.checked_sub(1)
    }

    /// Dispatch pointers that leave the driver that publishes them.
    pub fn irps_outside_owner(&self) -> usize {
        self.irps
            .iter()
            .filter(|irp| irp.in_owning_driver == Some(false))
            .count()
    }

    /// Whether any of the three names this driver could carry was readable.
    ///
    /// A driver object with no readable name at all is overwhelmingly a tag
    /// that matched by accident; upstream drops those rows outright. They are
    /// kept here and flagged, because "an allocation tagged as a driver whose
    /// every name was unreadable" is a different statement from "no such
    /// allocation existed".
    pub fn has_any_name(&self) -> bool {
        self.name.name().is_some() || self.service_key.name().is_some()
    }

    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "pool_header": self.pool_header,
            "tag": self.tag,
            "freed": self.freed,
            "type_verified": self.type_verified,
            "object_type": self.object_type,
            "start": self.start,
            "size": self.size,
            "end": self.end(),
            "name": self.name.to_json(),
            "service_key": self.service_key.to_json(),
            "init": self.init,
            "unload": self.unload,
            "irps": self.irps.iter().map(IrpEntry::to_json).collect::<Vec<_>>(),
            "irp_count": self.irps.len(),
            "irps_outside_owner": self.irps_outside_owner(),
            "has_any_name": self.has_any_name(),
            "notes": self.notes,
        })
    }
}

/// What one driver sweep found, and everything it could not do.
#[derive(Debug, Clone, Default)]
pub struct DriverSweep {
    /// The driver objects.
    pub drivers: Vec<DriverRecord>,
    /// Notes, capped by [`KernelHookConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes were raised in total.
    pub notes_total: usize,
    /// Whether a cap fired, or the underlying sweep was incomplete.
    pub capped: bool,
}

/// One loader entry recovered from the pool.
#[derive(Debug, Clone)]
pub struct ScannedModule {
    /// Where the `_LDR_DATA_TABLE_ENTRY` is, in the space that was swept.
    pub address: u64,
    /// Where its allocation starts.
    pub pool_header: u64,
    /// The tag, rendered so that every byte survives.
    pub tag: String,
    /// Whether the allocation is freed — an unloaded driver, historically.
    pub freed: bool,
    /// Where the image is mapped.
    pub base: Option<u64>,
    /// How large the mapped image is.
    pub size: Option<u64>,
    /// The path the image came from.
    pub full_path: NameField,
    /// The image's file name.
    pub base_name: NameField,
    /// Whether the kernel's own loaded-module list holds this image. `None`
    /// means the comparison could not be made — because the list was
    /// incomplete, or because this entry had no readable base — and it is never
    /// rendered as `false`, which would be an accusation.
    pub in_loaded_list: Option<bool>,
    /// Everything odd about the entry that did not disqualify it.
    pub notes: Vec<String>,
}

impl ScannedModule {
    /// Serializable form for artifact metadata.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "address": self.address,
            "pool_header": self.pool_header,
            "tag": self.tag,
            "freed": self.freed,
            "base": self.base,
            "size": self.size,
            "full_path": self.full_path.to_json(),
            "base_name": self.base_name.to_json(),
            "in_loaded_list": self.in_loaded_list,
            "unlinked": self.in_loaded_list == Some(false),
            "notes": self.notes,
        })
    }
}

/// What one loader-entry sweep found, and everything it could not do.
#[derive(Debug, Clone, Default)]
pub struct ModuleScanSweep {
    /// The loader entries.
    pub modules: Vec<ScannedModule>,
    /// Notes, capped by [`KernelHookConfig::max_recorded_notes`].
    pub notes: Vec<String>,
    /// How many notes were raised in total.
    pub notes_total: usize,
    /// Whether a cap fired, or the underlying sweep was incomplete.
    pub capped: bool,
}

// ── The groups ──────────────────────────────────────────────────────────────

/// Sweep the pool for driver objects and read each one's dispatch table.
///
/// # What an examiner learns
///
/// Every driver object the allocator still holds — including unloaded ones,
/// whose allocations are freed, and unlinked ones, which no list walk reaches —
/// with its image range, its object-manager path, its service key, and all 28
/// dispatch pointers with the module each lands in.
///
/// # What a wrong answer looks like
///
/// A dispatch pointer reported as leaving its driver because `DriverSize` was
/// read from the wrong offset, which would flag every driver in the image. The
/// range is therefore built only from members the symbol table named, and a
/// zero or unreadable size makes the question unanswerable rather than answered.
///
/// # Errors
///
/// Only for a failure that makes the whole sweep meaningless: a pool layout that
/// cannot be established, or a scan configuration that cannot produce a correct
/// walk.
pub fn scan_drivers(
    profile: &WindowsProfile,
    symbols: &DriverSymbols,
    pool: &PoolSymbols,
    modules: &ModuleMap,
    config: &KernelHookConfig,
) -> Result<DriverSweep, KernelHookError> {
    let constraints = builtin_constraints_for(&[TAG_DRIVER_PROTECTED, TAG_DRIVER]);
    if constraints.is_empty() {
        return Err(KernelHookError::unsupported(
            "neither driver pool tag is among the builtin constraints, so the sweep would look for \
             nothing and its empty result would read as a machine with no drivers",
        ));
    }
    let outcome = pool_scan(profile, pool, &constraints, &config.pool)?;
    let reader = swept_reader(profile, pool);

    let mut sweep = DriverSweep {
        capped: !outcome.is_complete(),
        ..DriverSweep::default()
    };
    absorb_sweep_notes(&mut sweep.notes, &mut sweep.notes_total, config, &outcome);

    for object in &outcome.objects {
        if object.type_name != TYPE_DRIVER_OBJECT {
            continue;
        }
        if sweep.drivers.len() >= config.max_drivers {
            sweep.capped = true;
            break;
        }
        sweep
            .drivers
            .push(read_driver(&reader, symbols, modules, object));
    }
    Ok(sweep)
}

/// Sweep the pool for loader entries and mark those the kernel's list has lost.
///
/// # What an examiner learns
///
/// Every loader entry the allocator still holds, and for each whether the
/// kernel's own `PsLoadedModuleList` holds an image at the same base. An entry
/// found here and absent there is the classic direct-kernel-object-manipulation
/// hiding technique.
///
/// # What a wrong answer looks like
///
/// A driver reported as unlinked because the module list walk stopped at a hole.
/// That is why the comparison is only made against an authoritative
/// [`ModuleMap`], and why [`ScannedModule::in_loaded_list`] is `None` otherwise.
/// The same wrong answer comes from the other side: four tag bytes that occur
/// inside the kernel's own data decode as a loader entry holding whatever lay at
/// those offsets, and the list holds no image at a base no image was mapped at.
/// An entry whose `DllBase` is off a page, or whose `SizeOfImage` no capture
/// could hold, is therefore published with the question left open rather than
/// answered "no".
///
/// # Errors
///
/// Only for a failure that makes the whole sweep meaningless.
pub fn scan_loader_entries(
    profile: &WindowsProfile,
    symbols: &LdrScanSymbols,
    pool: &PoolSymbols,
    modules: &ModuleMap,
    config: &KernelHookConfig,
) -> Result<ModuleScanSweep, KernelHookError> {
    let constraints = builtin_constraints_for(&[TAG_MODULE]);
    if constraints.is_empty() {
        return Err(KernelHookError::unsupported(
            "the loader-entry pool tag is not among the builtin constraints, so the sweep would \
             look for nothing and its empty result would read as a machine with no drivers loaded",
        ));
    }
    let outcome = pool_scan(profile, pool, &constraints, &config.pool)?;
    let reader = swept_reader(profile, pool);
    let capture_bytes = capture_span(&*profile.physical);

    let mut sweep = ModuleScanSweep {
        capped: !outcome.is_complete(),
        ..ModuleScanSweep::default()
    };
    absorb_sweep_notes(&mut sweep.notes, &mut sweep.notes_total, config, &outcome);
    if !modules.is_authoritative() {
        push_note(
            &mut sweep.notes,
            &mut sweep.notes_total,
            config.max_recorded_notes,
            format!(
                "no entry here may be called unlinked, because {}",
                modules
                    .note()
                    .unwrap_or("the loaded-module list held no usable entry")
            ),
        );
    }

    for object in &outcome.objects {
        if object.type_name != symbols.entry_type {
            continue;
        }
        if sweep.modules.len() >= config.max_scanned_modules {
            sweep.capped = true;
            break;
        }
        let record = read_loader_entry(&reader, symbols, modules, object, capture_bytes);
        sweep.modules.push(record);
    }
    Ok(sweep)
}

// ── Reading ─────────────────────────────────────────────────────────────────

/// A reader over the layer the sweep ran against, with pointers resolved in the
/// kernel's own space.
///
/// Built exactly the way [`pool_scan`] builds its own: getting the two spaces
/// the wrong way round does not fail, it silently reads unrelated bytes that
/// parse.
fn swept_reader(profile: &WindowsProfile, pool: &PoolSymbols) -> StructReader {
    let layer: Arc<dyn MemoryLayer> = match pool.space {
        ScanSpace::Physical => Arc::clone(&profile.physical),
        ScanSpace::KernelVirtual => Arc::clone(&profile.kernel_space),
    };
    StructReader::with_native(
        layer,
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    )
}

/// Carry the underlying sweep's own account of what it could not read.
fn absorb_sweep_notes(
    notes: &mut Vec<String>,
    total: &mut usize,
    config: &KernelHookConfig,
    outcome: &PoolScanOutcome,
) {
    for incomplete in &outcome.incomplete {
        push_note(
            notes,
            total,
            config.max_recorded_notes,
            format!("the pool sweep is incomplete: {}", incomplete.detail),
        );
    }
}

/// Read one recovered driver object and its dispatch table.
fn read_driver(
    reader: &StructReader,
    symbols: &DriverSymbols,
    modules: &ModuleMap,
    object: &PoolObject,
) -> DriverRecord {
    let mut notes = object.notes.clone();
    let mut record = DriverRecord {
        address: object.address,
        pool_header: object.pool_header,
        tag: object.tag.clone(),
        freed: object.freed,
        type_verified: object.type_verified,
        object_type: object.object_type.clone(),
        start: None,
        size: None,
        name: NameField::Unavailable("the driver object could not be read".to_string()),
        service_key: NameField::Unavailable("the driver extension was not reached".to_string()),
        init: None,
        unload: None,
        irps: Vec::new(),
        notes: Vec::new(),
    };

    let driver = match reader.object(object.address, TYPE_DRIVER_OBJECT) {
        Ok(driver) => driver,
        Err(err) => {
            notes.push(format!(
                "'{TYPE_DRIVER_OBJECT}' at {:#x} could not be read: {err}",
                object.address
            ));
            record.notes = notes;
            return record;
        }
    };

    record.start = optional_address(&driver, symbols.driver_start.as_deref(), &mut notes);
    record.size = optional_unsigned(&driver, symbols.driver_size.as_deref(), &mut notes);
    record.init = optional_address(&driver, symbols.driver_init.as_deref(), &mut notes);
    record.unload = optional_address(&driver, symbols.driver_unload.as_deref(), &mut notes);
    record.name = match symbols.driver_name.as_deref() {
        Some(path) => name_field(&driver, path),
        None => NameField::Unavailable(format!(
            "'{TYPE_DRIVER_OBJECT}' has no DriverName on this build"
        )),
    };
    record.service_key = read_service_key(&driver, symbols);

    // The driver's own range, which is what a dispatch pointer is measured
    // against. A zeroed `DriverStart` — which rootkits write deliberately —
    // makes the question unanswerable rather than answerable as "outside".
    let owner_range = match (record.start, record.size) {
        (Some(start), Some(size)) if start != 0 && size != 0 => start
            .checked_add(size)
            .and_then(|end| end.checked_sub(1))
            .map(|end| (start, end)),
        _ => None,
    };
    if owner_range.is_none() {
        notes.push(
            "this driver object does not give a usable image range, so no dispatch pointer can be \
             said to leave it"
                .to_string(),
        );
    }

    for index in 0..symbols.major_function_count {
        let handler = match driver.element_int(&symbols.major_function, index) {
            Ok(value) => value
                .as_u64()
                .or_else(|| value.as_i64().map(|signed| signed as u64))
                .unwrap_or(0),
            Err(err) => {
                notes.push(format!(
                    "'{}[{index}]' could not be read: {err}",
                    symbols.major_function
                ));
                continue;
            }
        };
        let mut irp_notes = Vec::new();
        let (in_owning_driver, ownership) = if handler == 0 {
            irp_notes.push(
                "the entry is null, so the kernel would not dispatch this IRP to this driver"
                    .to_string(),
            );
            (
                None,
                Ownership::Undetermined("a null dispatch entry names no routine".to_string()),
            )
        } else {
            (
                owner_range.map(|(start, end)| start <= handler && handler <= end),
                modules.attribute(handler),
            )
        };
        record.irps.push(IrpEntry {
            index,
            name: irp_name(index),
            handler,
            in_owning_driver,
            ownership,
            notes: irp_notes,
        });
    }

    record.notes = notes;
    record
}

/// The service key name inside a driver's extension.
fn read_service_key(driver: &Obj, symbols: &DriverSymbols) -> NameField {
    let Some(extension_member) = symbols.driver_extension.as_deref() else {
        return NameField::Unavailable(format!(
            "'{TYPE_DRIVER_OBJECT}' has no DriverExtension on this build"
        ));
    };
    let Some(name_member) = symbols.service_key_name.as_deref() else {
        return NameField::Unavailable(format!(
            "'{TYPE_DRIVER_EXTENSION}' has no ServiceKeyName on this build"
        ));
    };
    match driver.follow(extension_member) {
        Ok(Some(extension)) => name_field(&extension, name_member),
        Ok(None) => NameField::Empty,
        Err(err) => NameField::Unavailable(format!("'{extension_member}': {err}")),
    }
}

/// Read one recovered loader entry.
///
/// `capture_bytes` is the ceiling any mapped image must fit under, from
/// [`capture_span`].
fn read_loader_entry(
    reader: &StructReader,
    symbols: &LdrScanSymbols,
    modules: &ModuleMap,
    object: &PoolObject,
    capture_bytes: u64,
) -> ScannedModule {
    let mut notes = object.notes.clone();
    let mut record = ScannedModule {
        address: object.address,
        pool_header: object.pool_header,
        tag: object.tag.clone(),
        freed: object.freed,
        base: None,
        size: None,
        full_path: NameField::Unavailable("the loader entry could not be read".to_string()),
        base_name: NameField::Unavailable("the loader entry could not be read".to_string()),
        in_loaded_list: None,
        notes: Vec::new(),
    };

    let entry = match reader.object(object.address, &symbols.entry_type) {
        Ok(entry) => entry,
        Err(err) => {
            notes.push(format!(
                "'{}' at {:#x} could not be read: {err}",
                symbols.entry_type, object.address
            ));
            record.notes = notes;
            return record;
        }
    };

    record.base = optional_address(&entry, Some(&symbols.base), &mut notes);
    record.size = optional_unsigned(&entry, Some(&symbols.size_of_image), &mut notes);
    // Read with the loader rule, not the general one. This sweep exists to find
    // allocations the loaded-module list no longer holds, so a freed entry
    // whose pool has since been handed to something else is not an edge case
    // here — it is half of what the sweep returns. Its `BaseDllName` decodes as
    // valid UTF-16 that is not a name, and a row of mojibake in the list an
    // examiner searches for an unlinked driver reads as a finding.
    record.full_path = loader_name_field(&entry, &symbols.full_name);
    record.base_name = loader_name_field(&entry, &symbols.base_name);

    // What the `MmLd` constraint proved is that an allocation of the right size
    // and pool type carries those four bytes — not that a loader entry is
    // inside it. Four bytes recur inside the kernel's own data by chance, and
    // the fields then decode to whatever was there. So before the entry may be
    // measured against the kernel's list, it has to hold values the loader
    // could have written.
    let unusable = unloadable_image(&record, symbols, capture_bytes);
    let undecidable = unusable.is_some();
    if let Some(reason) = unusable {
        notes.push(reason);
    }

    // The comparison the sweep exists for — and it may only be made against a
    // module list that was itself complete.
    //
    // A zeroed `DllBase` answers nothing at all. Rootkits zero the member
    // deliberately, so "the list holds no module at zero" is what an erased
    // entry and an unlinked one both produce, and only one of them is an
    // accusation.
    record.in_loaded_list = match (record.base, modules.is_authoritative()) {
        // Zero is not an image base any Windows has loaded a driver at, so
        // neither answer can be drawn from it. A *miss* would accuse an erased
        // entry of having been unlinked; a *match* is two zeroed fields agreeing
        // with each other, which vouches for the entry on the strength of the
        // very erasure that made it unreadable.
        (Some(0), _) => {
            notes.push(format!(
                "'{}' is zero, which is what an erased entry looks like as well as an unlinked \
                 one, so this entry is neither called unlinked nor said to be held by the \
                 kernel's list",
                symbols.base
            ));
            None
        }
        // Fields no loader wrote decide nothing either. The list holds no image
        // at an address no image was mapped at, so a miss here would be the
        // coincidence accusing itself.
        (Some(_), _) if undecidable => None,
        (Some(base), true) => Some(modules.ranges().iter().any(|range| range.base == base)),
        _ => None,
    };

    record.notes = notes;
    record
}

/// Why the loader cannot have written this entry's fields, when it cannot.
///
/// The `MmLd` constraint tests the *allocation* — its size and its pool type —
/// and nothing about the object inside it, so four bytes that recur inside the
/// kernel's own data are recovered as a loader entry whose members are whatever
/// happened to lie at those offsets. Two properties separate a real entry from
/// that: Windows maps an image at a page boundary, and an image resident in the
/// capture is no larger than the capture.
///
/// An entry failing either is still published, because the allocation did
/// decode this way and dropping the row would say no such allocation existed.
/// What it may not do is answer the unlinked question: "the kernel's list holds
/// no image at this base" is true of every coincidence as well as of every
/// unlinked driver, and only one of the two is a rootkit.
fn unloadable_image(
    record: &ScannedModule,
    symbols: &LdrScanSymbols,
    capture_bytes: u64,
) -> Option<String> {
    // A zeroed base is the erased entry, which the caller answers separately and
    // more precisely. It is anti-forensics, not a tag that matched by accident.
    if let Some(base) = record.base.filter(|base| *base != 0) {
        if base % PAGE_SIZE != 0 {
            return Some(format!(
                "'{}' is {base:#x}, which is not a page boundary and so is not an address any \
                 image was mapped at, so this entry is neither called unlinked nor said to be \
                 held by the kernel's list",
                symbols.base
            ));
        }
    }
    match record.size {
        Some(0) => Some(format!(
            "'{}' is zero, which describes no image, so this entry is neither called unlinked nor \
             said to be held by the kernel's list",
            symbols.size_of_image
        )),
        Some(size) if size > capture_bytes => Some(format!(
            "'{}' is {size:#x}, larger than the {capture_bytes:#x} bytes of memory the capture \
             holds, so no image of that size was resident and this entry is neither called \
             unlinked nor said to be held by the kernel's list",
            symbols.size_of_image
        )),
        // An unreadable size is absent, not implausible: the failure is already
        // its own note, and it is no reason to decline the base comparison.
        _ => None,
    }
}

/// How many bytes of memory the capture holds, as the ceiling on any image size.
///
/// Measured on the physical layer rather than on the layer the sweep ran
/// against: a kernel virtual space is addressable far beyond whatever the
/// machine had, so its span bounds nothing.
fn capture_span(physical: &dyn MemoryLayer) -> u64 {
    physical
        .max_address()
        .saturating_sub(physical.min_address())
        .saturating_add(1)
}

/// Read an optional member that holds an address, recording rather than
/// swallowing a failure.
fn optional_address(object: &Obj, path: Option<&str>, notes: &mut Vec<String>) -> Option<u64> {
    let path = path?;
    match object.int(path) {
        Ok(value) => value
            .as_u64()
            .or_else(|| value.as_i64().map(|signed| signed as u64)),
        Err(err) => {
            notes.push(format!("'{path}' could not be read: {err}"));
            None
        }
    }
}

/// Read an optional unsigned member, recording rather than swallowing a failure.
fn optional_unsigned(object: &Obj, path: Option<&str>, notes: &mut Vec<String>) -> Option<u64> {
    let path = path?;
    match object.int(path) {
        Ok(value) => match value.as_u64() {
            Some(value) => Some(value),
            None => {
                notes.push(format!("'{path}' is negative, which is not a size"));
                None
            }
        },
        Err(err) => {
            notes.push(format!("'{path}' could not be read: {err}"));
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel_hooks::test_support::{
        hook_isf, hook_profile, off, populated_image, BLANK_DISPATCH, DRIVER_BLANK_ALLOC,
        DRIVER_FLT_ALLOC, FLT_BASE, FLT_DISPATCH, FLT_DRIVER_PATH, FLT_HOOKED_DISPATCH, FLT_NAME,
        FLT_SERVICE_KEY, FLT_SIZE, HIDDEN_BASE, HIDDEN_BASE_NAME_BUFFER, HIDDEN_NAME,
        HOOKED_IRP_INDEX, LDR_HIDDEN_ALLOC, NT_BASE, NT_NAME,
    };
    use crate::kernel_hooks::ModuleMap;
    use crate::poolscan::{ObjectTypeMap, PoolScanConfig, PoolSymbols};
    use crate::profile::WindowsProfile;
    use std::sync::Arc;

    /// The configuration the stage actually runs with: an object-type map, so a
    /// driver object is checked against the type the kernel believes it has.
    fn config(profile: &WindowsProfile) -> KernelHookConfig {
        let type_map = ObjectTypeMap::from_profile(profile)
            .ok()
            .filter(|map| !map.is_empty())
            .map(Arc::new);
        KernelHookConfig {
            pool: PoolScanConfig {
                type_map,
                ..PoolScanConfig::default()
            },
            ..KernelHookConfig::default()
        }
    }

    fn drivers_of(profile: &WindowsProfile, modules: &ModuleMap) -> DriverSweep {
        let pool = PoolSymbols::from_profile(profile).expect("a describable pool");
        let symbols = DriverSymbols::from_profile(profile).expect("a describable build");
        scan_drivers(profile, &symbols, &pool, modules, &config(profile)).expect("a runnable sweep")
    }

    fn loaders_of(profile: &WindowsProfile, modules: &ModuleMap) -> ModuleScanSweep {
        let pool = PoolSymbols::from_profile(profile).expect("a describable pool");
        let symbols = LdrScanSymbols::from_profile(profile).expect("a describable build");
        scan_loader_entries(profile, &symbols, &pool, modules, &config(profile))
            .expect("a runnable sweep")
    }

    // ── Driver objects ──────────────────────────────────────────────────────

    #[test]
    fn every_driver_object_in_the_pool_is_recovered_with_its_names() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        assert_eq!(sweep.drivers.len(), 2, "{:?}", sweep.notes);

        let flt = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_FLT_ALLOC)
            .expect("the listed driver");
        assert_eq!(flt.name.name(), Some(FLT_DRIVER_PATH));
        assert_eq!(flt.service_key.name(), Some(FLT_SERVICE_KEY));
        assert_eq!(flt.start, Some(FLT_BASE));
        assert_eq!(flt.size, Some(FLT_SIZE));
        assert_eq!(flt.end(), Some(FLT_BASE + FLT_SIZE - 1));
        assert!(flt.has_any_name());
    }

    #[test]
    fn a_driver_object_is_checked_against_the_type_the_object_manager_gave_it() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        for driver in &sweep.drivers {
            assert!(driver.type_verified, "{driver:?}");
            assert_eq!(driver.object_type.as_deref(), Some("Driver"));
        }
    }

    #[test]
    fn all_twenty_eight_dispatch_pointers_are_read_and_named() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        let flt = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_FLT_ALLOC)
            .expect("the listed driver");
        assert_eq!(flt.irps.len(), IRP_MAJOR_FUNCTIONS.len());
        assert_eq!(flt.irps[0].name, "IRP_MJ_CREATE");
        assert_eq!(flt.irps[27].name, "IRP_MJ_PNP");
    }

    #[test]
    fn a_dispatch_pointer_that_leaves_its_own_driver_is_the_finding() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        let flt = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_FLT_ALLOC)
            .expect("the listed driver");
        let hooked = &flt.irps[HOOKED_IRP_INDEX as usize];
        assert_eq!(hooked.name, "IRP_MJ_READ");
        assert_eq!(hooked.handler, FLT_HOOKED_DISPATCH);
        assert_eq!(hooked.in_owning_driver, Some(false));
        assert!(hooked.ownership.is_outside_any_module());
        assert_eq!(flt.irps_outside_owner(), 1);
    }

    #[test]
    fn a_dispatch_pointer_inside_its_own_driver_is_ordinary_and_not_counted() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        let flt = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_FLT_ALLOC)
            .expect("the listed driver");
        let ordinary = &flt.irps[0];
        assert_eq!(ordinary.handler, FLT_DISPATCH);
        assert_eq!(ordinary.in_owning_driver, Some(true));
        assert_eq!(ordinary.ownership.module(), Some(FLT_NAME));
    }

    #[test]
    fn a_driver_with_a_zeroed_start_makes_the_question_unanswerable_not_answered_no() {
        // Rootkits zero `DriverStart` precisely so that this test cannot be
        // made. Reporting `false` there would flag every dispatch pointer of a
        // driver whose range is simply unknown.
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        let blank = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_BLANK_ALLOC)
            .expect("the zeroed driver");
        assert_eq!(blank.start, Some(0));
        assert_eq!(blank.end(), None);
        assert!(blank.irps.iter().all(|irp| irp.in_owning_driver.is_none()));
        assert_eq!(blank.irps_outside_owner(), 0);
        assert!(blank.irps.iter().all(|irp| irp.handler == BLANK_DISPATCH));
        assert!(
            blank
                .notes
                .iter()
                .any(|note| note.contains("does not give a usable image range")),
            "{:?}",
            blank.notes
        );
    }

    #[test]
    fn a_driver_with_no_extension_reports_an_absent_service_key_rather_than_an_unreadable_one() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        let blank = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_BLANK_ALLOC)
            .expect("the zeroed driver");
        assert_eq!(blank.service_key, NameField::Empty);
        assert!(blank.service_key.is_known());
    }

    #[test]
    fn a_build_without_a_dispatch_table_is_refused_rather_than_swept() {
        let isf = hook_isf().replace(
            r#""MajorFunction": {"offset": 72"#,
            r#""MajorFunctionX": {"offset": 72"#,
        );
        let profile = hook_profile(populated_image(), &isf);
        let err = DriverSymbols::from_profile(&profile).expect_err("nothing to report");
        assert!(err.to_string().contains("MajorFunction"), "{err}");
        assert_eq!(err.class(), "unsupported_build");
    }

    #[test]
    fn a_dispatch_pointer_that_is_null_names_no_routine_and_says_so() {
        let mut image = populated_image();
        let flt_body = DRIVER_FLT_ALLOC + off::POOL_HEADER_SIZE + off::OH_BODY;
        image.put_u64(flt_body + off::DRIVER_MAJOR_FUNCTION, 0);
        let profile = hook_profile(image, &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        let flt = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_FLT_ALLOC)
            .expect("the listed driver");
        let entry = &flt.irps[0];
        assert_eq!(entry.handler, 0);
        assert_eq!(entry.in_owning_driver, None);
        assert!(matches!(entry.ownership, Ownership::Undetermined(_)));
        assert!(!entry.notes.is_empty());
    }

    // ── Loader entries ──────────────────────────────────────────────────────

    #[test]
    fn the_pool_sweep_finds_every_loader_entry_including_the_one_the_list_lost() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);
        assert_eq!(sweep.modules.len(), 3, "{:?}", sweep.notes);
        let names: Vec<Option<&str>> = sweep
            .modules
            .iter()
            .map(|module| module.base_name.name())
            .collect();
        assert!(names.contains(&Some(NT_NAME)), "{names:?}");
        assert!(names.contains(&Some(FLT_NAME)), "{names:?}");
        assert!(names.contains(&Some(HIDDEN_NAME)), "{names:?}");
    }

    #[test]
    fn an_entry_the_kernels_own_list_does_not_hold_is_marked_unlinked() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);
        let hidden = sweep
            .modules
            .iter()
            .find(|module| module.pool_header == LDR_HIDDEN_ALLOC)
            .expect("the unlinked entry");
        assert_eq!(hidden.base, Some(HIDDEN_BASE));
        assert_eq!(hidden.in_loaded_list, Some(false));
        assert_eq!(hidden.to_json()["unlinked"], true);
    }

    #[test]
    fn an_entry_the_list_does_hold_is_marked_as_held_and_not_as_a_finding() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);
        let listed: Vec<Option<u64>> = sweep
            .modules
            .iter()
            .filter(|module| module.in_loaded_list == Some(true))
            .map(|module| module.base)
            .collect();
        assert!(listed.contains(&Some(FLT_BASE)), "{listed:?}");

        // `ntoskrnl.exe` is based at zero in this fixture — the profile's kernel
        // base is zero, so every symbol address is its own RVA — and zero is not
        // a base any kernel loads at. The sweep therefore refuses to decide on
        // it in either direction, which is the same rule
        // `an_entry_whose_base_was_zeroed_is_undecided_rather_than_accused`
        // pins: it must not be listed as held either.
        assert_eq!(NT_BASE, 0, "the fixture bases the kernel at zero");
        assert!(!listed.contains(&Some(NT_BASE)), "{listed:?}");
    }

    /// An entry whose `DllBase` was zeroed must not be published as unlinked.
    ///
    /// Zeroing the base is a standard anti-forensic move, and it is also what a
    /// smeared entry looks like. Asking the loaded-module list whether it holds
    /// an image at zero answers "no" every time, so a decoder that trusts the
    /// answer turns an erased field into a rootkit finding.
    #[test]
    fn an_entry_whose_base_was_zeroed_is_undecided_rather_than_accused() {
        let mut image = populated_image();
        // Erase the unlinked entry's base and leave everything else alone.
        image.put_u64(
            LDR_HIDDEN_ALLOC + off::POOL_HEADER_SIZE + off::LDR_DLL_BASE,
            0,
        );
        let profile = hook_profile(image, &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);
        let erased = sweep
            .modules
            .iter()
            .find(|module| module.pool_header == LDR_HIDDEN_ALLOC)
            .expect("the entry is still recovered");
        assert_eq!(erased.base, Some(0));
        assert_eq!(
            erased.in_loaded_list, None,
            "a zeroed base is not evidence that the kernel's list lost this entry"
        );
        assert_eq!(erased.to_json()["unlinked"], false);
        assert!(
            erased
                .notes
                .iter()
                .any(|note| note.contains("erased entry")),
            "{:?}",
            erased.notes
        );
    }

    /// An entry whose `DllBase` is not on a page boundary must not be published
    /// as unlinked.
    ///
    /// The `MmLd` constraint tests the allocation, not the object inside it, so
    /// the four tag bytes occurring inside the kernel's own data yield an entry
    /// whose members are whatever lay at those offsets. Windows maps every image
    /// on a page, so a base that is not on one belongs to no image — and asking
    /// the loaded-module list whether it holds an image there answers "no" every
    /// time, which turns the coincidence into a hidden-driver finding.
    #[test]
    fn an_entry_whose_base_is_not_page_aligned_is_undecided_rather_than_accused() {
        let mut image = populated_image();
        // Nudge the unlinked entry's base off its page and leave everything else
        // alone: the row is still recovered, it is the accusation that must go.
        image.put_u64(
            LDR_HIDDEN_ALLOC + off::POOL_HEADER_SIZE + off::LDR_DLL_BASE,
            HIDDEN_BASE + 0x40,
        );
        let profile = hook_profile(image, &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);
        let coincidence = sweep
            .modules
            .iter()
            .find(|module| module.pool_header == LDR_HIDDEN_ALLOC)
            .expect("the entry is still recovered");
        assert_eq!(coincidence.base, Some(HIDDEN_BASE + 0x40));
        assert_eq!(
            coincidence.in_loaded_list, None,
            "a base no image was mapped at is not evidence that the kernel's list lost an entry"
        );
        assert_eq!(coincidence.to_json()["unlinked"], false);
        assert!(
            coincidence
                .notes
                .iter()
                .any(|note| note.contains("page boundary")),
            "{:?}",
            coincidence.notes
        );
    }

    /// An entry whose `SizeOfImage` is zero must not be published as unlinked.
    ///
    /// No image is nought bytes long, so the member did not come from a loader.
    #[test]
    fn an_entry_with_no_image_size_is_undecided_rather_than_accused() {
        let mut image = populated_image();
        image.put_u32(
            LDR_HIDDEN_ALLOC + off::POOL_HEADER_SIZE + off::LDR_SIZE_OF_IMAGE,
            0,
        );
        let profile = hook_profile(image, &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);
        let coincidence = sweep
            .modules
            .iter()
            .find(|module| module.pool_header == LDR_HIDDEN_ALLOC)
            .expect("the entry is still recovered");
        assert_eq!(coincidence.size, Some(0));
        assert_eq!(coincidence.in_loaded_list, None);
        assert_eq!(coincidence.to_json()["unlinked"], false);
        assert!(
            coincidence
                .notes
                .iter()
                .any(|note| note.contains("describes no image")),
            "{:?}",
            coincidence.notes
        );
    }

    /// An entry claiming an image larger than the capture must not be published
    /// as unlinked.
    ///
    /// The fixture holds 192 KiB, so two gigabytes of `SizeOfImage` is memory
    /// the machine did not have, let alone hold a driver in.
    #[test]
    fn an_entry_whose_image_could_not_fit_the_capture_is_undecided_rather_than_accused() {
        let mut image = populated_image();
        image.put_u32(
            LDR_HIDDEN_ALLOC + off::POOL_HEADER_SIZE + off::LDR_SIZE_OF_IMAGE,
            0x8000_0000,
        );
        let profile = hook_profile(image, &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);
        let coincidence = sweep
            .modules
            .iter()
            .find(|module| module.pool_header == LDR_HIDDEN_ALLOC)
            .expect("the entry is still recovered");
        assert_eq!(coincidence.size, Some(0x8000_0000));
        assert_eq!(
            coincidence.in_loaded_list, None,
            "a size the capture cannot hold is not evidence that the kernel's list lost an entry"
        );
        assert_eq!(coincidence.to_json()["unlinked"], false);
        assert!(
            coincidence
                .notes
                .iter()
                .any(|note| note.contains("bytes of memory the capture holds")),
            "{:?}",
            coincidence.notes
        );
    }

    #[test]
    fn without_a_complete_module_list_nothing_is_called_unlinked() {
        // The rule that stops a short list walk being reported as a rootkit.
        let profile = hook_profile(populated_image(), &hook_isf());
        let unusable = ModuleMap::unavailable("the list walk stopped at a hole");
        let sweep = loaders_of(&profile, &unusable);
        assert_eq!(sweep.modules.len(), 3);
        assert!(sweep
            .modules
            .iter()
            .all(|module| module.in_loaded_list.is_none()));
        assert!(
            sweep
                .notes
                .iter()
                .any(|note| note.contains("may be called unlinked")),
            "{:?}",
            sweep.notes
        );
    }

    #[test]
    fn a_build_without_a_loader_entry_type_is_refused_rather_than_swept() {
        let isf = hook_isf().replace(
            r#""_LDR_DATA_TABLE_ENTRY": {"size": 112,"#,
            r#""_LDR_DATA_TABLE_ENTRY_X": {"size": 112,"#,
        );
        let profile = hook_profile(populated_image(), &isf);
        let err = LdrScanSymbols::from_profile(&profile).expect_err("nothing to report");
        assert!(err.to_string().contains(TYPE_LDR_DATA_TABLE_ENTRY), "{err}");
    }

    #[test]
    fn a_cap_that_fires_is_reported_as_a_cap_and_never_as_the_end_of_the_pool() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let pool = PoolSymbols::from_profile(&profile).expect("a describable pool");
        let symbols = LdrScanSymbols::from_profile(&profile).expect("a describable build");
        let capped = KernelHookConfig {
            max_scanned_modules: 1,
            ..config(&profile)
        };
        let sweep = scan_loader_entries(&profile, &symbols, &pool, &modules, &capped)
            .expect("a runnable sweep");
        assert_eq!(sweep.modules.len(), 1);
        assert!(sweep.capped);
    }

    /// A swept entry whose name is reallocated pool must be declined, not
    /// published.
    ///
    /// This sweep exists to find `MmLd` allocations the loaded-module list no
    /// longer holds, so an entry whose pool has since been handed to something
    /// else is not a corner case here — it is half of what the sweep returns.
    /// The bytes below are one of the three `BaseDllName` strings the Windows 11
    /// parity image holds, ten characters where the fixture's `hidden.sys` is
    /// ten, so `Length` and `MaximumLength` are untouched and the only thing
    /// that changed is what the buffer says. They decode as perfectly valid
    /// UTF-16: no NUL, no unpaired surrogate, no control character, so the
    /// structural rule cannot catch them. Only the loader rule can, and this
    /// path did not apply it.
    #[test]
    fn a_swept_loader_entry_holding_reallocated_pool_is_declined_rather_than_named() {
        let damaged = "쏀쳌쳌쳌쳌쳌쳌쳌\u{f071}囚";
        assert_eq!(
            damaged.encode_utf16().count(),
            HIDDEN_NAME.encode_utf16().count(),
            "the fixture's Length must still describe the buffer, or this test would be \
             exercising the length check instead of the name check"
        );
        let mut image = populated_image();
        image.put_utf16(HIDDEN_BASE_NAME_BUFFER, damaged);
        let profile = hook_profile(image, &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = loaders_of(&profile, &modules);

        let recovered = sweep
            .modules
            .iter()
            .find(|module| module.pool_header == LDR_HIDDEN_ALLOC)
            .expect("the entry is still recovered");
        match &recovered.base_name {
            NameField::Unavailable(detail) => assert!(
                detail.contains("outside ASCII"),
                "the refusal must say why, so an examiner can tell a reallocated entry from an \
                 unreadable one: {detail}"
            ),
            other => panic!(
                "reallocated pool was published as the file name of an unlinked driver: {other:?}"
            ),
        }
        // And the rule did not fire on the two ordinary entries, which is the
        // error it must not make: refusing a real name hides a loaded module.
        let named: Vec<_> = sweep
            .modules
            .iter()
            .filter_map(|module| module.base_name.name())
            .collect();
        assert!(named.contains(&NT_NAME), "{named:?}");
        assert!(named.contains(&FLT_NAME), "{named:?}");
    }

    // ── Naming ──────────────────────────────────────────────────────────────

    #[test]
    fn every_published_irp_code_has_its_own_name_and_a_longer_array_still_reads() {
        assert_eq!(irp_name(0), "IRP_MJ_CREATE");
        assert_eq!(irp_name(14), "IRP_MJ_DEVICE_CONTROL");
        assert_eq!(irp_name(27), "IRP_MJ_PNP");
        // An index past the published codes is named by its number rather than
        // left blank, so a build with a longer array still produces rows an
        // examiner can read.
        assert_eq!(irp_name(40), "IRP_MJ_40");
    }

    #[test]
    fn a_driver_row_carries_the_dispatch_table_and_the_count_that_left_it() {
        let profile = hook_profile(populated_image(), &hook_isf());
        let modules = ModuleMap::from_profile(&profile);
        let sweep = drivers_of(&profile, &modules);
        let flt = sweep
            .drivers
            .iter()
            .find(|d| d.pool_header == DRIVER_FLT_ALLOC)
            .expect("the listed driver");
        let value = flt.to_json();
        assert_eq!(value["irp_count"], 28);
        assert_eq!(value["irps_outside_owner"], 1);
        assert_eq!(value["name"]["name"], FLT_DRIVER_PATH);
        assert_eq!(value["service_key"]["name"], FLT_SERVICE_KEY);
        assert_eq!(value["type_verified"], true);
        assert_eq!(
            value["irps"][HOOKED_IRP_INDEX as usize]["in_owning_driver"],
            false
        );
    }
}
