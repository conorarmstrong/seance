//! The device tree: which driver owns which device, and what is attached on
//! top of it (`ROADMAP` §5.3, upstream's `devicetree`).
//!
//! # What an examiner learns
//!
//! **Where a filter driver inserted itself.** Windows lets a driver attach its
//! own device object on top of another driver's, so that every request to the
//! lower device passes through it first. That is how a legitimate filter works
//! — a volume encryptor, an antivirus, a USB class filter — and it is how a
//! rootkit intercepts disk, keyboard or network I/O without patching any code.
//! The attachment is visible in memory as a chain, and the question this stage
//! answers is which driver is on top of whose device.
//!
//! # The drivers are not swept again
//!
//! They come from the `kernel_hooks` stage's own pool sweep, passed in. A second
//! sweep is a second chance for two records to disagree about which drivers the
//! machine has, which is the same reason the `ModuleMap` is shared.
//!
//! # A device's name comes from its object header, and may not be there
//!
//! A device object is a named kernel object, so its name lives in the
//! `_OBJECT_HEADER_NAME_INFO` in front of it — reached through the same
//! `handles_name` machinery the handle table uses, so a device named here and a
//! device named there cannot differ. Many devices are **unnamed**, which is
//! ordinary: a name is how user mode opens a device, and a device only
//! reachable from its own driver needs none. `Unnamed` and "the name could not
//! be read" are different answers and are kept apart.
//!
//! # The device-type table is Microsoft's, not a transcription
//!
//! `FILE_DEVICE_*` codes are published constants from the Windows Driver Kit's
//! `wdm.h`. The table below carries the ones that header defines; a code it does
//! not define is reported as the **number** rather than as `UNKNOWN`, because an
//! examiner can look up a number and cannot look up a word this build invented.

use std::collections::BTreeSet;
use std::sync::Arc;

use seance_core::io::IncompleteReason;
use seance_memory::binding::first_member;
use seance_memory::object::StructReader;
use seance_memory::Incomplete;
use serde_json::{json, Value};

use crate::handles::name::{generic_name, HandleName, NameSymbols};
use crate::kernel_hooks::drivers::DriverRecord;
use crate::profile::WindowsProfile;

/// Devices one driver's `NextDevice` chain will yield.
///
/// A real driver owns a handful; `storport` owns dozens. This bounds a corrupt
/// chain and reaching it is reported as a cap.
pub const MAX_DEVICES_PER_DRIVER: usize = 4096;

/// How deep an `AttachedDevice` stack will be followed.
///
/// A real stack is two to six deep. A self-referential `AttachedDevice` — which
/// no healthy kernel produces, and which a smeared acquisition does — would
/// otherwise never end.
pub const MAX_ATTACHED_DEPTH: usize = 64;

/// `FILE_DEVICE_*` device types, as the Windows Driver Kit's `wdm.h` defines
/// them.
///
/// The name for a code that header does not define is deliberately absent: see
/// the module comment.
pub const DEVICE_TYPES: &[(u32, &str)] = &[
    (0x00000001, "FILE_DEVICE_BEEP"),
    (0x00000002, "FILE_DEVICE_CD_ROM"),
    (0x00000003, "FILE_DEVICE_CD_ROM_FILE_SYSTEM"),
    (0x00000004, "FILE_DEVICE_CONTROLLER"),
    (0x00000005, "FILE_DEVICE_DATALINK"),
    (0x00000006, "FILE_DEVICE_DFS"),
    (0x00000007, "FILE_DEVICE_DISK"),
    (0x00000008, "FILE_DEVICE_DISK_FILE_SYSTEM"),
    (0x00000009, "FILE_DEVICE_FILE_SYSTEM"),
    (0x0000000A, "FILE_DEVICE_INPORT_PORT"),
    (0x0000000B, "FILE_DEVICE_KEYBOARD"),
    (0x0000000C, "FILE_DEVICE_MAILSLOT"),
    (0x0000000D, "FILE_DEVICE_MIDI_IN"),
    (0x0000000E, "FILE_DEVICE_MIDI_OUT"),
    (0x0000000F, "FILE_DEVICE_MOUSE"),
    (0x00000010, "FILE_DEVICE_MULTI_UNC_PROVIDER"),
    (0x00000011, "FILE_DEVICE_NAMED_PIPE"),
    (0x00000012, "FILE_DEVICE_NETWORK"),
    (0x00000013, "FILE_DEVICE_NETWORK_BROWSER"),
    (0x00000014, "FILE_DEVICE_NETWORK_FILE_SYSTEM"),
    (0x00000015, "FILE_DEVICE_NULL"),
    (0x00000016, "FILE_DEVICE_PARALLEL_PORT"),
    (0x00000017, "FILE_DEVICE_PHYSICAL_NETCARD"),
    (0x00000018, "FILE_DEVICE_PRINTER"),
    (0x00000019, "FILE_DEVICE_SCANNER"),
    (0x0000001A, "FILE_DEVICE_SERIAL_MOUSE_PORT"),
    (0x0000001B, "FILE_DEVICE_SERIAL_PORT"),
    (0x0000001C, "FILE_DEVICE_SCREEN"),
    (0x0000001D, "FILE_DEVICE_SOUND"),
    (0x0000001E, "FILE_DEVICE_STREAMS"),
    (0x0000001F, "FILE_DEVICE_TAPE"),
    (0x00000020, "FILE_DEVICE_TAPE_FILE_SYSTEM"),
    (0x00000021, "FILE_DEVICE_TRANSPORT"),
    (0x00000022, "FILE_DEVICE_UNKNOWN"),
    (0x00000023, "FILE_DEVICE_VIDEO"),
    (0x00000024, "FILE_DEVICE_VIRTUAL_DISK"),
    (0x00000025, "FILE_DEVICE_WAVE_IN"),
    (0x00000026, "FILE_DEVICE_WAVE_OUT"),
    (0x00000027, "FILE_DEVICE_8042_PORT"),
    (0x00000028, "FILE_DEVICE_NETWORK_REDIRECTOR"),
    (0x00000029, "FILE_DEVICE_BATTERY"),
    (0x0000002A, "FILE_DEVICE_BUS_EXTENDER"),
    (0x0000002B, "FILE_DEVICE_MODEM"),
    (0x0000002C, "FILE_DEVICE_VDM"),
    (0x0000002D, "FILE_DEVICE_MASS_STORAGE"),
    (0x0000002E, "FILE_DEVICE_SMB"),
    (0x0000002F, "FILE_DEVICE_KS"),
    (0x00000030, "FILE_DEVICE_CHANGER"),
    (0x00000031, "FILE_DEVICE_SMARTCARD"),
    (0x00000032, "FILE_DEVICE_ACPI"),
    (0x00000033, "FILE_DEVICE_DVD"),
    (0x00000034, "FILE_DEVICE_FULLSCREEN_VIDEO"),
    (0x00000035, "FILE_DEVICE_DFS_FILE_SYSTEM"),
    (0x00000036, "FILE_DEVICE_DFS_VOLUME"),
    (0x00000037, "FILE_DEVICE_SERENUM"),
    (0x00000038, "FILE_DEVICE_TERMSRV"),
    (0x00000039, "FILE_DEVICE_KSEC"),
    (0x0000003A, "FILE_DEVICE_FIPS"),
    (0x0000003B, "FILE_DEVICE_INFINIBAND"),
    (0x0000003E, "FILE_DEVICE_VMBUS"),
    (0x0000003F, "FILE_DEVICE_CRYPT_PROVIDER"),
    (0x00000040, "FILE_DEVICE_WPD"),
    (0x00000041, "FILE_DEVICE_BLUETOOTH"),
    (0x00000042, "FILE_DEVICE_MT_COMPOSITE"),
    (0x00000043, "FILE_DEVICE_MT_TRANSPORT"),
    (0x00000044, "FILE_DEVICE_BIOMETRIC"),
    (0x00000045, "FILE_DEVICE_PMI"),
    (0x00000046, "FILE_DEVICE_EHSTOR"),
    (0x00000047, "FILE_DEVICE_DEVAPI"),
    (0x00000048, "FILE_DEVICE_GPIO"),
    (0x00000049, "FILE_DEVICE_USBEX"),
    (0x00000050, "FILE_DEVICE_CONSOLE"),
    (0x00000051, "FILE_DEVICE_NFP"),
    (0x00000052, "FILE_DEVICE_SYSENV"),
    (0x00000053, "FILE_DEVICE_VIRTUAL_BLOCK"),
    (0x00000054, "FILE_DEVICE_POINT_OF_SERVICE"),
    (0x00000055, "FILE_DEVICE_STORAGE_REPLICATION"),
    (0x00000056, "FILE_DEVICE_TRUST_ENV"),
    (0x00000057, "FILE_DEVICE_UCM"),
    (0x00000058, "FILE_DEVICE_UCMTCPCI"),
    (0x00000059, "FILE_DEVICE_PERSISTENT_MEMORY"),
    (0x0000005A, "FILE_DEVICE_NVDIMM"),
    (0x0000005B, "FILE_DEVICE_HOLOGRAPHIC"),
    (0x0000005C, "FILE_DEVICE_SDFXHCI"),
    (0x0000005D, "FILE_DEVICE_UCMUCSI"),
];

/// The name `wdm.h` gives a device type, when it gives one.
pub fn device_type_name(code: u32) -> Option<&'static str> {
    DEVICE_TYPES
        .iter()
        .find(|(value, _)| *value == code)
        .map(|(_, name)| *name)
}

/// What stopped the whole survey.
#[derive(Debug, Clone)]
pub enum DeviceTreeError {
    Unsupported { detail: String },
}

impl DeviceTreeError {
    pub fn unsupported(detail: impl Into<String>) -> Self {
        Self::Unsupported {
            detail: detail.into(),
        }
    }

    pub fn class(&self) -> &'static str {
        "unsupported_build"
    }

    pub fn detail(&self) -> String {
        match self {
            Self::Unsupported { detail } => detail.clone(),
        }
    }

    pub fn incomplete_reason(&self) -> IncompleteReason {
        IncompleteReason::UnresolvedStructure
    }
}

impl std::fmt::Display for DeviceTreeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.detail())
    }
}

/// The members this build's device objects are read through.
#[derive(Debug, Clone)]
pub struct DeviceTreeSymbols {
    /// `_DRIVER_OBJECT` path to its first device.
    pub driver_device: String,
    /// `_DEVICE_OBJECT` paths.
    pub next_device: String,
    pub attached_device: String,
    pub device_driver: String,
    pub device_type: Option<String>,
    /// How an object's name is reached, shared with the handle table.
    pub names: NameSymbols,
}

impl DeviceTreeSymbols {
    /// Resolve what this build declares.
    ///
    /// Measured across the 1,724 `ntkrnlmp.pdb` ISFs on this machine: all 1,650
    /// that declare `_DEVICE_OBJECT` declare `DriverObject`, `NextDevice`,
    /// `AttachedDevice` and `DeviceType`, and all 1,650 declare
    /// `_DRIVER_OBJECT.DeviceObject`. An absence here is a build unlike
    /// anything measured, and is answered rather than assumed.
    pub fn from_profile(profile: &WindowsProfile) -> Result<Self, DeviceTreeError> {
        let reader = StructReader::new(
            Arc::clone(&profile.kernel_space),
            Arc::clone(&profile.symbols),
        );
        if !profile.symbols.has_type("_DEVICE_OBJECT") {
            return Err(DeviceTreeError::unsupported(
                "this build's symbol table has no '_DEVICE_OBJECT', so no device can be read and \
                 nothing can be said about where a filter driver attached itself",
            ));
        }
        let required =
            |type_name: &'static str, member: &'static str, what: &str| match first_member(
                &reader,
                type_name,
                &[member],
            ) {
                Ok(Some(path)) => Ok(path.to_string()),
                Ok(None) => Err(DeviceTreeError::unsupported(format!(
                    "this build declares no {type_name}.{member}, so {what}"
                ))),
                Err(err) => Err(DeviceTreeError::unsupported(format!(
                    "the symbol table could not answer for {type_name}.{member}: {err}"
                ))),
            };
        Ok(Self {
            driver_device: required(
                "_DRIVER_OBJECT",
                "DeviceObject",
                "a driver's own devices cannot be reached at all",
            )?,
            next_device: required(
                "_DEVICE_OBJECT",
                "NextDevice",
                "only the first device of each driver could be read, and a driver's remaining \
                 devices would be missing with nothing to say so",
            )?,
            attached_device: required(
                "_DEVICE_OBJECT",
                "AttachedDevice",
                "the attachment stack cannot be walked -- which is the whole question this \
                 stage exists for, since that is where a filter driver inserts itself",
            )?,
            device_driver: required(
                "_DEVICE_OBJECT",
                "DriverObject",
                "an attached device could not be traced back to the driver that owns it, so an \
                 attachment could not be attributed",
            )?,
            device_type: first_member(&reader, "_DEVICE_OBJECT", &["DeviceType"])
                .ok()
                .flatten()
                .map(str::to_string),
            names: NameSymbols::from_profile(profile).map_err(|err| {
                DeviceTreeError::unsupported(format!(
                    "this build's object names cannot be read: {err}. A device tree of unnamed \
                     devices would say which driver owns how many devices and nothing about \
                     which devices they are."
                ))
            })?,
        })
    }

    pub fn to_json(&self) -> Value {
        json!({
            "driver_device_path": self.driver_device,
            "next_device_path": self.next_device,
            "attached_device_path": self.attached_device,
            "device_driver_path": self.device_driver,
            "device_type_path": self.device_type,
            "object_body_offset": self.names.body_offset,
            "basis":
                "Every path resolved from this build's own symbol table. A device's name comes \
                 from the `_OBJECT_HEADER_NAME_INFO` in front of it, reached through the same \
                 code the handle table uses, so a device named here and the same device named \
                 there cannot differ.",
        })
    }
}

/// One device attached on top of another.
#[derive(Debug, Clone)]
pub struct AttachedDevice {
    /// Depth above the device the driver owns: 1 is directly on top of it.
    pub level: usize,
    pub device: u64,
    pub name: HandleName,
    /// The driver that owns *this* device — the filter, in other words.
    pub driver: Option<u64>,
    pub driver_name: Option<String>,
    pub device_type: Option<u32>,
}

impl AttachedDevice {
    pub fn to_json(&self) -> Value {
        json!({
            "level": self.level,
            "device": format!("{:#018x}", self.device),
            "name": self.name.to_json(),
            "attaching_driver": self.driver.map(|d| format!("{d:#018x}")),
            "attaching_driver_name": self.driver_name,
            "device_type": self.device_type,
            "device_type_name": self.device_type.and_then(device_type_name),
        })
    }
}

/// One device a driver owns, with whatever is attached above it.
#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub device: u64,
    pub name: HandleName,
    pub device_type: Option<u32>,
    pub attached: Vec<AttachedDevice>,
    /// Why the attachment walk stopped, when it did not run out naturally.
    pub attached_stop: Option<String>,
}

impl DeviceRecord {
    pub fn to_json(&self) -> Value {
        json!({
            "device": format!("{:#018x}", self.device),
            "name": self.name.to_json(),
            "device_type": self.device_type,
            "device_type_name": self.device_type.and_then(device_type_name),
            "device_type_note": self.device_type.filter(|c| device_type_name(*c).is_none()).map(
                |code| format!(
                    "the Windows Driver Kit's wdm.h defines no FILE_DEVICE_* name for {code} \
                     ({code:#x}); the number is reported as read rather than as a word this \
                     build invented"
                )
            ),
            "attached": self.attached.iter().map(AttachedDevice::to_json).collect::<Vec<_>>(),
            "attached_total": self.attached.len(),
            "attached_stop": self.attached_stop,
        })
    }
}

/// One driver and the devices it owns.
#[derive(Debug, Clone)]
pub struct DriverDevices {
    pub driver: u64,
    pub driver_name: Option<String>,
    pub devices: Vec<DeviceRecord>,
    /// Why the `NextDevice` chain stopped, when it did not end naturally.
    pub device_stop: Option<String>,
}

impl DriverDevices {
    /// Devices of this driver that something is attached on top of.
    pub fn attached_to(&self) -> usize {
        self.devices
            .iter()
            .filter(|d| !d.attached.is_empty())
            .count()
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "MemoryDriverDevices",
            "name": format!(
                "{} with {} device(s)",
                self.driver_name.clone().unwrap_or_else(|| format!("{:#018x}", self.driver)),
                self.devices.len()
            ),
            "driver": format!("{:#018x}", self.driver),
            "driver_name": self.driver_name,
            "devices": self.devices.iter().map(DeviceRecord::to_json).collect::<Vec<_>>(),
            "devices_total": self.devices.len(),
            "devices_with_something_attached": self.attached_to(),
            "device_stop": self.device_stop,
        })
    }
}

/// What one survey produced.
#[derive(Debug, Clone)]
pub struct DeviceTree {
    pub symbols: DeviceTreeSymbols,
    pub drivers: Vec<DriverDevices>,
    /// Drivers handed to this survey, including those with no device at all.
    pub drivers_examined: u64,
    pub notes: Vec<String>,
    pub capped: Option<String>,
}

impl DeviceTree {
    pub fn devices(&self) -> usize {
        self.drivers.iter().map(|d| d.devices.len()).sum()
    }

    pub fn attachments(&self) -> usize {
        self.drivers
            .iter()
            .flat_map(|d| d.devices.iter())
            .map(|d| d.attached.len())
            .sum()
    }

    /// Attachments where the attaching driver is **not** the driver that owns
    /// the device beneath it — which is what a filter is.
    pub fn foreign_attachments(&self) -> usize {
        self.drivers
            .iter()
            .flat_map(|driver| {
                driver
                    .devices
                    .iter()
                    .flat_map(move |device| device.attached.iter().map(move |a| (driver, a)))
            })
            .filter(|(driver, attached)| attached.driver.is_some_and(|d| d != driver.driver))
            .count()
    }

    pub fn is_complete(&self) -> bool {
        self.capped.is_none()
            && self.drivers.iter().all(|d| {
                d.device_stop.is_none() && d.devices.iter().all(|dev| dev.attached_stop.is_none())
            })
    }

    pub fn incomplete(&self) -> Vec<Incomplete> {
        let mut out = Vec::new();
        if let Some(capped) = &self.capped {
            out.push(Incomplete::new(
                IncompleteReason::CapReached,
                capped.clone(),
            ));
        }
        for driver in &self.drivers {
            if let Some(stop) = &driver.device_stop {
                out.push(Incomplete::new(
                    IncompleteReason::ShortRead,
                    format!(
                        "the device chain of the driver at {:#018x} stopped: {stop}. It may own \
                         devices this walk did not reach.",
                        driver.driver
                    ),
                ));
            }
            for device in &driver.devices {
                if let Some(stop) = &device.attached_stop {
                    out.push(Incomplete::new(
                        IncompleteReason::ShortRead,
                        format!(
                            "the attachment stack above the device at {:#018x} stopped: {stop}. \
                             Something may be attached above it that this walk did not reach, \
                             which is exactly what this stage is read for.",
                            device.device
                        ),
                    ));
                }
            }
        }
        out
    }

    pub fn describe(&self) -> String {
        format!(
            "{} driver(s) own {} device(s) between them, with {} attachment(s) above those \
             devices; {} of the attachments are by a driver other than the one owning the \
             device beneath, which is what a filter driver is. An attachment is not by itself a \
             finding: a volume encryptor, an antivirus and a USB class filter all attach.",
            self.drivers.len(),
            self.devices(),
            self.attachments(),
            self.foreign_attachments()
        )
    }

    pub fn to_json(&self) -> Value {
        json!({
            "symbols": self.symbols.to_json(),
            "drivers": self.drivers.iter().map(DriverDevices::to_json).collect::<Vec<_>>(),
            "drivers_total": self.drivers.len(),
            "drivers_examined": self.drivers_examined,
            "devices_total": self.devices(),
            "attachments_total": self.attachments(),
            "foreign_attachments": self.foreign_attachments(),
            "statement": self.describe(),
            "notes": self.notes,
            "content_complete": self.is_complete(),
            "incomplete": self.incomplete().iter().map(Incomplete::to_json).collect::<Vec<_>>(),
        })
    }
}

/// Walk the device tree of every driver handed in.
///
/// The drivers come from the `kernel_hooks` stage's pool sweep rather than a
/// second sweep of this stage's own: see the module comment.
pub fn survey_devices(
    profile: &WindowsProfile,
    symbols: &DeviceTreeSymbols,
    drivers: &[DriverRecord],
) -> DeviceTree {
    let reader = StructReader::new(
        Arc::clone(&profile.kernel_space),
        Arc::clone(&profile.symbols),
    );
    let mut out = DeviceTree {
        symbols: symbols.clone(),
        drivers: Vec::new(),
        drivers_examined: drivers.len() as u64,
        notes: Vec::new(),
        capped: None,
    };

    for driver in drivers {
        let mut record = DriverDevices {
            driver: driver.address,
            driver_name: driver.name.name().map(str::to_string),
            devices: Vec::new(),
            device_stop: None,
        };
        let first = match reader
            .object(driver.address, "_DRIVER_OBJECT")
            .and_then(|object| object.pointer(&symbols.driver_device))
        {
            Ok(value) => value,
            Err(err) => {
                record.device_stop = Some(format!("its first device could not be read: {err}"));
                out.drivers.push(record);
                continue;
            }
        };

        // The `NextDevice` chain. A visited set, because a chain that points
        // back into itself is what a smeared acquisition produces and an
        // unbounded walk in an ingest is an outage.
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        let mut next = first;
        while next != 0 {
            if !seance_memory::object::is_canonical(next, 8) {
                record.device_stop = Some(format!(
                    "the chain reached {next:#018x}, which is not a canonical address"
                ));
                break;
            }
            if !seen.insert(next) {
                record.device_stop = Some(format!(
                    "the chain returned to {next:#018x}, which it had already visited"
                ));
                break;
            }
            if record.devices.len() >= MAX_DEVICES_PER_DRIVER {
                record.device_stop = Some(format!(
                    "the device cap of {MAX_DEVICES_PER_DRIVER} was reached"
                ));
                break;
            }
            let Ok(device) = reader.object(next, "_DEVICE_OBJECT") else {
                record.device_stop = Some(format!("the device at {next:#018x} could not be read"));
                break;
            };
            let mut entry = DeviceRecord {
                device: next,
                name: device_name(&reader, symbols, next),
                device_type: symbols
                    .device_type
                    .as_deref()
                    .and_then(|path| device.unsigned(path).ok())
                    .map(|value| value as u32),
                attached: Vec::new(),
                attached_stop: None,
            };
            walk_attached(&reader, symbols, &device, &mut entry);
            record.devices.push(entry);

            match device.pointer(&symbols.next_device) {
                Ok(value) => next = value,
                Err(err) => {
                    record.device_stop =
                        Some(format!("the next-device link would not read: {err}"));
                    break;
                }
            }
        }
        out.drivers.push(record);
    }
    out
}

/// The name in the object header in front of a device.
fn device_name(reader: &StructReader, symbols: &DeviceTreeSymbols, device: u64) -> HandleName {
    match device.checked_sub(symbols.names.body_offset) {
        Some(header) => generic_name(reader, &symbols.names, header),
        None => HandleName::Unavailable(
            "the object header in front of this device would lie below the address space"
                .to_string(),
        ),
    }
}

/// Walk what is attached above one device.
fn walk_attached(
    reader: &StructReader,
    symbols: &DeviceTreeSymbols,
    device: &seance_memory::object::Obj,
    out: &mut DeviceRecord,
) {
    let mut seen: BTreeSet<u64> = BTreeSet::new();
    seen.insert(out.device);
    let mut next = match device.pointer(&symbols.attached_device) {
        Ok(value) => value,
        Err(err) => {
            out.attached_stop = Some(format!("the attachment link would not read: {err}"));
            return;
        }
    };
    let mut level = 1;
    while next != 0 {
        if !seance_memory::object::is_canonical(next, 8) {
            out.attached_stop = Some(format!(
                "the stack reached {next:#018x}, which is not a canonical address"
            ));
            return;
        }
        if !seen.insert(next) {
            // No healthy kernel produces this; a smeared acquisition and a
            // corrupted page do, and the reference captures on this machine
            // show the class is not hypothetical.
            out.attached_stop = Some(format!(
                "the stack returned to {next:#018x}, which it had already visited: a device \
                 attached above itself, which no healthy kernel produces"
            ));
            return;
        }
        if level > MAX_ATTACHED_DEPTH {
            out.attached_stop = Some(format!(
                "the attachment depth ceiling of {MAX_ATTACHED_DEPTH} was reached; a real stack \
                 is two to six deep"
            ));
            return;
        }
        let Ok(attached) = reader.object(next, "_DEVICE_OBJECT") else {
            out.attached_stop = Some(format!(
                "the device attached at {next:#018x} could not be read"
            ));
            return;
        };
        let driver = attached
            .pointer(&symbols.device_driver)
            .ok()
            .filter(|d| *d != 0);
        let driver_name = driver.and_then(|d| {
            reader
                .object(d, "_DRIVER_OBJECT")
                .ok()
                .and_then(|object| crate::poolscan::unicode_string(&object, "DriverName").ok())
                .flatten()
        });
        out.attached.push(AttachedDevice {
            level,
            device: next,
            name: device_name(reader, symbols, next),
            driver,
            driver_name,
            device_type: symbols
                .device_type
                .as_deref()
                .and_then(|path| attached.unsigned(path).ok())
                .map(|value| value as u32),
        });
        level += 1;
        match attached.pointer(&symbols.attached_device) {
            Ok(value) => next = value,
            Err(err) => {
                out.attached_stop = Some(format!("the next attachment link would not read: {err}"));
                return;
            }
        }
    }
}
