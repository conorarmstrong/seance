//! The device tree: where a filter attached, an unnamed device, a type the WDK
//! does not define, and a stack that eats itself.
//!
//! The fixture is the handles tier's, extended with the device members and one
//! filter attachment — which is right rather than convenient: the device name
//! comes from the same object-header machinery the handle table uses, and a
//! second fixture for it would be a second implementation of that lookup.

use super::device_tree::*;
use crate::handles::name::HandleName;
use crate::handles::test_support::{
    win10_image, win10_profile, win10_symbols, WIN10_ATTACHED_DEVICE, WIN10_DEVICE_OBJECT,
    WIN10_DRIVER_OBJECT, WIN10_FILTER_DRIVER, WIN10_SECOND_DEVICE,
};
use crate::kernel_hooks::drivers::DriverRecord;
use crate::modules::NameField;
use seance_memory::Architecture;

/// The driver the fixture's tree hangs off, as the pool sweep would hand it
/// over.
fn driver(address: u64, name: &str) -> DriverRecord {
    DriverRecord {
        address,
        pool_header: 0,
        tag: "Driv".to_string(),
        freed: false,
        type_verified: true,
        object_type: Some("Driver".to_string()),
        start: Some(0x1_0000),
        size: Some(0x1000),
        name: NameField::Name(name.to_string()),
        service_key: NameField::Empty,
        init: None,
        unload: None,
        irps: Vec::new(),
        notes: Vec::new(),
    }
}

fn survey(drivers: &[DriverRecord]) -> DeviceTree {
    let profile = win10_profile();
    let symbols = DeviceTreeSymbols::from_profile(&profile).expect("this build declares them");
    survey_devices(&profile, &symbols, drivers)
}

/// **The whole point: a device attached above another driver's device.**
#[test]
fn a_filter_attached_above_a_device_is_reported_with_the_driver_that_attached_it() {
    let out = survey(&[driver(WIN10_DRIVER_OBJECT, "\\Driver\\disk")]);
    assert_eq!(out.drivers.len(), 1);
    let record = &out.drivers[0];
    assert_eq!(record.devices.len(), 2, "the NextDevice chain walked whole");

    let first = &record.devices[0];
    assert_eq!(first.device, WIN10_DEVICE_OBJECT);
    assert_eq!(first.attached.len(), 1);
    let attached = &first.attached[0];
    assert_eq!(attached.level, 1);
    assert_eq!(attached.device, WIN10_ATTACHED_DEVICE);
    assert_eq!(attached.driver, Some(WIN10_FILTER_DRIVER));
    assert_eq!(
        attached.driver_name.as_deref(),
        Some("\\Driver\\volsnap"),
        "the attaching driver is named from its own _DRIVER_OBJECT"
    );
    assert_eq!(attached.name.text(), Some("FilterDevice"));

    // And it is a FOREIGN attachment: the attaching driver is not the one that
    // owns the device beneath, which is what a filter is.
    assert_eq!(out.foreign_attachments(), 1);
    assert_eq!(out.attachments(), 1);
    assert_eq!(out.devices(), 2);
    assert!(out.is_complete());
    assert!(
        out.describe().contains("not by itself a finding"),
        "got {}",
        out.describe()
    );
}

/// The device's own name comes from its object header, and an **unnamed**
/// device is not a device whose name could not be read.
#[test]
fn an_unnamed_device_is_distinguished_from_one_whose_name_would_not_read() {
    let out = survey(&[driver(WIN10_DRIVER_OBJECT, "\\Driver\\disk")]);
    let devices = &out.drivers[0].devices;
    assert_eq!(devices[0].name.text(), Some("HarddiskVolume2"));
    assert!(
        matches!(devices[1].name, HandleName::Unnamed),
        "the second device has no name info, which is ordinary: {:?}",
        devices[1].name
    );
    assert!(!devices[1].name.is_unavailable());
    // The JSON keeps the two apart, so a viewer cannot render one as the other.
    let j = devices[1].to_json();
    assert_eq!(j["name"]["kind"], serde_json::json!("unnamed"));
}

/// **A device type the WDK does not define is reported as the number**, never
/// as a word this build invented.
#[test]
fn a_device_type_the_wdk_does_not_define_is_reported_as_its_number() {
    let out = survey(&[driver(WIN10_DRIVER_OBJECT, "\\Driver\\disk")]);
    let devices = &out.drivers[0].devices;
    assert_eq!(devices[0].device_type, Some(0x7));
    assert_eq!(device_type_name(0x7), Some("FILE_DEVICE_DISK"));
    assert_eq!(devices[1].device_type, Some(0x7FFF));
    assert_eq!(device_type_name(0x7FFF), None);
    let j = devices[1].to_json();
    assert_eq!(j["device_type"], serde_json::json!(0x7FFF));
    assert!(j["device_type_name"].is_null());
    assert!(
        j["device_type_note"]
            .as_str()
            .unwrap_or_default()
            .contains("defines no FILE_DEVICE_* name"),
        "got {:?}",
        j["device_type_note"]
    );
    // And a defined code carries no note.
    assert!(devices[0].to_json()["device_type_note"].is_null());
}

/// A driver with no device at all is a record with none — not an absence.
#[test]
fn a_driver_with_no_device_is_a_record_with_no_devices() {
    // The filter driver's own `DeviceObject` is null in the fixture.
    let out = survey(&[driver(WIN10_FILTER_DRIVER, "\\Driver\\volsnap")]);
    assert_eq!(out.drivers.len(), 1);
    assert!(out.drivers[0].devices.is_empty());
    assert!(out.drivers[0].device_stop.is_none(), "nothing went wrong");
    assert_eq!(out.devices(), 0);
    assert!(out.is_complete());
}

/// **A device attached above itself is refused and named**, because no healthy
/// kernel produces it and an unbounded walk in an ingest is an outage.
#[test]
fn a_self_referential_attachment_stops_the_walk_and_says_what_it_saw() {
    let mut image = win10_image();
    // Point the attached device's own `AttachedDevice` back at itself.
    image.put_u64(WIN10_ATTACHED_DEVICE + 24, WIN10_ATTACHED_DEVICE);
    let profile = crate::poolscan::test_support::profile(
        image.layer(),
        win10_symbols(),
        Architecture::X64,
        10,
        0,
        Some(19041),
    );
    let symbols = DeviceTreeSymbols::from_profile(&profile).expect("symbols");
    let out = survey_devices(
        &profile,
        &symbols,
        &[driver(WIN10_DRIVER_OBJECT, "\\Driver\\disk")],
    );
    let first = &out.drivers[0].devices[0];
    let stop = first.attached_stop.clone().expect("the walk stopped");
    assert!(
        stop.contains("already visited") && stop.contains("no healthy kernel"),
        "got {stop}"
    );
    assert!(!out.is_complete());
    // And the incompleteness says what is at stake: something may be attached
    // above it that was not reached.
    let incomplete = out.incomplete();
    assert!(
        incomplete
            .iter()
            .any(|i| i.detail.contains("what this stage is read for")),
        "got {incomplete:?}"
    );
}

/// A `NextDevice` chain that points back into itself is refused the same way.
#[test]
fn a_cycle_in_the_device_chain_stops_it_and_is_stated() {
    let mut image = win10_image();
    image.put_u64(WIN10_SECOND_DEVICE + 16, WIN10_DEVICE_OBJECT);
    let profile = crate::poolscan::test_support::profile(
        image.layer(),
        win10_symbols(),
        Architecture::X64,
        10,
        0,
        Some(19041),
    );
    let symbols = DeviceTreeSymbols::from_profile(&profile).expect("symbols");
    let out = survey_devices(
        &profile,
        &symbols,
        &[driver(WIN10_DRIVER_OBJECT, "\\Driver\\disk")],
    );
    let record = &out.drivers[0];
    assert_eq!(record.devices.len(), 2, "both real devices were still read");
    let stop = record.device_stop.clone().expect("the chain stopped");
    assert!(stop.contains("already visited"), "got {stop}");
    assert!(!out.is_complete());
}

/// Every resolved path is on the record, including the object-body offset a
/// device's name depends on.
#[test]
fn the_resolved_paths_are_published_with_their_basis() {
    let out = survey(&[driver(WIN10_DRIVER_OBJECT, "\\Driver\\disk")]);
    let j = out.symbols.to_json();
    assert_eq!(j["next_device_path"], serde_json::json!("NextDevice"));
    assert_eq!(
        j["attached_device_path"],
        serde_json::json!("AttachedDevice")
    );
    assert_eq!(j["device_driver_path"], serde_json::json!("DriverObject"));
    assert_eq!(j["device_type_path"], serde_json::json!("DeviceType"));
    assert_eq!(j["object_body_offset"], serde_json::json!(48));
    assert!(
        j["basis"]
            .as_str()
            .unwrap_or_default()
            .contains("the same code the handle table uses"),
        "got {:?}",
        j["basis"]
    );
}

/// The device-type table is the WDK's, and the two ends of it are what a real
/// machine actually carries.
#[test]
fn the_device_type_table_is_the_wdks_own() {
    assert_eq!(device_type_name(0x00000001), Some("FILE_DEVICE_BEEP"));
    assert_eq!(device_type_name(0x00000007), Some("FILE_DEVICE_DISK"));
    assert_eq!(device_type_name(0x00000022), Some("FILE_DEVICE_UNKNOWN"));
    assert_eq!(
        device_type_name(0x0000002D),
        Some("FILE_DEVICE_MASS_STORAGE")
    );
    assert_eq!(device_type_name(0x0000003E), Some("FILE_DEVICE_VMBUS"));
    // Codes between the defined ones are not invented.
    assert_eq!(device_type_name(0x0000003C), None);
    assert_eq!(device_type_name(0), None);
    // And no two codes share a name, which a copy-paste in that table would
    // produce.
    let mut names: Vec<&str> = DEVICE_TYPES.iter().map(|(_, name)| *name).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(names.len(), before, "a duplicated FILE_DEVICE_* name");
}
