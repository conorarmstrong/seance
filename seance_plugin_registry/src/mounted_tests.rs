//! `MountedDevices` — stated before it was decoded.
//!
//! # Ground truth
//!
//! `reference/plaso/test_data/SYSTEM`, whose `MountedDevices` holds eleven
//! values, measured off the bytes:
//!
//! ```text
//! \DosDevices\C:  12 bytes  3e a0 be 5c 00 00 10 00 00 00 00 00
//! \DosDevices\A:  a floppy device instance path
//! \DosDevices\D:  an IDE CD-ROM device instance path
//! \DosDevices\E:  _??_USBSTOR#Disk&Ven_HP&Prod_v100w&Rev_1024#AA951D0000007252&0#{53f56307-…}
//! ```
//!
//! `E:` is **the same device** whose install date `devprops` decodes: the
//! serial `AA951D0000007252&0` is the serial on its `Enum\USBSTOR` key. That
//! join is the whole point of reading this key.

use super::mounted::*;

/// The real `\DosDevices\C:` bytes: an MBR signature and a partition offset.
const REAL_C: [u8; 12] = [
    0x3e, 0xa0, 0xbe, 0x5c, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00,
];

fn utf16(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

// --- The two value shapes --------------------------------------------------

/// Twelve bytes are an MBR disk signature and a partition offset.
///
/// The real `C:` is `3ea0be5c` at offset 1,048,576 — one mebibyte in, which is
/// the standard first-partition alignment and the tell that the decode is
/// right.
#[test]
fn a_twelve_byte_value_is_an_mbr_signature_and_a_partition_offset() {
    match classify_target(&REAL_C) {
        MountedTarget::MbrPartition {
            disk_signature_hex,
            partition_offset,
        } => {
            assert_eq!(disk_signature_hex, "3ea0be5c");
            assert_eq!(
                partition_offset, 1_048_576,
                "one mebibyte: the standard first-partition alignment"
            );
        }
        other => panic!("expected an MBR partition, got {other:?}"),
    }
}

/// A device instance path is recognised, and the USB serial read out of it.
#[test]
fn a_device_instance_path_yields_its_usb_serial() {
    let real = r"_??_USBSTOR#Disk&Ven_HP&Prod_v100w&Rev_1024#AA951D0000007252&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    match classify_target(&utf16(real)) {
        MountedTarget::DeviceInstance { path } => {
            assert_eq!(path, real);
            assert_eq!(
                serial_from_instance_path(&path).as_deref(),
                Some("AA951D0000007252&0"),
                "the third #-delimited field -- the same instance id the device's own \
                 Enum\\USBSTOR key carries, which is what lets the two records be joined"
            );
        }
        other => panic!("expected a device instance, got {other:?}"),
    }
}

/// A serial is read **only** from a `USBSTOR` path.
///
/// The third field means something else on other device classes, and a wrong
/// serial joined to a device is worse than no join at all.
#[test]
fn a_serial_is_read_only_from_a_usbstor_path() {
    let cdrom = r"\??\IDE#CdRomNECVMWar_VMware_IDE_CDR10_______________1.00___#5&35b0e099&0&1.0.0#{53f56308-b6bf-11d0-94f2-00a0c91efb8b}";
    assert!(
        serial_from_instance_path(cdrom).is_none(),
        "an IDE CD-ROM's third field is not a USB serial"
    );
    let floppy =
        r"\??\FDC#GENERIC_FLOPPY_DRIVE#6&2bc13940&0&0#{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";
    assert!(serial_from_instance_path(floppy).is_none());
}

/// Bytes that are neither shape are reported as bytes, not guessed at.
#[test]
fn a_value_of_neither_shape_is_reported_as_bytes() {
    // Text that decodes but is not a device path.
    match classify_target(&utf16("just some text here")) {
        MountedTarget::Unrecognised { len, head_hex } => {
            assert!(len > 0 && !head_hex.is_empty());
        }
        other => panic!("a run of text that decodes is not a device path: {other:?}"),
    }
    // And a short binary value.
    assert!(matches!(
        classify_target(&[1, 2, 3]),
        MountedTarget::Unrecognised { len: 3, .. }
    ));

    let j = MountedDevice {
        mount_name: r"\DosDevices\Z:".into(),
        mount_point: MountPoint::DriveLetter,
        drive_letter: Some("Z:".into()),
        target: classify_target(&[1, 2, 3]),
        device_serial: None,
        key_last_written: None,
    }
    .to_json();
    assert_eq!(j["content_incomplete"], serde_json::json!(true));
    assert!(
        j["content_incomplete_detail"]
            .as_str()
            .unwrap_or("")
            .contains("nothing was decoded from them"),
        "got {:?}",
        j["content_incomplete_detail"]
    );
}

// --- The mount point ------------------------------------------------------

/// A drive letter, a volume GUID, and neither.
#[test]
fn the_mount_point_forms_are_distinguished() {
    let (p, l) = classify_mount(r"\DosDevices\E:");
    assert_eq!(p, MountPoint::DriveLetter);
    assert_eq!(l.as_deref(), Some("E:"));

    let (p, l) = classify_mount(r"\??\Volume{eba74da6-5bb2-11e0-95d1-000c2971073c}");
    assert_eq!(p, MountPoint::VolumeGuid);
    assert!(l.is_none(), "a volume GUID is not a letter");

    // `\DosDevices\` with something that is not `X:` is still a DOS device,
    // and carries no letter rather than a guessed one.
    let (p, l) = classify_mount(r"\DosDevices\SomethingElse");
    assert_eq!(p, MountPoint::DriveLetter);
    assert!(l.is_none());

    assert_eq!(classify_mount("Whatever").0, MountPoint::Other);
}

/// The key is recognised, and nothing near it is.
#[test]
fn the_mounted_devices_key_is_recognised_and_nothing_else_is() {
    assert!(is_mounted_devices_key(
        r"CMI-CreateHive{F10156BE}\MountedDevices"
    ));
    assert!(is_mounted_devices_key(r"ROOT\mounteddevices"));
    for k in [
        r"ROOT\MountedDevices\Deeper",
        r"ROOT\ControlSet001\Services\MountMgr",
        r"ROOT",
    ] {
        assert!(!is_mounted_devices_key(k), "for {k}");
    }
}

// --- What the record refuses ----------------------------------------------

/// A mapping is an **assignment**, not an observation that the device was
/// present when the evidence was taken.
///
/// `MountedDevices` is persistent: a letter stays recorded for a device not
/// attached in years, and letters are reassigned. Without this, a record
/// reading "E: was the HP v100w" invites "so it was plugged in".
#[test]
fn a_mapping_does_not_claim_the_device_was_present_at_acquisition() {
    let real = r"_??_USBSTOR#Disk&Ven_HP&Prod_v100w&Rev_1024#AA951D0000007252&0#{53f56307-b6bf-11d0-94f2-00a0c91efb8b}";
    let target = classify_target(&utf16(real));
    let j = MountedDevice {
        mount_name: r"\DosDevices\E:".into(),
        mount_point: MountPoint::DriveLetter,
        drive_letter: Some("E:".into()),
        device_serial: serial_from_instance_path(real),
        target,
        key_last_written: Some("2011-04-01T04:52:38Z".into()),
    }
    .to_json();
    assert_eq!(j["mounted_at_acquisition"], serde_json::json!(false));
    assert!(
        j["basis"]
            .as_str()
            .unwrap_or("")
            .contains("does not say the device was present when the evidence was taken"),
        "got {:?}",
        j["basis"]
    );
    // And the key's time is scoped to the key.
    assert_eq!(
        j["key_last_written_scope"],
        "the MountedDevices key, not this assignment"
    );
}

/// An MBR-signature record names no disk, and says why.
#[test]
fn an_mbr_partition_record_names_no_disk_and_says_why() {
    let j = MountedDevice {
        mount_name: r"\DosDevices\C:".into(),
        mount_point: MountPoint::DriveLetter,
        drive_letter: Some("C:".into()),
        target: classify_target(&REAL_C),
        device_serial: None,
        key_last_written: None,
    }
    .to_json();
    assert_eq!(j["mbr_disk_signature"], "3ea0be5c");
    assert_eq!(j["partition_offset"], serde_json::json!(1_048_576));
    assert!(
        j["disk_not_resolved"]
            .as_str()
            .unwrap_or("")
            .contains("not in this hive"),
        "got {:?}",
        j["disk_not_resolved"]
    );
}

// --- End to end, on the real hive -----------------------------------------

/// The real hive's eleven mount points come through, and `E:` joins to the USB
/// device whose install date this build also decodes.
#[test]
fn the_real_hive_maps_the_usb_device_to_its_drive_letter() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    let mounts: Vec<_> = all
        .iter()
        .filter(|r| r["type"] == "MountedDevice")
        .collect();
    assert!(
        mounts.len() >= 10,
        "this hive's MountedDevices holds eleven values, got {}",
        mounts.len()
    );

    let e = mounts
        .iter()
        .find(|m| m["drive_letter"] == "E:")
        .expect("this hive assigns E:");
    assert_eq!(e["target_kind"], "device_instance");
    assert_eq!(
        e["device_serial"], "AA951D0000007252&0",
        "the same instance id the device's own USBSTOR key carries"
    );

    // And the join actually closes: a UsbDevice record carries that serial.
    let usb_serials: Vec<&str> = all
        .iter()
        .filter(|r| r["type"] == "UsbDevice")
        .filter_map(|r| r["serial"].as_str())
        .collect();
    assert!(
        usb_serials
            .iter()
            .any(|s| s.starts_with("AA951D0000007252")),
        "the drive letter must be joinable to a device this build also records; got {usb_serials:?}"
    );

    // C: is the local disk, by signature and offset.
    let c = mounts
        .iter()
        .find(|m| m["drive_letter"] == "C:")
        .expect("this hive assigns C:");
    assert_eq!(c["target_kind"], "mbr_partition");
    assert_eq!(c["mbr_disk_signature"], "3ea0be5c");

    // No record claims the device was present at acquisition.
    for m in &mounts {
        assert_eq!(m["mounted_at_acquisition"], serde_json::json!(false));
    }
}
