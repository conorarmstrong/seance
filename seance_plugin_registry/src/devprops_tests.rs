//! Device properties — stated before they were decoded.
//!
//! # Ground truth
//!
//! `reference/plaso/test_data/SYSTEM`, a real Windows 7 (6.1.7600) hive in this
//! repository, read key by key. Its USB mass-storage device is
//! `Disk&Ven_HP&Prod_v100w&Rev_1024\AA951D0000007252&0`, and its properties are
//! in the **Windows 7** layout:
//!
//! ```text
//! …\Properties\{83da6326-…}\00000064\00000000  Type=10000000  Data=4028cfa028f0cb01
//! …\Properties\{a8b865dd-…}\00000002\00000000  Type=10000000  Data=00808ca3c594c601
//! …\Properties\{a8b865dd-…}\00000007\00000000  Type=12000000  Data=<a string>
//! ```
//!
//! `0x10` is `DEVPROP_TYPE_FILETIME` and `0x12` is `DEVPROP_TYPE_STRING`.
//! Decoded: `4028cfa028f0cb01` is 2011-04-01T04:52:39.748Z and
//! `00808ca3c594c601` is **2006-06-21T00:00:00Z** — a driver-package date,
//! which its clean midnight is the tell for.
//!
//! The plan for this work put that second value in 2011 and described a
//! "seven-year gap". It is 2006, and the gap is twelve years. A test written
//! from the plan fails on the real bytes, which is why these numbers were
//! taken off the hive instead.

use super::devprops::*;

/// The real Windows 7 install-date bytes.
const WIN7_INSTALL_DATE: [u8; 8] = [0x40, 0x28, 0xcf, 0xa0, 0x28, 0xf0, 0xcb, 0x01];
/// The real Windows 7 driver-date bytes.
const WIN7_DRIVER_DATE: [u8; 8] = [0x00, 0x80, 0x8c, 0xa3, 0xc5, 0x94, 0xc6, 0x01];

fn win7_key(guid: &str, id: &str) -> String {
    format!(
        r"CMI-CreateHive{{F10156BE}}\ControlSet001\Enum\USBSTOR\Disk&Ven_HP&Prod_v100w&Rev_1024\AA951D0000007252&0\Properties\{guid}\{id}\00000000"
    )
}

// --- Both layouts ----------------------------------------------------------

/// **The blocking correction.** The Windows 7 layout is one key deeper, with an
/// eight-digit property id, and it must be recognised.
///
/// A parser written to the Windows 8 layout alone reports no connection time on
/// any Windows 7 machine — a false absence, on the very operating system
/// §2.6's exit criterion is graded against.
#[test]
fn the_windows_seven_property_layout_is_recognised() {
    let k = property_key(&win7_key(
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        "00000064",
    ))
    .expect("the Windows 7 layout");
    assert_eq!(k.layout, PropertyLayout::Win7TypeData);
    assert_eq!(k.property_id, 0x64);
    assert_eq!(k.property_guid, "{83da6326-97a6-4088-9453-a1923f573b29}");
    assert!(
        k.device_key.ends_with(r"AA951D0000007252&0"),
        "the device the property belongs to: {}",
        k.device_key
    );
    assert_eq!(k.known().map(|(f, _)| f), Some("install_date"));
}

/// And the Windows 8 layout: four digits, one level shallower.
#[test]
fn the_windows_eight_property_layout_is_recognised() {
    let path = r"ROOT\ControlSet001\Enum\USBSTOR\Disk&Ven_X\SERIAL&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066";
    let k = property_key(path).expect("the Windows 8 layout");
    assert_eq!(k.layout, PropertyLayout::Win8Unnamed);
    assert_eq!(k.property_id, 0x66);
    assert_eq!(k.known().map(|(f, _)| f), Some("last_arrival_date"));
}

/// Neither shape is matched loosely.
#[test]
fn a_key_that_is_not_a_property_leaf_is_not_recognised() {
    for path in [
        r"ROOT\ControlSet001\Enum\USBSTOR\Disk&Ven_X\SERIAL&0\Properties",
        r"ROOT\ControlSet001\Enum\USBSTOR\Disk&Ven_X\SERIAL&0\Properties\{83da6326-97a6-4088-9453-a1923f573b29}",
        // A three-digit id is neither layout.
        r"ROOT\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\064",
        // Eight digits without the 00000000 leaf is the container, not the leaf.
        r"ROOT\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\00000064",
        // A non-GUID segment.
        r"ROOT\...\Properties\NotAGuid\0064",
    ] {
        assert!(property_key(path).is_none(), "for {path}");
    }
}

// --- The decode is gated on the type, never the length ---------------------

/// The install date decodes to its known answer, with sub-second precision.
#[test]
fn the_real_windows_seven_install_date_decodes_to_its_known_answer() {
    let k = property_key(&win7_key(
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        "00000064",
    ))
    .expect("a property");
    let p = decode_filetime(&k, Some(DEVPROP_TYPE_FILETIME), &WIN7_INSTALL_DATE)
        .expect("a known property");
    assert_eq!(p.field, "install_date");
    assert_eq!(
        p.time.as_deref(),
        Some("2011-04-01T04:52:39.748+00:00"),
        "the FILETIME at sub-second precision -- whole seconds would lose the cross-check \
         against the key's own write time"
    );
    assert!(p.undecoded_reason.is_none());
}

/// The driver date is **2006**, and it is described as a package date rather
/// than an event on the machine.
#[test]
fn the_driver_date_is_a_package_date_and_is_not_presented_as_an_event() {
    let k = property_key(&win7_key(
        "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}",
        "00000002",
    ))
    .expect("a property");
    let p = decode_filetime(&k, Some(DEVPROP_TYPE_FILETIME), &WIN7_DRIVER_DATE)
        .expect("a known property");
    assert_eq!(p.field, "driver_date");
    assert_eq!(
        p.time.as_deref(),
        Some("2006-06-21T00:00:00+00:00"),
        "2006, not the 2011 the plan asserted -- and the clean midnight is the tell that it \
         is a package date"
    );
    assert!(
        p.description.contains("not an event on this machine"),
        "got {:?}",
        p.description
    );
}

/// **A string of the right length must not become a date.**
///
/// On the real hive, `{a8b865dd-…}\00000007` carries a `DEVPROP_TYPE_STRING`.
/// Deciding "eight bytes, so a FILETIME" would turn a driver's version string
/// into a date in 1601 and put it on the record as a connection time.
#[test]
fn a_string_property_is_not_read_as_a_filetime_however_long_it_is() {
    let k = property_key(&win7_key(
        "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}",
        "00000002",
    ))
    .expect("a property");
    // The same eight bytes, declared a STRING.
    let p = decode_filetime(&k, Some(DEVPROP_TYPE_STRING), &WIN7_DRIVER_DATE)
        .expect("a known property");
    assert!(
        p.time.is_none(),
        "a string must never be read as a time, whatever its length"
    );
    let why = p.undecoded_reason.as_deref().unwrap_or("");
    assert!(
        why.contains("type is 0x12") && why.contains("not a date"),
        "and the record says why: {why:?}"
    );
}

/// A FILETIME property shorter than a FILETIME yields no time, with a reason.
#[test]
fn a_filetime_property_too_short_to_be_one_says_so() {
    let k = property_key(&win7_key(
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        "00000064",
    ))
    .expect("a property");
    let p = decode_filetime(&k, Some(DEVPROP_TYPE_FILETIME), &[0u8; 4]).expect("known");
    assert!(p.time.is_none());
    assert!(
        p.undecoded_reason
            .as_deref()
            .unwrap_or("")
            .contains("fewer than the eight"),
        "got {:?}",
        p.undecoded_reason
    );
}

/// A zero FILETIME is the absence of a time, not 1601-01-01.
#[test]
fn a_zero_property_filetime_yields_no_time() {
    let k = property_key(&win7_key(
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        "00000064",
    ))
    .expect("a property");
    let p = decode_filetime(&k, Some(DEVPROP_TYPE_FILETIME), &[0u8; 8]).expect("known");
    assert!(p.time.is_none());
    assert!(p.undecoded_reason.is_some());
}

/// A property id this build does not name is not decoded at all.
///
/// A date named as the wrong event is worse than a date not shown.
#[test]
fn an_unnamed_property_id_is_not_decoded() {
    let k = property_key(&win7_key(
        "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}",
        "0000000e",
    ))
    .expect("a property key");
    assert!(k.known().is_none());
    assert!(
        decode_filetime(&k, Some(DEVPROP_TYPE_FILETIME), &WIN7_INSTALL_DATE).is_none(),
        "this build does not name 0x0e, so it does not put a date on the record for it"
    );
}

// --- What the record says --------------------------------------------------

/// A device with no property subtree says that the **registry** records no
/// time, not that this reader could not find one.
#[test]
fn a_device_with_no_properties_says_the_registry_holds_none() {
    let mut device = serde_json::json!({ "type": "UsbDevice", "serial": "X" });
    stamp(&mut device, &[]);
    let note = device["connection_times_note"].as_str().unwrap_or("");
    assert!(
        note.contains("absence of the properties, not a limit of this reader"),
        "got {note:?}"
    );
    assert!(device["install_date"].is_null());
}

/// **Windows 7 records no last-arrival or last-removal at all**, and the record
/// says that is the operating system's doing.
///
/// Those two properties are Windows 8 and later. Without this sentence, "no
/// last connection time" reads as "this device was never disconnected".
#[test]
fn a_windows_seven_device_says_why_it_has_no_last_connection_time() {
    let k = property_key(&win7_key(
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        "00000064",
    ))
    .expect("a property");
    let p = decode_filetime(&k, Some(DEVPROP_TYPE_FILETIME), &WIN7_INSTALL_DATE).expect("known");
    let mut device = serde_json::json!({ "type": "UsbDevice", "serial": "AA951D0000007252" });
    stamp(&mut device, &[p]);

    assert_eq!(device["install_date"], "2011-04-01T04:52:39.748+00:00");
    assert_eq!(device["property_layout"], "windows_7_type_data");
    let why = device["last_connection_unavailable_reason"]
        .as_str()
        .unwrap_or("");
    assert!(
        why.contains("Windows 8 and later") && why.contains("not by this reader"),
        "got {why:?}"
    );
}

/// A Windows 8 device that has the arrival property gets no such note.
#[test]
fn a_windows_eight_device_with_an_arrival_time_carries_no_unavailable_note() {
    let path = r"ROOT\...\Properties\{83da6326-97a6-4088-9453-a1923f573b29}\0066";
    let k = property_key(path).expect("a property");
    let p = decode_filetime(&k, None, &WIN7_INSTALL_DATE).expect("known");
    let mut device = serde_json::json!({ "type": "UsbDevice" });
    stamp(&mut device, &[p]);
    assert!(device["last_arrival_date"].is_string());
    assert!(
        device["last_connection_unavailable_reason"].is_null(),
        "the property is present, so there is nothing to explain"
    );
}

/// A property that would not decode is listed, and the record is marked
/// incomplete — a device whose times are partly unread must not read as a
/// device whose times are known.
#[test]
fn a_property_that_would_not_decode_marks_the_record_incomplete() {
    let k = property_key(&win7_key(
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        "00000064",
    ))
    .expect("a property");
    let bad = decode_filetime(&k, Some(DEVPROP_TYPE_STRING), &WIN7_DRIVER_DATE).expect("known");
    let mut device = serde_json::json!({ "type": "UsbDevice" });
    stamp(&mut device, &[bad]);
    assert_eq!(device["content_incomplete"], serde_json::json!(true));
    assert_eq!(
        device["content_incomplete_reason"],
        serde_json::json!("unresolved_structure")
    );
    let listed = device["properties_undecoded"].as_array().expect("a list");
    assert_eq!(listed.len(), 1);
    assert!(listed[0]
        .as_str()
        .unwrap_or("")
        .starts_with("install_date:"));
}

// --- End to end, on the real Windows 7 hive --------------------------------

/// The real Windows 7 `SYSTEM` hive's USB device carries its install date
/// through the whole pipeline.
///
/// This is the test that matters. Everything above pins a decoder; this proves
/// a `UsbDevice` record an examiner opens actually has the date on it — which
/// it did not before, for any Windows version.
#[test]
fn the_real_windows_seven_usb_device_carries_its_install_date_end_to_end() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    let usb: Vec<_> = all.iter().filter(|r| r["type"] == "UsbDevice").collect();
    assert!(
        !usb.is_empty(),
        "this hive holds a USB mass-storage device instance"
    );

    let hp = usb
        .iter()
        .find(|d| {
            d["serial"]
                .as_str()
                .unwrap_or("")
                .starts_with("AA951D0000007252")
        })
        .expect("the HP v100w this hive records");

    assert_eq!(
        hp["install_date"], "2011-04-01T04:52:38.686+00:00",
        "the FILETIME under {{83da6326-…}}\\00000064, at the precision the hive stores it"
    );
    assert_eq!(hp["property_layout"], "windows_7_type_data");
    assert!(
        hp["install_date_basis"]
            .as_str()
            .unwrap_or("")
            .contains("installed on this machine"),
        "what the date is must travel with it: {:?}",
        hp["install_date_basis"]
    );

    // Windows 7 writes no last-arrival property, and the record must say that
    // is the operating system's doing rather than leave "no last connection"
    // to read as "never disconnected".
    assert!(hp["last_arrival_date"].is_null());
    assert!(
        hp["last_connection_unavailable_reason"]
            .as_str()
            .unwrap_or("")
            .contains("Windows 8 and later"),
        "got {:?}",
        hp["last_connection_unavailable_reason"]
    );

    // The driver date is present, is 2006, and says it is a package date.
    assert_eq!(hp["driver_date"], "2006-06-21T00:00:00+00:00");
    assert!(
        hp["driver_date_basis"]
            .as_str()
            .unwrap_or("")
            .contains("not an event on this machine"),
        "a driver-package date must never read as a connection: {:?}",
        hp["driver_date_basis"]
    );
}

/// No USB record claims a time the hive does not hold.
#[test]
fn no_usb_record_carries_a_time_the_hive_does_not_hold() {
    let Some(bytes) = super::userassist_tests::corpus_hive_for_tests("SYSTEM") else {
        return;
    };
    let all = super::userassist_tests::records_for_tests("SYSTEM", bytes);
    for d in all.iter().filter(|r| r["type"] == "UsbDevice") {
        // Every date on the record is a real RFC3339 string, never a 1601
        // sentinel that a zero FILETIME would have produced.
        for field in ["install_date", "first_install_date", "driver_date"] {
            if let Some(t) = d[field].as_str() {
                assert!(
                    !t.starts_with("1601-"),
                    "{field} is the 1601 sentinel, which means a zero FILETIME was formatted \
                     rather than refused: {t}"
                );
            }
        }
        // And a device with no properties says so rather than being silent.
        if d["property_layout"].is_null() {
            assert!(
                d["connection_times_note"].is_string(),
                "a device with no properties must say the registry holds none: {:?}",
                d["serial"]
            );
        }
    }
}

// --- When the device's own properties disagree -----------------------------

/// Measured on the real Windows 10 `SYSTEM` hive (LoneWolf, extracted
/// 2026-09-15). Its SanDisk Extreme, serial `AA010215170355310594&0`, carries:
///
/// ```text
/// install_date       2018-03-27T12:11:32.021203500+00:00   ({83da6326-…}\0064)
/// first_install_date 2018-03-27T12:11:32.021203500+00:00   (…\0065)
/// last_arrival_date  2018-03-27T12:13:16.365329600+00:00   (…\0066)
/// last_removal_date  2018-03-27T09:22:13.088887100+00:00   (…\0067)
/// ```
///
/// The device was last removed **two hours and forty-nine minutes before it was
/// installed**. Each value is correctly read from its own key; the combination
/// is not something this build can vouch for. Printing "first connected
/// 12:11:32, last removed 09:22:13" with no word about it is worse than either
/// value alone, because a reader takes the pair as a single coherent account.
const WIN10_INSTALL: [u8; 8] = [0x43, 0x2e, 0x43, 0xbe, 0xc4, 0xc5, 0xd3, 0x01];
const WIN10_REMOVAL: [u8; 8] = [0xa7, 0x20, 0x11, 0x17, 0xad, 0xc5, 0xd3, 0x01];
const WIN10_ARRIVAL: [u8; 8] = [0xb0, 0xd4, 0x74, 0xfc, 0xc4, 0xc5, 0xd3, 0x01];

fn win8_key(guid: &str, id: &str) -> String {
    format!(
        r"ROOT\ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Extreme&Rev_0001\AA010215170355310594&0\Properties\{guid}\{id}"
    )
}

fn win10_prop(id: &str, bytes: &[u8]) -> DeviceProperty {
    let k = property_key(&win8_key("{83da6326-97a6-4088-9453-a1923f573b29}", id))
        .expect("a Windows 8 property leaf");
    decode_filetime(&k, Some(DEVPROP_TYPE_FILETIME), bytes).expect("a named property")
}

/// The two values are both kept, and the disagreement is stated.
#[test]
fn a_last_removal_earlier_than_the_install_is_stated_and_neither_value_is_dropped() {
    let mut device = serde_json::json!({
        "type": "UsbDevice", "serial": "AA010215170355310594&0"
    });
    stamp(
        &mut device,
        &[
            win10_prop("0064", &WIN10_INSTALL),
            win10_prop("0067", &WIN10_REMOVAL),
        ],
    );

    // Neither value is suppressed: the evidence holds both and so does the record.
    assert_eq!(
        device["install_date"],
        "2018-03-27T12:11:32.021203500+00:00"
    );
    assert_eq!(
        device["last_removal_date"],
        "2018-03-27T09:22:13.088887100+00:00"
    );

    let stated = device["time_contradictions"]
        .as_array()
        .expect("the disagreement is stated as its own field");
    assert_eq!(
        stated.len(),
        1,
        "one contradiction, stated once: {stated:?}"
    );
    let s = stated[0].as_str().unwrap_or("");
    assert!(
        s.contains("last_removal_date") && s.contains("install_date"),
        "the statement names both fields: {s:?}"
    );
    assert!(
        s.contains("2018-03-27T09:22:13.088887100+00:00")
            && s.contains("2018-03-27T12:11:32.021203500+00:00"),
        "and both values, so a reader can check it: {s:?}"
    );
    assert!(
        s.contains("earlier"),
        "and says which way round the disagreement runs: {s:?}"
    );
    // A contradiction is not a shortfall in this build's reach: it read both
    // values correctly. `content_incomplete` would say the opposite.
    assert!(device["content_incomplete"].is_null());
}

/// A device whose properties agree carries no such field — the statement must
/// appear only where there is something to state.
#[test]
fn a_device_whose_property_times_agree_carries_no_contradiction_field() {
    let mut device = serde_json::json!({ "type": "UsbDevice", "serial": "X" });
    stamp(
        &mut device,
        &[
            win10_prop("0064", &WIN10_INSTALL),
            // The real last-arrival on the same device: AFTER the install, which
            // is the ordinary case and must not be flagged.
            win10_prop("0066", &WIN10_ARRIVAL),
        ],
    );
    assert_eq!(
        device["last_arrival_date"], "2018-03-27T12:13:16.365329600+00:00",
        "the arrival bytes must be the ones the hive holds, or this test passes vacuously"
    );
    assert!(
        device["time_contradictions"].is_null(),
        "got {:?}",
        device["time_contradictions"]
    );
}

/// A device connected and left in has a last arrival after its last removal.
/// That is normal — the device is still plugged in — and must not be flagged.
#[test]
fn an_arrival_after_the_last_removal_is_the_ordinary_case_and_is_not_flagged() {
    let mut device = serde_json::json!({ "type": "UsbDevice", "serial": "X" });
    stamp(
        &mut device,
        &[
            win10_prop("0067", &WIN10_REMOVAL),
            win10_prop("0066", &WIN10_ARRIVAL),
        ],
    );
    assert!(
        device["time_contradictions"].is_null(),
        "a device still plugged in arrives after it was last removed: {:?}",
        device["time_contradictions"]
    );
}

/// A device kind first installed after this instance was installed is the other
/// ordering the properties can contradict.
#[test]
fn a_first_install_after_the_instance_install_is_stated() {
    let mut device = serde_json::json!({ "type": "UsbDevice", "serial": "X" });
    stamp(
        &mut device,
        &[
            win10_prop("0064", &WIN10_REMOVAL),
            win10_prop("0065", &WIN10_INSTALL),
        ],
    );
    let stated = device["time_contradictions"].as_array().expect("stated");
    assert_eq!(stated.len(), 1, "{stated:?}");
    assert!(
        stated[0]
            .as_str()
            .unwrap_or("")
            .contains("first_install_date"),
        "got {stated:?}"
    );
}
