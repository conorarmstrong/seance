//! Device properties: when a device was first and last connected.
//!
//! `ROADMAP` §2.6. The answer to "when was this USB device plugged in?" is in
//! the device-instance key's `Properties` subtree, and this build did not read
//! it — a `UsbDevice` record carried no timestamp of any kind.
//!
//! # Two layouts, and the one the exit criterion grades is the second
//!
//! **Windows 8 and later:** `Properties\{GUID}\<4 hex digits>`, holding one
//! **unnamed** value whose type is a `DEVPROP` code the registry renders as
//! `Unknown(…)`.
//!
//! **Windows 7:** `Properties\{GUID}\<EIGHT hex digits>\00000000` — one key
//! level deeper, the property id written as eight digits rather than four — and
//! the leaf holds **two named values**: `Type`, a four-byte `DEVPROP` type
//! code, and `Data`, the payload.
//!
//! Verified on `reference/plaso/test_data/SYSTEM`, a real 6.1.7600 hive in this
//! repository. A parser written to the Windows 8 layout alone reports **no
//! connection time on any Windows 7 machine** — a false absence, on the very
//! operating system §2.6's exit criterion is graded against.
//!
//! # The decode is gated on the type code, never on the length
//!
//! On that same hive, `{a8b865dd-…}\00000007` holds a `Data` that is a string,
//! and `{a8b865dd-…}\0000000e` holds four bytes. Deciding "eight bytes, so a
//! FILETIME" would turn a driver's version string into a date in 1601 and put
//! it on the record as a connection time. So a value is read as a FILETIME only
//! when its `Type` says `DEVPROP_TYPE_FILETIME`.

use seance_core::io::IncompleteReason;
use serde_json::{json, Value};

/// `DEVPROP_TYPE_FILETIME`.
pub const DEVPROP_TYPE_FILETIME: u32 = 0x10;
/// `DEVPROP_TYPE_STRING`.
pub const DEVPROP_TYPE_STRING: u32 = 0x12;

/// Which layout a property was read from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PropertyLayout {
    /// Windows 7: `…\{GUID}\<8 hex>\00000000` with `Type` and `Data` values.
    Win7TypeData,
    /// Windows 8+: `…\{GUID}\<4 hex>` with one unnamed value.
    Win8Unnamed,
}

impl PropertyLayout {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Win7TypeData => "windows_7_type_data",
            Self::Win8Unnamed => "windows_8_unnamed",
        }
    }
}

/// The device properties this build reads, and what each one is.
///
/// Deliberately short. A property id absent from this table is not decoded,
/// because a date named as the wrong event is worse than a date not shown.
///
/// `0x66` and `0x67` — last arrival and last removal — are **Windows 8 and
/// later only**. They are absent from the Windows 7 hive, and their absence
/// there is the operating system's, not this reader's.
const KNOWN: &[(&str, u32, &str, &str)] = &[
    (
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        0x64,
        "install_date",
        "when this device instance was installed on this machine",
    ),
    (
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        0x65,
        "first_install_date",
        "when a device of this kind was first installed on this machine",
    ),
    (
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        0x66,
        "last_arrival_date",
        "when this device was last connected (Windows 8 and later only)",
    ),
    (
        "{83da6326-97a6-4088-9453-a1923f573b29}",
        0x67,
        "last_removal_date",
        "when this device was last removed (Windows 8 and later only)",
    ),
    (
        "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}",
        0x02,
        "driver_date",
        "the date of the driver package, not an event on this machine",
    ),
];

/// A property key, recognised from its path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PropertyKey {
    /// The device-instance path the property belongs to, up to `\Properties`.
    pub device_key: String,
    pub property_guid: String,
    pub property_id: u32,
    pub layout: PropertyLayout,
}

impl PropertyKey {
    /// The field name and description this build gives the property, or `None`
    /// when it does not name it.
    pub fn known(&self) -> Option<(&'static str, &'static str)> {
        KNOWN
            .iter()
            .find(|(g, id, _, _)| {
                *id == self.property_id && g.eq_ignore_ascii_case(&self.property_guid)
            })
            .map(|(_, _, field, desc)| (*field, *desc))
    }
}

/// Recognise a device-property key.
pub fn property_key(key_path: &str) -> Option<PropertyKey> {
    let segments: Vec<&str> = key_path.split('\\').filter(|s| !s.is_empty()).collect();
    let props_at = segments
        .iter()
        .position(|s| s.eq_ignore_ascii_case("Properties"))?;
    let guid = segments.get(props_at + 1)?;
    if !(guid.starts_with('{') && guid.ends_with('}')) {
        return None;
    }
    let device_key = segments[..props_at].join("\\");
    let id_seg = segments.get(props_at + 2)?;
    let id = u32::from_str_radix(id_seg, 16).ok()?;

    match segments.len() - (props_at + 2) {
        // `…\{GUID}\<4 hex>` — Windows 8 and later.
        1 if id_seg.len() == 4 => Some(PropertyKey {
            device_key,
            property_guid: guid.to_string(),
            property_id: id,
            layout: PropertyLayout::Win8Unnamed,
        }),
        // `…\{GUID}\<8 hex>\00000000` — Windows 7.
        2 if id_seg.len() == 8 && segments[props_at + 3] == "00000000" => Some(PropertyKey {
            device_key,
            property_guid: guid.to_string(),
            property_id: id,
            layout: PropertyLayout::Win7TypeData,
        }),
        _ => None,
    }
}

/// One decoded device property.
#[derive(Clone, Debug)]
pub struct DeviceProperty {
    pub field: &'static str,
    pub description: &'static str,
    pub layout: PropertyLayout,
    /// The decoded time, when the property is a FILETIME that decoded.
    pub time: Option<String>,
    /// The raw FILETIME behind `time`.
    ///
    /// Kept so that two properties are ordered on the number rather than on
    /// their rendering: comparing two RFC 3339 strings is a comparison of a
    /// display format, and one day a format change makes it silently wrong.
    pub filetime: Option<u64>,
    /// Why there is no time, when there is not.
    pub undecoded_reason: Option<String>,
}

/// Decode a property's payload, given its `DEVPROP` type code.
///
/// `type_code` is `None` for the Windows 8 layout, where the type travels in
/// the value's own type field rather than in a sibling value. In that case the
/// caller has already established that the value is a FILETIME property from
/// the id table, and the length is checked here.
pub fn decode_filetime(
    key: &PropertyKey,
    type_code: Option<u32>,
    data: &[u8],
) -> Option<DeviceProperty> {
    let (field, description) = key.known()?;

    // The type code decides. Length never does: a string of eight bytes would
    // otherwise become a date in 1601 and reach the record as a connection
    // time.
    if let Some(code) = type_code {
        if code != DEVPROP_TYPE_FILETIME {
            return Some(DeviceProperty {
                field,
                description,
                layout: key.layout,
                time: None,
                filetime: None,
                undecoded_reason: Some(format!(
                    "This property's DEVPROP type is 0x{code:02X}, not FILETIME (0x{:02X}), so \
                     it was not read as a time. Its {} byte(s) are in the registry and are not \
                     a date.",
                    DEVPROP_TYPE_FILETIME,
                    data.len()
                )),
            });
        }
    }
    if data.len() < 8 {
        return Some(DeviceProperty {
            field,
            description,
            layout: key.layout,
            time: None,
            filetime: None,
            undecoded_reason: Some(format!(
                "This property declares a FILETIME and holds {} byte(s), fewer than the eight \
                 a FILETIME needs. No time was read.",
                data.len()
            )),
        });
    }
    let raw = u64::from_le_bytes(data[..8].try_into().ok()?);
    // `filetime_to_rfc3339` refuses the zero sentinel, so a zero yields no
    // time rather than 1601-01-01.
    let time = seance_core::time::filetime_to_rfc3339(raw);
    Some(DeviceProperty {
        field,
        description,
        layout: key.layout,
        filetime: time.is_some().then_some(raw),
        undecoded_reason: time.is_none().then(|| {
            format!(
                "This property's FILETIME is 0x{raw:016X}, which is not a time this build will \
                 render -- zero, or before the Unix epoch. No time was read."
            )
        }),
        time,
    })
}

/// Stamp a device's properties onto its record.
pub fn stamp(device: &mut Value, properties: &[DeviceProperty]) {
    let Some(map) = device.as_object_mut() else {
        return;
    };
    if properties.is_empty() {
        // The distinction that matters: this build looked and the device has no
        // property subtree, which is not the same as the times being unknown
        // for want of a reader.
        map.insert(
            "connection_times_note".to_string(),
            json!(
                "This device instance carries no device-property subtree, so the registry \
                   records no install or connection time for it. That is the absence of the \
                   properties, not a limit of this reader."
            ),
        );
        return;
    }
    let mut layouts: Vec<&str> = properties.iter().map(|p| p.layout.as_str()).collect();
    layouts.sort_unstable();
    layouts.dedup();
    map.insert("property_layout".to_string(), json!(layouts.join(", ")));

    let mut undecoded = Vec::new();
    for p in properties {
        match (&p.time, &p.undecoded_reason) {
            (Some(t), _) => {
                map.insert(p.field.to_string(), json!(t));
                map.insert(format!("{}_basis", p.field), json!(p.description));
            }
            (None, Some(why)) => undecoded.push(format!("{}: {why}", p.field)),
            (None, None) => {}
        }
    }
    if !undecoded.is_empty() {
        map.insert("properties_undecoded".to_string(), json!(undecoded));
        map.insert("content_incomplete".to_string(), json!(true));
        map.insert(
            "content_incomplete_reason".to_string(),
            json!(IncompleteReason::UnresolvedStructure.as_str()),
        );
    }
    // Two values from the same device's own property keys that cannot both
    // describe it. Each was read correctly; the COMBINATION is not something
    // this build can vouch for, and the reader takes the pair as one coherent
    // account unless told otherwise.
    //
    // Real on the Windows 10 hive measured for §2.6: a SanDisk Extreme whose
    // last-removal property is two hours and forty-nine minutes EARLIER than
    // its install property. A screen printing "first connected 12:11:32, last
    // removed 09:22:13" with no word about it is worse than either value alone.
    //
    // Only orderings that cannot hold are stated. A last arrival after a last
    // removal is the ordinary case -- the device is still plugged in -- and is
    // deliberately not among them.
    let at = |field: &str| {
        properties.iter().find(|p| p.field == field).and_then(|p| {
            p.filetime
                .map(|ft| (ft, p.time.clone().unwrap_or_default()))
        })
    };
    let mut contradictions: Vec<String> = Vec::new();
    for (earlier, later, why) in [
        (
            "last_removal_date",
            "install_date",
            "a device cannot have been removed before it was installed",
        ),
        (
            "last_arrival_date",
            "install_date",
            "a device cannot have been connected before it was installed",
        ),
        (
            "install_date",
            "first_install_date",
            "a device of this kind cannot have been first installed after this instance of it \
             was installed",
        ),
    ] {
        if let (Some((a, a_time)), Some((b, b_time))) = (at(earlier), at(later)) {
            if a < b {
                contradictions.push(format!(
                    "`{earlier}` ({a_time}) is earlier than `{later}` ({b_time}): {why}. Both \
                     values are read from this device's own property keys and both are reported \
                     as stored; this build does not choose between them."
                ));
            }
        }
    }
    if !contradictions.is_empty() {
        map.insert("time_contradictions".to_string(), json!(contradictions));
    }

    // Windows 7 writes no last-arrival or last-removal property at all, and
    // saying so is the difference between "this device was never removed" and
    // "this version of Windows does not record that".
    let win7_only = properties
        .iter()
        .all(|p| p.layout == PropertyLayout::Win7TypeData);
    let has_arrival = properties
        .iter()
        .any(|p| p.field == "last_arrival_date" || p.field == "last_removal_date");
    if win7_only && !has_arrival {
        map.insert(
            "last_connection_unavailable_reason".to_string(),
            json!(
                "The last-arrival and last-removal properties are written by Windows 8 and \
                   later. This device's properties are in the Windows 7 layout and do not \
                   include them, so when it was last connected is not recorded here -- by the \
                   operating system, not by this reader."
            ),
        );
    }
}

/// Read every device property the walk captured, grouped by device key.
///
/// The Windows 7 leaf holds `Type` and `Data` as separate values; the Windows 8
/// leaf holds one unnamed value whose own type the registry has already
/// rendered, so its type code is taken from the property-id table instead. In
/// both cases the payload is the RAW bytes, because `all_values` renders an
/// 8-byte `REG_BINARY` to a hex string and decoding a FILETIME from that would
/// make this parser depend on a display format.
pub fn read(
    capture: &crate::resident::ResidentCapture,
) -> std::collections::BTreeMap<String, Vec<DeviceProperty>> {
    use crate::resident::Anchor;
    let mut out: std::collections::BTreeMap<String, Vec<DeviceProperty>> = Default::default();

    for key in capture.keys_matching(|a| matches!(a, Anchor::DeviceProperty { .. })) {
        let Anchor::DeviceProperty { key: prop } = &key.anchor else {
            continue;
        };
        if prop.known().is_none() {
            continue;
        }
        let decoded = match prop.layout {
            PropertyLayout::Win7TypeData => {
                let type_code = key
                    .values
                    .iter()
                    .find(|v| v.name.eq_ignore_ascii_case("Type"))
                    .and_then(|v| v.data.get(..4))
                    .and_then(|b| b.try_into().ok())
                    .map(u32::from_le_bytes);
                let data = key
                    .values
                    .iter()
                    .find(|v| v.name.eq_ignore_ascii_case("Data"))
                    .map(|v| v.data.clone())
                    .unwrap_or_default();
                // No `Type` value is not a licence to guess: without it the
                // payload's meaning is unknown and nothing is decoded.
                match type_code {
                    Some(code) => decode_filetime(prop, Some(code), &data),
                    None => Some(DeviceProperty {
                        field: prop.known().map(|(f, _)| f).unwrap_or(""),
                        description: prop.known().map(|(_, d)| d).unwrap_or(""),
                        layout: prop.layout,
                        time: None,
                        filetime: None,
                        undecoded_reason: Some(
                            "This property leaf holds no Type value, so what its Data means is \
                             not established and nothing was read from it."
                                .to_string(),
                        ),
                    }),
                }
            }
            PropertyLayout::Win8Unnamed => {
                // The single unnamed value. Its DEVPROP type is in the value's
                // own type field, which the property-id table already tells us
                // to expect as a FILETIME.
                let data = key
                    .values
                    .iter()
                    .find(|v| v.name.is_empty() || v.name == "(Default)")
                    .map(|v| v.data.clone())
                    .unwrap_or_default();
                decode_filetime(prop, None, &data)
            }
        };
        if let Some(d) = decoded {
            out.entry(prop.device_key.clone()).or_default().push(d);
        }
    }
    out
}
