//! `MountedDevices`: which drive letter a volume or device was mounted at.
//!
//! `ROADMAP` §2.6. This is the key that answers "what was `E:`?" — and it is
//! what lets a USB device's serial be tied to a letter an examiner has seen in
//! a document path, a shortcut, or a user's account.
//!
//! # The two value shapes, both real
//!
//! Measured on `reference/plaso/test_data/SYSTEM`, whose `MountedDevices` holds
//! eleven values:
//!
//! * **A device instance path**, UTF-16LE, for a removable or optical device —
//!   `_??_USBSTOR#Disk&Ven_HP&Prod_v100w&Rev_1024#AA951D0000007252&0#{53f56307-…}`
//!   under `\DosDevices\E:`. The serial in that string is the same serial the
//!   device's own `Enum\USBSTOR` key carries, so the two can be joined.
//! * **Twelve bytes** for a partition on a local disk: a four-byte MBR disk
//!   signature and an eight-byte partition offset. `\DosDevices\C:` on that
//!   hive is `3e a0 be 5c` at offset `0x0000100000` — one mebibyte in, the
//!   standard first-partition alignment.
//!
//! # What this will not do
//!
//! **It does not say a device was mounted at that letter *when the evidence was
//! taken*.** `MountedDevices` is a persistent assignment table: a letter stays
//! recorded for a device that has not been attached in years, and a letter can
//! be reassigned. The record states the mapping and says that it is an
//! assignment rather than an observation of the device being present.
//!
//! **It does not resolve an MBR signature to a disk.** That needs the disk's
//! own bytes, which are not in this hive.

use serde_json::{json, Value};

/// Bytes of the MBR-signature form.
const MBR_FORM_BYTES: usize = 12;

/// What a `MountedDevices` value names.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MountedTarget {
    /// A device instance path — a removable, optical or otherwise enumerated
    /// device. Carries the serial, which joins to the device's own key.
    DeviceInstance { path: String },
    /// A partition on a local disk: an MBR disk signature and a byte offset.
    MbrPartition {
        disk_signature_hex: String,
        partition_offset: u64,
    },
    /// Neither shape. Reported as bytes rather than guessed at.
    Unrecognised { len: usize, head_hex: String },
}

impl MountedTarget {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DeviceInstance { .. } => "device_instance",
            Self::MbrPartition { .. } => "mbr_partition",
            Self::Unrecognised { .. } => "unrecognised",
        }
    }
}

/// How a mount point is named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MountPoint {
    /// `\DosDevices\X:` — a drive letter.
    DriveLetter,
    /// `\??\Volume{GUID}` — a volume GUID.
    VolumeGuid,
    /// Something else.
    Other,
}

impl MountPoint {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::DriveLetter => "drive_letter",
            Self::VolumeGuid => "volume_guid",
            Self::Other => "other",
        }
    }
}

/// One entry in the table.
#[derive(Clone, Debug)]
pub struct MountedDevice {
    /// The value name, verbatim: `\DosDevices\E:` or `\??\Volume{…}`.
    pub mount_name: String,
    pub mount_point: MountPoint,
    /// The drive letter, when the mount point is one.
    pub drive_letter: Option<String>,
    pub target: MountedTarget,
    /// The device serial, when one can be read out of a device instance path.
    pub device_serial: Option<String>,
    pub key_last_written: Option<String>,
}

/// Classify a mount-point name.
pub fn classify_mount(name: &str) -> (MountPoint, Option<String>) {
    let lower = name.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix(r"\dosdevices\") {
        // `X:` — one letter and a colon, and nothing else.
        let bytes = rest.as_bytes();
        if bytes.len() == 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            let letter = name[name.len() - 2..].to_ascii_uppercase();
            return (MountPoint::DriveLetter, Some(letter));
        }
        return (MountPoint::DriveLetter, None);
    }
    if lower.starts_with(r"\??\volume{") {
        return (MountPoint::VolumeGuid, None);
    }
    (MountPoint::Other, None)
}

/// Classify a value's payload.
///
/// The two shapes are distinguished by **length and content**, not by the
/// mount-point name: the same letter can name either.
pub fn classify_target(data: &[u8]) -> MountedTarget {
    if data.len() == MBR_FORM_BYTES {
        let sig: String = data[..4].iter().map(|b| format!("{b:02x}")).collect();
        let offset = u64::from_le_bytes(data[4..12].try_into().unwrap_or([0; 8]));
        return MountedTarget::MbrPartition {
            disk_signature_hex: sig,
            partition_offset: offset,
        };
    }
    // A device instance path is UTF-16LE. It must decode to something that
    // looks like one, rather than to any text at all — a run of bytes that
    // happens to decode is not a device path.
    let text = utf16le(data);
    let looks_like_a_path = text.len() > 8
        && (text.starts_with(r"\??\") || text.starts_with("_??_"))
        && text.contains('#');
    if looks_like_a_path {
        return MountedTarget::DeviceInstance { path: text };
    }
    MountedTarget::Unrecognised {
        len: data.len(),
        head_hex: data.iter().take(12).map(|b| format!("{b:02x}")).collect(),
    }
}

/// The serial out of a device instance path.
///
/// `_??_USBSTOR#Disk&Ven_HP&Prod_v100w&Rev_1024#AA951D0000007252&0#{GUID}` —
/// the third `#`-delimited field. Returned only for a `USBSTOR` path, because
/// the field means something else on other device classes and a wrong serial
/// joined to a device is worse than no join.
pub fn serial_from_instance_path(path: &str) -> Option<String> {
    if !path.to_ascii_uppercase().contains("USBSTOR#") {
        return None;
    }
    let mut parts = path.split('#');
    let _prefix = parts.next()?;
    let _class = parts.next()?;
    let serial = parts.next()?;
    // Windows appends `&0` to the instance. Kept as the instance id, with the
    // bare serial beside it, because the device's own key uses the full form.
    (!serial.is_empty()).then(|| serial.to_string())
}

impl MountedDevice {
    pub fn to_json(&self) -> Value {
        let mut m = serde_json::Map::new();
        m.insert("type".into(), json!("MountedDevice"));
        m.insert(
            "name".into(),
            json!(match &self.drive_letter {
                Some(l) => l.clone(),
                None => self.mount_name.clone(),
            }),
        );
        m.insert("mount_name".into(), json!(self.mount_name));
        m.insert("mount_point".into(), json!(self.mount_point.as_str()));
        m.insert("drive_letter".into(), json!(self.drive_letter));
        m.insert("target_kind".into(), json!(self.target.as_str()));
        match &self.target {
            MountedTarget::DeviceInstance { path } => {
                m.insert("device_instance_path".into(), json!(path));
                m.insert("device_serial".into(), json!(self.device_serial));
                if self.device_serial.is_some() {
                    m.insert(
                        "device_serial_basis".into(),
                        json!(
                            "the third #-delimited field of the device instance path. The \
                               same value appears on the device's own Enum\\USBSTOR key, so \
                               the two records describe one device."
                        ),
                    );
                }
            }
            MountedTarget::MbrPartition {
                disk_signature_hex,
                partition_offset,
            } => {
                m.insert("mbr_disk_signature".into(), json!(disk_signature_hex));
                m.insert("partition_offset".into(), json!(partition_offset));
                m.insert(
                    "disk_not_resolved".into(),
                    json!(
                        "This names a partition by its disk's MBR signature and a byte \
                           offset. Which disk that signature belongs to needs the disk's own \
                           bytes, which are not in this hive, so no disk is named here."
                    ),
                );
            }
            MountedTarget::Unrecognised { len, head_hex } => {
                m.insert("value_bytes".into(), json!(len));
                m.insert("value_head_hex".into(), json!(head_hex));
                m.insert("content_incomplete".into(), json!(true));
                m.insert(
                    "content_incomplete_reason".into(),
                    json!(seance_core::io::IncompleteReason::UnresolvedStructure.as_str()),
                );
                m.insert(
                    "content_incomplete_detail".into(),
                    json!(format!(
                        "This mount point's value is {len} byte(s) and matches neither shape \
                         this build reads -- a twelve-byte MBR signature and offset, or a \
                         UTF-16 device instance path. Its first bytes are recorded above and \
                         nothing was decoded from them."
                    )),
                );
            }
        }
        m.insert("key_last_written".into(), json!(self.key_last_written));
        m.insert(
            "key_last_written_scope".into(),
            json!("the MountedDevices key, not this assignment"),
        );
        // The claim this record will not make.
        m.insert("mounted_at_acquisition".into(), json!(false));
        m.insert(
            "basis".into(),
            json!(
                "MountedDevices is a persistent assignment table. A letter stays recorded \
                   for a device that has not been attached in years, and letters are \
                   reassigned. This record says the letter was assigned to this device; it \
                   does not say the device was present when the evidence was taken."
            ),
        );
        Value::Object(m)
    }
}

/// Recognise the `MountedDevices` key.
pub fn is_mounted_devices_key(key_path: &str) -> bool {
    key_path
        .rsplit('\\')
        .next()
        .is_some_and(|s| s.eq_ignore_ascii_case("MountedDevices"))
}

/// Turn the walk's capture into records.
pub fn emit(capture: &crate::resident::ResidentCapture) -> Vec<Value> {
    use crate::resident::Anchor;

    let mut out = Vec::new();
    for key in capture.keys_matching(|a| matches!(a, Anchor::MountedDevices)) {
        let when = seance_core::time::filetime_to_rfc3339(key.last_written_filetime);
        for value in &key.values {
            let (mount_point, drive_letter) = classify_mount(&value.name);
            let target = classify_target(&value.data);
            let device_serial = match &target {
                MountedTarget::DeviceInstance { path } => serial_from_instance_path(path),
                _ => None,
            };
            out.push(
                MountedDevice {
                    mount_name: value.name.clone(),
                    mount_point,
                    drive_letter,
                    target,
                    device_serial,
                    key_last_written: when.clone(),
                }
                .to_json(),
            );
        }
    }
    out
}

fn utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units)
}
