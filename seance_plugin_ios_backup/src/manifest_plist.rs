//! Manifest.plist parser for iOS backup metadata
//!
//! Contains backup-level metadata including:
//! - IsEncrypted flag
//! - Device information
//! - Backup date
//! - iOS version
//! - Keybag data (for encrypted backups)

use anyhow::{Context, Result};
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ManifestPlist {
    pub is_encrypted: bool,
    pub version: String,
    pub date: Option<plist::Date>,
    pub display_name: Option<String>,
    pub product_type: Option<String>,
    pub product_version: Option<String>,
    pub build_version: Option<String>,
    pub serial_number: Option<String>,
    pub unique_identifier: Option<String>,
    /// The phone's IMEI, which only `Info.plist` carries.
    pub imei: Option<String>,
    /// Raw keybag TLV data from BackupKeyBag (encrypted backups only)
    pub keybag_data: Option<Vec<u8>>,
    /// ManifestKey: protection class (4 bytes LE) + wrapped key (encrypted backups only)
    pub manifest_key: Option<Vec<u8>>,
}

impl ManifestPlist {
    /// Parse Manifest.plist from file
    pub fn from_file(path: &Path) -> Result<Self> {
        let plist_value =
            plist::from_file::<_, plist::Value>(path).context("Failed to parse Manifest.plist")?;
        Self::from_value(plist_value)
    }

    /// Parse a backup manifest from bytes the case already holds.
    ///
    /// A backup inside a disk image has no path on this machine, and the
    /// file-path reader above cannot see it at all.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let plist_value = plist::from_bytes::<plist::Value>(bytes)
            .context("Failed to parse backup manifest bytes")?;
        Self::from_value(plist_value)
    }

    fn from_value(plist_value: plist::Value) -> Result<Self> {
        if let plist::Value::Dictionary(dict) = plist_value {
            // This flag decides whether every stored file in the backup is
            // ciphertext, so it must be *read*, not defaulted. iTunes writes a
            // Boolean; other tools write 0/1. A value of any other shape — or no
            // value at all — leaves the question open, and it is then answered by
            // the manifest's own evidence: `ManifestKey` exists only to decrypt
            // an encrypted `Manifest.db`. Defaulting to "not encrypted" walks an
            // encrypted backup as if it were clear and attaches ciphertext as
            // file content (the B8-026 class).
            let is_encrypted = match dict.get("IsEncrypted") {
                Some(plist::Value::Boolean(b)) => *b,
                Some(plist::Value::Integer(i)) => i.as_signed() != Some(0),
                _ => dict.contains_key("ManifestKey"),
            };

            let version = dict
                .get("Version")
                .and_then(|v| {
                    if let plist::Value::String(s) = v {
                        Some(s.clone())
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "Unknown".to_string());

            let date = dict.get("Date").and_then(|v| {
                if let plist::Value::Date(d) = v {
                    Some(*d)
                } else {
                    None
                }
            });

            // The device identifies itself in two different shapes and this
            // parser only ever read one of them. `Info.plist`, which iTunes
            // writes beside the backup, uses spaced keys at the top level
            // ("Display Name", "Product Type"). `Manifest.plist` — the file
            // this parser is named for — puts the same facts inside a
            // `Lockdown` dictionary under the device's own key names
            // (`DeviceName`, `ProductType`). Reading only the first shape meant
            // every real iTunes backup was recorded with no device on it at
            // all, encrypted ones included, although none of this needs the
            // password (HUNT-091). Both shapes are read, top level first.
            let lockdown = match dict.get("Lockdown") {
                Some(plist::Value::Dictionary(d)) => Some(d),
                _ => None,
            };
            let string_field = |top: &str, lockdown_key: &str| -> Option<String> {
                let from = |d: &plist::Dictionary, k: &str| match d.get(k) {
                    Some(plist::Value::String(s)) => Some(s.clone()),
                    _ => None,
                };
                from(&dict, top).or_else(|| lockdown.and_then(|d| from(d, lockdown_key)))
            };

            let display_name = string_field("Display Name", "DeviceName");
            let product_type = string_field("Product Type", "ProductType");
            let product_version = string_field("Product Version", "ProductVersion");
            let build_version = string_field("Build Version", "BuildVersion");
            let serial_number = string_field("Serial Number", "SerialNumber");
            let unique_identifier = string_field("Unique Identifier", "UniqueDeviceID");
            // Only `Info.plist` carries the IMEI, under its own unspaced key.
            let imei = string_field("IMEI", "IMEI");

            let keybag_data = dict.get("BackupKeyBag").and_then(|v| {
                if let plist::Value::Data(d) = v {
                    Some(d.clone())
                } else {
                    None
                }
            });

            let manifest_key = dict.get("ManifestKey").and_then(|v| {
                if let plist::Value::Data(d) = v {
                    Some(d.clone())
                } else {
                    None
                }
            });

            Ok(Self {
                is_encrypted,
                version,
                date,
                display_name,
                product_type,
                product_version,
                build_version,
                serial_number,
                unique_identifier,
                imei,
                keybag_data,
                manifest_key,
            })
        } else {
            Err(anyhow::anyhow!("Manifest.plist root is not a dictionary"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_backup_dir() -> PathBuf {
        let crate_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        crate_dir
            .parent()
            .unwrap()
            .join("test_data")
            .join("ios_backup")
    }

    #[test]
    fn test_parse_real_manifest_plist() {
        let plist_path = test_backup_dir().join("Manifest.plist");
        if !plist_path.exists() {
            eprintln!(
                "Skipping test_parse_real_manifest_plist: {:?} not found",
                plist_path
            );
            return;
        }

        let manifest = ManifestPlist::from_file(&plist_path).unwrap();

        // Basic fields should be populated
        assert!(!manifest.version.is_empty(), "Version should not be empty");
        assert!(manifest.date.is_some(), "Date should be present");

        // This backup has a keybag (even though unencrypted)
        assert!(
            manifest.keybag_data.is_some(),
            "Expected BackupKeyBag data in Manifest.plist"
        );

        if let Some(ref keybag) = manifest.keybag_data {
            assert!(
                keybag.len() > 100,
                "Keybag should be substantial, got {} bytes",
                keybag.len()
            );
        }

        eprintln!(
            "Manifest.plist: encrypted={}, version={}, device={:?}",
            manifest.is_encrypted, manifest.version, manifest.display_name
        );
    }

    /// Write a `Manifest.plist` holding `entries` and return its path.
    fn write_plist(entries: Vec<(&str, plist::Value)>) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("seance_ios_plist_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("Manifest.plist");
        let mut dict = plist::Dictionary::new();
        for (key, value) in entries {
            dict.insert(key.to_string(), value);
        }
        plist::Value::Dictionary(dict).to_file_xml(&path).unwrap();
        path
    }

    /// `IsEncrypted` used to be read only as a Boolean, and anything else — an
    /// integer flag, or no flag at all — silently became "not encrypted". The
    /// whole backup would then be walked as clear text, attaching ciphertext as
    /// file content (the B8-026 class). It is read, and when it cannot be read
    /// the manifest's own `ManifestKey` answers.
    #[test]
    fn is_encrypted_is_read_not_defaulted() {
        let as_int = write_plist(vec![
            (
                "IsEncrypted",
                plist::Value::Integer(plist::Integer::from(1i64)),
            ),
            ("Version", plist::Value::String("10.0".into())),
        ]);
        assert!(
            ManifestPlist::from_file(&as_int).unwrap().is_encrypted,
            "an integer 1 flag means encrypted"
        );
        let _ = std::fs::remove_dir_all(as_int.parent().unwrap());

        let int_zero = write_plist(vec![(
            "IsEncrypted",
            plist::Value::Integer(plist::Integer::from(0i64)),
        )]);
        assert!(!ManifestPlist::from_file(&int_zero).unwrap().is_encrypted);
        let _ = std::fs::remove_dir_all(int_zero.parent().unwrap());

        // No flag, but a ManifestKey: that key exists only to decrypt an
        // encrypted Manifest.db.
        let no_flag = write_plist(vec![("ManifestKey", plist::Value::Data(vec![3u8; 44]))]);
        assert!(
            ManifestPlist::from_file(&no_flag).unwrap().is_encrypted,
            "a ManifestKey is evidence the manifest is encrypted"
        );
        let _ = std::fs::remove_dir_all(no_flag.parent().unwrap());

        // No flag and no ManifestKey: nothing says encrypted.
        let plain = write_plist(vec![("Version", plist::Value::String("9.0".into()))]);
        assert!(!ManifestPlist::from_file(&plain).unwrap().is_encrypted);
        let _ = std::fs::remove_dir_all(plain.parent().unwrap());
    }

    /// HUNT-091. A real iTunes `Manifest.plist` carries the device under a
    /// `Lockdown` dictionary; only `Info.plist` uses the spaced top-level keys
    /// this parser read. So every real backup — an encrypted one included, where
    /// this is the *only* thing readable without the password — was recorded
    /// with no device on it: an anonymous locked blob, when the phone names
    /// itself in the clear two keys away.
    #[test]
    fn the_device_is_read_from_the_lockdown_dictionary_too() {
        let mut lockdown = plist::Dictionary::new();
        lockdown.insert(
            "DeviceName".into(),
            plist::Value::String("Ada's iPhone".into()),
        );
        lockdown.insert(
            "ProductType".into(),
            plist::Value::String("iPhone12,1".into()),
        );
        lockdown.insert("ProductVersion".into(), plist::Value::String("17.3".into()));
        lockdown.insert("BuildVersion".into(), plist::Value::String("21D50".into()));
        lockdown.insert(
            "SerialNumber".into(),
            plist::Value::String("F4GZ987AN72N".into()),
        );
        lockdown.insert(
            "UniqueDeviceID".into(),
            plist::Value::String("00008030-001259123E50802E".into()),
        );

        let path = write_plist(vec![
            ("IsEncrypted", plist::Value::Boolean(true)),
            ("Version", plist::Value::String("10.0".into())),
            ("Lockdown", plist::Value::Dictionary(lockdown)),
        ]);
        let manifest = ManifestPlist::from_file(&path).unwrap();
        assert_eq!(manifest.display_name.as_deref(), Some("Ada's iPhone"));
        assert_eq!(manifest.product_type.as_deref(), Some("iPhone12,1"));
        assert_eq!(manifest.product_version.as_deref(), Some("17.3"));
        assert_eq!(manifest.build_version.as_deref(), Some("21D50"));
        assert_eq!(manifest.serial_number.as_deref(), Some("F4GZ987AN72N"));
        assert_eq!(
            manifest.unique_identifier.as_deref(),
            Some("00008030-001259123E50802E")
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());

        // The Info.plist shape still wins where both are present: it is the one
        // iTunes writes for the backup itself.
        let mut lockdown = plist::Dictionary::new();
        lockdown.insert("DeviceName".into(), plist::Value::String("stale".into()));
        let path = write_plist(vec![
            ("Display Name", plist::Value::String("Ada's iPhone".into())),
            ("Lockdown", plist::Value::Dictionary(lockdown)),
        ]);
        assert_eq!(
            ManifestPlist::from_file(&path)
                .unwrap()
                .display_name
                .as_deref(),
            Some("Ada's iPhone")
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn test_keybag_parses_from_real_plist() {
        let plist_path = test_backup_dir().join("Manifest.plist");
        if !plist_path.exists() {
            eprintln!(
                "Skipping test_keybag_parses_from_real_plist: {:?} not found",
                plist_path
            );
            return;
        }

        let manifest = ManifestPlist::from_file(&plist_path).unwrap();
        if let Some(ref keybag_data) = manifest.keybag_data {
            // Verify our keybag parser can handle real Apple keybag data
            let keybag = crate::crypto::parse_keybag(keybag_data).unwrap();

            assert!(!keybag.salt.is_empty(), "Keybag SALT should not be empty");
            assert!(keybag.iter > 0, "Keybag ITER should be > 0");
            assert!(
                !keybag.class_keys.is_empty(),
                "Keybag should contain class keys"
            );

            eprintln!(
                "Real keybag: {} class keys, iter={}, uuid={} bytes, dpsl={}",
                keybag.class_keys.len(),
                keybag.iter,
                keybag.uuid.len(),
                keybag.dpsl.is_some()
            );
        }
    }
}
