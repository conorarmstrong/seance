//! IOS-KEYCHAIN-1: the known answer for the iOS keychain inside an encrypted
//! backup (HUNT-111), on real evidence.
//!
//! The evidence is Josh Hickman's public iOS 17 image (Digital Corpora,
//! `iOS_17_Public_Image.tar.gz`), whose Finder backup
//! `iOS_17/Backup/00008030-001259123E50802E.zip` (SHA-256
//! `ACEA6302…499E0B`, as published) is encrypted with the password published
//! in the image's creation PDF, `MyPassword123`. Set `SEANCE_IOS17_BACKUP` to
//! the unzipped backup directory (the one holding `Manifest.plist`); see
//! `documentation/VALIDATION.md` (IOS-KEYCHAIN-1) for the extraction step.
//! Without it the test says it could not look and passes vacuously.
//!
//! The counts were measured first with an independent Python reader
//! (`cryptography`'s AES key unwrap and AES-ECB, its own GHASH) before this
//! reader existed; nothing here was tuned to them.

use seance_core::artifact::{Artifact, ArtifactType};
use seance_core::module::ForensicsModule;
use seance_plugin_ios_backup::IosBackupParser;
use serde_json::{json, Value};
use std::collections::BTreeMap;

const KEYCHAIN_FILE_ID: &str = "51a4616e576dd33cd2abadfea874eb8ff246bf0e";

fn backup_dir() -> Option<String> {
    match std::env::var("SEANCE_IOS17_BACKUP") {
        Ok(d) if std::path::Path::new(&d).join("Manifest.plist").exists() => Some(d),
        _ => {
            eprintln!(
                "IOS-KEYCHAIN-1 could not look: SEANCE_IOS17_BACKUP is not set to the \
                 unzipped Hickman iOS 17 backup directory"
            );
            None
        }
    }
}

fn run(dir: &str, password: &str) -> Result<Vec<Artifact>, String> {
    let input = Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::RawEvidence,
        None,
        json!({ "path": dir }),
    );
    IosBackupParser::with_password(password.to_string())
        .process(&input)
        .map_err(|e| e.to_string())
}

fn of_type<'a>(out: &'a [Artifact], t: &str) -> Vec<&'a Value> {
    out.iter()
        .map(|a| &a.metadata)
        .filter(|m| m["type"] == t)
        .collect()
}

#[test]
fn hickman_ios17_keychain_known_answer() {
    let Some(dir) = backup_dir() else { return };

    let out = run(&dir, "MyPassword123").expect("the published password opens the backup");
    // The keybag: 14 classes, of which the password opens 9. Classes
    // 5/9/10/11/19 are WRAP=3 (device-bound): their passcode layer checks out
    // but what it yields is not a class key (§1.5 slice A).
    let info = of_type(&out, "IosBackupInfo")
        .into_iter()
        .find(|m| m["status"] == "decrypted")
        .expect("a decrypted-backup record");
    let classes = &info["keybag_classes"];
    assert_eq!(classes["total"], 14);
    let sorted = |v: &Value| {
        let mut c: Vec<u64> = v
            .as_array()
            .expect("an array of class numbers")
            .iter()
            .map(|n| n.as_u64().unwrap())
            .collect();
        c.sort_unstable();
        c
    };
    assert_eq!(sorted(&classes["usable"]), [1, 2, 3, 4, 6, 7, 8, 17, 18]);
    assert_eq!(sorted(&classes["device_bound"]), [5, 9, 10, 11, 19]);
    assert_eq!(classes["not_unwrapped"], json!([]));
    let unlocked =
        seance_plugin_ios_backup::unlock_backup(std::path::Path::new(&dir), "MyPassword123")
            .expect("unlock for reading");
    let states = unlocked.class_key_states();
    assert_eq!(states.len(), 14);
    assert_eq!(
        states
            .iter()
            .filter(|(_, s)| *s == seance_plugin_ios_backup::ClassKeyState::DeviceBound)
            .count(),
        5
    );

    let items = of_type(&out, "IosKeychainItem");
    let summaries = of_type(&out, "IosKeychainSummary");
    assert_eq!(summaries.len(), 1);
    let summary = summaries[0];
    assert_eq!(summary["source_file_id"], KEYCHAIN_FILE_ID);

    // Every item record is parented to the keychain file's own FileEntry.
    let keychain_file = out
        .iter()
        .find(|a| {
            a.metadata["file_id"] == KEYCHAIN_FILE_ID && a.metadata["type"] == "IosBackupFile"
        })
        .expect("keychain-backup.plist is a decrypted file entry");
    assert_eq!(keychain_file.metadata["protection_class_used"], 1);
    let items_parented = out
        .iter()
        .filter(|a| a.metadata["type"] == "IosKeychainItem")
        .all(|a| a.parent_id == Some(keychain_file.id));
    assert!(items_parented);

    let count_by = |key: &str| {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for i in &items {
            let v = match &i[key] {
                Value::String(s) => s.clone(),
                other => other.to_string(),
            };
            *m.entry(v).or_default() += 1;
        }
        m
    };
    assert_eq!(items.len(), 1368);
    assert_eq!(
        count_by("table"),
        BTreeMap::from([
            ("cert".into(), 9),
            ("genp".into(), 1111),
            ("inet".into(), 201),
            ("keys".into(), 47)
        ])
    );
    assert_eq!(
        count_by("keychain_class"),
        BTreeMap::from([
            ("6".into(), 151),
            ("7".into(), 432),
            ("8".into(), 70),
            ("9".into(), 32),
            ("10".into(), 320),
            ("11".into(), 363)
        ])
    );
    // Classes 6/7/8 open with the backup's class keys; every one also
    // verifies its GCM tag. Classes 9/10/11 are device-bound.
    assert_eq!(
        count_by("state"),
        BTreeMap::from([("device_bound".into(), 715), ("read".into(), 653)])
    );
    for i in &items {
        let class = i["keychain_class"].as_u64().unwrap();
        let expect = if class >= 9 { "device_bound" } else { "read" };
        assert_eq!(i["state"], expect, "class {class}");
    }

    let gi: Vec<_> = items
        .iter()
        .filter(|i| i["state"] == "read" && (i["table"] == "genp" || i["table"] == "inet"))
        .collect();
    assert_eq!(gi.len(), 616);
    assert_eq!(gi.iter().filter(|i| i["account"].is_string()).count(), 614);
    assert_eq!(
        gi.iter().filter(|i| i["account_hex"].is_string()).count(),
        2
    );
    assert_eq!(
        gi.iter().filter(|i| i["secret_present"] == true).count(),
        579
    );
    assert_eq!(
        items
            .iter()
            .filter(|i| i["secret_state"] == "withheld")
            .count(),
        616
    );
    assert_eq!(summary["secrets_withheld"], 616);
    assert_eq!(
        items
            .iter()
            .filter(|i| i["table"] == "genp" && i["service"] == "AirPort")
            .count(),
        10
    );

    // Nothing carries the secret or the digest over it.
    for i in &items {
        let attrs = i.get("attributes").and_then(Value::as_object);
        if let Some(a) = attrs {
            assert!(!a.contains_key("v_Data") && !a.contains_key("sha1"));
        }
        assert!(i.get("v_Data").is_none());
    }

    // The wrong password yields no keychain item at all.
    let wrong = run(&dir, "NotThePassword").unwrap_or_default();
    assert!(of_type(&wrong, "IosKeychainItem").is_empty());
    assert!(of_type(&wrong, "IosKeychainSummary").is_empty());
}
