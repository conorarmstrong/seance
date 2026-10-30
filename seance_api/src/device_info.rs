//! "Whose phone is this?" — compiled from what the parsers already recorded.
//!
//! It is the first question asked of a mobile exhibit and Séance had no surface
//! that answered it: `system_info` compiles Windows registry hives and returns
//! empty on an Android or iOS image, so a Pixel's model, serial and build were
//! reachable only by searching raw files (HUNT-079).
//!
//! Two rules shape what this produces, and they are the same two the Windows
//! compiler follows:
//!
//! * **Every fact names where it came from** — the file, and the property or
//!   plist key inside it. An examiner asked to stand over "the model is Pixel
//!   7a" has to be able to say what they read.
//! * **Disagreement is shown, never resolved silently.** A device has several
//!   property files and they can differ — a vendor image reflashed over a system
//!   image is exactly the kind of thing that matters. Every distinct value for a
//!   fact is listed, with its source; nothing is averaged, and no rule picks a
//!   winner behind the examiner's back.

use serde_json::{json, Value};
use std::collections::BTreeMap;

/// The order a device summary reads in. Facts outside this list still appear,
/// after these, in the order they were met — an unknown fact is shown, not
/// dropped.
const FACT_ORDER: &[&str] = &[
    "host_name",
    "computer_name",
    "dns_host_name",
    "pretty_name",
    "os_name",
    "manufacturer",
    "model",
    "device",
    "product_name",
    "device_name",
    "bluetooth_name",
    "google_account",
    "account",
    "phone_number",
    "sim_name",
    "carrier",
    "iccid",
    "imsi",
    "android_id",
    "bluetooth_address",
    "serial_number",
    "unique_identifier",
    "imei",
    "os_version",
    "version_id",
    "codename",
    "os_id",
    "os_like",
    "variant",
    "machine_id",
    "user_account",
    "android_version",
    "sdk_level",
    "build_id",
    "build_display_id",
    "build_fingerprint",
    "security_patch",
    "build_date_utc",
    "build_type",
    "build_tags",
    "hardware",
    "bootloader",
    "cpu_abi",
    "locale",
    "timezone",
    "encryption_state",
    "encryption_type",
    "verified_boot_state",
    "clock_set_automatically",
    "time_zone_set_automatically",
    "adb_enabled",
    "developer_options_enabled",
    "sideloading_allowed",
    "location_mode",
    "user_setup_complete",
    "last_backup",
];

/// Facts a device can legitimately have more than one of.
///
/// A dual-SIM phone has two numbers and two ICCIDs; a phone can hold two Google
/// accounts and a dozen app ones. Several values for one of these is the
/// ordinary case, and reporting it the way a *disagreement* is reported — two
/// property files claiming different models — would turn the normal into an
/// alarm and teach an examiner to ignore the one that matters.
const MULTI_VALUED: &[&str] = &[
    "account",
    "user_account",
    "google_account",
    "phone_number",
    "iccid",
    "imsi",
    "carrier",
    "sim_name",
];

/// One reading of one fact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Reading {
    value: String,
    source_file: String,
    source_key: String,
}

fn string_of(record: &Value, key: &str) -> Option<String> {
    record
        .get(key)
        .and_then(|v| v.as_str())
        .map(str::to_string)
        .filter(|s| !s.is_empty())
}

/// Fold the Android property records, the iOS backup records and the Linux host
/// identity files into one device-facts view per platform.
///
/// `android` are `MobileDeviceInfo` record metadata, `ios` are `IosBackupInfo`
/// record metadata, and `linux` are `HostDeviceInfo` record metadata — the same
/// `facts` / `fact_sources` shape as the Android records, so the Linux identity
/// files fold in the same way. Returns the JSON the device-facts screen renders.
pub fn compile_device_info(android: &[Value], ios: &[Value], linux: &[Value]) -> Value {
    let mut platforms: BTreeMap<String, BTreeMap<String, Vec<Reading>>> = BTreeMap::new();
    let mut incomplete: Vec<Value> = Vec::new();

    for (default_platform, records) in [("android", android), ("linux", linux)] {
        for record in records {
            // A host record names its own platform: the same reader family
            // writes Linux and macOS facts, and a Mac must not be filed under
            // the platform the endpoint happened to fetch it with.
            let platform = record
                .get("platform")
                .and_then(|v| v.as_str())
                .unwrap_or(default_platform)
                .to_string();
            let source_file = string_of(record, "source_file").unwrap_or_else(|| "unknown".into());
            if record.get("content_incomplete").and_then(|v| v.as_bool()) == Some(true) {
                incomplete.push(json!({
                "source_file": source_file,
                "reason": record.get("content_incomplete_reason").cloned().unwrap_or(Value::Null),
                "detail": record.get("content_incomplete_detail").cloned().unwrap_or(Value::Null),
            }));
            }
            let Some(facts) = record.get("facts").and_then(|v| v.as_object()) else {
                continue;
            };
            let sources = record.get("fact_sources").and_then(|v| v.as_object());
            let into = platforms.entry(platform).or_default();
            for (fact, value) in facts {
                let source_key = sources
                    .and_then(|s| s.get(fact))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                // A fact is one value or several: the property files write a string,
                // and the accounts and SIM readers write a list, because a device
                // really does have more than one account and more than one SIM.
                let values: Vec<String> = match value {
                    Value::String(v) => vec![v.clone()],
                    Value::Array(items) => items
                        .iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect(),
                    _ => continue,
                };
                for value in values.into_iter().filter(|v| !v.is_empty()) {
                    into.entry(fact.clone()).or_default().push(Reading {
                        value,
                        source_file: source_file.clone(),
                        source_key: source_key.clone(),
                    });
                }
            }
        }
    }

    // The iOS backup manifest names the device in the clear, password or no
    // password (HUNT-091), so a locked backup still answers this question.
    const IOS_FACTS: &[(&str, &str, &str)] = &[
        ("device_name", "device_name", "Lockdown.DeviceName"),
        ("model", "product_type", "Lockdown.ProductType"),
        ("os_version", "product_version", "Lockdown.ProductVersion"),
        ("build_id", "build_version", "Lockdown.BuildVersion"),
        ("serial_number", "serial_number", "Lockdown.SerialNumber"),
        (
            "unique_identifier",
            "unique_identifier",
            "Lockdown.UniqueDeviceID",
        ),
        ("imei", "imei", "IMEI"),
        ("last_backup", "date", "Date"),
    ];
    for record in ios {
        let source_file = string_of(record, "backup_path")
            .or_else(|| string_of(record, "source_file"))
            .unwrap_or_else(|| "iOS backup".into());
        // A backup read from inside an image names its device and does NOT put
        // the device's files back at their own paths (HUNT-108). That is a
        // shortfall in the inventory rather than in the facts above, and the
        // panel has to carry it: an examiner who reads "Eli's iPhone" here and
        // then finds no messages would otherwise conclude the phone held none.
        for key in ["content_incomplete", "inventory_incomplete"] {
            if record.get(key).and_then(|v| v.as_bool()) == Some(true) {
                incomplete.push(json!({
                    "source_file": source_file,
                    "reason": record.get(format!("{key}_reason").as_str()).cloned().unwrap_or(Value::Null),
                    "detail": record.get(format!("{key}_detail").as_str()).cloned().unwrap_or(Value::Null),
                }));
            }
        }
        let into = platforms.entry("ios".to_string()).or_default();
        for (fact, key, plist_key) in IOS_FACTS {
            if let Some(value) = string_of(record, key) {
                into.entry((*fact).to_string()).or_default().push(Reading {
                    value,
                    source_file: source_file.clone(),
                    source_key: (*plist_key).to_string(),
                });
            }
        }
    }

    let devices: Vec<Value> = platforms
        .into_iter()
        .map(|(platform, facts)| {
            let mut ordered: Vec<(String, Vec<Reading>)> = facts.into_iter().collect();
            ordered.sort_by_key(|(fact, _)| {
                FACT_ORDER
                    .iter()
                    .position(|f| f == fact)
                    .unwrap_or(FACT_ORDER.len())
            });
            let mut disagreements = 0usize;
            let rows: Vec<Value> = ordered
                .into_iter()
                .map(|(fact, mut readings)| {
                    readings.sort();
                    readings.dedup();
                    let distinct: Vec<&str> = {
                        let mut v: Vec<&str> = readings.iter().map(|r| r.value.as_str()).collect();
                        v.sort_unstable();
                        v.dedup();
                        v
                    };
                    let multi_valued = MULTI_VALUED.contains(&fact.as_str());
                    if distinct.len() > 1 && !multi_valued {
                        disagreements += 1;
                    }
                    json!({
                        "fact": fact,
                        // A multi-valued fact is never "disagreed": two SIMs are
                        // two SIMs, not two answers to one question.
                        "agreed": distinct.len() == 1 || multi_valued,
                        "multi_valued": multi_valued,
                        "readings": readings.iter().map(|r| json!({
                            "value": r.value,
                            "source_file": r.source_file,
                            "source_key": r.source_key,
                        })).collect::<Vec<_>>(),
                    })
                })
                .collect();
            json!({
                "platform": platform,
                "facts": rows,
                "disagreements": disagreements,
            })
        })
        .collect();

    json!({
        "devices": devices,
        // Sources that could not be read whole. A device summary compiled from a
        // truncated property file is a subset, and saying so is the difference
        // between "this device has no serial" and "we did not reach it".
        "incomplete": incomplete,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn android(source: &str, facts: Value, sources: Value) -> Value {
        json!({
            "type": "MobileDeviceInfo",
            "platform": "android",
            "source_file": source,
            "facts": facts,
            "fact_sources": sources,
        })
    }

    fn linux(source: &str, facts: Value, sources: Value) -> Value {
        json!({
            "type": "HostDeviceInfo",
            "platform": "linux",
            "source_file": source,
            "facts": facts,
            "fact_sources": sources,
        })
    }

    #[test]
    fn a_linux_hosts_identity_files_answer_whose_machine_this_is() {
        let out = compile_device_info(
            &[],
            &[],
            &[
                linux(
                    "/etc/hostname",
                    json!({"host_name": "rshell-lenovo"}),
                    json!({"host_name": "file contents"}),
                ),
                linux(
                    "/usr/lib/os-release",
                    json!({"os_name": "Ubuntu", "version_id": "21.10"}),
                    json!({"os_name": "NAME", "version_id": "VERSION_ID"}),
                ),
            ],
        );
        let device = &out["devices"][0];
        assert_eq!(device["platform"], "linux");
        // The host name leads the summary, the way the model leads a phone's.
        assert_eq!(device["facts"][0]["fact"], "host_name");
        assert_eq!(device["facts"][0]["readings"][0]["value"], "rshell-lenovo");
        assert_eq!(
            device["facts"][0]["readings"][0]["source_file"],
            "/etc/hostname"
        );
        let version = device["facts"]
            .as_array()
            .expect("facts")
            .iter()
            .find(|f| f["fact"] == "version_id")
            .expect("version_id");
        assert_eq!(version["readings"][0]["value"], "21.10");
        assert_eq!(version["readings"][0]["source_key"], "VERSION_ID");
    }

    #[test]
    fn two_release_files_that_disagree_about_the_version_are_both_shown() {
        // `/etc/os-release` is usually a symlink to `/usr/lib/os-release`, but
        // on a system upgraded in place the two can differ, and which one an
        // examiner quoted matters.
        let out = compile_device_info(
            &[],
            &[],
            &[
                linux(
                    "/etc/os-release",
                    json!({"version_id": "21.04"}),
                    json!({"version_id": "VERSION_ID"}),
                ),
                linux(
                    "/usr/lib/os-release",
                    json!({"version_id": "21.10"}),
                    json!({"version_id": "VERSION_ID"}),
                ),
            ],
        );
        let device = &out["devices"][0];
        assert_eq!(device["disagreements"], json!(1));
        assert_eq!(device["facts"][0]["agreed"], json!(false));
        assert_eq!(device["facts"][0]["readings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_machine_with_several_people_on_it_is_not_a_disagreement() {
        let out = compile_device_info(
            &[],
            &[],
            &[linux(
                "/etc/passwd",
                json!({"user_account": ["root (uid 0, /root, /bin/bash)", "rafael (uid 1000, /home/rafael, /bin/bash)"]}),
                json!({"user_account": "passwd entry"}),
            )],
        );
        let device = &out["devices"][0];
        assert_eq!(device["disagreements"], json!(0));
        assert_eq!(device["facts"][0]["multi_valued"], json!(true));
        assert_eq!(device["facts"][0]["readings"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn a_backup_found_on_a_laptop_puts_the_phones_imei_on_the_summary() {
        // HUNT-108. The backup manifest is the only file that names the phone
        // without the password, and `Info.plist` is where its IMEI is.
        let out = compile_device_info(
            &[],
            &[json!({
                "type": "IosBackupInfo",
                "backup_path": "/eliflatt/Library/Application Support/MobileSync/Backup/518e8d76",
                "device_name": "Eli's iPhone",
                "imei": "356759080486567",
            })],
            &[],
        );
        let device = &out["devices"][0];
        assert_eq!(device["platform"], "ios");
        let imei = device["facts"]
            .as_array()
            .expect("facts")
            .iter()
            .find(|f| f["fact"] == "imei")
            .expect("imei");
        assert_eq!(imei["readings"][0]["value"], "356759080486567");
        assert_eq!(imei["readings"][0]["source_key"], "IMEI");
    }

    #[test]
    fn a_backup_whose_files_were_not_reassembled_says_so() {
        let out = compile_device_info(
            &[],
            &[json!({
                "type": "IosBackupInfo",
                "backup_path": "/eliflatt/.../Backup/518e8d76",
                "device_name": "Eli's iPhone",
                "inventory_incomplete": true,
                "inventory_incomplete_reason": "unresolved_structure",
                "inventory_incomplete_detail": "its stored files keep their hashed names",
            })],
            &[],
        );
        assert_eq!(out["incomplete"].as_array().expect("incomplete").len(), 1);
        assert_eq!(
            out["incomplete"][0]["detail"],
            "its stored files keep their hashed names"
        );
    }

    #[test]
    fn a_mac_is_filed_under_its_own_platform_not_the_one_it_was_fetched_with() {
        // Linux and macOS host facts come from one reader family and one record
        // type. A Mac filed under "Linux machine" would be a false statement on
        // the first line of the screen.
        let out = compile_device_info(
            &[],
            &[],
            &[json!({
                "type": "HostDeviceInfo",
                "platform": "macos",
                "source_file": "/System/Library/CoreServices/SystemVersion.plist",
                "facts": {"build_id": "20D74"},
                "fact_sources": {"build_id": "ProductBuildVersion"},
            })],
        );
        assert_eq!(out["devices"][0]["platform"], "macos");
    }

    #[test]
    fn a_phone_and_a_laptop_in_one_case_are_two_devices() {
        let out = compile_device_info(
            &[android(
                "/system/build.prop",
                json!({"model": "Pixel 3"}),
                json!({"model": "ro.product.model"}),
            )],
            &[],
            &[linux(
                "/etc/hostname",
                json!({"host_name": "rshell-lenovo"}),
                json!({"host_name": "file contents"}),
            )],
        );
        let platforms: Vec<&str> = out["devices"]
            .as_array()
            .expect("devices")
            .iter()
            .map(|d| d["platform"].as_str().unwrap())
            .collect();
        assert_eq!(platforms, vec!["android", "linux"]);
    }

    #[test]
    fn a_pixels_property_file_answers_whose_phone_this_is() {
        let out = compile_device_info(
            &[android(
                "/system/build.prop",
                json!({"model": "Pixel 7a", "serial_number": "1B031JEG500741"}),
                json!({"model": "ro.product.model", "serial_number": "ro.serialno"}),
            )],
            &[],
            &[],
        );
        let device = &out["devices"][0];
        assert_eq!(device["platform"], "android");
        let model = &device["facts"][0];
        assert_eq!(model["fact"], "model");
        assert_eq!(model["agreed"], json!(true));
        assert_eq!(model["readings"][0]["value"], "Pixel 7a");
        // The file AND the key: "where did you read that?" has to be answerable.
        assert_eq!(model["readings"][0]["source_file"], "/system/build.prop");
        assert_eq!(model["readings"][0]["source_key"], "ro.product.model");
    }

    /// Two property files disagreeing about the model is a finding, not noise:
    /// a vendor image reflashed over a system image looks exactly like this.
    /// Resolving it silently would hide the one thing worth seeing.
    #[test]
    fn property_files_that_disagree_are_both_shown() {
        let out = compile_device_info(
            &[
                android(
                    "/system/build.prop",
                    json!({"model": "Pixel 7a"}),
                    json!({"model": "ro.product.model"}),
                ),
                android(
                    "/vendor/build.prop",
                    json!({"model": "lynx"}),
                    json!({"model": "ro.product.vendor.model"}),
                ),
            ],
            &[],
            &[],
        );
        let device = &out["devices"][0];
        assert_eq!(device["disagreements"], 1);
        let model = &device["facts"][0];
        assert_eq!(model["agreed"], json!(false));
        assert_eq!(model["readings"].as_array().unwrap().len(), 2);
    }

    /// The same value from two files is agreement, not a disagreement — and it
    /// is listed once per source, because which files agreed is itself a fact.
    #[test]
    fn the_same_value_from_two_files_is_agreement() {
        let out = compile_device_info(
            &[
                android(
                    "/system/build.prop",
                    json!({"model": "Pixel 7a"}),
                    json!({}),
                ),
                android(
                    "/odm/etc/build.prop",
                    json!({"model": "Pixel 7a"}),
                    json!({}),
                ),
            ],
            &[],
            &[],
        );
        let model = &out["devices"][0]["facts"][0];
        assert_eq!(model["agreed"], json!(true));
        assert_eq!(model["readings"].as_array().unwrap().len(), 2);
    }

    /// A locked iOS backup still names its device — the manifest carries it in
    /// the clear — so the panel answers the question without the password.
    #[test]
    fn a_locked_ios_backup_still_names_its_device() {
        let out = compile_device_info(
            &[],
            &[json!({
                "type": "IosBackupInfo",
                "status": "encrypted_no_password",
                "backup_path": "/ev/Backup/00008030",
                "device_name": "This Is's iPhone",
                "product_type": "iPhone12,1",
                "product_version": "17.3",
                "serial_number": "F4GZ987AN72N",
            })],
            &[],
        );
        let device = &out["devices"][0];
        assert_eq!(device["platform"], "ios");
        let by_fact = |name: &str| -> Value {
            device["facts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["fact"] == name)
                .cloned()
                .unwrap_or(Value::Null)
        };
        assert_eq!(by_fact("model")["readings"][0]["value"], "iPhone12,1");
        assert_eq!(by_fact("os_version")["readings"][0]["value"], "17.3");
        assert_eq!(
            by_fact("serial_number")["readings"][0]["source_key"],
            "Lockdown.SerialNumber"
        );
    }

    /// A dual-SIM phone has two numbers and a phone can hold several accounts.
    /// Reporting that the way a *disagreement* is reported — two property files
    /// claiming different models — would turn the ordinary into an alarm and
    /// teach an examiner to ignore the one that matters.
    #[test]
    fn several_accounts_and_sims_are_not_a_disagreement() {
        let out = compile_device_info(
            &[
                json!({
                    "type": "MobileDeviceInfo",
                    "source_file": "/data/system_de/0/accounts_de.db",
                    "facts": {"google_account": ["ada@gmail.com", "ada.work@gmail.com"]},
                    "fact_sources": {"google_account": "accounts.name"},
                }),
                json!({
                    "type": "MobileDeviceInfo",
                    "source_file": "/data/user_de/0/com.android.providers.telephony/databases/telephony.db",
                    "facts": {"phone_number": ["+15551234567", "+15557654321"]},
                    "fact_sources": {"phone_number": "siminfo.number"},
                }),
            ],
            &[],
            &[],
        );
        let device = &out["devices"][0];
        assert_eq!(
            device["disagreements"], 0,
            "two SIMs are not a contradiction"
        );

        let by_fact = |name: &str| -> Value {
            device["facts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|f| f["fact"] == name)
                .cloned()
                .unwrap_or(Value::Null)
        };
        let accounts = by_fact("google_account");
        assert_eq!(accounts["multi_valued"], json!(true));
        assert_eq!(accounts["agreed"], json!(true));
        assert_eq!(accounts["readings"].as_array().unwrap().len(), 2);
        assert_eq!(
            by_fact("phone_number")["readings"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        // And each still names the column it came from.
        assert_eq!(
            by_fact("phone_number")["readings"][0]["source_key"],
            "siminfo.number"
        );
    }

    /// The model is single-valued, and two files claiming two models still has
    /// to read as a disagreement after the multi-valued facts were added.
    #[test]
    fn a_single_valued_fact_still_disagrees() {
        let out = compile_device_info(
            &[
                android(
                    "/system/build.prop",
                    json!({"model": "Pixel 7a"}),
                    json!({}),
                ),
                android("/vendor/build.prop", json!({"model": "lynx"}), json!({})),
            ],
            &[],
            &[],
        );
        assert_eq!(out["devices"][0]["disagreements"], 1);
        assert_eq!(out["devices"][0]["facts"][0]["multi_valued"], json!(false));
        assert_eq!(out["devices"][0]["facts"][0]["agreed"], json!(false));
    }

    /// A truncated property file makes the summary a subset, and the difference
    /// between "this device has no serial" and "we never reached it" is the
    /// whole point of saying so.
    #[test]
    fn a_source_that_was_not_read_whole_is_declared() {
        let mut record = android(
            "/system/build.prop",
            json!({"model": "Pixel 7a"}),
            json!({}),
        );
        record["content_incomplete"] = json!(true);
        record["content_incomplete_reason"] = json!("short_read");
        record["content_incomplete_detail"] = json!("only 200 byte(s) were acquired");

        let out = compile_device_info(&[record], &[], &[]);
        assert_eq!(out["incomplete"].as_array().unwrap().len(), 1);
        assert_eq!(out["incomplete"][0]["source_file"], "/system/build.prop");
        assert_eq!(out["incomplete"][0]["reason"], "short_read");
    }

    /// A case with no mobile evidence says so with an empty list rather than a
    /// device with no facts on it.
    #[test]
    fn no_mobile_evidence_is_an_empty_list() {
        let out = compile_device_info(&[], &[], &[]);
        assert!(out["devices"].as_array().unwrap().is_empty());
        assert!(out["incomplete"].as_array().unwrap().is_empty());
    }
}
