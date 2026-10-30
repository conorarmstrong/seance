//! What the phone had paired with, and when it last saw it.

use super::bluetooth::{is_bt_config, AndroidBluetoothParser};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource},
    module::ForensicsModule,
};
use serde_json::json;
use std::sync::Arc;

/// A real `bt_config.conf`, trimmed: the adapter, a device with no timestamp
/// (the first one ever paired) and one with a timestamp.
const BT_CONFIG: &[u8] = b"[Info]
FileSource = Empty
TimeCreated = 2022-01-14 17:47:42

[Adapter]
Address = 3c:28:6d:00:8e:c8
LE_LOCAL_KEY_IRK = ed9afa3dc8baec372eb0b34576d7bc5b
ScanMode = 1

[d0:5f:b8:33:df:00]
Manufacturer = 13
Name = Moto 360 DF00
DevClass = 657156
DevType = 1
LinkKeyType = 5
LinkKey = 38a5fb3db4e433040818f0fdaad037e2
Service = 0000110a-0000-1000-8000-00805f9b34fb 00001115-0000-1000-8000-00805f9b34fb

[50:18:09:17:74:22]
Timestamp = 1644731632
Name = Mpow Flame
DevClass = 2360324
DevType = 1
LinkKeyType = 4
LinkKey = 5d0cf334c802fbc87d35f2e954bbfed5
";

fn artifact(name: &str, bytes: &[u8]) -> Artifact {
    let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes.to_vec()));
    Artifact::new(
        uuid::Uuid::new_v4(),
        ArtifactType::FileEntry,
        Some(data),
        json!({"name": name, "path": format!("/data/misc/bluedroid/{name}")}),
    )
}

fn parse(bytes: &[u8]) -> Vec<Artifact> {
    AndroidBluetoothParser::new()
        .process(&artifact("bt_config.conf", bytes))
        .expect("parsed")
}

fn pairings(out: &[Artifact]) -> Vec<&Artifact> {
    out.iter()
        .filter(|a| a.metadata["type"] == "BluetoothPairing")
        .collect()
}

#[test]
fn every_remembered_device_becomes_a_pairing_record() {
    let out = parse(BT_CONFIG);
    let devices = pairings(&out);
    assert_eq!(devices.len(), 2, "the adapter is not a paired device");

    let watch = devices[0];
    assert_eq!(watch.metadata["address"], "d0:5f:b8:33:df:00");
    assert_eq!(watch.metadata["device_name"], "Moto 360 DF00");
    assert_eq!(
        watch.metadata["source_file"],
        "/data/misc/bluedroid/bt_config.conf"
    );
    // The file's order is evidence: Android appends a device when it is first
    // remembered, so the first section is the earliest pairing — which is the
    // only thing that answers "what was the FIRST device connected" for an
    // entry that carries no timestamp at all.
    assert_eq!(watch.metadata["order"], 0);
    assert_eq!(devices[1].metadata["order"], 1);
}

#[test]
fn a_last_seen_time_is_carried_and_its_absence_is_not_invented() {
    let devices_out = parse(BT_CONFIG);
    let devices = pairings(&devices_out);

    // 1644731632 = 2022-02-13T05:53:52Z.
    assert_eq!(
        devices[1].metadata["last_seen"],
        "2022-02-13T05:53:52+00:00"
    );
    // The watch has no Timestamp line. An invented date would put a pairing on
    // the timeline that the evidence never recorded.
    assert!(devices[0].metadata.get("last_seen").is_none());
    assert_eq!(devices[0].metadata["last_seen_recorded"], json!(false));
}

/// The link key decrypts this device's Bluetooth traffic. Its presence is a
/// finding; its value is a secret, and putting it in the case metadata would
/// put it in the search index and every export drawn from it.
#[test]
fn the_link_key_is_reported_as_present_and_never_copied() {
    let out = parse(BT_CONFIG);
    let devices = pairings(&out);
    assert_eq!(devices[0].metadata["link_key_present"], json!(true));
    assert_eq!(devices[0].metadata["link_key_type"], 5);
    let text = serde_json::to_string(&devices[0].metadata).unwrap();
    assert!(
        !text.contains("38a5fb3db4e433040818f0fdaad037e2"),
        "the link key itself must not be copied into the case: {text}"
    );
}

/// The adapter section is the phone's own radio, not something it paired with —
/// and its address is a device fact, which is where it belongs.
#[test]
fn the_adapter_is_a_device_fact_not_a_pairing() {
    let out = parse(BT_CONFIG);
    let facts = out
        .iter()
        .find(|a| a.metadata["type"] == "MobileDeviceInfo")
        .expect("the adapter's own address is a device fact");
    assert_eq!(
        facts.metadata["facts"]["bluetooth_address"],
        "3c:28:6d:00:8e:c8"
    );
    assert_eq!(
        facts.metadata["fact_sources"]["bluetooth_address"],
        "Adapter.Address"
    );
}

#[test]
fn the_services_a_device_offered_are_kept() {
    let out = parse(BT_CONFIG);
    let watch = pairings(&out)[0];
    let services = watch.metadata["services"].as_array().expect("a list");
    assert_eq!(services.len(), 2);
    assert_eq!(services[0], "0000110a-0000-1000-8000-00805f9b34fb");
}

#[test]
fn only_the_bluedroid_config_is_claimed() {
    assert!(is_bt_config("bt_config.conf"));
    assert!(is_bt_config("bt_config.bak"));
    assert!(!is_bt_config("bt_config.conf.tmp"));
    assert!(!is_bt_config("config.conf"));

    // A file with the name and something else inside is not claimed: an INI
    // with no `[Adapter]` and no MAC-shaped section is not this file.
    let out = parse(b"[General]\nfoo = bar\n");
    assert!(out.is_empty());
}

/// A device section with no name still happened, and dropping it would leave
/// the pairing list short of what the phone remembered.
#[test]
fn a_nameless_device_is_still_a_pairing() {
    let out =
        parse(b"[Adapter]\nAddress = 00:11:22:33:44:55\n\n[aa:bb:cc:dd:ee:ff]\nDevType = 2\n");
    let devices = pairings(&out);
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].metadata["address"], "aa:bb:cc:dd:ee:ff");
    assert!(devices[0].metadata.get("device_name").is_none());
}
