//! The data-protection keychain — `keychain-2.db`.
//!
//! macOS 11 keeps **two** keychains, and they are different databases with
//! different honesty. The classic `kych` file (`login.keychain-db`,
//! `System.keychain`, read by [`crate::KeychainParser`]) is an encrypted store
//! with a **cleartext index**: its item attributes — the service, the account,
//! the label — sit in the file in plain text. This one, the iOS-style
//! data-protection keychain under
//! `~/Library/Keychains/<UUID>/keychain-2.db`, does not.
//!
//! # What this database does and does not name
//!
//! Measured on the real file in the Magnet 2021 macOS image (4.7 MB, schema
//! version 11.9, 128 generic and 158 internet items): **every one of the
//! `acct`, `svce`, `srvr`, `path`, `atyp` and `sdmn` values is exactly twenty
//! bytes of non-text.** They are SHA-1 hashes of the attribute, and the value
//! each names is not recoverable from this file. 128 of 128 and 158 of 158,
//! with no exceptions. Even the `cert` table's subject, issuer and serial are
//! hashed, and its `data` is a wrapped blob rather than the raw DER the classic
//! keychain stores.
//!
//! So this reader **does not report an account or a service**, and the fields
//! it does emit for them are named `account_sha1`, `service_sha1` and so on, so
//! nothing downstream can render a hash where an examiner reads a username.
//!
//! What it *can* state, because these columns are text:
//!
//! * the **access group** (`agrp`) — which application or daemon owns the
//!   secret: `com.apple.continuity.unlock`, `com.apple.sbd`,
//!   `com.apple.security.sos`, `InternetAccounts`. That is the useful answer
//!   here, and it is what the hashed attributes were hashed to hide;
//!   the corpus file holds fourteen distinct groups on its generic items alone;
//! * the **protection class** (`pdmn`), decoded — and the
//!   `…ThisDeviceOnly` classes are forensically load-bearing, because such an
//!   item never syncs to iCloud Keychain. Three of them (`aku`, `cku`, `dku`)
//!   **are** written to an encrypted backup, wrapped there under a key derived
//!   from the device's hardware UID, so they can be restored only to the same
//!   device (the Hickman iOS 17 backup carries 715 such items, all in these
//!   three classes). The fourth, `akpu` (`WhenPasscodeSetThisDeviceOnly`),
//!   exists only in the system keybag: it is not backed up, not in an escrow
//!   keybag, and is rendered useless if the passcode is removed (Apple
//!   Platform Security, "Keychain data class protections"). Either way the
//!   item's absence from iCloud Keychain, or from a backup where that
//!   applies, is explained rather than suspicious;
//! * the **sync view** (`vwht`) — which iCloud keychain view the item syncs
//!   in (`Manatee`, `PCS-MasterKey`, `AutoUnlock`, `ApplePay`, `Home`);
//! * the creation and modification dates, the sync and tombstone flags, and
//!   the item's UUID.
//!
//! # `ckdevicestate`: the devices in the iCloud keychain circle
//!
//! One table here is entirely in the clear, and it is the one worth the most.
//! `ckdevicestate` records, per CloudKit zone, every device the Apple ID's
//! keychain circle has held: its identifier, its OS and build, its Secure
//! Object Sync circle status, its **Octagon peer id**, its Octagon status, its
//! key state and when it last unlocked.
//!
//! On the corpus image that is three devices — `iphone 20.3.0 (18D52)`,
//! `watch 19.6.0 (17U63)` and `macOS 20.3.0 (20D74)` — across 36 zone rows,
//! two of the devices being **not in the image at all**. A device inventory of
//! what an account trusted, from a file on one machine. Twenty-nine of those
//! rows read `kSOSCCInCircle` and **seven read `kSOSCCError`**: the circle
//! status is per zone, not per device, and reporting only the happy value
//! would hide that seven of this account's keychain zones were not syncing.
//!
//! It is also the answer to question 14 of the Magnet Virtual Summit 2021
//! macOS CTF, the one question `VALIDATION.md` recorded as unanswered: the
//! Mac's own Octagon peer id,
//! `SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=`.
//!
//! # What it will not do
//!
//! **No secret is decrypted.** Every item's `data` is wrapped under a class key
//! from the device keybag, which is protected by hardware this reader is never
//! given, so every item is reported `locked`. Unlike the classic keychain there
//! is no password that would open it from an image alone — the class keys live
//! in the Secure Enclave — and that is stated on the record rather than left to
//! be discovered.

use anyhow::{Context, Result};
use rusqlite::Connection;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use seance_sqlite_util::{looks_like_sqlite, probe_table, table_columns, Presence, TempDb};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use tracing::{info, warn};

use crate::{
    basename_lower, cfabsolute_to_unix_parts, stamp_incomplete, to_rfc3339_nanos, unix_ns,
    MAX_DB_BYTES,
};

/// Largest number of rows read from one item table.
const MAX_ITEMS_PER_TABLE: usize = 200_000;
/// Largest number of device-state rows read.
const MAX_DEVICE_ROWS: usize = 10_000;
/// Length of the SHA-1 the attribute columns hold.
const SHA1_BYTES: usize = 20;

/// The item tables, and what each holds.
///
/// `cert` and `keys` are included because their *presence* and their access
/// groups are evidence even though their contents are wrapped: a keychain
/// holding a key for `com.apple.security.octagon` says something about how the
/// account was enrolled.
const ITEM_TABLES: &[(&str, &str)] = &[
    ("genp", "generic_password"),
    ("inet", "internet_password"),
    ("cert", "certificate"),
    ("keys", "key"),
];

/// Columns that hold a **hash** of the attribute rather than the attribute.
///
/// Measured, not assumed: across the corpus file's 286 password items every
/// value in every one of these is exactly twenty bytes of non-text. They are
/// emitted under names ending `_sha1` for that reason.
const HASHED_COLUMNS: &[(&str, &str)] = &[
    ("acct", "account"),
    ("svce", "service"),
    ("srvr", "server"),
    ("path", "path"),
    ("atyp", "authentication_type"),
    ("sdmn", "security_domain"),
    ("labl", "label"),
    ("desc", "kind_description"),
    ("gena", "generic_field"),
    ("alis", "alias"),
    ("subj", "certificate_subject"),
    ("issr", "certificate_issuer"),
    ("slnr", "certificate_serial"),
    ("klbl", "key_label"),
    ("atag", "application_tag"),
];

/// Protection classes, as `pdmn` spells them.
///
/// The `…ThisDeviceOnly` classes matter to an examiner beyond their
/// accessibility: an item in one of them is **never** synced to iCloud
/// Keychain. An `aku`, `cku` or `dku` item is present in an encrypted backup
/// but wrapped under a key derived from the device's hardware UID, so it can
/// be restored only to the same device. An `akpu` item is not backed up at
/// all: its class exists only in the system keybag, and its class key is
/// discarded if the passcode is removed.
fn protection_class(code: &str) -> Option<(&'static str, bool)> {
    Some(match code {
        "ak" => ("when_unlocked", false),
        "ck" => ("after_first_unlock", false),
        "dk" => ("always", false),
        "aku" => ("when_unlocked_this_device_only", true),
        "cku" => ("after_first_unlock_this_device_only", true),
        "dku" => ("always_this_device_only", true),
        "akpu" => ("when_passcode_set_this_device_only", true),
        _ => return None,
    })
}

/// What an item in a `…ThisDeviceOnly` class means for where else it can be
/// found. The passcode-set class is not backed up at all, so it is said
/// separately from the three that are (Apple Platform Security, "Keychain
/// data class protections").
fn this_device_only_note(name: &str) -> &'static str {
    if name == "when_passcode_set_this_device_only" {
        "An item in the `WhenPasscodeSetThisDeviceOnly` class is never synced to iCloud \
         Keychain and is not backed up: its class exists only in the device's system keybag, \
         and is not in a backup or escrow keybag. If the passcode is removed or reset, the class \
         key is discarded and the item can no longer be decrypted. Its absence from iCloud \
         Keychain and from any backup is explained rather than notable."
    } else {
        "An item in a `ThisDeviceOnly` class is never synced to iCloud Keychain. It is written \
         to an encrypted backup, but wrapped there under a key derived from this device's \
         hardware UID, so it can be restored only to the same device and cannot be opened from \
         the backup anywhere else. Its absence from iCloud Keychain, and its being unreadable in \
         a backup, are explained rather than notable."
    }
}

/// Longer form of a protection class, for a screen.
fn protection_description(name: &str) -> &'static str {
    match name {
        "when_unlocked" => "readable only while the device is unlocked",
        "after_first_unlock" => "readable after the first unlock since boot",
        "always" => "readable whenever the device is running (a deprecated class)",
        "when_unlocked_this_device_only" => {
            "readable only while unlocked; bound to this device's hardware"
        }
        "after_first_unlock_this_device_only" => {
            "readable after the first unlock since boot; bound to this device's hardware"
        }
        "always_this_device_only" => {
            "readable whenever the device is running; bound to this device's hardware"
        }
        "when_passcode_set_this_device_only" => {
            "readable only while unlocked, requires a passcode to be set; not synced and \
             not backed up, and unreadable once the passcode is removed"
        }
        _ => "not a class this reader names",
    }
}

/// The sentence every item carries.
const LOCKED_NOTE: &str = "This database's item attributes are stored as SHA-1 hashes, so it \
     names no account and no service; what it does name is the application that owns the secret, \
     the protection class and the sync view. The secret itself is wrapped under a class key from \
     the device keybag, which is protected by hardware an image does not carry, so unlike the \
     classic keychain there is no password that would open it from this file. An absent password \
     here is NOT evidence that the item held none.";

pub struct DataProtectionKeychainParser;

fn is_keychain_2(name: &str) -> bool {
    // Apple has shipped this file under this name since iOS 4, and macOS uses
    // the same one. The `-wal` and `-shm` siblings are not it; `TempDb::spill`
    // attaches the WAL to the main file, which is where uncheckpointed rows
    // are read from.
    basename_lower(name) == "keychain-2.db"
}

/// How a `BLOB` attribute reads.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Attr {
    /// Twenty bytes of non-text: a SHA-1 of the value, which is not
    /// recoverable from this file.
    Hash(String),
    /// Printable text, which some columns do carry.
    Text(String),
    /// Bytes that are neither, reported as what they are.
    Bytes { hex: String, len: usize },
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(char::from(HEX[usize::from(b >> 4)]));
        out.push(char::from(HEX[usize::from(b & 0x0f)]));
    }
    out
}

/// Classify a blob attribute.
///
/// A twenty-byte value that is not text is a hash; anything that decodes as
/// printable text is reported as text, because `agrp`, `pdmn` and `vwht` are
/// text in this schema and a future column might be. Nothing is guessed: the
/// three cases are reported under three different names.
fn classify(raw: &[u8]) -> Option<Attr> {
    if raw.is_empty() {
        return None;
    }
    if let Ok(text) = std::str::from_utf8(raw) {
        let trimmed = text.trim_end_matches('\0');
        if !trimmed.is_empty() && trimmed.chars().all(|c| !c.is_control()) {
            return Some(Attr::Text(trimmed.to_string()));
        }
    }
    if raw.len() == SHA1_BYTES {
        return Some(Attr::Hash(hex(raw)));
    }
    Some(Attr::Bytes {
        hex: hex(raw),
        len: raw.len(),
    })
}

/// One row of `ckdevicestate`: a device the account's keychain circle held.
#[derive(Debug, Clone)]
struct DeviceState {
    zone: String,
    device: Option<String>,
    os_version: Option<String>,
    last_unlock: Option<String>,
    peer_id: Option<String>,
    circle_status: Option<String>,
    octagon_peer_id: Option<String>,
    octagon_status: Option<String>,
    key_state: Option<String>,
    current_tlk: Option<String>,
    current_class_a: Option<String>,
    current_class_c: Option<String>,
}

fn read_device_states(conn: &Connection) -> Result<(Vec<DeviceState>, bool)> {
    let columns = table_columns(conn, "ckdevicestate");
    // Every column is read by name and absent ones are reported absent, so a
    // schema from another OS version is read rather than refused.
    // `table_columns` lower-cases what it returns, so a column is probed in
    // lower case and named in the projection as the schema spells it.
    let want = |name: &str| columns.contains(&name.to_ascii_lowercase());
    let mut sql = String::from("SELECT ckzone");
    let optional = [
        "device",
        "osversion",
        "lastunlock",
        "peerid",
        "circlestatus",
        "octagonpeerid",
        "octagonstatus",
        "keystate",
        "currentTLK",
        "currentClassA",
        "currentClassC",
    ];
    for col in optional {
        if want(col) {
            sql.push_str(&format!(", \"{col}\""));
        } else {
            sql.push_str(", NULL");
        }
    }
    sql.push_str(" FROM ckdevicestate LIMIT ?1");
    let mut stmt = conn.prepare(&sql).context("prepare ckdevicestate")?;
    let rows = stmt
        .query_map([MAX_DEVICE_ROWS as i64 + 1], |r| {
            Ok(DeviceState {
                zone: r.get::<_, Option<String>>(0)?.unwrap_or_default(),
                device: r.get(1)?,
                os_version: r.get(2)?,
                last_unlock: r.get(3)?,
                peer_id: r.get(4)?,
                circle_status: r.get(5)?,
                octagon_peer_id: r.get(6)?,
                octagon_status: r.get(7)?,
                key_state: r.get(8)?,
                current_tlk: r.get(9)?,
                current_class_a: r.get(10)?,
                current_class_c: r.get(11)?,
            })
        })
        .context("query ckdevicestate")?;
    let mut out = Vec::new();
    let mut capped = false;
    for row in rows {
        if out.len() >= MAX_DEVICE_ROWS {
            capped = true;
            break;
        }
        out.push(row.context("read a ckdevicestate row")?);
    }
    Ok((out, capped))
}

/// One item row, reduced to what this database actually states.
#[derive(Debug, Clone)]
struct Item {
    table: &'static str,
    kind: &'static str,
    rowid: i64,
    access_group: Option<String>,
    protection: Option<String>,
    /// True when the protection class is one of the `…ThisDeviceOnly` ones.
    this_device_only: bool,
    sync_view: Option<String>,
    synced: Option<bool>,
    tombstone: Option<bool>,
    uuid: Option<String>,
    created: Option<(i64, u32)>,
    modified: Option<(i64, u32)>,
    /// Hashed and textual attributes, under the names they are emitted as.
    attributes: Vec<(String, Attr)>,
    /// Length of the wrapped payload, when the row has one.
    payload_bytes: Option<i64>,
}

fn read_items(
    conn: &Connection,
    table: &'static str,
    kind: &'static str,
) -> Result<(Vec<Item>, bool)> {
    let columns = table_columns(conn, table);
    // Build the projection from the columns the table actually has.
    let mut names: Vec<&str> = vec!["rowid"];
    let optional = [
        "agrp", "pdmn", "vwht", "sync", "tomb", "UUID", "cdat", "mdat", "data",
    ];
    let mut present: Vec<&str> = Vec::new();
    for col in optional {
        // Lower-cased because that is how `table_columns` reports names, while
        // the projection uses the schema's own spelling (`UUID`).
        if columns.contains(&col.to_ascii_lowercase()) {
            present.push(col);
        }
    }
    let mut hashed: Vec<(&str, &str)> = Vec::new();
    for (col, label) in HASHED_COLUMNS {
        if columns.contains(&col.to_ascii_lowercase()) {
            hashed.push((col, label));
        }
    }
    let mut sql = String::from("SELECT rowid");
    for col in &present {
        if *col == "data" {
            sql.push_str(", length(\"data\")");
        } else {
            sql.push_str(&format!(", \"{col}\""));
        }
    }
    for (col, _) in &hashed {
        sql.push_str(&format!(", \"{col}\""));
    }
    names.extend(present.iter().copied());
    sql.push_str(&format!(" FROM \"{table}\" LIMIT ?1"));

    let mut stmt = conn
        .prepare(&sql)
        .with_context(|| format!("prepare {table}"))?;
    let base = 1; // rowid occupies index 0
    let mut out = Vec::new();
    let mut capped = false;
    let mut rows = stmt
        .query([MAX_ITEMS_PER_TABLE as i64 + 1])
        .with_context(|| format!("query {table}"))?;
    while let Some(row) = rows.next().with_context(|| format!("read {table}"))? {
        if out.len() >= MAX_ITEMS_PER_TABLE {
            capped = true;
            break;
        }
        let at = |col: &str| present.iter().position(|c| *c == col).map(|i| base + i);
        let text = |idx: Option<usize>| -> Option<String> {
            idx.and_then(|i| row.get::<_, Option<String>>(i).ok().flatten())
        };
        let number = |idx: Option<usize>| -> Option<i64> {
            idx.and_then(|i| row.get::<_, Option<i64>>(i).ok().flatten())
        };
        let real = |idx: Option<usize>| -> Option<f64> {
            idx.and_then(|i| row.get::<_, Option<f64>>(i).ok().flatten())
        };
        let protection = text(at("pdmn"));
        let (protection_name, this_device_only) = match protection.as_deref().map(protection_class)
        {
            Some(Some((name, only))) => (Some(name.to_string()), only),
            // A class this reader does not name is reported as the code the
            // file holds rather than mapped to a nearby one.
            Some(None) => (protection, false),
            None => (None, false),
        };
        let mut attributes = Vec::new();
        for (i, (_, label)) in hashed.iter().enumerate() {
            let idx = base + present.len() + i;
            // Read through the raw value rather than as `Vec<u8>`: these
            // columns are declared BLOB but SQLite stores whatever was put in
            // them, and asking for bytes from a TEXT value fails — which would
            // silently drop the readable labels this reader exists to report.
            let raw: Option<Vec<u8>> = match row.get_ref(idx) {
                Ok(rusqlite::types::ValueRef::Blob(b)) => Some(b.to_vec()),
                Ok(rusqlite::types::ValueRef::Text(t)) => Some(t.to_vec()),
                _ => None,
            };
            if let Some(raw) = raw {
                if let Some(attr) = classify(&raw) {
                    attributes.push(((*label).to_string(), attr));
                }
            }
        }
        out.push(Item {
            table,
            kind,
            rowid: row.get::<_, i64>(0).unwrap_or_default(),
            access_group: text(at("agrp")),
            protection: protection_name,
            this_device_only,
            sync_view: text(at("vwht")).filter(|v| !v.is_empty()),
            synced: number(at("sync")).map(|v| v != 0),
            tombstone: number(at("tomb")).map(|v| v != 0),
            uuid: text(at("UUID")),
            created: real(at("cdat")).and_then(cfabsolute_to_unix_parts),
            modified: real(at("mdat")).and_then(cfabsolute_to_unix_parts),
            attributes,
            payload_bytes: number(at("data")),
        });
    }
    Ok((out, capped))
}

// --- artifact emission -------------------------------------------------------

fn provenance(meta: &mut Map<String, Value>, file_name: &str) {
    meta.insert("source_file_name".into(), json!(file_name));
    meta.insert(
        "source_format".into(),
        json!("apple_data_protection_keychain"),
    );
}

fn item_artifact(
    case_id: uuid::Uuid,
    parent: uuid::Uuid,
    file_name: &str,
    item: &Item,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("KeychainItem"));
    meta.insert("subtype".into(), json!("data_protection_keychain_item"));
    provenance(&mut meta, file_name);
    meta.insert("item_kind".into(), json!(item.kind));
    meta.insert("relation".into(), json!(item.table));
    meta.insert("row_id".into(), json!(item.rowid));
    if let Some(group) = &item.access_group {
        // The one attribute this database does not hash, and therefore the
        // answer to "whose secret is this".
        meta.insert("access_group".into(), json!(group));
    }
    if let Some(class) = &item.protection {
        meta.insert("protection_class".into(), json!(class));
        meta.insert(
            "protection_class_description".into(),
            json!(protection_description(class)),
        );
        if item.this_device_only {
            meta.insert("this_device_only".into(), json!(true));
            meta.insert(
                "this_device_only_note".into(),
                json!(this_device_only_note(class)),
            );
        }
    }
    if let Some(view) = &item.sync_view {
        meta.insert("sync_view".into(), json!(view));
    }
    if let Some(synced) = item.synced {
        meta.insert("syncs_to_icloud".into(), json!(synced));
    }
    if let Some(tomb) = item.tombstone {
        // A tombstone is a deletion that syncs. Its presence is the record of
        // an item having been removed.
        meta.insert("tombstone".into(), json!(tomb));
    }
    if let Some(uuid) = &item.uuid {
        meta.insert("item_uuid".into(), json!(uuid));
    }
    for (label, attr) in &item.attributes {
        match attr {
            // Named `_sha1`, because it is a hash and an examiner must never
            // read it as the value.
            Attr::Hash(hex) => {
                meta.insert(format!("{label}_sha1"), json!(hex));
            }
            Attr::Text(text) => {
                meta.insert(label.clone(), json!(text));
            }
            Attr::Bytes { hex, len } => {
                meta.insert(format!("{label}_bytes"), json!(format!("0x{hex}")));
                meta.insert(format!("{label}_byte_length"), json!(len));
            }
        }
    }
    if let Some((secs, nanos)) = item.created {
        meta.insert("created".into(), json!(secs));
        meta.insert("date".into(), json!(secs));
        if let Some(ns) = unix_ns(secs, nanos) {
            meta.insert("created_unix_nanos".into(), json!(ns));
        }
        if let Some(text) = to_rfc3339_nanos(secs, nanos) {
            meta.insert("created_rfc3339".into(), json!(text));
        }
    }
    if let Some((secs, nanos)) = item.modified {
        meta.insert("modified".into(), json!(secs));
        if let Some(text) = to_rfc3339_nanos(secs, nanos) {
            meta.insert("modified_rfc3339".into(), json!(text));
        }
    }
    match item.payload_bytes {
        Some(len) if len > 0 => {
            meta.insert("payload_bytes".into(), json!(len));
            meta.insert("secret_state".into(), json!("locked"));
            meta.insert("secret_wrapping".into(), json!("device_keybag_class_key"));
            meta.insert("secret_note".into(), json!(LOCKED_NOTE));
            let _ = stamp_incomplete(
                &mut meta,
                "content",
                &[(
                    IncompleteReason::Encrypted,
                    format!(
                        "the item's {len} byte payload is wrapped under a class key from the \
                         device keybag and was not decrypted; the class keys are protected by \
                         hardware an image does not carry"
                    ),
                )],
            );
        }
        _ => {
            meta.insert("secret_state".into(), json!("no_payload"));
        }
    }
    meta.insert(
        "attribute_note".into(),
        json!(
            "Every account, service, server and label in this database is stored as a SHA-1 of \
               the value, so this file names neither the account nor the service. The hashes are \
               reported under names ending `_sha1` so they cannot be read as the values they \
               stand for."
        ),
    );
    let who = item.access_group.as_deref().unwrap_or("an unnamed group");
    meta.insert("name".into(), json!(format!("{}: {who}", item.kind)));
    meta.insert(
        "short_desc".into(),
        json!(match &item.protection {
            Some(class) => format!("{} owned by {who} ({class}); secret locked", item.kind),
            None => format!("{} owned by {who}; secret locked", item.kind),
        }),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent)
    .with_subtype("data_protection_keychain_item")
}

fn device_artifact(
    case_id: uuid::Uuid,
    parent: uuid::Uuid,
    file_name: &str,
    device: &DeviceState,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("ICloudKeychainDevice"));
    meta.insert("subtype".into(), json!("ckdevicestate"));
    provenance(&mut meta, file_name);
    meta.insert("cloudkit_zone".into(), json!(device.zone));
    for (key, value) in [
        ("device_id", &device.device),
        ("os_version", &device.os_version),
        ("last_unlock", &device.last_unlock),
        ("sos_peer_id", &device.peer_id),
        ("sos_circle_status", &device.circle_status),
        ("octagon_peer_id", &device.octagon_peer_id),
        ("octagon_status", &device.octagon_status),
        ("key_state", &device.key_state),
        ("current_tlk", &device.current_tlk),
        ("current_class_a_key", &device.current_class_a),
        ("current_class_c_key", &device.current_class_c),
    ] {
        if let Some(text) = value {
            if !text.is_empty() {
                meta.insert(key.into(), json!(text));
            }
        }
    }
    meta.insert(
        "device_note".into(),
        json!(
            "A device the Apple ID's keychain circle has held, recorded per CloudKit zone. A \
               device named here need not be the machine this file came from, and need not be in \
               the evidence at all: this is what the account trusted."
        ),
    );
    let what = device
        .os_version
        .clone()
        .unwrap_or_else(|| "an unnamed device".to_string());
    meta.insert(
        "name".into(),
        json!(format!("{what} in the {} zone", device.zone)),
    );
    meta.insert(
        "short_desc".into(),
        json!(match &device.circle_status {
            Some(status) => format!("iCloud keychain device: {what} ({status})"),
            None => format!("iCloud keychain device: {what}"),
        }),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent)
    .with_subtype("ckdevicestate")
}

#[allow(clippy::too_many_arguments)]
fn status_artifact(
    case_id: uuid::Uuid,
    parent: uuid::Uuid,
    file_name: &str,
    version: Option<(i64, i64)>,
    items: &[Item],
    devices: usize,
    capped_tables: &[&str],
    devices_capped: bool,
) -> Artifact {
    let mut meta = Map::new();
    meta.insert("type".into(), json!("KeychainStatus"));
    meta.insert("subtype".into(), json!("data_protection_keychain_status"));
    provenance(&mut meta, file_name);
    meta.insert("detected".into(), json!(true));
    if let Some((major, minor)) = version {
        meta.insert("schema_version".into(), json!(format!("{major}.{minor}")));
    }
    meta.insert("items".into(), json!(items.len()));
    meta.insert("icloud_keychain_devices".into(), json!(devices));

    let mut by_kind: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_group: BTreeMap<String, usize> = BTreeMap::new();
    let mut by_class: BTreeMap<String, usize> = BTreeMap::new();
    let mut device_only = 0usize;
    let mut syncing = 0usize;
    let mut tombstones = 0usize;
    let mut locked = 0usize;
    for item in items {
        *by_kind.entry(item.kind).or_default() += 1;
        if let Some(group) = &item.access_group {
            *by_group.entry(group.clone()).or_default() += 1;
        }
        if let Some(class) = &item.protection {
            *by_class.entry(class.clone()).or_default() += 1;
        }
        if item.this_device_only {
            device_only += 1;
        }
        if item.synced == Some(true) {
            syncing += 1;
        }
        if item.tombstone == Some(true) {
            tombstones += 1;
        }
        if item.payload_bytes.unwrap_or(0) > 0 {
            locked += 1;
        }
    }
    meta.insert("items_by_kind".into(), json!(by_kind));
    meta.insert("items_by_access_group".into(), json!(by_group));
    meta.insert("items_by_protection_class".into(), json!(by_class));
    meta.insert("items_this_device_only".into(), json!(device_only));
    meta.insert("items_syncing_to_icloud".into(), json!(syncing));
    meta.insert("tombstoned_items".into(), json!(tombstones));
    meta.insert("items_with_locked_secret".into(), json!(locked));
    meta.insert(
        "attribute_note".into(),
        json!(
            "This database names neither an account nor a service: every such attribute is \
               stored as a SHA-1 of the value. What it names is the application that owns each \
               secret, the protection class, the sync view and the dates — and, in \
               `ckdevicestate`, every device the Apple ID's keychain circle has held."
        ),
    );

    let mut reasons = Vec::new();
    if locked > 0 {
        reasons.push((
            IncompleteReason::Encrypted,
            format!(
                "{locked} item(s) carry a secret wrapped under a class key from the device \
                 keybag, which is protected by hardware an image does not carry; none was \
                 decrypted and no password would open them"
            ),
        ));
    }
    if !capped_tables.is_empty() {
        reasons.push((
            IncompleteReason::CapReached,
            format!(
                "the row cap of {MAX_ITEMS_PER_TABLE} was reached in {}; later rows were not \
                 read",
                capped_tables.join(", ")
            ),
        ));
    }
    if devices_capped {
        reasons.push((
            IncompleteReason::CapReached,
            format!("more than {MAX_DEVICE_ROWS} device-state rows; later ones were not read"),
        ));
    }
    let _ = stamp_incomplete(&mut meta, "content", &reasons);

    meta.insert(
        "name".into(),
        json!(format!("Data-protection keychain parsed: {file_name}")),
    );
    meta.insert(
        "short_desc".into(),
        json!(format!(
            "{file_name}: {} item(s) across {} access group(s), {devices} iCloud keychain \
             device row(s); every secret locked",
            items.len(),
            by_group.len()
        )),
    );
    Artifact::new(
        case_id,
        ArtifactType::ParsedRecord,
        None,
        Value::Object(meta),
    )
    .with_parent(parent)
    .with_subtype("data_protection_keychain_status")
}

impl ForensicsModule for DataProtectionKeychainParser {
    fn id(&self) -> &str {
        "macos.keychain_data_protection"
    }
    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }
    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();
        if !is_keychain_2(name) {
            return Ok(Vec::new());
        }
        let Some(ds) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        let temp = TempDb::spill(ds.as_ref(), "keychain_2", MAX_DB_BYTES)
            .map_err(|e| ModuleError::ParsingError(format!("spill failed: {e}")))?;

        let result = (|| -> Result<Vec<Artifact>> {
            let staged = std::fs::read(temp.path()).unwrap_or_default();
            if !looks_like_sqlite(&staged) {
                return Ok(Vec::new());
            }
            let conn = temp.open().context("open keychain-2.db")?;
            // `genp` is in every version of this schema. Its absence means the
            // file is not this keychain, whatever it is called.
            match probe_table(&conn, "genp") {
                Presence::Present => {}
                Presence::Absent => return Ok(Vec::new()),
                Presence::Undetermined(why) => anyhow::bail!("schema unreadable: {why}"),
            }

            let version = conn
                .query_row("SELECT version, minor FROM tversion LIMIT 1", [], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, i64>(1).unwrap_or(0)))
                })
                .ok();

            let mut items = Vec::new();
            let mut capped_tables: Vec<&str> = Vec::new();
            for (table, kind) in ITEM_TABLES {
                if probe_table(&conn, table) != Presence::Present {
                    continue;
                }
                let (rows, capped) = read_items(&conn, table, kind)?;
                if capped {
                    capped_tables.push(table);
                }
                items.extend(rows);
            }

            let (devices, devices_capped) =
                if probe_table(&conn, "ckdevicestate") == Presence::Present {
                    read_device_states(&conn)?
                } else {
                    (Vec::new(), false)
                };

            let mut out = Vec::with_capacity(items.len() + devices.len() + 1);
            for item in &items {
                out.push(item_artifact(artifact.case_id, artifact.id, name, item));
            }
            for device in &devices {
                out.push(device_artifact(artifact.case_id, artifact.id, name, device));
            }
            out.push(status_artifact(
                artifact.case_id,
                artifact.id,
                name,
                version,
                &items,
                devices.len(),
                &capped_tables,
                devices_capped,
            ));
            Ok(out)
        })();

        match result {
            Ok(mut artifacts) => {
                temp.stamp_incompleteness(artifact.case_id, artifact.id, name, &mut artifacts);
                if !artifacts.is_empty() {
                    info!(
                        "DataProtectionKeychainParser: {} record(s) from {name}",
                        artifacts.len()
                    );
                }
                Ok(artifacts)
            }
            Err(e) => {
                warn!("DataProtectionKeychainParser failed on {name}: {e}");
                let mut meta = Map::new();
                meta.insert("type".into(), json!("KeychainStatus"));
                meta.insert(
                    "subtype".into(),
                    json!("data_protection_keychain_not_parsed"),
                );
                provenance(&mut meta, name);
                meta.insert("detected".into(), json!(false));
                meta.insert("failure_detail".into(), json!(e.to_string()));
                meta.insert(
                    "message".into(),
                    json!(
                        "This file is named as the data-protection keychain but was not read, \
                           so nothing is reported from it. Absence of credentials here is NOT \
                           evidence that the account held none."
                    ),
                );
                let _ = stamp_incomplete(
                    &mut meta,
                    "content",
                    &[(IncompleteReason::UnresolvedStructure, e.to_string())],
                );
                meta.insert(
                    "name".into(),
                    json!(format!("Data-protection keychain not parsed: {name}")),
                );
                meta.insert(
                    "short_desc".into(),
                    json!(format!("{name} was not parsed: {e}")),
                );
                Ok(vec![Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    Value::Object(meta),
                )
                .with_parent(artifact.id)
                .with_subtype("data_protection_keychain_not_parsed")])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn home(rel: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(rel)
    }
    use rusqlite::params;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use std::sync::Arc;
    use uuid::Uuid;

    // --- fixture construction ------------------------------------------------
    //
    // A real SQLite database is built with Apple's own column names, so the
    // reader is exercised through `rusqlite` exactly as it is in production.

    /// Build a `keychain-2.db` and return its bytes.
    fn build(rows: impl FnOnce(&Connection)) -> Vec<u8> {
        let dir = std::env::temp_dir().join(format!("kc2_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("keychain-2.db");
        {
            let conn = Connection::open(&path).expect("create");
            conn.execute_batch(
                "CREATE TABLE tversion(rowid INTEGER PRIMARY KEY AUTOINCREMENT, version INTEGER \
                     NOT NULL, minor INTEGER NOT NULL DEFAULT 0, UNIQUE(version));
                 CREATE TABLE genp(rowid INTEGER PRIMARY KEY AUTOINCREMENT, cdat REAL, mdat REAL, \
                     desc BLOB, labl BLOB, gena BLOB, acct BLOB NOT NULL DEFAULT '', \
                     svce BLOB NOT NULL DEFAULT '', data BLOB, agrp TEXT NOT NULL, pdmn TEXT, \
                     sync INTEGER NOT NULL DEFAULT 0, tomb INTEGER NOT NULL DEFAULT 0, \
                     vwht TEXT, UUID TEXT);
                 CREATE TABLE inet(rowid INTEGER PRIMARY KEY AUTOINCREMENT, cdat REAL, mdat REAL, \
                     acct BLOB NOT NULL DEFAULT '', sdmn BLOB NOT NULL DEFAULT '', \
                     srvr BLOB NOT NULL DEFAULT '', ptcl INTEGER NOT NULL DEFAULT 0, \
                     atyp BLOB NOT NULL DEFAULT '', port INTEGER NOT NULL DEFAULT 0, \
                     path BLOB NOT NULL DEFAULT '', data BLOB, agrp TEXT NOT NULL, pdmn TEXT, \
                     sync INTEGER NOT NULL DEFAULT 0, tomb INTEGER NOT NULL DEFAULT 0, \
                     vwht TEXT, UUID TEXT);
                 CREATE TABLE ckdevicestate(ckzone TEXT PRIMARY KEY, device TEXT, \
                     osversion TEXT, lastunlock TEXT, peerid TEXT, circlestatus TEXT, \
                     octagonpeerid TEXT, octagonstatus TEXT, keystate TEXT, currentTLK TEXT, \
                     currentClassA TEXT, currentClassC TEXT, ckrecord BLOB);
                 INSERT INTO tversion(version, minor) VALUES (11, 9);",
            )
            .expect("schema");
            rows(&conn);
        }
        std::fs::read(&path).expect("read back")
    }

    /// The twenty-byte SHA-1 the attribute columns hold in the real file.
    fn sha1(seed: u8) -> Vec<u8> {
        (0..SHA1_BYTES as u8)
            .map(|i| i.wrapping_add(seed))
            .collect()
    }

    /// A wrapped item payload: the real ones begin with a version word and are
    /// ciphertext after it.
    fn wrapped(len: usize) -> Vec<u8> {
        let mut out = vec![0x07, 0x00, 0x00, 0x00];
        out.extend(std::iter::repeat_n(0xa5u8, len));
        out
    }

    /// 2021-02-12T00:35:07Z as a CFAbsoluteTime, which is what `cdat` holds —
    /// the creation time of the first generic item in the real file.
    const CDAT: f64 = 634_782_907.980_81;

    fn run(bytes: Vec<u8>, name: &str) -> Vec<Artifact> {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(bytes)) as Arc<dyn DataSource>),
            json!({ "name": name, "path": format!("/Users/eliflatt/Library/Keychains/X/{name}") }),
        );
        DataProtectionKeychainParser
            .process(&art)
            .expect("never fails the pipeline")
    }

    fn of_type<'a>(out: &'a [Artifact], wanted: &str) -> Vec<&'a Value> {
        out.iter()
            .map(|a| &a.metadata)
            .filter(|m| m.get("type").and_then(|v| v.as_str()) == Some(wanted))
            .collect()
    }

    fn status_of(out: &[Artifact]) -> &Value {
        of_type(out, "KeychainStatus")
            .first()
            .copied()
            .expect("every read file produces a status row")
    }

    fn s<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(|x| x.as_str())
    }
    fn n(v: &Value, key: &str) -> Option<i64> {
        v.get(key).and_then(|x| x.as_i64())
    }

    // --- items ----------------------------------------------------------------

    /// The whole point of this reader: what the database states, and what it
    /// deliberately does not.
    #[test]
    fn an_item_names_the_application_that_owns_it_and_never_the_account() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO genp(cdat, mdat, acct, svce, labl, data, agrp, pdmn, sync, tomb, \
                 vwht, UUID) VALUES (?1, ?1, ?2, ?3, ?4, ?5, ?6, ?7, 0, 0, ?8, ?9)",
                params![
                    CDAT,
                    sha1(1),
                    sha1(2),
                    sha1(3),
                    wrapped(2048),
                    "com.apple.continuity.unlock",
                    "dku",
                    "ContinuityUnlock",
                    "8C2A7B10-0000-0000-0000-000000000001",
                ],
            )
            .expect("insert");
        });
        let out = run(bytes, "keychain-2.db");
        let items = of_type(&out, "KeychainItem");
        assert_eq!(items.len(), 1);
        let item = items[0];

        assert_eq!(s(item, "item_kind"), Some("generic_password"));
        assert_eq!(s(item, "access_group"), Some("com.apple.continuity.unlock"));
        assert_eq!(s(item, "sync_view"), Some("ContinuityUnlock"));
        assert_eq!(
            s(item, "item_uuid"),
            Some("8C2A7B10-0000-0000-0000-000000000001")
        );
        assert_eq!(n(item, "created"), Some(634_782_907 + 978_307_200));
        assert!(
            s(item, "created_rfc3339")
                .expect("a date")
                .starts_with("2021-02-12T00:35:07"),
            "got {:?}",
            s(item, "created_rfc3339")
        );

        // The account and the service are hashes, and the field names say so.
        assert!(
            item.get("account").is_none() && item.get("service").is_none(),
            "this database names neither; emitting either would put a hash where an examiner \
             reads a username"
        );
        assert_eq!(s(item, "account_sha1"), Some(hex(&sha1(1)).as_str()));
        assert_eq!(s(item, "service_sha1"), Some(hex(&sha1(2)).as_str()));
        assert!(s(item, "attribute_note")
            .expect("a note")
            .contains("names neither the account nor the service"));

        assert_eq!(s(item, "secret_state"), Some("locked"));
        assert_eq!(n(item, "payload_bytes"), Some(2052));
        assert_eq!(s(item, "content_incomplete_reason"), Some("encrypted"));
        assert!(s(item, "secret_note")
            .expect("a note")
            .contains("no password that would open it"));
    }

    /// A `ThisDeviceOnly` class explains an absence elsewhere, so it is said
    /// rather than left as a three-letter code.
    #[test]
    fn a_this_device_only_class_is_decoded_and_says_why_it_matters() {
        let bytes = build(|conn| {
            for (i, class) in ["ak", "ck", "dk", "aku", "cku", "dku", "akpu"]
                .iter()
                .enumerate()
            {
                conn.execute(
                    "INSERT INTO genp(cdat, acct, svce, data, agrp, pdmn) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        CDAT,
                        sha1(i as u8),
                        sha1(i as u8 + 40),
                        wrapped(16),
                        "apple",
                        class
                    ],
                )
                .expect("insert");
            }
        });
        let out = run(bytes, "keychain-2.db");
        let items = of_type(&out, "KeychainItem");
        assert_eq!(items.len(), 7);
        let classes: Vec<&str> = items
            .iter()
            .filter_map(|i| s(i, "protection_class"))
            .collect();
        assert!(classes.contains(&"when_unlocked"));
        assert!(classes.contains(&"after_first_unlock_this_device_only"));

        let device_only: Vec<&&Value> = items
            .iter()
            .filter(|i| i.get("this_device_only") == Some(&json!(true)))
            .collect();
        assert_eq!(
            device_only.len(),
            4,
            "aku, cku, dku and akpu are the ThisDeviceOnly classes"
        );
        // HUNT-111a: a ThisDeviceOnly item does not sync to iCloud Keychain.
        // Apple Platform Security, "Keychain data class protections", then
        // splits the four classes, and the note must split them the same way:
        //
        // * aku, cku, dku are "always protected with the UID when being
        //   copied from the device during a backup, rendering it useless if
        //   it's restored to a different device" — so they ARE in an
        //   encrypted backup, restorable only to the same device;
        // * akpu (WhenPasscodeSetThisDeviceOnly) "exists only in the system
        //   keybag": it does not sync, is not backed up, is not in escrow
        //   keybags, and is rendered useless when the passcode is removed.
        //
        // This fixture is synthetic: it pins the wording per class, not any
        // figure from real evidence.
        for item in &device_only {
            let class = s(item, "protection_class").expect("a class");
            let note = s(item, "this_device_only_note").expect("a note");
            let description = s(item, "protection_class_description").expect("a description");
            if class == "when_passcode_set_this_device_only" {
                assert!(
                    note.contains("is not backed up"),
                    "an akpu item is not in a backup, and the note must say so: {note}"
                );
                assert!(
                    !note.contains("is written to an encrypted backup")
                        && !note.contains("restored only to the same device"),
                    "an akpu item must not be said to be in a backup: {note}"
                );
                assert!(
                    note.contains("passcode is removed"),
                    "an akpu item's class key is discarded when the passcode goes: {note}"
                );
                assert!(
                    description.contains("not backed up"),
                    "the akpu description must not imply a backup copy: {description}"
                );
            } else {
                assert!(
                    note.contains("is written to an encrypted backup"),
                    "the note must say the item reaches a backup: {note}"
                );
                assert!(
                    note.contains("restored only to the same device"),
                    "the note must say why it cannot be opened elsewhere: {note}"
                );
            }
            assert!(
                !note.contains("never written to a backup") && !note.contains("never reaches"),
                "the note repeats the old claim: {note}"
            );
            assert!(
                !description.contains("never leaves this device"),
                "the class description repeats the old claim: {description}"
            );
            assert!(
                item.get("never_leaves_this_device").is_none(),
                "the field whose name made the false claim is gone"
            );
        }
        assert_eq!(n(status_of(&out), "items_this_device_only"), Some(4));
        assert!(status_of(&out)
            .get("items_never_leaving_this_device")
            .is_none());
    }

    #[test]
    fn a_protection_class_this_reader_does_not_name_is_reported_as_the_code_the_file_holds() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO genp(cdat, acct, svce, data, agrp, pdmn) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![CDAT, sha1(1), sha1(2), wrapped(8), "apple", "zz"],
            )
            .expect("insert");
        });
        let out = run(bytes, "keychain-2.db");
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(
            s(item, "protection_class"),
            Some("zz"),
            "an unrecognised class keeps the code rather than being mapped to a nearby one"
        );
        assert!(item.get("this_device_only").is_none());
    }

    #[test]
    fn a_tombstoned_item_is_reported_because_it_is_the_record_of_a_deletion() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO genp(cdat, acct, svce, agrp, pdmn, sync, tomb) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 1, 1)",
                params![CDAT, sha1(1), sha1(2), "apple", "ck"],
            )
            .expect("insert");
        });
        let out = run(bytes, "keychain-2.db");
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(item["tombstone"], json!(true));
        assert_eq!(item["syncs_to_icloud"], json!(true));
        assert_eq!(
            s(item, "secret_state"),
            Some("no_payload"),
            "a tombstone carries no secret; calling it locked would imply one was there"
        );
        assert_eq!(n(status_of(&out), "tombstoned_items"), Some(1));
    }

    #[test]
    fn an_internet_item_reports_its_server_as_a_hash_and_its_port_as_a_number() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO inet(cdat, acct, srvr, path, atyp, sdmn, port, data, agrp, pdmn, \
                 sync, vwht) VALUES (?1, ?2, ?3, ?4, ?5, ?6, 443, ?7, ?8, 'ck', 1, 'Manatee')",
                params![
                    CDAT,
                    sha1(1),
                    sha1(2),
                    sha1(3),
                    sha1(4),
                    sha1(5),
                    wrapped(1024),
                    "com.apple.ProtectedCloudStorage"
                ],
            )
            .expect("insert");
        });
        let out = run(bytes, "keychain-2.db");
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "item_kind"), Some("internet_password"));
        assert!(
            item.get("server").is_none(),
            "the server is a hash in this database and must not be named"
        );
        assert_eq!(s(item, "server_sha1"), Some(hex(&sha1(2)).as_str()));
        assert_eq!(s(item, "sync_view"), Some("Manatee"));
        assert_eq!(
            s(item, "access_group"),
            Some("com.apple.ProtectedCloudStorage")
        );
    }

    /// A column that *is* text must read as text: the classifier is measured,
    /// not assumed, and a future schema may stop hashing something.
    #[test]
    fn an_attribute_that_holds_text_reads_as_text_rather_than_as_a_hash() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO genp(cdat, acct, svce, labl, agrp, pdmn) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'ck')",
                params![CDAT, sha1(1), sha1(2), "a readable label", "apple"],
            )
            .expect("insert");
        });
        let out = run(bytes, "keychain-2.db");
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "label"), Some("a readable label"));
        assert!(
            item.get("label_sha1").is_none(),
            "text is text; only a twenty-byte non-text value is reported as a hash"
        );
    }

    #[test]
    fn a_blob_that_is_neither_text_nor_a_hash_is_reported_as_the_bytes_it_is() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO genp(cdat, acct, svce, gena, agrp, pdmn) \
                 VALUES (?1, ?2, ?3, ?4, ?5, 'ck')",
                params![CDAT, sha1(1), sha1(2), vec![0xffu8, 0x00, 0xfe], "apple"],
            )
            .expect("insert");
        });
        let out = run(bytes, "keychain-2.db");
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "generic_field_bytes"), Some("0xff00fe"));
        assert_eq!(n(item, "generic_field_byte_length"), Some(3));
        assert!(item.get("generic_field_sha1").is_none());
    }

    // --- the iCloud keychain circle -------------------------------------------

    /// The table that is entirely in the clear, and the one worth the most: a
    /// device inventory of what the Apple ID trusted.
    #[test]
    fn the_device_state_table_names_every_device_the_account_trusted() {
        let bytes = build(|conn| {
            for (zone, device, os, peer) in [
                (
                    "Manatee",
                    "01EA7CA9-5E12-4166-9700-FEBE10DFAC58",
                    "macOS 20.3.0 (20D74)",
                    "SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=",
                ),
                (
                    "WiFi",
                    "EE63B6163CAC406541ABD908B0EF8BDCCB268C5A9FDDC3F61B6E6CADB74C60AC",
                    "iphone 20.3.0 (18D52)",
                    "SHA256:OPhPqE+jAsdNZoMq0oolJEwNyZITInuquFTsVD6MV4M=",
                ),
            ] {
                conn.execute(
                    "INSERT INTO ckdevicestate(ckzone, device, osversion, circlestatus, \
                     octagonpeerid, octagonstatus, keystate) \
                     VALUES (?1, ?2, ?3, 'kSOSCCInCircle', ?4, 'CliqueStatusIn', 'ready')",
                    params![zone, device, os, peer],
                )
                .expect("insert");
            }
        });
        let out = run(bytes, "keychain-2.db");
        let devices = of_type(&out, "ICloudKeychainDevice");
        assert_eq!(devices.len(), 2);

        let mac = devices
            .iter()
            .find(|d| s(d, "os_version") == Some("macOS 20.3.0 (20D74)"))
            .expect("the Mac's own row");
        assert_eq!(
            s(mac, "octagon_peer_id"),
            Some("SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os=")
        );
        assert_eq!(s(mac, "sos_circle_status"), Some("kSOSCCInCircle"));
        assert_eq!(s(mac, "cloudkit_zone"), Some("Manatee"));
        assert!(s(mac, "device_note")
            .expect("a note")
            .contains("need not be in the evidence at all"));

        let phone = devices
            .iter()
            .find(|d| s(d, "os_version") == Some("iphone 20.3.0 (18D52)"))
            .expect("a device that is not this machine");
        assert!(s(phone, "octagon_peer_id").is_some());
        assert_eq!(n(status_of(&out), "icloud_keychain_devices"), Some(2));
    }

    // --- the file, and refusals ------------------------------------------------

    #[test]
    fn the_status_row_counts_the_items_by_what_the_file_actually_names() {
        let bytes = build(|conn| {
            for (group, class) in [
                ("com.apple.cloudd", "dku"),
                ("com.apple.cloudd", "dku"),
                ("InternetAccounts", "ck"),
            ] {
                conn.execute(
                    "INSERT INTO genp(cdat, acct, svce, data, agrp, pdmn, sync) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1)",
                    params![CDAT, sha1(1), sha1(2), wrapped(32), group, class],
                )
                .expect("insert");
            }
        });
        let out = run(bytes, "keychain-2.db");
        let st = status_of(&out);
        assert_eq!(s(st, "schema_version"), Some("11.9"));
        assert_eq!(n(st, "items"), Some(3));
        assert_eq!(st["items_by_access_group"]["com.apple.cloudd"], json!(2));
        assert_eq!(
            st["items_by_protection_class"]["always_this_device_only"],
            json!(2)
        );
        assert_eq!(st["items_by_kind"]["generic_password"], json!(3));
        assert_eq!(n(st, "items_syncing_to_icloud"), Some(3));
        assert_eq!(n(st, "items_with_locked_secret"), Some(3));
        assert_eq!(s(st, "content_incomplete_reason"), Some("encrypted"));
        assert!(s(st, "attribute_note")
            .expect("a note")
            .contains("names neither an account nor a service"));
    }

    #[test]
    fn a_file_that_is_not_this_keychain_is_passed_over_in_silence() {
        // Right name, wrong contents.
        assert!(run(b"not a database".to_vec(), "keychain-2.db").is_empty());
        // A SQLite database with no `genp`: the name is not enough.
        let other = build(|conn| {
            conn.execute_batch("DROP TABLE genp;").expect("drop");
        });
        assert!(run(other, "keychain-2.db").is_empty());
    }

    #[test]
    fn a_file_under_another_name_is_not_claimed() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO genp(cdat, acct, svce, agrp, pdmn) VALUES (?1, ?2, ?3, 'apple', 'ck')",
                params![CDAT, sha1(1), sha1(2)],
            )
            .expect("insert");
        });
        assert!(
            run(bytes, "keychain-2.db-wal").is_empty(),
            "a write-ahead log is not the database; reading one as the keychain would be worse \
             than declining"
        );
    }

    #[test]
    fn a_schema_with_columns_this_reader_has_not_seen_is_still_read() {
        // A table missing `vwht` and `UUID` — an older OS version's shape.
        let dir = std::env::temp_dir().join(format!("kc2_old_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let path = dir.join("keychain-2.db");
        {
            let conn = Connection::open(&path).expect("create");
            conn.execute_batch(
                "CREATE TABLE tversion(version INTEGER NOT NULL, minor INTEGER DEFAULT 0);
                 CREATE TABLE genp(rowid INTEGER PRIMARY KEY AUTOINCREMENT, cdat REAL, \
                     acct BLOB, svce BLOB, data BLOB, agrp TEXT NOT NULL, pdmn TEXT);
                 INSERT INTO tversion(version, minor) VALUES (9, 0);",
            )
            .expect("schema");
            conn.execute(
                "INSERT INTO genp(cdat, acct, svce, data, agrp, pdmn) \
                 VALUES (?1, ?2, ?3, ?4, 'apple', 'ak')",
                params![CDAT, sha1(1), sha1(2), wrapped(8)],
            )
            .expect("insert");
        }
        let out = run(std::fs::read(&path).expect("read"), "keychain-2.db");
        let item = of_type(&out, "KeychainItem")[0];
        assert_eq!(s(item, "access_group"), Some("apple"));
        assert!(
            item.get("sync_view").is_none() && item.get("item_uuid").is_none(),
            "a column the schema has not got is absent, not invented"
        );
        assert_eq!(s(status_of(&out), "schema_version"), Some("9.0"));
    }

    #[test]
    fn every_emitted_record_names_its_source_file_and_format() {
        let bytes = build(|conn| {
            conn.execute(
                "INSERT INTO genp(cdat, acct, svce, data, agrp, pdmn) \
                 VALUES (?1, ?2, ?3, ?4, 'apple', 'ck')",
                params![CDAT, sha1(1), sha1(2), wrapped(8)],
            )
            .expect("insert");
            conn.execute(
                "INSERT INTO ckdevicestate(ckzone, osversion) VALUES ('Manatee', 'macOS')",
                [],
            )
            .expect("insert");
        });
        let out = run(bytes, "keychain-2.db");
        assert_eq!(out.len(), 3, "the item, the device and the status row");
        for a in &out {
            assert_eq!(
                s(&a.metadata, "source_format"),
                Some("apple_data_protection_keychain")
            );
            assert_eq!(s(&a.metadata, "source_file_name"), Some("keychain-2.db"));
        }
    }

    // --- the real keychain ----------------------------------------------------

    /// **The real `keychain-2.db` from the Magnet 2021 macOS image.**
    ///
    /// This closes question 14 of that CTF — the one `VALIDATION.md` recorded
    /// as unanswered — and the answer comes out of a column that is in the
    /// clear, beside 286 items whose accounts and services are not.
    #[test]
    fn the_real_data_protection_keychain_answers_the_question_utmpx_and_the_classic_one_cannot() {
        let path = home(
            "ctf-evidence/macos2021/tree/Users/eliflatt/Library/Keychains/\
             622523FF-A9E8-5BFC-9142-B14980A33465/keychain-2.db",
        );
        let Ok(bytes) = std::fs::read(&path) else {
            eprintln!(
                "skipping: {} not present (gitignored corpus)",
                path.display()
            );
            return;
        };
        assert_eq!(bytes.len(), 4_677_632);

        let out = run(bytes, "keychain-2.db");
        let st = status_of(&out);
        assert_eq!(s(st, "schema_version"), Some("11.9"));

        // --- the answer to question 14 ---
        let devices = of_type(&out, "ICloudKeychainDevice");
        assert_eq!(devices.len(), 36, "thirty-six device-state rows");
        let versions: std::collections::BTreeSet<&str> =
            devices.iter().filter_map(|d| s(d, "os_version")).collect();
        assert_eq!(
            versions,
            [
                "iphone 20.3.0 (18D52)",
                "macOS 20.3.0 (20D74)",
                "watch 19.6.0 (17U63)"
            ]
            .into_iter()
            .collect::<std::collections::BTreeSet<&str>>(),
            "three devices in the account's keychain circle, two of which are not in the image"
        );
        let mac_peers: std::collections::BTreeSet<&str> = devices
            .iter()
            .filter(|d| s(d, "os_version") == Some("macOS 20.3.0 (20D74)"))
            .filter_map(|d| s(d, "octagon_peer_id"))
            .collect();
        assert_eq!(
            mac_peers,
            ["SHA256:fUpf9J+cLRI3OCJ/KdFpZoaZXgfj2DC3ZrQnW7XT9Os="]
                .into_iter()
                .collect::<std::collections::BTreeSet<&str>>(),
            "Magnet Virtual Summit 2021 macOS CTF question 14: the Mac's iCloud encryption key"
        );
        // The circle status is per zone, not per device, and seven of the 36
        // rows report an error. Pinned as the split it is: a test asserting
        // only the happy value would let a reader that dropped the other seven
        // pass.
        let in_circle = devices
            .iter()
            .filter(|d| s(d, "sos_circle_status") == Some("kSOSCCInCircle"))
            .count();
        let errored = devices
            .iter()
            .filter(|d| s(d, "sos_circle_status") == Some("kSOSCCError"))
            .count();
        assert_eq!(
            (in_circle, errored),
            (29, 7),
            "twenty-nine zones syncing and seven in error"
        );

        // --- the items, and what they refuse to say ---
        let items = of_type(&out, "KeychainItem");
        assert_eq!(
            items.len(),
            306,
            "128 generic, 158 internet, 2 certificates and 18 keys"
        );
        assert!(
            items
                .iter()
                .all(|i| i.get("account").is_none() && i.get("service").is_none()),
            "not one of the 306 names an account or a service: every such attribute in this \
             database is a SHA-1"
        );
        let hashed = items
            .iter()
            .filter(|i| s(i, "account_sha1").is_some())
            .count();
        assert_eq!(
            hashed, 286,
            "the 286 password items each carry an account hash; certificates and keys have no \
             account column"
        );

        // What it does name: the application behind each secret.
        let groups = st["items_by_access_group"]
            .as_object()
            .expect("an access-group census");
        assert!(groups.len() >= 14, "got {} groups", groups.len());
        for expected in [
            "com.apple.cloudd",
            "com.apple.security.sos",
            "com.apple.continuity.unlock",
            "InternetAccounts",
        ] {
            assert!(
                groups.contains_key(expected),
                "{expected} owns items in this keychain"
            );
        }

        // And it names the protection class, including the ThisDeviceOnly
        // items bound to this machine's hardware.
        let classes = st["items_by_protection_class"]
            .as_object()
            .expect("a protection-class census");
        assert!(classes.contains_key("after_first_unlock"));
        assert!(classes.contains_key("always_this_device_only"));
        assert!(
            n(st, "items_this_device_only").unwrap_or(0) > 0,
            "some of this keychain is ThisDeviceOnly: it never syncs to iCloud Keychain"
        );

        // Every secret locked, and the status row says so.
        assert_eq!(
            n(st, "items_with_locked_secret"),
            Some(306),
            "every item carries a wrapped payload and none was decrypted"
        );
        assert_eq!(s(st, "content_incomplete_reason"), Some("encrypted"));
    }
}
