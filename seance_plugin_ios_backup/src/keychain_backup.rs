//! The iOS keychain inside an encrypted backup (HUNT-111).
//!
//! An encrypted iTunes/Finder backup carries the device keychain as
//! `KeychainDomain/keychain-backup.plist` — a binary plist, **not** a
//! `keychain-2.db` — with one array per item table (`genp` generic passwords,
//! `inet` internet passwords, `cert` certificates, `keys` keys) of
//! `{v_Data, v_PersistentRef}` dictionaries, and a `keybag-uuid` string.
//!
//! Each `v_Data` (version 3) is
//! `<u32 LE version><u32 LE keychain class><u32 LE wrapped-key length>
//! <RFC 3394 wrapped item key><AES-256-GCM ciphertext, empty IV, 16-byte tag>`.
//! The item key is wrapped under the backup keybag's class key for that
//! class; the GCM plaintext is a DER set of the item's attributes
//! ([`crate::der`]), including the secret itself as the `v_Data` attribute.
//!
//! What this reader does, and what it will not:
//!
//! * Items in classes 6/7/8 (`WhenUnlocked`, `AfterFirstUnlock`, `Always`) open
//!   with the backup's class keys; their attributes — access group, account,
//!   service, server, label, dates — are reported in the clear.
//! * Items in classes 9/10/11 (the `ThisDeviceOnly` classes) **are** in the
//!   backup, but their item keys are wrapped under a key bound to the device's
//!   hardware, which a backup does not carry. They are reported as
//!   `device_bound`, with their table and class and nothing else, because
//!   nothing else can be read.
//! * The secret (`v_Data` attribute) is **withheld**: the record says whether
//!   one is present, never its value or length. So is the `sha1` attribute,
//!   the keychain's digest over the item *including* its secret, from which a
//!   short password could be confirmed by guessing. Release goes through the
//!   audited per-record reveal (the owner's 2026-09-26 decision): the API
//!   re-derives one item's secret with [`secret_of`] from a backup unlocked
//!   for reading, and writes the audit row before returning it.
//! * A GCM tag that does not verify gives `authentication_failed` and no
//!   attributes: nothing unauthenticated is presented as the item's contents.

use crate::crypto::{ClassKeyState, Keybag};
use crate::der::{self, DerValue};
use crate::gcm;
use anyhow::{anyhow, Result};
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

/// Where the keychain lives in a backup's manifest.
pub(crate) const KEYCHAIN_DOMAIN: &str = "KeychainDomain";
pub(crate) const KEYCHAIN_BACKUP_PATH: &str = "keychain-backup.plist";
/// A keychain plist larger than this is not read into memory (the Hickman
/// iOS 17 device's is 1.3 MB).
pub(crate) const MAX_KEYCHAIN_PLIST_BYTES: u64 = 256 * 1024 * 1024;

/// The only `v_Data` layout this reader knows.
const VDATA_VERSION: u32 = 3;

/// Attributes never copied into a record: the secret itself, and the digest
/// computed over the item including its secret.
const WITHHELD_ATTRIBUTES: &[&str] = &["v_Data", "sha1"];

pub(crate) fn is_keychain_backup(domain: &str, relative_path: &str) -> bool {
    domain == KEYCHAIN_DOMAIN && relative_path == KEYCHAIN_BACKUP_PATH
}

/// What reading one `keychain-backup.plist` produced: one record per item and
/// a summary. Each is ParsedRecord metadata; the caller parents them.
pub(crate) struct KeychainReadout {
    pub items: Vec<Value>,
    pub summary: Value,
}

fn table_kind(table: &str) -> &'static str {
    match table {
        "genp" => "generic_password",
        "inet" => "internet_password",
        "cert" => "certificate",
        "keys" => "key",
        _ => "unknown_table",
    }
}

/// The keychain protection class, by number (`kSecAttrAccessible*`).
fn class_name(class: u32) -> Option<&'static str> {
    Some(match class {
        6 => "WhenUnlocked",
        7 => "AfterFirstUnlock",
        8 => "Always",
        9 => "WhenUnlockedThisDeviceOnly",
        10 => "AfterFirstUnlockThisDeviceOnly",
        11 => "AlwaysThisDeviceOnly",
        _ => return None,
    })
}

fn this_device_only(class: u32) -> bool {
    matches!(class, 9..=11)
}

/// The `pdmn` attribute's short code, spelled out.
fn pdmn_name(code: &str) -> Option<&'static str> {
    Some(match code {
        "ak" => "WhenUnlocked",
        "ck" => "AfterFirstUnlock",
        "dk" => "Always",
        "aku" => "WhenUnlockedThisDeviceOnly",
        "cku" => "AfterFirstUnlockThisDeviceOnly",
        "dku" => "AlwaysThisDeviceOnly",
        "akpu" => "WhenPasscodeSetThisDeviceOnly",
        _ => return None,
    })
}

/// A GeneralizedTime (`20230701201621.637078Z`) as RFC 3339, if it parses.
fn generalized_time_rfc3339(s: &str) -> Option<String> {
    let naive = chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%S%.fZ")
        .or_else(|_| chrono::NaiveDateTime::parse_from_str(s, "%Y%m%d%H%M%SZ"))
        .ok()?;
    Some(
        naive
            .and_utc()
            .to_rfc3339_opts(chrono::SecondsFormat::AutoSi, true),
    )
}

/// Text for an attribute that is text in practice, whichever string type it
/// was stored as. An OCTET STRING counts only when it is valid UTF-8.
fn as_text<'a>(v: &DerValue<'a>) -> Option<&'a str> {
    match *v {
        DerValue::Utf8(s) => Some(s),
        DerValue::Octets(b) => std::str::from_utf8(b).ok(),
        _ => None,
    }
}

/// One attribute value as JSON, typed so that a reader can tell text from
/// bytes: strings stay strings, bytes become `{"hex": …}` (plus `"text"` when
/// they happen to be UTF-8), times keep their stored text beside RFC 3339.
fn value_json(v: &DerValue<'_>) -> Value {
    match *v {
        DerValue::Utf8(s) => json!(s),
        DerValue::InvalidUtf8(b) => json!({ "hex": hex::encode(b), "invalid_utf8": true }),
        DerValue::Octets(b) => match std::str::from_utf8(b) {
            Ok(s) => json!({ "hex": hex::encode(b), "text": s }),
            Err(_) => json!({ "hex": hex::encode(b) }),
        },
        DerValue::Integer(i) => json!(i),
        DerValue::BigInteger(b) => json!({ "integer_hex": hex::encode(b) }),
        DerValue::Time(s) => json!({ "generalized_time": s, "utc": generalized_time_rfc3339(s) }),
        DerValue::Boolean(b) => json!(b),
        DerValue::Null => Value::Null,
        DerValue::Other { tag, bytes } => json!({ "der_tag": tag, "hex": hex::encode(bytes) }),
    }
}

/// Why an item's attributes are not in its record.
#[derive(Debug)]
enum ItemFailure {
    Malformed(String),
    UnsupportedVersion(u32),
    NoClassKey(u32),
    DeviceBound(u32),
    KeyUnwrapFailed(u32),
    AuthenticationFailed,
    AttributesUndecodable(String),
}

impl ItemFailure {
    fn state(&self) -> &'static str {
        match self {
            ItemFailure::Malformed(_) => "malformed",
            ItemFailure::UnsupportedVersion(_) => "unsupported_version",
            ItemFailure::NoClassKey(_) => "no_class_key",
            ItemFailure::DeviceBound(_) => "device_bound",
            ItemFailure::KeyUnwrapFailed(_) => "key_unwrap_failed",
            ItemFailure::AuthenticationFailed => "authentication_failed",
            ItemFailure::AttributesUndecodable(_) => "attributes_undecodable",
        }
    }

    fn sentence(&self) -> String {
        match self {
            ItemFailure::Malformed(d) => format!("The item's v_Data is not laid out as expected: {d}. Nothing in it was read."),
            ItemFailure::UnsupportedVersion(v) => format!("The item's v_Data is version {v}; this reader knows version 3 only. Nothing in it was read."),
            ItemFailure::NoClassKey(c) => format!("The backup keybag holds no unwrapped key for keychain class {c}, so the item key could not be unwrapped. Nothing in it was read."),
            ItemFailure::DeviceBound(c) => format!("Keychain class {c} ({}) is bound to the device: the item key is wrapped under a key derived from the device's hardware, which a backup does not carry. The item is present in the backup but neither its attributes nor its secret can be read from it.", class_name(*c).unwrap_or("ThisDeviceOnly")),
            ItemFailure::KeyUnwrapFailed(c) => format!("The item key did not unwrap under the backup's class {c} key (RFC 3394 integrity check failed). Nothing in it was read."),
            ItemFailure::AuthenticationFailed => "The item key unwrapped but the AES-GCM authentication tag did not verify, so the decrypted bytes are not presented: they may not be what was stored.".to_string(),
            ItemFailure::AttributesUndecodable(d) => format!("The item decrypted and authenticated, but its attributes are not the DER set this reader expects: {d}."),
        }
    }
}

/// Open one item's `v_Data`: unwrap its key, authenticate and decrypt, and
/// hand the attribute set to `with_attrs` while the plaintext is alive. The
/// plaintext is zeroed when this returns.
fn open_item<R>(
    v_data: &[u8],
    keybag: &Keybag,
    with_attrs: impl FnOnce(u32, &[(&str, DerValue<'_>)]) -> R,
) -> std::result::Result<R, (Option<u32>, ItemFailure)> {
    if v_data.len() < 12 {
        return Err((
            None,
            ItemFailure::Malformed(format!(
                "{} bytes, shorter than its 12-byte header",
                v_data.len()
            )),
        ));
    }
    let u32_at = |o: usize| u32::from_le_bytes(v_data[o..o + 4].try_into().expect("4 bytes"));
    let (version, class, wrapped_len) = (u32_at(0), u32_at(4), u32_at(8) as usize);
    if version != VDATA_VERSION {
        return Err((Some(class), ItemFailure::UnsupportedVersion(version)));
    }
    let Some(wrapped) = v_data.get(12..12 + wrapped_len) else {
        return Err((
            Some(class),
            ItemFailure::Malformed(format!(
                "the wrapped key claims {wrapped_len} bytes, past the end"
            )),
        ));
    };
    let body = &v_data[12 + wrapped_len..];

    let entry = keybag.class_keys.iter().find(|ck| ck.class == class);
    // The keybag itself says the class is wrapped under the device key
    // (WRAP & 1): no class key exists to try.
    if entry.map(|ck| ck.state()) == Some(ClassKeyState::DeviceBound) {
        return Err((Some(class), ItemFailure::DeviceBound(class)));
    }
    let class_key = crate::crypto::usable_class_key(keybag, class).ok();
    let Some(class_key) = class_key else {
        return Err((Some(class), ItemFailure::NoClassKey(class)));
    };
    let item_key = match crate::crypto::unwrap_file_key(wrapped, class_key) {
        Ok(k) => Zeroizing::new(k),
        // Tried and failed. For a ThisDeviceOnly class that is the expected
        // outcome, and the reason is stated as such; for any other class it is
        // an integrity failure.
        Err(_) if this_device_only(class) => {
            return Err((Some(class), ItemFailure::DeviceBound(class)))
        }
        Err(_) => return Err((Some(class), ItemFailure::KeyUnwrapFailed(class))),
    };
    let item_key: Zeroizing<[u8; 32]> = match item_key.as_slice().try_into() {
        Ok(k) => Zeroizing::new(k),
        Err(_) => {
            return Err((
                Some(class),
                ItemFailure::Malformed(format!("the item key is {} bytes, not 32", item_key.len())),
            ))
        }
    };
    let plaintext = gcm::decrypt_empty_iv(&item_key, body).map_err(|e| {
        (
            Some(class),
            match e {
                gcm::GcmError::TagMismatch => ItemFailure::AuthenticationFailed,
                gcm::GcmError::Truncated => ItemFailure::Malformed(e.to_string()),
            },
        )
    })?;
    let attrs = der::read_attribute_set(&plaintext)
        .map_err(|e| (Some(class), ItemFailure::AttributesUndecodable(e.0)))?;
    Ok(with_attrs(class, &attrs))
}

/// The record fields drawn from an opened item's attributes. The secret and
/// the digest over it are never copied; only their presence is.
fn attribute_fields(attrs: &[(&str, DerValue<'_>)], meta: &mut Map<String, Value>) {
    let get = |k: &str| attrs.iter().find(|(n, _)| *n == k).map(|(_, v)| v);
    let text = |k: &str| get(k).and_then(as_text);

    let mut all = Map::new();
    for (name, v) in attrs {
        if WITHHELD_ATTRIBUTES.contains(name) {
            continue;
        }
        all.insert((*name).to_string(), value_json(v));
    }
    meta.insert("attributes".into(), Value::Object(all));

    for (key, field) in [
        ("agrp", "access_group"),
        ("acct", "account"),
        ("svce", "service"),
        ("srvr", "server"),
        ("labl", "label"),
        ("desc", "kind_description"),
        ("icmt", "comment"),
        ("vwht", "view_hint"),
        ("UUID", "uuid"),
        ("path", "path"),
        ("sdmn", "security_domain"),
    ] {
        if let Some(t) = text(key) {
            meta.insert(field.into(), json!(t));
        }
    }
    // An account stored as bytes that are not UTF-8 is still an account.
    if meta.get("account").is_none() {
        if let Some(DerValue::Octets(b)) = get("acct") {
            meta.insert("account_hex".into(), json!(hex::encode(b)));
        }
    }
    for (key, field) in [
        ("sync", "synchronizable"),
        ("tomb", "tombstone"),
        ("port", "port"),
    ] {
        if let Some(DerValue::Integer(i)) = get(key) {
            meta.insert(field.into(), json!(i));
        }
    }
    for (key, field) in [("cdat", "created"), ("mdat", "modified")] {
        if let Some(DerValue::Time(t)) = get(key) {
            meta.insert(
                field.into(),
                json!(generalized_time_rfc3339(t).unwrap_or_else(|| t.to_string())),
            );
        }
    }
    if let Some(code) = text("pdmn") {
        meta.insert("protection_domain".into(), json!(code));
        if let Some(n) = pdmn_name(code) {
            meta.insert("protection_domain_name".into(), json!(n));
        }
    }

    let secret_present = get("v_Data").is_some();
    meta.insert("secret_present".into(), json!(secret_present));
    meta.insert(
        "secret_state".into(),
        json!(if secret_present { "withheld" } else { "absent" }),
    );
    if secret_present {
        meta.insert(
            "secret_statement".into(),
            json!("The item's secret decrypted with the item but is withheld: it is not in this record, its export, or search, and is not stored. It is released only by the audited per-record reveal (POST /api/v1/cases/{case}/keychain/{record}/reveal), which re-derives it from the backup while the backup is unlocked for reading and writes the audit row first."),
        );
    }
}

/// A short display name for an item.
fn display_name(meta: &Map<String, Value>, kind: &str) -> String {
    let s = |k: &str| {
        meta.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    let what = s("label")
        .or(s("service"))
        .or(s("server"))
        .or(s("access_group"));
    match (what, s("account")) {
        (Some(w), Some(a)) => format!("{w} ({a})"),
        (Some(w), None) => w.to_string(),
        (None, Some(a)) => a.to_string(),
        (None, None) => format!("keychain {kind}"),
    }
}

/// Read a decrypted keychain file whole, refusing one over
/// [`MAX_KEYCHAIN_PLIST_BYTES`] or one that reads short. The error is a
/// sentence for the record.
pub(crate) fn read_whole(
    source: &dyn seance_core::data_source::DataSource,
) -> std::result::Result<Vec<u8>, String> {
    let size = source.size();
    if size > MAX_KEYCHAIN_PLIST_BYTES {
        return Err(format!(
            "it is {size} bytes, over the {MAX_KEYCHAIN_PLIST_BYTES} byte limit"
        ));
    }
    let mut bytes = vec![0u8; size as usize];
    let mut filled = 0usize;
    while filled < bytes.len() {
        match source.read_at(filled as u64, &mut bytes[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) => return Err(format!("reading it failed at byte {filled}: {e}")),
        }
    }
    if filled < bytes.len() {
        return Err(format!("only {filled} of {size} bytes could be read"));
    }
    Ok(bytes)
}

/// The secret (`v_Data` attribute) of one item, for the audited reveal
/// (HUNT-111, the owner's decision of 2026-09-26: re-derived on reveal, never
/// stored). The item is named as its record names it — table and position —
/// and, when the record carries one, its `v_PersistentRef` must match, so a
/// changed file can never answer for a different item.
///
/// Every refusal is a sentence; none carries a byte of the secret.
pub(crate) fn secret_of(
    plist_bytes: &[u8],
    keybag: &Keybag,
    table: &str,
    index: usize,
    persistent_ref_hex: Option<&str>,
) -> Result<Zeroizing<Vec<u8>>> {
    let root = plist::Value::from_reader(std::io::Cursor::new(plist_bytes))
        .map_err(|e| anyhow!("keychain-backup.plist is not a property list: {e}"))?;
    let entry = root
        .as_dictionary()
        .and_then(|d| d.get(table))
        .and_then(|t| t.as_array())
        .ok_or_else(|| anyhow!("the keychain has no table {table:?}"))?
        .get(index)
        .and_then(|e| e.as_dictionary())
        .ok_or_else(|| anyhow!("the keychain's {table:?} table has no item {index}"))?;
    if let Some(expected) = persistent_ref_hex {
        let found = entry
            .get("v_PersistentRef")
            .and_then(|v| v.as_data())
            .map(hex::encode);
        if found.as_deref() != Some(expected) {
            return Err(anyhow!(
                "item {index} of {table:?} does not carry the persistent reference the record \
                 names: the keychain file is not the one this record was read from, and no \
                 secret is released for a different item"
            ));
        }
    }
    let v_data = entry
        .get("v_Data")
        .and_then(|v| v.as_data())
        .ok_or_else(|| anyhow!("item {index} of {table:?} has no v_Data"))?;
    let secret = open_item(v_data, keybag, |_, attrs| {
        attrs.iter().find_map(|(name, v)| match (*name, v) {
            ("v_Data", DerValue::Octets(b)) => Some(Zeroizing::new(b.to_vec())),
            _ => None,
        })
    })
    .map_err(|(_, failure)| anyhow!("{}", failure.sentence()))?;
    secret.ok_or_else(|| {
        anyhow!("item {index} of {table:?} decrypted but carries no secret (no v_Data attribute)")
    })
}

/// Read a decrypted `keychain-backup.plist` with the backup's unlocked keybag.
///
/// An `Err` is only for a file that is not a keychain plist at all; every
/// per-item failure is a record with its state and reason.
pub(crate) fn read(plist_bytes: &[u8], keybag: &Keybag) -> Result<KeychainReadout> {
    let root = plist::Value::from_reader(std::io::Cursor::new(plist_bytes))
        .map_err(|e| anyhow!("keychain-backup.plist is not a property list: {e}"))?;
    let dict = root
        .as_dictionary()
        .ok_or_else(|| anyhow!("keychain-backup.plist is not a dictionary"))?;

    let keybag_uuid = dict
        .get("keybag-uuid")
        .and_then(|v| v.as_string())
        .map(str::to_string);

    let mut items = Vec::new();
    let mut per_table: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_class: BTreeMap<String, u64> = BTreeMap::new();
    let mut per_state: BTreeMap<&'static str, u64> = BTreeMap::new();
    let mut secrets_withheld = 0u64;
    let mut unread_entries = Vec::new();

    for (table, value) in dict.iter() {
        if table == "keybag-uuid" {
            continue;
        }
        let Some(array) = value.as_array() else {
            unread_entries.push(table.clone());
            continue;
        };
        let kind = table_kind(table);
        for (index, entry) in array.iter().enumerate() {
            *per_table.entry(table.clone()).or_default() += 1;
            let entry = entry.as_dictionary();
            let v_data = entry
                .and_then(|d| d.get("v_Data"))
                .and_then(|v| v.as_data());
            let persistent_ref = entry
                .and_then(|d| d.get("v_PersistentRef"))
                .and_then(|v| v.as_data())
                .map(hex::encode);

            let mut meta = Map::new();
            meta.insert("type".into(), json!("IosKeychainItem"));
            meta.insert("table".into(), json!(table));
            meta.insert("item_kind".into(), json!(kind));
            meta.insert("index_in_table".into(), json!(index));
            meta.insert("persistent_ref".into(), json!(persistent_ref));

            let outcome = match v_data {
                None => Err((
                    None,
                    ItemFailure::Malformed("the entry has no v_Data".into()),
                )),
                Some(v) => open_item(v, keybag, |class, attrs| {
                    attribute_fields(attrs, &mut meta);
                    class
                }),
            };
            let (class, state) = match outcome {
                Ok(class) => {
                    if meta.get("secret_state").and_then(Value::as_str) == Some("withheld") {
                        secrets_withheld += 1;
                    }
                    meta.insert("state".into(), json!("read"));
                    (Some(class), "read")
                }
                Err((class, failure)) => {
                    let state = failure.state();
                    meta.insert("state".into(), json!(state));
                    meta.insert("state_detail".into(), json!(failure.sentence()));
                    // Nothing was decrypted, so whether a secret exists is
                    // unknown; it is not "absent".
                    meta.insert("secret_present".into(), Value::Null);
                    meta.insert("secret_state".into(), json!("locked"));
                    meta.insert("content_incomplete".into(), json!(true));
                    meta.insert(
                        "content_incomplete_reason".into(),
                        json!(seance_core::io::IncompleteReason::Encrypted.as_str()),
                    );
                    (class, state)
                }
            };
            if let Some(c) = class {
                meta.insert("keychain_class".into(), json!(c));
                meta.insert("keychain_class_name".into(), json!(class_name(c)));
                meta.insert("this_device_only".into(), json!(this_device_only(c)));
                *per_class.entry(c.to_string()).or_default() += 1;
            }
            *per_state.entry(state).or_default() += 1;
            let name = display_name(&meta, kind);
            meta.insert("name".into(), json!(name));
            items.push(Value::Object(meta));
        }
    }

    let total = items.len() as u64;
    let read = per_state.get("read").copied().unwrap_or(0);
    let device_bound = per_state.get("device_bound").copied().unwrap_or(0);
    let summary = json!({
        "type": "IosKeychainSummary",
        "name": "iOS keychain (from the encrypted backup)",
        "keybag_uuid": keybag_uuid,
        "items_total": total,
        "items_read": read,
        "items_device_bound": device_bound,
        "items_by_table": per_table,
        "items_by_class": per_class,
        "items_by_state": per_state,
        "secrets_withheld": secrets_withheld,
        "unread_entries": unread_entries,
        "content_incomplete": read < total,
        "statement": format!(
            "{read} of {total} keychain items were decrypted and their attributes are reported. \
             {device_bound} are in a ThisDeviceOnly class and are wrapped under the device's \
             hardware-bound key, which a backup does not carry: they are listed, not read. \
             {secrets_withheld} decrypted secrets (saved passwords, tokens, keys, certificates) \
             are withheld from every record, export and search; their digest (sha1) is withheld \
             with them."
        ),
    });
    Ok(KeychainReadout { items, summary })
}

/// Build synthetic keychain fixtures. They pin the mechanism; they are made
/// with this crate's own GCM and key wrap, so they are not validation — the
/// Hickman iOS 17 known answer is (`tests/hickman_ios17_keychain.rs`).
#[cfg(any(test, feature = "test-support"))]
pub mod fixture {
    /// A version-3 `v_Data`: the item key wrapped under `class_key`, then the
    /// DER attribute set sealed with AES-GCM (empty IV) under the item key.
    pub fn v_data(
        class: u32,
        class_key: &[u8; 32],
        item_key: &[u8; 32],
        attrs_der: &[u8],
    ) -> Vec<u8> {
        let wrapped = aes_kw::KekAes256::from(*class_key)
            .wrap_vec(item_key)
            .unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(&3u32.to_le_bytes());
        out.extend_from_slice(&class.to_le_bytes());
        out.extend_from_slice(&(wrapped.len() as u32).to_le_bytes());
        out.extend_from_slice(&wrapped);
        out.extend(crate::gcm::encrypt_empty_iv(item_key, attrs_der));
        out
    }

    /// `SET { SEQUENCE { UTF8String name, value } }` with UTF8String values
    /// and, for `v_Data`, an OCTET STRING.
    pub fn attributes(attrs: &[(&str, &[u8])]) -> Vec<u8> {
        let typed: Vec<(&str, u8, &[u8])> = attrs
            .iter()
            .map(|(k, v)| {
                (
                    *k,
                    if *k == "v_Data" || *k == "sha1" {
                        0x04
                    } else {
                        0x0c
                    },
                    *v,
                )
            })
            .collect();
        crate::der::build::attribute_set(&typed)
    }

    /// A binary `keychain-backup.plist` with the given tables of `v_Data`s.
    pub fn plist(tables: &[(&str, Vec<Vec<u8>>)]) -> Vec<u8> {
        let mut d = plist::Dictionary::new();
        d.insert(
            "keybag-uuid".into(),
            plist::Value::String("00000000-0000-0000-0000-000000000001".into()),
        );
        for (name, items) in tables {
            let arr = items
                .iter()
                .enumerate()
                .map(|(i, v)| {
                    let mut e = plist::Dictionary::new();
                    e.insert("v_Data".into(), plist::Value::Data(v.clone()));
                    e.insert(
                        "v_PersistentRef".into(),
                        plist::Value::Data(vec![i as u8; 20]),
                    );
                    plist::Value::Dictionary(e)
                })
                .collect();
            d.insert((*name).into(), plist::Value::Array(arr));
        }
        let mut out = Vec::new();
        plist::Value::Dictionary(d)
            .to_writer_binary(&mut out)
            .unwrap();
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ClassKey;

    const K7: [u8; 32] = [0x07; 32];
    const K10: [u8; 32] = [0x10; 32];
    /// Stands in for the device's hardware-bound key: not in the keybag.
    const DEVICE_KEY: [u8; 32] = [0xD0; 32];
    const SECRET: &[u8] = b"hunter2-the-saved-password";

    fn keybag() -> Keybag {
        let ck = |class: u32, k: [u8; 32]| ClassKey {
            class,
            wrap_type: 2,
            wrapped_key: vec![],
            unwrapped_key: Some(k.to_vec()),
        };
        Keybag {
            uuid: vec![0; 16],
            salt: vec![],
            iter: 1,
            dpsl: None,
            dpic: None,
            class_keys: vec![ck(7, K7), ck(10, K10)],
        }
    }

    fn open_attrs() -> Vec<u8> {
        fixture::attributes(&[
            ("agrp", b"com.apple.cfnetwork"),
            ("acct", b"someone@example.com"),
            ("svce", b"AirPort"),
            ("pdmn", b"ck"),
            ("sha1", &[0x5A; 20]),
            ("v_Data", SECRET),
        ])
    }

    #[test]
    fn keychain_backup_plist_items_are_read_and_secret_withheld() {
        let class7 = fixture::v_data(7, &K7, &[0x71; 32], &open_attrs());
        // A ThisDeviceOnly item: its key is wrapped under the device key.
        let class10 = fixture::v_data(10, &DEVICE_KEY, &[0x72; 32], &open_attrs());
        let mut tampered = fixture::v_data(7, &K7, &[0x73; 32], &open_attrs());
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let plist = fixture::plist(&[("genp", vec![class7, class10, tampered])]);

        let out = read(&plist, &keybag()).unwrap();
        assert_eq!(out.items.len(), 3);

        let open = &out.items[0];
        assert_eq!(open["state"], "read");
        assert_eq!(open["account"], "someone@example.com");
        assert_eq!(open["access_group"], "com.apple.cfnetwork");
        assert_eq!(open["service"], "AirPort");
        assert_eq!(open["protection_domain_name"], "AfterFirstUnlock");
        assert_eq!(open["keychain_class"], 7);
        assert_eq!(open["secret_present"], true);
        assert_eq!(open["secret_state"], "withheld");

        let bound = &out.items[1];
        assert_eq!(bound["state"], "device_bound");
        assert_eq!(bound["this_device_only"], true);
        assert!(bound.get("account").is_none());
        assert!(bound.get("attributes").is_none());
        assert_eq!(bound["secret_state"], "locked");

        let bad = &out.items[2];
        assert_eq!(bad["state"], "authentication_failed");
        assert!(bad.get("account").is_none());
        assert!(bad.get("attributes").is_none());

        // The secret — and the digest over it — are in no record, in any
        // encoding.
        let all = serde_json::to_string(&out.items).unwrap()
            + &serde_json::to_string(&out.summary).unwrap();
        for needle in [
            String::from_utf8_lossy(SECRET).to_string(),
            hex::encode(SECRET),
            hex::encode([0x5A; 20]),
        ] {
            assert!(!all.contains(&needle), "{needle} leaked");
        }
        assert!(!all.contains("\"v_Data\""));

        assert_eq!(out.summary["items_total"], 3);
        assert_eq!(out.summary["items_read"], 1);
        assert_eq!(out.summary["items_device_bound"], 1);
        assert_eq!(out.summary["secrets_withheld"], 1);
    }

    /// As the real keybag has it after unlock: class 10 is WRAP=3, so no
    /// class key is held for it. Its items are device-bound, not "no class
    /// key" — the reason is the device key, not a missing keybag entry.
    #[test]
    fn items_in_a_device_bound_keybag_class_are_device_bound() {
        let mut kb = keybag();
        kb.class_keys[1].wrap_type = 3;
        kb.class_keys[1].unwrapped_key = None;
        let class10 = fixture::v_data(10, &DEVICE_KEY, &[0x72; 32], &open_attrs());
        let plist = fixture::plist(&[("genp", vec![class10])]);
        let out = read(&plist, &kb).unwrap();
        assert_eq!(out.items[0]["state"], "device_bound");
        assert_eq!(out.summary["items_device_bound"], 1);
    }
}
