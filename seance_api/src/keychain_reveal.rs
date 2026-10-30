//! The audited reveal of an iOS backup keychain item's secret (HUNT-111).
//!
//! # The decision this implements (owner, 2026-09-26)
//!
//! A keychain item read from an encrypted backup's `keychain-backup.plist`
//! (`IosKeychainItem`) carries its attributes in the clear and its secret —
//! the `v_Data` attribute: a saved password, a token, a private key — nowhere.
//! The parser never copies it into the record, so no listing, `GET`, search
//! snippet or export can carry it, and it is never at rest in the case.
//!
//! It is released only here, one record at a time, following the
//! `MemoryCredential` discipline (`memory::reveal_memory_credential`):
//!
//! * the value is **re-derived on reveal**, from the backup itself, through
//!   the class keys an examiner has unlocked for reading in this case
//!   (`POST …/artifacts/{id}/unlock`, `BUG-026`) — so no plaintext secret is
//!   stored, and a backup that is not unlocked reveals nothing;
//! * the audit row (`ios_keychain_secret_revealed`: who, when, which record,
//!   and the item's table, access group and service — never the value) is
//!   written **before** the value leaves the process, and a failed audit write
//!   refuses the reveal;
//! * a record that is not a readable keychain item with a withheld secret is
//!   refused in words that say why, never answered with an empty value.

use crate::{audit_required, backup_keyring, ApiError, AppState, AuthenticatedUser};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use seance_core::db::DatabaseConnection;
use serde_json::{json, Value};
use tracing::error;
use uuid::Uuid;

/// What a macOS reveal was handed to open the keychain, zeroed on drop.
enum RevealCredential {
    Password(zeroize::Zeroizing<String>),
    SystemKey(zeroize::Zeroizing<Vec<u8>>),
}

/// The record type this route reveals from.
pub const IOS_KEYCHAIN_ITEM_RECORD: &str = "IosKeychainItem";

/// The record type of a macOS `kych` keychain item.
pub const MACOS_KEYCHAIN_ITEM_RECORD: &str = "KeychainItem";

/// The longest keychain password accepted: a bound on input, not a policy.
const MAX_PASSWORD_CHARS: usize = 4096;

/// The largest keychain file read to re-derive a secret (the parser's own bound).
const MAX_KEYCHAIN_BYTES: u64 = 64 * 1024 * 1024;

/// The body of a macOS reveal. Deliberately not `Debug`: nothing may format it.
#[derive(serde::Deserialize)]
pub struct MacosRevealRequest {
    /// The keychain password. Exactly one of `password` and `system_key` is given.
    #[serde(default)]
    pub password: Option<String>,
    /// For `System.keychain`: the 48 bytes of the Mac's `/var/db/SystemKey` as hex.
    #[serde(default)]
    pub system_key: Option<String>,
}

/// Hex to bytes; `None` for anything that is not an even run of hex characters.
fn decode_hex(s: &str) -> Option<zeroize::Zeroizing<Vec<u8>>> {
    let s = s.trim();
    if s.is_empty() || !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect::<Option<Vec<u8>>>()
        .map(zeroize::Zeroizing::new)
}

/// `POST /api/v1/cases/:case_id/keychain/:artifact_id/reveal`
///
/// Hand back one keychain item's secret, and record that it was revealed. An iOS backup item is
/// re-derived from the unlocked backup; a macOS item from the keychain file and the password in
/// the request. See the module documentation for the discipline.
pub async fn reveal_keychain_secret(
    Path((case_id, record_id)): Path<(Uuid, Uuid)>,
    Extension(user): Extension<AuthenticatedUser>,
    State(state): State<AppState>,
    body: Option<Json<MacosRevealRequest>>,
) -> Result<Json<Value>, ApiError> {
    let artifact = state
        .db
        .get_artifact(record_id)
        .await
        .map_err(|e| {
            error!("keychain: failed to load record {record_id}: {e}");
            ApiError::InternalServerError("Failed to load keychain record".to_string())
        })?
        // Another case's id is "not found", not "forbidden": confirming that
        // another case holds a keychain item is itself a disclosure.
        .filter(|a| a.case_id == case_id)
        .ok_or_else(|| {
            ApiError::ResourceNotFound(format!("No keychain record {record_id} in this case"))
        })?;
    if artifact.metadata.get("type").and_then(Value::as_str) == Some(MACOS_KEYCHAIN_ITEM_RECORD) {
        return reveal_macos_keychain_secret(&state, &user, case_id, &artifact, body).await;
    }
    reveal_ios_keychain_secret(&state, &user, case_id, record_id, &artifact).await
}

/// The iOS backup path of [`reveal_keychain_secret`].
async fn reveal_ios_keychain_secret(
    state: &AppState,
    user: &AuthenticatedUser,
    case_id: Uuid,
    record_id: Uuid,
    artifact: &seance_core::artifact::Artifact,
) -> Result<Json<Value>, ApiError> {
    let md = &artifact.metadata;
    let text = |k: &str| md.get(k).and_then(Value::as_str);

    if text("type") != Some(IOS_KEYCHAIN_ITEM_RECORD) {
        return Err(ApiError::InvalidRequest(format!(
            "Artifact {record_id} is not an iOS backup keychain item, so there is no keychain \
             secret to reveal"
        )));
    }
    if text("state") != Some("read") {
        return Err(ApiError::InvalidRequest(format!(
            "Keychain record {record_id} was not read ({}): {} No secret can be revealed from it.",
            text("state").unwrap_or("state not recorded"),
            text("state_detail").unwrap_or("")
        )));
    }
    if text("secret_state") != Some("withheld") {
        return Err(ApiError::InvalidRequest(format!(
            "Keychain record {record_id} carries no secret (secret_state: {}), so there is \
             nothing to reveal. This is not a secret that was empty.",
            text("secret_state").unwrap_or("not recorded")
        )));
    }
    let (Some(backup_path), Some(file_id), Some(table), Some(index)) = (
        text("backup_path"),
        text("source_file_id"),
        text("table"),
        md.get("index_in_table").and_then(Value::as_u64),
    ) else {
        return Err(ApiError::InvalidRequest(format!(
            "Keychain record {record_id} does not say where in the backup it was read from \
             (backup_path, source_file_id, table, index_in_table), so its secret cannot be \
             re-derived"
        )));
    };
    let persistent_ref = text("persistent_ref");

    let checked = state
        .evidence_roots
        .check(std::path::Path::new(backup_path))
        .map_err(ApiError::InvalidRequest)?;
    let key = backup_keyring::source_key(&checked);
    let Some(unlocked) = backup_keyring::ios_backups().get(case_id, &key) else {
        return Err(ApiError::InvalidRequest(format!(
            "The secret of keychain record {record_id} is not stored anywhere: it is re-derived \
             from the backup on reveal, and this backup is not unlocked for reading in this \
             case. Unlock it with the backup password (POST \
             /api/v1/cases/{case_id}/artifacts/{record_id}/unlock, kind ios_backup_password), \
             then reveal again."
        )));
    };

    // Re-derive, then audit, then release. A decryption that fails is not a
    // reveal and is not audited as one.
    let secret = unlocked
        .keychain_secret(file_id, table, index as usize, persistent_ref)
        .map_err(|e| {
            ApiError::InvalidRequest(format!(
                "The secret of keychain record {record_id} could not be re-derived: {e}"
            ))
        })?;

    // Mandatory, not best effort: a failed audit write aborts before the value
    // leaves the process. The row names the item, never its value.
    audit_required(
        state,
        Some(case_id),
        &user.0,
        "ios_keychain_secret_revealed",
        Some("ios_keychain_item"),
        Some(record_id),
        Some(&format!(
            "table={table} access_group={} service={}",
            text("access_group").unwrap_or("not recorded"),
            text("service")
                .or_else(|| text("server"))
                .unwrap_or("not recorded"),
        )),
    )
    .await?;

    let (value, encoding) = match std::str::from_utf8(secret.expose()) {
        Ok(s) => (s.to_string(), "utf8"),
        Err(_) => (
            secret.expose().iter().map(|b| format!("{b:02x}")).collect(),
            "hex",
        ),
    };
    Ok(Json(json!({
        "value": value,
        // Bytes that are not UTF-8 (a key, a token blob) come back as hex and
        // say so, rather than as text with replacement characters.
        "encoding": encoding,
        // The audit writer does not return the row id it wrote, so none is
        // claimed.
        "audit_event_id": Value::Null,
    })))
}

/// A macOS keychain item's secret: re-derived from the keychain file with the password in the request.
///
/// The password is used for this one request and kept nowhere: it is moved into a zeroizing holder,
/// checked against the file's `DbBlob`, and dropped. Nothing is held in process memory afterwards, so
/// each reveal asks for it again. The attempt is on the record first (`macos_keychain_reveal_attempted`,
/// by kind), a refusal is on the record (`macos_keychain_reveal_refused`), and the release is audited
/// (`macos_keychain_secret_revealed`: who, when, which record, the item's service or server and
/// account's absence of value) before the value leaves the process; a failed audit write refuses.
async fn reveal_macos_keychain_secret(
    state: &AppState,
    user: &AuthenticatedUser,
    case_id: Uuid,
    item: &seance_core::artifact::Artifact,
    body: Option<Json<MacosRevealRequest>>,
) -> Result<Json<Value>, ApiError> {
    let md = &item.metadata;
    let text = |k: &str| md.get(k).and_then(Value::as_str);
    let record_id = item.id;
    if !matches!(
        text("item_kind"),
        Some("generic_password" | "internet_password" | "appleshare_password" | "private_key")
    ) || text("secret_wrapping").is_none()
    {
        return Err(ApiError::InvalidRequest(format!(
            "Keychain record {record_id} is not a password item or a private key with a wrapped \
             secret (item kind: {}), so there is no secret to reveal from it. Only a password item \
             or a private key is decrypted; the symmetric keys that wrap them, and certificates \
             (which are not secret), are not",
            text("item_kind").unwrap_or("not recorded")
        )));
    }
    let (Some(relation), Some(record_number), Some(parent)) = (
        text("relation"),
        md.get("record_number").and_then(Value::as_u64),
        item.parent_id,
    ) else {
        return Err(ApiError::InvalidRequest(format!(
            "Keychain record {record_id} does not say where in its keychain file it was read from \
             (relation, record_number, parent), so its secret cannot be re-derived"
        )));
    };
    let Some(Json(MacosRevealRequest {
        password,
        system_key,
    })) = body
    else {
        return Err(ApiError::InvalidRequest(
            "revealing a macOS keychain secret takes the keychain password in the request body: \
             {\"password\": \"...\"}, or for System.keychain the hex of /var/db/SystemKey: \
             {\"system_key\": \"...\"}. It is used for this request and kept nowhere"
                .to_string(),
        ));
    };
    // Exactly one credential, held in zeroizing buffers from here on.
    let credential = match (password, system_key) {
        (Some(p), None) => {
            let p = zeroize::Zeroizing::new(p);
            if p.is_empty() || p.chars().count() > MAX_PASSWORD_CHARS {
                return Err(ApiError::InvalidRequest(format!(
                    "the keychain password must be 1 to {MAX_PASSWORD_CHARS} characters"
                )));
            }
            RevealCredential::Password(p)
        }
        (None, Some(k)) => {
            let k = zeroize::Zeroizing::new(k);
            let Some(file) = decode_hex(&k) else {
                return Err(ApiError::InvalidRequest(
                    "the system_key must be the 48 bytes of /var/db/SystemKey as 96 hex characters"
                        .to_string(),
                ));
            };
            RevealCredential::SystemKey(file)
        }
        _ => {
            return Err(ApiError::InvalidRequest(
                "give exactly one of \"password\" and \"system_key\"".to_string(),
            ))
        }
    };
    let kind = match credential {
        RevealCredential::Password(_) => "kind=macos_keychain_password",
        RevealCredential::SystemKey(_) => "kind=macos_system_key",
    };

    audit_required(
        state,
        Some(case_id),
        &user.0,
        "macos_keychain_reveal_attempted",
        Some("keychain_item"),
        Some(record_id),
        Some(kind),
    )
    .await?;

    let resolved = crate::content_resolver::resolve_artifact_content(
        &state.db,
        &state.evidence_roots,
        case_id,
        parent,
    )
    .await?;
    let relation = relation.to_string();
    let derived = tokio::task::spawn_blocking(move || {
        let size = resolved.source.size();
        if size > MAX_KEYCHAIN_BYTES {
            return Err(format!(
                "the keychain file is {size} bytes, past the {MAX_KEYCHAIN_BYTES} read"
            ));
        }
        let mut bytes = vec![0u8; size as usize];
        let mut got = 0usize;
        while got < bytes.len() {
            match resolved.source.read_at(got as u64, &mut bytes[got..]) {
                Ok(0) => break,
                Ok(n) => got += n,
                Err(e) => return Err(format!("the keychain file could not be read: {e}")),
            }
        }
        bytes.truncate(got);
        let opened = match &credential {
            RevealCredential::Password(p) => {
                seance_plugin_macos_artifacts::unlock_keychain(&bytes, p.as_bytes())
            }
            RevealCredential::SystemKey(k) => {
                seance_plugin_macos_artifacts::unlock_keychain_with_system_key(&bytes, k)
            }
        };
        let unlock = match opened {
            Ok(Some(u)) => u,
            Ok(None) => {
                return Err(
                    "no DbBlob was found in this file, so no credential can open it".to_string(),
                )
            }
            Err(seance_plugin_macos_artifacts::UnlockError::WrongPassword) => {
                return Err(
                    "REFUSED: the credential did not open this keychain's DbBlob".to_string(),
                )
            }
            Err(e) => return Err(format!("the keychain's DbBlob could not be opened ({e:?})")),
        };
        drop(credential);
        let all = seance_plugin_macos_artifacts::decrypt_item_secrets(&bytes, &unlock);
        match all
            .decrypted
            .into_iter()
            .find(|d| d.relation == relation && u64::from(d.record_number) == record_number)
        {
            Some(d) => Ok(zeroize::Zeroizing::new(d.secret().to_vec())),
            None => Err(
                match all
                    .failed
                    .iter()
                    .find(|(r, n, _)| *r == relation && u64::from(*n) == record_number)
                {
                    Some((_, _, why)) => format!("the item's secret did not decrypt: {why}"),
                    None => "the item was not found in the keychain file".to_string(),
                },
            ),
        }
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("reveal did not finish: {e}")))?;

    let secret = match derived {
        Ok(s) => s,
        Err(why) => {
            let refused = why.starts_with("REFUSED: ");
            audit_required(
                state,
                Some(case_id),
                &user.0,
                "macos_keychain_reveal_refused",
                Some("keychain_item"),
                Some(record_id),
                Some(if refused {
                    "outcome=wrong_password"
                } else {
                    "outcome=not_decrypted"
                }),
            )
            .await?;
            return Err(ApiError::InvalidRequest(format!(
                "The secret of keychain record {record_id} was not revealed: {}. Nothing is held.",
                why.trim_start_matches("REFUSED: ")
            )));
        }
    };

    // Audited before the value leaves the process; the row names the item, never its value.
    audit_required(
        state,
        Some(case_id),
        &user.0,
        "macos_keychain_secret_revealed",
        Some("keychain_item"),
        Some(record_id),
        Some(&format!(
            "item_kind={} service={}",
            text("item_kind").unwrap_or("not recorded"),
            text("service")
                .or_else(|| text("server"))
                .unwrap_or("not recorded"),
        )),
    )
    .await?;
    let (value, encoding) = match std::str::from_utf8(&secret) {
        Ok(s) => (s.to_string(), "utf8"),
        Err(_) => (secret.iter().map(|b| format!("{b:02x}")).collect(), "hex"),
    };
    Ok(Json(
        json!({ "value": value, "encoding": encoding, "audit_event_id": Value::Null }),
    ))
}
