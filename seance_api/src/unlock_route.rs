//! `POST` / `DELETE /api/v1/cases/{case_id}/artifacts/{artifact_id}/unlock`
//! — unlock an encrypted iOS backup, or a BitLocker or LUKS volume decrypted
//! in a run, for reading, and lock it again (`BUG-026`, `HUNT-254`; owner
//! decision of 2026-09-26 on key retention).
//!
//! # Volumes (`HUNT-254`)
//!
//! With `kind` `bitlocker_password`, `bitlocker_recovery_password` or
//! `luks_passphrase`, the target is the locked volume, the decrypted volume
//! recorded beneath it, or anything beneath that. The secret is tried on the
//! locked volume's own bytes — after `unlock_supplied` is written — and, if it
//! opens it, the decrypting view is held in process memory
//! ([`crate::unlocked_volumes`]) for this case and the TTL, and the decrypted
//! volume and everything beneath it resolve to plaintext. The same audit rows
//! as for a backup, with `volume=<locked volume id>`; a kind aimed at the other
//! family's volume, or at something that is not a volume, is refused
//! (`outcome=not_applicable`) and nothing is held. `DELETE` forgets the view
//! (`kind=…; reason=lock`), as do expiry (`kind=volume; reason=expired`), a
//! case delete and a restart; each also drops the resolver's cached sources,
//! which could otherwise keep the view — and its key — alive.
//!
//! After ingest the backup password is gone, and the files of an encrypted
//! backup cannot be streamed, hex-viewed, exported or re-hashed: the only
//! bytes on disk are ciphertext, which the content resolver refuses to serve
//! (`HUNT-004`). This route is the explicit step that makes them readable
//! again.
//!
//! # What `POST` does
//!
//! The target is the backup folder, the parser's "encrypted" record, or any
//! file of the backup — anything that names the backup directory. The body is
//! `{kind: "ios_backup_password", secret}`. The route writes
//! `unlock_supplied` to the audit log (if it cannot, nothing is tried), checks
//! the password against the backup's keybag through the same code the ingest
//! run uses, and writes `unlock_outcome` (`accepted` or `rejected`). Only
//! then, and only if accepted, are the unwrapped class keys put in the
//! process-memory keyring ([`crate::backup_keyring`]), keyed by this case and
//! the backup's canonical path, for the keyring's TTL (default 8 hours,
//! `SEANCE_UNLOCK_TTL_SECS`). While they are held, every file of that backup
//! resolves to its plaintext in this case — and only in this case.
//!
//! # What `DELETE` does
//!
//! Forgets the keys for this case and backup, and writes `unlock_forgotten`
//! (`reason=lock`) saying whether any were held. Deleting the case forgets
//! them too (`reason=case_delete`, written before they are dropped), and so
//! does the TTL: an expired unlock is never returned, is dropped by the next
//! keyring operation or by the expiry sweep (at most a minute later), and
//! the sweep writes `reason=expired` by `system`. A restart forgets them
//! with no row (the process holding them is gone). After any of these the
//! refusal returns and names this route.
//!
//! # The discipline
//!
//! - **Authorised like every write route**: `read_write` or `owner` on the
//!   case (the case-access middleware), and the artifact is scoped to the case
//!   in the path.
//! - **Audited by kind, never by value.** No audit row, job row, response or
//!   log line carries the password or a key; the password is not an argument
//!   to any of them.
//! - **Memory only.** The password is moved into a zeroizing holder on
//!   arrival and dropped when the check returns. The class keys are held in
//!   process memory, zeroed when the last handle drops, and never written to
//!   the database, an export, a backup of the case or a log.
//!
//! # What it cannot promise
//!
//! The HTTP body buffer the password arrived in is freed by the framework,
//! not zeroed. For a volume, the BitLocker password stretch and the LUKS KDF
//! produce intermediate keys that are ordinary buffers for the length of the
//! check; the held key (FVEK, or LUKS master key) is zeroizing. The passcode key derived during the check and the per-file keys
//! unwrapped for each read are ordinary buffers for as long as that step or
//! read lasts. Process memory can be swapped or captured in a core dump; the
//! keyring does not lock pages. A read under way when the backup is locked
//! keeps its own handle until it finishes.

use crate::{audit_required, backup_keyring, ApiError, AppState, AuthenticatedUser};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use seance_core::artifact::Artifact;
use serde::Deserialize;
use std::time::{Duration, Instant};
use tracing::{error, info};
use uuid::Uuid;

/// The one kind this route takes today.
pub const IOS_BACKUP_PASSWORD: &str = "ios_backup_password";

/// The longest secret accepted: a bound on input, not a policy.
const MAX_SECRET_CHARS: usize = 4096;

/// The request body. Deliberately not `Debug`: nothing may format it.
#[derive(Deserialize)]
pub struct UnlockRequest {
    pub kind: String,
    pub secret: String,
}

const UNLOCK_NOTE: &str = "The backup's class keys are held in this server's memory for this \
    case only, until they expire, the backup is locked again (DELETE on this route), the case \
    is deleted or the server restarts. The password itself is not kept, and neither it nor the \
    keys are written to the case, an export or the audit log.";

/// The longest the expiry sweep waits between passes. An expired entry is
/// never returned (every keyring operation drops it first); the sweep is what
/// drops it — and writes its audit row — when nothing touches the keyring.
const MAX_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How often the expiry sweep runs for a keyring with this TTL: never less
/// often than the TTL itself, at most [`MAX_SWEEP_INTERVAL`] apart, at least
/// a second apart.
pub fn sweep_interval(ttl: Duration) -> Duration {
    ttl.min(MAX_SWEEP_INTERVAL).max(Duration::from_secs(1))
}

/// One pass of the expiry sweep: drop every expired unlock and write an
/// `unlock_forgotten` row (`reason=expired`, by `system`) for each unlock
/// forgotten by expiry since the last pass, whichever keyring operation
/// dropped it. A row that cannot be written is queued for the next pass.
pub async fn audit_expired_unlocks(state: &AppState) {
    let ring = backup_keyring::ios_backups();
    let expired = ring.sweep_at(Instant::now());
    if !expired.is_empty() {
        // Plaintext cached beneath an expired backup must not outlive its keys.
        crate::content_resolver::forget_cached_views();
    }
    let mut unaudited = Vec::new();
    for (case_id, source) in expired {
        let details =
            format!("kind={IOS_BACKUP_PASSWORD}; reason=expired; held=true; source={source}");
        let written = state
            .db
            .record_audit_event(
                Some(case_id),
                "system",
                "unlock_forgotten",
                Some("case"),
                Some(case_id),
                Some(&details),
            )
            .await;
        // A case deleted since has no row to hang this on; the row is still
        // found by the case as its resource.
        let written = match written {
            Ok(()) => Ok(()),
            Err(_) => {
                state
                    .db
                    .record_audit_event(
                        None,
                        "system",
                        "unlock_forgotten",
                        Some("case"),
                        Some(case_id),
                        Some(&details),
                    )
                    .await
            }
        };
        match written {
            Ok(()) => info!(
                "unlock: {} in case {} forgotten at expiry",
                IOS_BACKUP_PASSWORD, case_id
            ),
            Err(e) => {
                error!(
                    "unlock: could not audit the expiry of an unlock in case {}: {} (retried next pass)",
                    case_id, e
                );
                unaudited.push((case_id, source));
            }
        }
    }
    if !unaudited.is_empty() {
        ring.requeue_unaudited(unaudited);
    }

    // Volumes unlocked for reading (HUNT-254): the same pass, the same row.
    let volumes = crate::unlocked_volumes::volumes();
    let expired = volumes.sweep_at(Instant::now());
    if !expired.is_empty() {
        // A cached source built beneath an expired view would keep its key.
        crate::content_resolver::forget_cached_views();
    }
    let mut unaudited = Vec::new();
    for (case_id, source) in expired {
        let details = format!("kind=volume; reason=expired; held=true; source={source}");
        let mut written = state
            .db
            .record_audit_event(
                Some(case_id),
                "system",
                "unlock_forgotten",
                Some("case"),
                Some(case_id),
                Some(&details),
            )
            .await;
        if written.is_err() {
            written = state
                .db
                .record_audit_event(
                    None,
                    "system",
                    "unlock_forgotten",
                    Some("case"),
                    Some(case_id),
                    Some(&details),
                )
                .await;
        }
        match written {
            Ok(()) => info!("unlock: a volume in case {} forgotten at expiry", case_id),
            Err(e) => {
                error!(
                    "unlock: could not audit the expiry of a volume unlock in case {}: {} (retried next pass)",
                    case_id, e
                );
                unaudited.push((case_id, source));
            }
        }
    }
    if !unaudited.is_empty() {
        volumes.requeue_unaudited(unaudited);
    }
}

/// Start the expiry sweep if it is not running. Called on every accepted
/// unlock, so it runs whenever anything can be held; a sweep whose runtime has
/// gone is started again.
fn ensure_expiry_sweep(state: &AppState) {
    static SWEEP: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>> =
        std::sync::Mutex::new(None);
    let mut running = SWEEP.lock().unwrap_or_else(|e| e.into_inner());
    if running.as_ref().is_some_and(|h| !h.is_finished()) {
        return;
    }
    let state = state.clone();
    *running = Some(tokio::spawn(async move {
        let mut tick = tokio::time::interval(sweep_interval(backup_keyring::ios_backups().ttl()));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tick.tick().await;
            audit_expired_unlocks(&state).await;
        }
    }));
}

/// The backup directory the artifact names: `backup_path` on a backup file or
/// the parser's own records, `path` on the backup folder itself. Checked
/// against the evidence roots, exactly as the content resolver checks it, so
/// the keyring key here and there is the same.
async fn backup_dir_of(
    state: &AppState,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<std::path::PathBuf, ApiError> {
    let artifact: Artifact = state
        .db
        .get_artifact_details(case_id, artifact_id)
        .await
        .map_err(|_| ApiError::ResourceNotFound("Artifact not found".to_string()))?;
    let md = &artifact.metadata;
    let recorded = md
        .get("backup_path")
        .and_then(|v| v.as_str())
        .or_else(|| {
            (md.get("is_directory").and_then(|v| v.as_bool()) == Some(true))
                .then(|| md.get("path").and_then(|v| v.as_str()))
                .flatten()
        })
        .ok_or_else(|| {
            ApiError::InvalidRequest(format!(
                "Artifact {artifact_id} is not an iOS backup folder or a record of one: there \
                 is no backup to unlock"
            ))
        })?;
    state
        .evidence_roots
        .check(std::path::Path::new(recorded))
        .map_err(ApiError::InvalidRequest)
}

pub async fn unlock_for_reading(
    Path((case_id, artifact_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<UnlockRequest>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let UnlockRequest { kind, secret } = payload;
    // Into a zeroizing holder before anything can fail.
    let secret = zeroize::Zeroizing::new(secret);

    // A BitLocker or LUKS volume decrypted in a run (HUNT-254).
    if let Some(volume_kind) = crate::unlocked_volumes::volume_kind(&kind) {
        if secret.is_empty() {
            return Err(ApiError::InvalidRequest(format!(
                "the {volume_kind} is empty"
            )));
        }
        if secret.chars().count() > MAX_SECRET_CHARS {
            return Err(ApiError::InvalidRequest(format!(
                "the {volume_kind} is longer than {MAX_SECRET_CHARS} characters"
            )));
        }
        let v = crate::unlocked_volumes::unlock(
            &state,
            case_id,
            artifact_id,
            &user.0,
            volume_kind,
            secret,
        )
        .await?;
        ensure_expiry_sweep(&state);
        return Ok(Json(v));
    }
    if kind != IOS_BACKUP_PASSWORD {
        return Err(ApiError::InvalidRequest(format!(
            "unknown unlock kind; this build unlocks for reading with \
             {IOS_BACKUP_PASSWORD}, {}",
            crate::unlocked_volumes::VOLUME_KINDS.join(", ")
        )));
    }
    if secret.is_empty() {
        return Err(ApiError::InvalidRequest(
            "the iOS backup password is empty".to_string(),
        ));
    }
    if secret.chars().count() > MAX_SECRET_CHARS {
        return Err(ApiError::InvalidRequest(format!(
            "the iOS backup password is longer than {MAX_SECRET_CHARS} characters"
        )));
    }

    let dir = backup_dir_of(&state, case_id, artifact_id).await?;

    // The attempt is on the record before anything acts on it.
    audit_required(
        &state,
        Some(case_id),
        &user.0,
        "unlock_supplied",
        Some("artifact"),
        Some(artifact_id),
        Some(&format!("kind={IOS_BACKUP_PASSWORD}")),
    )
    .await?;

    let check_dir = dir.clone();
    let result = tokio::task::spawn_blocking(move || {
        let r = seance_plugin_ios_backup::unlock_backup(&check_dir, &secret);
        drop(secret);
        r
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("unlock check did not finish: {e}")))?;

    let unlocked = match result {
        Ok(u) => u,
        Err(e) => {
            let (outcome, err) = match e {
                seance_plugin_ios_backup::UnlockError::WrongPassword(reason) => (
                    "rejected",
                    ApiError::InvalidRequest(format!(
                        "the iOS backup password was refused: {reason}. Nothing is held."
                    )),
                ),
                seance_plugin_ios_backup::UnlockError::NotEncrypted => (
                    "not_encrypted",
                    ApiError::InvalidRequest(
                        "the backup is not encrypted: its files need no unlock".to_string(),
                    ),
                ),
                seance_plugin_ios_backup::UnlockError::Other(e) => (
                    "error",
                    ApiError::InvalidRequest(format!(
                        "the backup could not be unlocked: {e}. Nothing is held."
                    )),
                ),
            };
            audit_required(
                &state,
                Some(case_id),
                &user.0,
                "unlock_outcome",
                Some("artifact"),
                Some(artifact_id),
                Some(&format!("kind={IOS_BACKUP_PASSWORD}; outcome={outcome}")),
            )
            .await?;
            info!(
                "unlock: {} for artifact {} in case {} by {}: {}",
                IOS_BACKUP_PASSWORD, artifact_id, case_id, user.0, outcome
            );
            return Err(err);
        }
    };

    let ring = backup_keyring::ios_backups();
    let ttl = ring.ttl();
    let file_count = unlocked.file_count();
    // Accepted is on the record before the keys are held; if the row cannot
    // be written the keys are dropped (and zeroed) here.
    audit_required(
        &state,
        Some(case_id),
        &user.0,
        "unlock_outcome",
        Some("artifact"),
        Some(artifact_id),
        Some(&format!(
            "kind={IOS_BACKUP_PASSWORD}; outcome=accepted; expires_in_secs={}",
            ttl.as_secs()
        )),
    )
    .await?;
    ring.insert(case_id, &backup_keyring::source_key(&dir), unlocked);
    ensure_expiry_sweep(&state);
    info!(
        "unlock: {} for artifact {} in case {} by {}: accepted, held for {}s",
        IOS_BACKUP_PASSWORD,
        artifact_id,
        case_id,
        user.0,
        ttl.as_secs()
    );

    Ok(Json(serde_json::json!({
        "status": "unlocked",
        "kind": IOS_BACKUP_PASSWORD,
        "expires_in_secs": ttl.as_secs(),
        "file_count": file_count,
        "note": UNLOCK_NOTE,
    })))
}

/// Forget the keys held for one iOS backup in one case, and every cached
/// source that could have been built from them (BUG-026): a file decompressed
/// or a container opened beneath a backup file while it was unlocked is cached
/// as plaintext, so the lock drops the caches with the keys. `true` if keys
/// were held.
pub fn forget_ios_backup(case_id: Uuid, source: &str) -> bool {
    let held = backup_keyring::ios_backups().remove(case_id, source);
    crate::content_resolver::forget_cached_views();
    held
}

pub async fn lock_again(
    Path((case_id, artifact_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
) -> Result<Json<serde_json::Value>, ApiError> {
    // A volume, a decrypted volume or anything beneath one (HUNT-254): the
    // volume's view is forgotten. Anything else that is not an iOS backup is
    // treated as a volume too, so locking something never unlocked answers
    // `was_unlocked: false` rather than an error.
    let locked = crate::unlocked_volumes::locked_volume_for(&state, case_id, artifact_id).await?;
    let backup = if locked != artifact_id || crate::unlocked_volumes::is_held(case_id, locked) {
        None
    } else {
        backup_dir_of(&state, case_id, artifact_id).await.ok()
    };
    let Some(dir) = backup else {
        let v =
            crate::unlocked_volumes::lock(&state, case_id, locked, artifact_id, &user.0).await?;
        return Ok(Json(v));
    };
    let held = forget_ios_backup(case_id, &backup_keyring::source_key(&dir));
    audit_required(
        &state,
        Some(case_id),
        &user.0,
        "unlock_forgotten",
        Some("artifact"),
        Some(artifact_id),
        Some(&format!(
            "kind={IOS_BACKUP_PASSWORD}; reason=lock; held={held}"
        )),
    )
    .await?;
    info!(
        "unlock: {} for artifact {} in case {} forgotten by {} (held={})",
        IOS_BACKUP_PASSWORD, artifact_id, case_id, user.0, held
    );
    Ok(Json(serde_json::json!({
        "status": "locked",
        "kind": IOS_BACKUP_PASSWORD,
        "was_unlocked": held,
    })))
}
