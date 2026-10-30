//! `POST /api/v1/cases/{case_id}/artifacts/{artifact_id}/credential`
//! (`HUNT-120`, `HUNT-171`, `HUNT-227`, `SEC-204`).
//!
//! An examiner supplies a secret for **one** locked artifact the case already
//! reports — a BitLocker password or recovery password, a LUKS passphrase, a
//! 7z password, the Signal for iOS key spec, an iOS backup password, a Signal
//! for Android backup passphrase, the key of a WhatsApp `crypt14` or `crypt15`
//! backup whose key file is not in the case — and the module that opens that kind of
//! artifact runs again on it, once, with the secret.
//!
//! This is the only route a secret reaches an ad-hoc run by. `run_module`'s
//! `secrets` map — a plain string merged into the artifact's metadata, never
//! zeroed, with no outcome audit — is retired and refused (`SEC-204`). A
//! **directory** target (an iOS backup folder) is resolved from its `path`
//! exactly as `run_module` resolves one (`HUNT-087`), so the parser walks the
//! folder itself.
//!
//! # The discipline
//!
//! - **Authorised like every write route.** The case-access middleware
//!   requires a `read_write` or `owner` grant for any `POST` under a case; the
//!   handler then scopes the artifact to the case in the path.
//! - **Audited, by kind, never by value.** `credential_supplied` is written
//!   before the run is queued — if the audit log cannot take the row, nothing
//!   runs — naming the user, the artifact, the kind, the module and the job.
//!   The orchestrator writes `credential_outcome` (`accepted`, `rejected`,
//!   `not_used`, `module_error`) when the module returns. Neither row can carry
//!   the secret: it is not an argument to either.
//! - **Held for one run.** The secret is moved out of the request body into a
//!   [`RunCredential`] (a zeroizing string, redacted `Debug`, no `Clone` or
//!   `Serialize`), bound to this artifact, and handed to the orchestrator in a
//!   request field serde skips. It is never merged into artifact metadata, so
//!   it cannot reach a record, the job row or the processing log. The
//!   orchestrator drops it — zeroing it — as soon as the module returns.
//! - **What it cannot promise.** The HTTP body buffer the secret arrived in is
//!   freed by the framework, not zeroed; a library the module hands the secret
//!   to may keep its own copy for the call (the 7z reader keeps a UTF-16
//!   copy); keys *derived* from it (the BitLocker FVEK, the LUKS master key)
//!   live in the decrypting data source for as long as the pipeline reads
//!   that volume, in zeroizing buffers wiped when the source is dropped
//!   (`HUNT-254`); and the keys the iOS backup
//!   and Signal Android backup parsers derive (the passcode key, the unwrapped
//!   class keys, the backup's cipher and MAC keys) are ordinary buffers, not
//!   zeroed, for the length of the parse; the WhatsApp key decoded from its
//!   hex (and a crypt15's derived AES key) is zeroed when the parse returns.
//! - **Nothing is kept for reading later.** When the run ends, so do the
//!   secret and every key derived from it. Keeping keys for reading after the
//!   run is a separate, explicit step with its own audit: `POST …/unlock`
//!   ([`crate::unlock_route`]) — for encrypted iOS backups (`BUG-026`, the
//!   unwrapped class keys) and for BitLocker and LUKS volumes decrypted in a
//!   run (`HUNT-254`, the decrypting view and its key,
//!   [`crate::unlocked_volumes`]) — which holds them in process memory for one
//!   case and a TTL (8 h default, `SEANCE_UNLOCK_TTL_SECS`) and never on disk.
//!   Until then a decrypted volume, and everything beneath it, is refused.
//! - **An iOS backup's keychain secrets are never in a record.** The run
//!   reads `keychain-backup.plist` (`HUNT-111`) and records each item's
//!   attributes with `secret_state: withheld`; the secret itself reaches no
//!   record, listing, search snippet, export or log. One item's secret is
//!   released only by the audited per-record reveal
//!   ([`crate::keychain_reveal`]), which needs the backup unlocked for
//!   reading, writes `ios_keychain_secret_revealed` first (a failed write
//!   returns nothing) and re-derives the value from the held class keys, so
//!   no plaintext is kept at rest.
//!
//! # What a run does to the case
//!
//! An accepted secret's records are persisted like any re-run's: a decrypted
//! volume appears beneath the locked one, a 7z's entries beneath the archive,
//! the Signal store's messages beneath the file, an iOS backup's files beneath
//! the folder, and the earlier "locked"
//! statement is superseded (HUNT-107). A rejected one records nothing new: the
//! job fails saying so, and the locked record still stands.

use crate::{
    audit_required, content_resolver, queue_ad_hoc_request, record_unresolved_content_job,
    ApiError, AppState, AuthenticatedUser,
};
use axum::{
    extract::{Path, State},
    Extension, Json,
};
use seance_core::credential::{CredentialKind, RunCredential};
use seance_core::db::DatabaseConnection;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

/// The longest secret accepted. A 48-digit recovery password is 55
/// characters and a key spec 99; this is a bound on input, not a policy.
const MAX_SECRET_CHARS: usize = 4096;

/// The request body. Deliberately not `Debug`: nothing may format it.
#[derive(Deserialize)]
pub struct SupplyCredentialRequest {
    /// One of `bitlocker_password`, `bitlocker_recovery_password`,
    /// `luks_passphrase`, `sevenz_password`, `signal_ios_key_spec`,
    /// `ios_backup_password`, `signal_backup_passphrase`, `whatsapp_key`,
    /// `macos_keychain_password`, `macos_system_key`.
    pub kind: String,
    pub secret: String,
}

#[derive(Debug, Serialize)]
pub struct SupplyCredentialResponse {
    pub job_id: String,
    pub status: String,
    pub kind: &'static str,
    pub module_id: &'static str,
    pub note: &'static str,
}

const RESPONSE_NOTE: &str = "The secret is held in memory for this run only and is not written \
    to the case, an export or the audit log. Watch the job: if the secret opens the artifact, \
    what it contained appears beneath it and the record saying it was locked is superseded; if \
    not, the job fails saying so and nothing in the case changes.";

pub async fn supply_artifact_credential(
    Path((case_id, artifact_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
    Extension(user): Extension<AuthenticatedUser>,
    Json(payload): Json<SupplyCredentialRequest>,
) -> Result<Json<SupplyCredentialResponse>, ApiError> {
    let SupplyCredentialRequest { kind, secret } = payload;
    // Moved into a zeroizing holder before anything else can fail, so every
    // early return below drops (and zeroes) it.
    let mut secret = zeroize::Zeroizing::new(secret);

    let Some(kind) = CredentialKind::parse(&kind) else {
        let known: Vec<&str> = CredentialKind::ALL.iter().map(|k| k.as_str()).collect();
        return Err(ApiError::InvalidRequest(format!(
            "unknown credential kind; this build takes one of: {}",
            known.join(", ")
        )));
    };
    if secret.is_empty() {
        return Err(ApiError::InvalidRequest(format!(
            "the {} is empty",
            kind.label()
        )));
    }
    if secret.chars().count() > MAX_SECRET_CHARS {
        return Err(ApiError::InvalidRequest(format!(
            "the {} is longer than {MAX_SECRET_CHARS} characters",
            kind.label()
        )));
    }

    // Scope the artifact to this case: a credential cannot be aimed at (and a
    // run attributed from) another case's artifact.
    state
        .db
        .get_artifact_details(case_id, artifact_id)
        .await
        .map_err(|_| ApiError::ResourceNotFound("Artifact not found".to_string()))?;

    let module_id = kind.module_id();
    let mut request =
        seance_core::profile::AdHocRequest::new(case_id, module_id.to_string(), artifact_id);

    // A directory artifact (an iOS backup folder) has no bytes: the module
    // walks it from its `path`. It is resolved first, exactly as `run_module`
    // resolves it (HUNT-087), so the route does not refuse the one kind of
    // target the iOS backup password is for (SEC-204).
    let unresolved = match content_resolver::resolve_artifact_directory(
        &state.db,
        &state.evidence_roots,
        case_id,
        artifact_id,
    )
    .await
    {
        Ok(Some(_)) => None,
        Err(e) => Some(e.to_string()),
        // Otherwise the module reads the artifact's bytes; a DB-loaded
        // artifact holds none, so they are resolved here exactly as
        // `run_module` resolves them.
        Ok(None) => match content_resolver::resolve_artifact_content_through_parent(
            &state.db,
            &state.evidence_roots,
            case_id,
            artifact_id,
        )
        .await
        {
            Ok(resolved) => {
                request = request.with_data_source(resolved.source);
                None
            }
            Err(e) => Some(e.to_string()),
        },
    };
    if let Some(e) = unresolved {
        warn!(
            "credential: content for {} could not be resolved, so the module is not run: {}",
            artifact_id, e
        );
        let job = record_unresolved_content_job(
            &state,
            &request,
            format!(
                "the target's content could not be resolved, so the {} was not tried: {e}",
                kind.label()
            ),
        )
        .await?;
        audit_required(
            &state,
            Some(case_id),
            &user.0,
            "credential_supplied",
            Some("artifact"),
            Some(artifact_id),
            Some(&format!(
                "kind={}; module={}; job={}; not run: content unresolved",
                kind.as_str(),
                module_id,
                job.id
            )),
        )
        .await?;
        return Ok(Json(SupplyCredentialResponse {
            job_id: job.id.to_string(),
            status: job.status.to_string(),
            kind: kind.as_str(),
            module_id,
            note: RESPONSE_NOTE,
        }));
    }

    let mut job = seance_core::profile::AdHocJob::new(&request);
    state
        .db
        .create_job(&job)
        .await
        .map_err(|e| ApiError::InternalServerError(format!("Failed to create job: {}", e)))?;

    // The attempt is on the record before anything can act on it.
    if let Err(e) = audit_required(
        &state,
        Some(case_id),
        &user.0,
        "credential_supplied",
        Some("artifact"),
        Some(artifact_id),
        Some(&format!(
            "kind={}; module={}; job={}",
            kind.as_str(),
            module_id,
            job.id
        )),
    )
    .await
    {
        job.status = seance_core::profile::JobStatus::Failed;
        job.error_message = Some(
            "Not run: the audit log could not record that a credential was supplied.".to_string(),
        );
        job.completed_at = Some(chrono::Utc::now().timestamp());
        let _ = state.db.update_job(&job).await;
        return Err(e);
    }

    let credential = Arc::new(RunCredential::new(
        artifact_id,
        kind,
        // Moves the allocation out, leaving an empty string behind: no copy.
        std::mem::take(&mut *secret),
        user.0.clone(),
    ));
    request = request.with_credential(credential);
    info!(
        "credential: {} supplied for artifact {} in case {} by {}; job {}",
        kind.as_str(),
        artifact_id,
        case_id,
        user.0,
        job.id
    );
    queue_ad_hoc_request(&state, request, &mut job).await?;

    Ok(Json(SupplyCredentialResponse {
        job_id: job.id.to_string(),
        status: job.status.to_string(),
        kind: kind.as_str(),
        module_id,
        note: RESPONSE_NOTE,
    }))
}
