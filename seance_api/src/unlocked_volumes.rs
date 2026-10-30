//! Unlock-to-read for BitLocker and LUKS volumes (`HUNT-254`; owner decision
//! of 2026-09-26 on key retention).
//!
//! A volume the BitLocker or LUKS decryptor opened during a run is recorded
//! beneath the locked volume as a plaintext view (`bitlocker_decrypted` /
//! `luks_decrypted`), but the key that made it is gone when the run ends, and
//! the content resolver refuses to serve the ciphertext under it (`HUNT-253`).
//! This module is where the decrypting view is held, in process memory, once
//! an examiner has explicitly unlocked the volume for reading
//! (`POST …/artifacts/{id}/unlock` with a volume kind, [`crate::unlock_route`]).
//!
//! It uses the same [`Keyring`] as the iOS backup unlock, and so the same
//! discipline: keyed by `(case_id, source)` — here the locked volume's
//! artifact id — so it opens this volume in this case only; every entry
//! expires after the keyring's TTL (default 8 hours, `SEANCE_UNLOCK_TTL_SECS`);
//! nothing here is `Serialize` or `Clone`, `Debug` prints no key; nothing is
//! written to the database, an export, a backup of the case or a log. A
//! restart forgets everything.
//!
//! The value held is the decrypting data source itself. Its key buffers — the
//! BitLocker FVEK (or the diffuser's AES and tweak keys) and the LUKS master
//! key — are zeroizing and wiped when the last handle drops, which is when the
//! entry is forgotten and no read under way still holds it.

use crate::backup_keyring::{configured_ttl, Keyring};
use crate::{audit_required, content_resolver, ApiError, AppState};
use seance_core::data_source::DataSource;
use std::sync::{Arc, OnceLock};
use tracing::info;
use uuid::Uuid;

/// The credential kinds that unlock a volume for reading.
pub const VOLUME_KINDS: [&str; 3] = [
    "bitlocker_password",
    "bitlocker_recovery_password",
    "luks_passphrase",
];

/// The volume kind named `kind`, as a `'static` label for the audit.
pub fn volume_kind(kind: &str) -> Option<&'static str> {
    VOLUME_KINDS.iter().copied().find(|k| *k == kind)
}

const UNLOCK_NOTE: &str = "The volume's decrypting key is held in this server's memory for this \
    case only, until it expires, the volume is locked again (DELETE on this route), the case is \
    deleted or the server restarts. The secret itself is not kept, and neither it nor the key is \
    written to the case, an export or the audit log.";

/// A decrypting view of one volume, held for reading.
pub struct UnlockedVolumeView {
    /// The credential kind that opened it (`bitlocker_password`,
    /// `bitlocker_recovery_password`, `luks_passphrase`) — for the audit, never
    /// the value.
    pub kind: &'static str,
    /// The plaintext view of the locked volume.
    pub source: Arc<dyn DataSource>,
}

impl std::fmt::Debug for UnlockedVolumeView {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UnlockedVolumeView")
            .field("kind", &self.kind)
            .field("size", &self.source.size())
            .finish_non_exhaustive()
    }
}

/// The process-wide keyring of volumes unlocked for reading. Empty at
/// start-up: nothing survives a restart.
pub fn volumes() -> &'static Keyring<UnlockedVolumeView> {
    static RING: OnceLock<Keyring<UnlockedVolumeView>> = OnceLock::new();
    RING.get_or_init(|| Keyring::new(configured_ttl()))
}

/// The keyring key for a locked volume: its artifact id. The decrypted view
/// recorded beneath it resolves through this entry.
pub fn volume_key(locked_volume_id: Uuid) -> String {
    format!("volume:{locked_volume_id}")
}

/// The decrypting view held for the volume whose locked artifact is
/// `locked_volume_id` in `case_id`, if it is unlocked and has not expired.
pub fn lookup(case_id: Uuid, locked_volume_id: Uuid) -> Option<Arc<dyn DataSource>> {
    volumes()
        .get(case_id, &volume_key(locked_volume_id))
        .map(|v| Arc::clone(&v.source))
}

/// The locked volume an unlock or lock aimed at `artifact_id` means: the
/// volume above the nearest decrypted view in its chain (so the decrypted
/// volume, or any file beneath it, names it), else the artifact itself.
pub async fn locked_volume_for(
    state: &AppState,
    case_id: Uuid,
    artifact_id: Uuid,
) -> Result<Uuid, ApiError> {
    // Scoped to the case first: another case's artifact is not found.
    state
        .db
        .get_artifact_details(case_id, artifact_id)
        .await
        .map_err(|_| ApiError::ResourceNotFound("Artifact not found".to_string()))?;
    Ok(
        content_resolver::decrypted_volume_above(&state.db, case_id, artifact_id)
            .await?
            .map(|(locked, _)| locked)
            .unwrap_or(artifact_id),
    )
}

/// Why a volume unlock did not hold anything.
enum Failure {
    /// The target is not a volume of the kind's family: the secret was not
    /// tried.
    NotThatVolume(String),
    /// The secret was tried and refused.
    Rejected(String),
    /// The keys were recovered, but this build cannot decrypt the cipher.
    NotDecryptable(String),
    Error(String),
}

/// Try `secret` on the locked volume's content and return the decrypting view.
fn open_volume(
    kind: &'static str,
    volume: Arc<dyn DataSource>,
    secret: &str,
) -> Result<Arc<dyn DataSource>, Failure> {
    if kind == "luks_passphrase" {
        if !seance_plugin_luks::is_luks(volume.as_ref()) {
            let hint = if seance_plugin_bitlocker::is_bitlocker(volume.as_ref()) {
                "; it is a BitLocker volume: use bitlocker_password or \
                 bitlocker_recovery_password"
            } else {
                ""
            };
            return Err(Failure::NotThatVolume(format!(
                "the target is not a LUKS volume (no LUKS header): a LUKS passphrase \
                 cannot open it{hint}"
            )));
        }
        return seance_plugin_luks::unlock_luks(volume, secret).map_err(|e| match e {
            seance_plugin_luks::LuksError::BadPassphrase => Failure::Rejected(e.to_string()),
            other => Failure::Error(other.to_string()),
        });
    }
    if !seance_plugin_bitlocker::is_bitlocker(volume.as_ref()) {
        let hint = if seance_plugin_luks::is_luks(volume.as_ref()) {
            "; it is a LUKS volume: use luks_passphrase"
        } else {
            ""
        };
        return Err(Failure::NotThatVolume(format!(
            "the target is not a BitLocker volume (no BitLocker signature): a BitLocker \
             credential cannot open it{hint}"
        )));
    }
    let credential = if kind == "bitlocker_recovery_password" {
        seance_plugin_bitlocker::Credential::RecoveryKey(secret.to_string())
    } else {
        seance_plugin_bitlocker::Credential::Password(secret.to_string())
    };
    let result = seance_plugin_bitlocker::unlock_bitlocker(volume, &credential);
    // `Credential` wipes its copy of the secret when dropped.
    drop(credential);
    match result {
        Ok(unlocked) => unlocked.decrypting_source.ok_or_else(|| {
            Failure::NotDecryptable(format!(
                "the keys were recovered, but this build cannot decrypt {} volumes",
                unlocked.encryption_method.label()
            ))
        }),
        Err(e @ seance_plugin_bitlocker::BitlockerError::BadCredential)
        | Err(e @ seance_plugin_bitlocker::BitlockerError::InvalidRecoveryKey(_)) => {
            Err(Failure::Rejected(e.to_string()))
        }
        Err(e) => Err(Failure::Error(e.to_string())),
    }
}

/// `POST …/unlock` with a volume kind: check the secret against the locked
/// volume and, if it opens it, hold the decrypting view for this case.
pub async fn unlock(
    state: &AppState,
    case_id: Uuid,
    artifact_id: Uuid,
    user: &str,
    kind: &'static str,
    secret: zeroize::Zeroizing<String>,
) -> Result<serde_json::Value, ApiError> {
    let locked = locked_volume_for(state, case_id, artifact_id).await?;
    let resolved = content_resolver::resolve_artifact_content(
        &state.db,
        &state.evidence_roots,
        case_id,
        locked,
    )
    .await
    .map_err(|e| {
        ApiError::InvalidRequest(format!(
            "the locked volume's content could not be resolved, so the {kind} was not \
                     tried: {e}"
        ))
    })?;

    // The attempt is on the record before the secret is tried.
    audit_required(
        state,
        Some(case_id),
        user,
        "unlock_supplied",
        Some("artifact"),
        Some(artifact_id),
        Some(&format!("kind={kind}; volume={locked}")),
    )
    .await?;

    let source = resolved.source;
    let result = tokio::task::spawn_blocking(move || {
        let r = open_volume(kind, source, &secret);
        drop(secret);
        r
    })
    .await
    .map_err(|e| ApiError::InternalServerError(format!("unlock check did not finish: {e}")))?;

    let view = match result {
        Ok(view) => view,
        Err(f) => {
            let (outcome, err) = match f {
                Failure::NotThatVolume(m) => ("not_applicable", format!("{m}. Nothing is held.")),
                Failure::Rejected(m) => (
                    "rejected",
                    format!("the {kind} was refused: {m}. Nothing is held."),
                ),
                Failure::NotDecryptable(m) => ("not_decryptable", format!("{m}. Nothing is held.")),
                Failure::Error(m) => (
                    "error",
                    format!("the volume could not be unlocked: {m}. Nothing is held."),
                ),
            };
            audit_required(
                state,
                Some(case_id),
                user,
                "unlock_outcome",
                Some("artifact"),
                Some(artifact_id),
                Some(&format!("kind={kind}; outcome={outcome}; volume={locked}")),
            )
            .await?;
            info!(
                "unlock: {} for volume {} in case {} by {}: {}",
                kind, locked, case_id, user, outcome
            );
            return Err(ApiError::InvalidRequest(err));
        }
    };

    let ring = volumes();
    let ttl = ring.ttl();
    // Accepted is on the record before the key is held; if the row cannot be
    // written the view — and its key — are dropped (and zeroed) here.
    audit_required(
        state,
        Some(case_id),
        user,
        "unlock_outcome",
        Some("artifact"),
        Some(artifact_id),
        Some(&format!(
            "kind={kind}; outcome=accepted; volume={locked}; expires_in_secs={}",
            ttl.as_secs()
        )),
    )
    .await?;
    ring.insert(
        case_id,
        &volume_key(locked),
        UnlockedVolumeView { kind, source: view },
    );
    info!(
        "unlock: {} for volume {} in case {} by {}: accepted, held for {}s",
        kind,
        locked,
        case_id,
        user,
        ttl.as_secs()
    );
    Ok(serde_json::json!({
        "status": "unlocked",
        "kind": kind,
        "volume_artifact_id": locked.to_string(),
        "expires_in_secs": ttl.as_secs(),
        "note": UNLOCK_NOTE,
    }))
}

/// `DELETE …/unlock` for a volume: forget the view held for it in this case,
/// and every cached source that could still hold it.
pub async fn lock(
    state: &AppState,
    case_id: Uuid,
    locked: Uuid,
    artifact_id: Uuid,
    user: &str,
) -> Result<serde_json::Value, ApiError> {
    let ring = volumes();
    let key = volume_key(locked);
    let kind = ring.get(case_id, &key).map(|v| v.kind).unwrap_or("volume");
    let held = ring.remove(case_id, &key);
    content_resolver::forget_cached_views();
    audit_required(
        state,
        Some(case_id),
        user,
        "unlock_forgotten",
        Some("artifact"),
        Some(artifact_id),
        Some(&format!(
            "kind={kind}; reason=lock; held={held}; volume={locked}"
        )),
    )
    .await?;
    info!(
        "unlock: {} for volume {} in case {} forgotten by {} (held={})",
        kind, locked, case_id, user, held
    );
    Ok(serde_json::json!({
        "status": "locked",
        "kind": kind,
        "volume_artifact_id": locked.to_string(),
        "was_unlocked": held,
    }))
}

/// Is `locked` in `case_id` a volume that is — or is beneath — something a
/// volume lock applies to? True when a view is held for it.
pub fn is_held(case_id: Uuid, locked: Uuid) -> bool {
    volumes().get(case_id, &volume_key(locked)).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use std::time::{Duration, Instant};

    fn view(bytes: &[u8]) -> UnlockedVolumeView {
        UnlockedVolumeView {
            kind: "luks_passphrase",
            source: Arc::new(ByteSliceDataSource::new(bytes.to_vec())),
        }
    }

    #[test]
    fn a_held_volume_is_returned_only_for_its_case_and_volume_and_expires() {
        let ring = Keyring::new(Duration::from_secs(60));
        let (case, other_case, vol, other_vol) = (
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
        );
        let t0 = Instant::now();
        ring.insert_at(case, &volume_key(vol), view(b"plain"), t0);
        assert!(ring.get_at(case, &volume_key(vol), t0).is_some());
        assert!(ring.get_at(other_case, &volume_key(vol), t0).is_none());
        assert!(ring.get_at(case, &volume_key(other_vol), t0).is_none());
        assert!(ring
            .get_at(case, &volume_key(vol), t0 + Duration::from_secs(60))
            .is_none());
    }

    /// The LUKS path of the volume unlock, on a volume made by the real
    /// `cryptsetup luksFormat` (skipped where cryptsetup is not installed).
    /// It pins acceptance, refusal and the kind check only; that the LUKS
    /// decryption of a cryptsetup volume is byte-correct is graded in
    /// `seance_plugin_luks/tests/cryptsetup_credential.rs`.
    #[test]
    fn a_cryptsetup_luks_volume_opens_with_its_passphrase_only() {
        use std::io::Write;
        use std::process::{Command, Stdio};
        const PASS: &str = "hunt-254 luks pass";
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("luks2.img");
        std::fs::File::create(&path)
            .unwrap()
            .set_len(20 * 1024 * 1024)
            .unwrap();
        let Ok(mut child) = Command::new("cryptsetup")
            .args([
                "luksFormat",
                "--type",
                "luks2",
                "--batch-mode",
                "--disable-locks",
                "--pbkdf",
                "pbkdf2",
                "--pbkdf-force-iterations",
                "1000",
                "--key-file",
                "-",
            ])
            .arg(&path)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            eprintln!("skipping: cryptsetup is not installed");
            return;
        };
        child
            .stdin
            .take()
            .unwrap()
            .write_all(PASS.as_bytes())
            .unwrap();
        assert!(child.wait().unwrap().success(), "luksFormat failed");
        let src: Arc<dyn DataSource> =
            Arc::new(seance_core::data_source::FileDataSource::new(path).unwrap());

        let view = open_volume("luks_passphrase", src.clone(), PASS)
            .unwrap_or_else(|_| panic!("the right passphrase opens the volume"));
        assert!(view.size() > 0 && view.size() < src.size());
        assert!(matches!(
            open_volume("luks_passphrase", src.clone(), "wrong"),
            Err(Failure::Rejected(_))
        ));
        match open_volume("bitlocker_password", src, PASS) {
            Err(Failure::NotThatVolume(m)) => assert!(m.contains("LUKS volume"), "{m}"),
            _ => panic!("a BitLocker kind must not be tried on a LUKS volume"),
        }
    }

    #[test]
    fn debug_names_the_kind_and_never_the_bytes() {
        let dbg = format!("{:?}", view(b"s3cr3t-plaintext"));
        assert!(dbg.contains("luks_passphrase"), "{dbg}");
        assert!(!dbg.contains("s3cr3t"), "{dbg}");
    }
}
