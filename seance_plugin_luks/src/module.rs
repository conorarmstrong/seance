//! Optional pipeline integration: a [`ForensicsModule`] that decrypts a LUKS
//! volume when the operator supplied a passphrase, emitting a plaintext volume
//! artifact for downstream filesystem/carver modules, and reports a LUKS
//! volume it could not open — no passphrase, or a wrong one — as a
//! `VolumeDecryption` record carrying the incompleteness pair.
//!
//! The passphrase is held **in process memory only**. It is deliberately not
//! read from artifact metadata: ingest metadata is written verbatim to
//! `artifacts.metadata_json` and served back by the artifact-detail API, so a
//! passphrase routed that way would outlive the process, sit next to the
//! evidence it unlocks, and land in every DB backup and export (B3-060). It
//! arrives one of two ways: for **one volume after ingest** (`HUNT-120`),
//! supplied through `POST /cases/{id}/artifacts/{id}/credential` and visible
//! to this module for one run on that artifact through
//! [`seance_core::credential`] — tried first, and reported back as accepted or
//! rejected so a wrong one leaves the locked record standing — or for **the
//! whole process at start** (`--luks-passphrase` / `SEANCE_LUKS_PASSPHRASE`),
//! held on the instance and zeroed when it drops.
//!
//! A successful unlock writes the plaintext child volume and a
//! `VolumeDecryption` record with status `Unlocked` naming the kind and source
//! of the credential (never its value); on a re-run that record supersedes the
//! earlier `NotUnlocked` statement (HUNT-107's same-module supersession).
//!
//! Wiring is a single registration line in the CLI module list; see the crate
//! README / task report. Without a passphrase it unlocks nothing, but still
//! reports each LUKS volume it sees as detected-and-not-unlocked (HUNT-196).

use crate::{is_luks, unlock_luks, LuksHeader};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    credential::{self, CredentialKind},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, info, warn};

/// Decrypts LUKS volumes using a passphrase supplied at process start.
///
/// # What an examiner learns
///
/// On success, a plaintext child volume the rest of the pipeline parses as if
/// the disk had never been encrypted. With no passphrase, or on failure — a
/// wrong passphrase, or a cipher this build does not implement — a
/// `VolumeDecryption` status record stating that the volume IS LUKS-encrypted
/// and was NOT decrypted.
///
/// A wrong answer would look like silence: no child volume and no record, which
/// an examiner reads as "this volume was never encrypted". That is the exact
/// confusion this module refuses to create.
#[derive(Default)]
pub struct LuksDecryptor {
    /// Supplied by the operator at launch. `None` unlocks nothing; a LUKS
    /// volume is then reported as detected-and-not-unlocked.
    passphrase: Option<String>,
}

/// Redacting `Debug`: the whole point of holding the passphrase in memory is
/// that it never reaches a log line, a panic message or a persisted record.
impl Drop for LuksDecryptor {
    fn drop(&mut self) {
        if let Some(p) = self.passphrase.as_mut() {
            zeroize::Zeroize::zeroize(p);
        }
    }
}

impl std::fmt::Debug for LuksDecryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LuksDecryptor")
            .field("passphrase_supplied", &self.passphrase.is_some())
            .finish()
    }
}

impl LuksDecryptor {
    /// A decryptor with no passphrase: no volume is unlocked, each LUKS volume
    /// is reported as detected-and-not-unlocked.
    pub fn new() -> Self {
        Self { passphrase: None }
    }

    /// A decryptor holding `passphrase` in process memory for this run.
    pub fn with_passphrase(passphrase: Option<String>) -> Self {
        Self { passphrase }
    }

    /// The record for a LUKS volume nobody handed this run a passphrase for.
    ///
    /// The ordinary case in casework, and it used to produce nothing: `process`
    /// returned before it asked whether the volume was LUKS (HUNT-196). The
    /// header is plaintext, so the record carries the version, cipher, UUID and
    /// the number of active keyslots — what an examiner needs to go and obtain
    /// a passphrase, or to say in a report exactly what was not opened. The
    /// same incompleteness pair as [`Self::unlock_failure_record`] puts it on
    /// the Needs attention queue under the `SupplyAtStartup` remedy.
    fn detected_locked_record(
        artifact: &Artifact,
        name: &str,
        data: &dyn seance_core::data_source::DataSource,
    ) -> Artifact {
        let header = crate::header::parse(data);
        let (version, cipher, uuid, active_keyslots) = match &header {
            Ok(LuksHeader::V1(h)) => (
                Some(1u16),
                Some(format!("{}-{}", h.cipher_name, h.cipher_mode)),
                Some(h.uuid.clone()),
                Some(h.keyslots.iter().filter(|k| k.active).count()),
            ),
            Ok(LuksHeader::V2(h)) => (
                Some(2u16),
                h.meta.segments.values().find_map(|s| s.encryption.clone()),
                None,
                Some(h.meta.keyslots.len()),
            ),
            Err(_) => (None, None, None, None),
        };
        let header_phrase = match (&header, &cipher, active_keyslots) {
            (Ok(_), Some(c), Some(n)) => {
                format!("Per its plaintext header it is encrypted with {c} and has {n} active keyslot(s).")
            }
            (Ok(_), _, _) => "Its plaintext header was read, but names no cipher.".to_string(),
            (Err(e), _, _) => format!(
                "Its header could not be parsed ({e}), so its cipher and keyslots are not stated."
            ),
        };
        let detail = format!(
            "LUKS volume '{name}' was detected as encrypted but no passphrase was supplied for \
             this run, so it was NOT unlocked and its contents are NOT present in this case. The \
             absence of files under this volume is a missing key, not evidence that the volume \
             was empty or unencrypted. {header_phrase}"
        );
        let metadata = json!({
            "type": "VolumeDecryption",
            "subtype": "detected_locked",
            "status": "NotUnlocked",
            "scheme": "LUKS",
            "volume_name": name,
            // The volume, by the id the encryption detector's LUKS record
            // for it also carries (HUNT-235).
            "volume_artifact_id": artifact.id.to_string(),
            "luks_version": version,
            "luks_cipher": cipher,
            "luks_uuid": uuid,
            "luks_active_keyslots": active_keyslots,
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "content_incomplete_detail": detail,
            "inventory_incomplete_detail": detail,
            "detail": detail,
            "name": format!(
                "LUKS volume '{name}': detected but NOT unlocked (no passphrase supplied)"
            ),
        });
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
            .with_subtype("detected_locked")
    }

    /// The statement that a LUKS volume was opened: the kind and source of the
    /// credential — never its value — and which child holds the plaintext. No
    /// incompleteness pair; on a re-run it supersedes the earlier locked record.
    fn unlocked_record(
        artifact: &Artifact,
        name: &str,
        credential_source: &str,
        decrypted_volume_id: String,
    ) -> Artifact {
        let how = match credential_source {
            "supplied_for_this_run" => "supplied by an examiner for this volume after ingest",
            _ => "supplied when the process started",
        };
        let detail = format!(
            "LUKS volume '{name}' was unlocked with a passphrase {how}. Its decrypted contents \
             are the child volume beneath it. The passphrase itself is not recorded."
        );
        Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "VolumeDecryption",
                "subtype": "unlocked",
                "status": "Unlocked",
                "scheme": "LUKS",
                "volume_name": name,
                "volume_artifact_id": artifact.id.to_string(),
                "decrypted_volume_artifact_id": decrypted_volume_id,
                "credential_kind": CredentialKind::LuksPassphrase.as_str(),
                "credential_source": credential_source,
                "detail": detail,
                "name": format!("LUKS volume '{name}': unlocked"),
            }),
        )
        .with_parent(artifact.id)
        .with_subtype("unlocked")
    }

    /// The status record emitted when a LUKS volume could not be unlocked.
    ///
    /// Carries the standard `content_incomplete` / `inventory_incomplete` pair
    /// that the API and export honesty paths read, so the case record cannot
    /// present this volume as fully recovered.
    fn unlock_failure_record(artifact: &Artifact, name: &str, error: &str) -> Artifact {
        let detail = format!(
            "LUKS volume '{name}' was detected as encrypted but could not be unlocked with the \
             supplied passphrase ({error}). Its contents are NOT present in this case: the \
             absence of files under this volume is a decryption failure, not evidence that the \
             volume was empty or unencrypted."
        );
        let metadata = json!({
            "type": "VolumeDecryption",
            "subtype": "unlock_failed",
            "status": "UnlockFailed",
            "scheme": "LUKS",
            "volume_name": name,
            "volume_artifact_id": artifact.id.to_string(),
            "error": error,
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "content_incomplete_detail": detail,
            "inventory_incomplete_detail": detail,
            "detail": detail,
            "name": format!("LUKS volume '{name}': unlock FAILED, contents not decrypted"),
        });
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
            .with_subtype("unlock_failed")
    }
}

impl ForensicsModule for LuksDecryptor {
    fn id(&self) -> &str {
        "plugin.crypto.luks_decryptor"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::Partition, ArtifactType::RawEvidence]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data = match artifact.data.as_ref() {
            Some(d) => d,
            None => return Ok(vec![]),
        };

        // A non-LUKS volume is silent on purpose: the passphrase may belong to
        // a different volume in the same image, and every partition in the case
        // reaches this module.
        //
        // This test comes FIRST, before the passphrase is looked at (HUNT-196).
        // Whether a volume is encrypted is a fact about the evidence; whether
        // anyone can open it is a fact about this run. Checking the passphrase
        // first made a locked volume byte-for-byte identical to an unencrypted
        // one in the case file.
        if !is_luks(data.as_ref()) {
            return Ok(vec![]);
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("volume")
            .to_string();

        // A passphrase an examiner supplied for this volume and this run is
        // tried first (HUNT-120); the process-level one otherwise.
        let run_credential =
            credential::for_artifact(artifact.id, &[CredentialKind::LuksPassphrase]);
        let credential_source = if run_credential.is_some() {
            "supplied_for_this_run"
        } else {
            "process_start"
        };

        // Encrypted, and nobody gave this run a passphrase. Report it.
        let Some(passphrase) = run_credential
            .as_ref()
            .map(|c| c.expose_secret())
            .or(self.passphrase.as_deref())
        else {
            warn!(
                "LUKS volume '{}' detected but no passphrase was supplied; reporting it as \
                 detected-and-not-unlocked",
                name
            );
            return Ok(vec![Self::detected_locked_record(
                artifact,
                &name,
                data.as_ref(),
            )]);
        };

        let result = unlock_luks(data.clone(), passphrase);
        if let Some(c) = run_credential.as_ref() {
            match &result {
                Ok(_) => c.accepted(),
                Err(e) => c.rejected(e.to_string()),
            }
        }
        match result {
            Ok(decrypted) => {
                let size = decrypted.size();
                info!("LUKS volume '{}' unlocked ({} plaintext bytes)", name, size);
                let metadata = json!({
                    "name": format!("{name} (LUKS decrypted)"),
                    "luks_decrypted": true,
                    "offset_bytes": 0,
                    "size_bytes": size,
                    "sector_size": 512,
                    "source_name": name,
                    "volume_artifact_id": artifact.id.to_string(),
                });
                let out = Artifact::new(
                    artifact.case_id,
                    artifact.artifact_type.clone(),
                    Some(decrypted),
                    metadata,
                )
                .with_parent(artifact.id);
                let record =
                    Self::unlocked_record(artifact, &name, credential_source, out.id.to_string());
                Ok(vec![out, record])
            }
            Err(e) => {
                // A wrong passphrase or unsupported cipher is not fatal to the
                // pipeline, but it must not be invisible either: returning an
                // empty vec made a failed unlock look identical to a volume
                // that was never encrypted (B3-084).
                warn!("LUKS unlock failed for '{}': {}", name, e);
                debug!("LUKS unlock error detail: {:?}", e);
                Ok(vec![Self::unlock_failure_record(
                    artifact,
                    &name,
                    &e.to_string(),
                )])
            }
        }
    }
}
