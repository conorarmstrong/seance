//! Pipeline integration: a [`ForensicsModule`] that unlocks a BitLocker volume
//! using a credential supplied by the operator at process start. For the
//! ciphers this build decrypts — AES-XTS (Windows 10 1511 and later) and
//! AES-CBC with the Elephant diffuser (Vista through 8.1; `diffuser.rs`) — it
//! emits a plaintext volume artifact for downstream filesystem and carver
//! modules; for the ciphers it does not (plain AES-CBC without the diffuser,
//! and XTS over a non-512-byte sector), and for a failed unlock, it emits a
//! status record. This paragraph used to name AES-XTS alone, from before the
//! diffuser path existed and was verified; `documentation/Container_Formats.md`
//! is the statement of what is and is not decrypted.
//!
//! **Detection is not conditional on holding the key.** With no credential the
//! module unlocks nothing, but it still reports every BitLocker volume it
//! finds, because "an encrypted volume is present and was not opened" is the
//! finding an examiner most needs and the one a silent module destroys.
//!
//! The credential is held **in process memory only**. It is deliberately not
//! read from artifact metadata: ingest metadata is written verbatim to
//! `artifacts.metadata_json` and served back by the artifact-detail API, so a
//! password or recovery key routed that way would outlive the process and land
//! in every DB backup and export (B3-060). It arrives one of two ways:
//!
//! - **for one volume, after ingest** (`HUNT-120`): an examiner supplies it
//!   through `POST /cases/{id}/artifacts/{id}/credential`, and the orchestrator
//!   makes it visible to this module for one run on that one artifact
//!   ([`seance_core::credential`]). It is tried first, and the module reports
//!   whether it opened the volume, so a wrong one leaves the locked record
//!   standing;
//! - **for the whole process, at start** (`--bitlocker-password` /
//!   `--bitlocker-recovery-key` and their `SEANCE_*` variables), held on the
//!   module instance and tried on every BitLocker volume.
//!
//! A successful unlock writes the plaintext child volume **and** a
//! `VolumeDecryption` record with status `Unlocked`, naming the kind of
//! credential and where it came from (never its value). That record is what
//! supersedes the earlier `NotUnlocked` statement when the unlock is a re-run.

use crate::{is_bitlocker, unlock_bitlocker, Credential};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    credential::{self, CredentialKind},
    data_source::DataSource,
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{info, warn};

/// Unlocks BitLocker volumes using a credential supplied at process start.
///
/// # What an examiner learns
///
/// On success, a plaintext child volume the rest of the pipeline parses as if
/// the disk had never been encrypted. Otherwise a `VolumeDecryption` status
/// record distinguishing the three ways this can go wrong: no credential was
/// supplied at all, the credential did not unlock the volume, or the keys were
/// recovered but this build cannot decrypt that cipher. A wrong answer would
/// look like silence, which an examiner reads as "this volume was never
/// encrypted".
#[derive(Default)]
pub struct BitlockerDecryptor {
    /// Supplied by the operator at launch. `None` leaves the module inert.
    credential: Option<Credential>,
}

/// Redacting `Debug`: the whole point of holding the credential in memory is
/// that it never reaches a log line, a panic message or a persisted record.
impl std::fmt::Debug for BitlockerDecryptor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.credential {
            Some(Credential::Password(_)) => "password",
            Some(Credential::RecoveryKey(_)) => "recovery_key",
            None => "none",
        };
        f.debug_struct("BitlockerDecryptor")
            .field("credential", &kind)
            .finish()
    }
}

impl BitlockerDecryptor {
    /// An inert decryptor: no credential, so no volume is ever unlocked.
    pub fn new() -> Self {
        Self { credential: None }
    }

    /// A decryptor holding `credential` in process memory for this run.
    pub fn with_credential(credential: Option<Credential>) -> Self {
        Self { credential }
    }

    /// A decryptor built from the raw CLI arguments. A password takes priority
    /// over a recovery key when both were given.
    pub fn from_secrets(password: Option<String>, recovery_key: Option<String>) -> Self {
        let credential = password
            .map(Credential::Password)
            .or_else(|| recovery_key.map(Credential::RecoveryKey));
        Self::with_credential(credential)
    }

    /// Status record for a BitLocker volume whose contents did not reach the
    /// case. Carries the standard `content_incomplete` / `inventory_incomplete`
    /// pair the API and export honesty paths read.
    fn undecrypted_record(
        artifact: &Artifact,
        name: &str,
        subtype: &str,
        status: &str,
        summary: &str,
        detail: String,
        extra: Option<(&str, String)>,
    ) -> Artifact {
        let mut metadata = json!({
            "type": "VolumeDecryption",
            "subtype": subtype,
            "status": status,
            "scheme": "BitLocker",
            "volume_name": name,
            // The volume, by the id the encryption detector's BitLocker
            // record for it also carries (HUNT-239).
            "volume_artifact_id": artifact.id.to_string(),
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "content_incomplete_detail": detail,
            "inventory_incomplete_detail": detail,
            "detail": detail,
            "name": format!("BitLocker volume '{name}': {summary}"),
        });
        if let (Some(obj), Some((key, value))) = (metadata.as_object_mut(), extra) {
            obj.insert(key.to_string(), json!(value));
        }
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
            .with_subtype(subtype)
    }

    /// The record for a BitLocker volume nobody handed this run a key to.
    ///
    /// This is the ordinary case in casework, not an edge case, and it used to
    /// produce nothing at all: `process` returned early on the missing
    /// credential *before* it ever asked whether the volume was BitLocker, so
    /// a locked volume was byte-for-byte indistinguishable from an unencrypted
    /// one — the examiner is told there was nothing there.
    ///
    /// Nothing else in the tree covers this for BitLocker-To-Go. The generic
    /// content detector in `seance_plugin_file_analysis` fingerprints
    /// BitLocker by the `-FVE-FS-` OEM ID at offset 3 of the boot sector, and
    /// a To Go volume's boot sector is a genuine FAT32 BPB reading `MSWIN4.1`
    /// there — the whole point of the "discovery volume" is that legacy
    /// Windows sees a FAT32 disk. Only this crate, which reads the BitLocker
    /// GUID at 0x1a8/0xa0, can see such a volume at all.
    ///
    /// The FVE metadata is unencrypted, so the record carries the cipher, the
    /// volume identifier and the key protectors: enough for an examiner to go
    /// and obtain the right key, or to say in a report exactly what was not
    /// opened.
    fn detected_locked_record(artifact: &Artifact, name: &str, data: &dyn DataSource) -> Artifact {
        let detection = crate::describe_bitlocker(data);
        let cipher = detection
            .as_ref()
            .map(|d| d.encryption_method.label())
            .unwrap_or_else(|| "unknown (FVE metadata unreadable)".to_string());
        let protectors: Vec<String> = detection
            .as_ref()
            .map(|d| d.key_protectors.clone())
            .unwrap_or_default();
        let protectors_phrase = if protectors.is_empty() {
            "its key protectors could not be read".to_string()
        } else {
            format!("it can be unlocked by: {}", protectors.join(", "))
        };
        let detail = format!(
            "BitLocker volume '{name}' was detected as encrypted ({cipher}) but no credential was \
             supplied for this run, so it was NOT unlocked and its contents are NOT present in \
             this case. The absence of files under this volume is a missing key, not evidence \
             that the volume was empty or unencrypted. Per its unencrypted FVE metadata, \
             {protectors_phrase}."
        );
        let mut record = Self::undecrypted_record(
            artifact,
            name,
            "detected_locked",
            "NotUnlocked",
            "detected but NOT unlocked (no credential supplied)",
            detail,
            None,
        );
        if let Some(obj) = record.metadata.as_object_mut() {
            obj.insert("bitlocker_encryption_method".into(), json!(cipher));
            obj.insert("bitlocker_key_protectors".into(), json!(protectors));
            if let Some(d) = detection.as_ref() {
                obj.insert(
                    "bitlocker_volume_identifier".into(),
                    json!(d.volume_identifier()),
                );
                obj.insert("sector_size".into(), json!(d.bytes_per_sector));
            }
        }
        record
    }
}

impl BitlockerDecryptor {
    /// The statement that a BitLocker volume was opened: which cipher, which
    /// kind of credential, where it came from — never its value — and which
    /// child artifact holds the plaintext. It carries no incompleteness pair,
    /// and on a re-run it supersedes the earlier `NotUnlocked` record for the
    /// same volume (same module, parent and record type: HUNT-107).
    fn unlocked_record(
        artifact: &Artifact,
        name: &str,
        method: &str,
        credential_kind: &str,
        credential_source: &str,
        decrypted_volume_id: String,
    ) -> Artifact {
        let how = match credential_source {
            "supplied_for_this_run" => "supplied by an examiner for this volume after ingest",
            _ => "supplied when the process started",
        };
        let detail = format!(
            "BitLocker volume '{name}' ({method}) was unlocked with a {} {how}. Its decrypted \
             contents are the child volume beneath it. The credential itself is not recorded.",
            credential_kind.replace('_', " ")
        );
        Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            json!({
                "type": "VolumeDecryption",
                "subtype": "unlocked",
                "status": "Unlocked",
                "scheme": "BitLocker",
                "volume_name": name,
                "volume_artifact_id": artifact.id.to_string(),
                "decrypted_volume_artifact_id": decrypted_volume_id,
                "bitlocker_encryption_method": method,
                "credential_kind": credential_kind,
                "credential_source": credential_source,
                "detail": detail,
                "name": format!("BitLocker volume '{name}': unlocked"),
            }),
        )
        .with_parent(artifact.id)
        .with_subtype("unlocked")
    }
}

impl ForensicsModule for BitlockerDecryptor {
    fn id(&self) -> &str {
        "plugin.crypto.bitlocker_decryptor"
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
        let Some(data) = artifact.data.as_ref() else {
            return Ok(vec![]);
        };

        // A non-BitLocker volume is silent on purpose: every partition in the
        // case reaches this module, and a credential (if any) may belong to a
        // different volume in the same image.
        //
        // This test comes FIRST, before the credential is even looked at.
        // Detection is not conditional on holding the key: whether a volume is
        // encrypted is a fact about the evidence, whether anyone can open it
        // is a fact about this run, and collapsing the two is how an encrypted
        // volume becomes silence in the case file.
        if !is_bitlocker(data.as_ref()) {
            return Ok(vec![]);
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("volume")
            .to_string();

        // A credential an examiner supplied for this volume and this run is
        // tried first; it is the one they are waiting on (HUNT-120).
        let run_credential = credential::for_artifact(
            artifact.id,
            &[
                CredentialKind::BitlockerPassword,
                CredentialKind::BitlockerRecoveryPassword,
            ],
        );
        let per_run = run_credential.as_ref().map(|c| match c.kind() {
            CredentialKind::BitlockerRecoveryPassword => {
                Credential::RecoveryKey(c.expose_secret().to_string())
            }
            _ => Credential::Password(c.expose_secret().to_string()),
        });
        let credential_source = if per_run.is_some() {
            "supplied_for_this_run"
        } else {
            "process_start"
        };

        // Encrypted, and nobody gave this run a key. Report it, do not skip it.
        let Some(credential) = per_run.as_ref().or(self.credential.as_ref()) else {
            warn!(
                "BitLocker volume '{}' detected but no credential was supplied; reporting it as \
                 detected-and-not-unlocked",
                name
            );
            return Ok(vec![Self::detected_locked_record(
                artifact,
                &name,
                data.as_ref(),
            )]);
        };

        let result = unlock_bitlocker(data.clone(), credential);
        if let Some(c) = run_credential.as_ref() {
            match &result {
                // Keys recovered: the credential was right, whether or not
                // this build can then decrypt the cipher.
                Ok(_) => c.accepted(),
                Err(e) => c.rejected(e.to_string()),
            }
        }
        let credential_kind = credential.kind_name();
        match result {
            Ok(unlocked) => {
                let method = unlocked.encryption_method.label();
                match unlocked.decrypting_source {
                    Some(decrypted) => {
                        let size = decrypted.size();
                        info!(
                            "BitLocker volume '{}' unlocked ({}, {} plaintext bytes)",
                            name, method, size
                        );
                        let metadata = json!({
                            "name": format!("{name} (BitLocker decrypted)"),
                            "bitlocker_decrypted": true,
                            "bitlocker_encryption_method": method,
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
                        let record = Self::unlocked_record(
                            artifact,
                            &name,
                            &method,
                            credential_kind,
                            credential_source,
                            out.id.to_string(),
                        );
                        Ok(vec![out, record])
                    }
                    None => {
                        // Keys recovered, but this cipher is not decryptable in
                        // this build. Say so in the case record: an empty return
                        // reads as "not encrypted" (B3-084).
                        warn!(
                            "BitLocker volume '{}' keys recovered but cipher '{}' is not \
                             decryptable in this build",
                            name, method
                        );
                        Ok(vec![Self::undecrypted_record(
                            artifact,
                            &name,
                            "unlock_failed",
                            "CipherNotDecryptable",
                            "keys recovered, cipher not decryptable in this build",
                            format!(
                                "The credential unlocked the key hierarchy for BitLocker volume \
                                 '{name}', but its cipher ({method}) is not implemented for \
                                 sector decryption in this build. The volume's contents are NOT \
                                 present in this case: the absence of files under this volume is \
                                 a decryption gap, not evidence the volume was empty."
                            ),
                            Some(("bitlocker_encryption_method", method.to_string())),
                        )])
                    }
                }
            }
            Err(e) => {
                warn!("BitLocker unlock failed for '{}': {}", name, e);
                Ok(vec![Self::undecrypted_record(
                    artifact,
                    &name,
                    "unlock_failed",
                    "UnlockFailed",
                    "unlock FAILED, contents not decrypted",
                    format!(
                        "BitLocker volume '{name}' was detected as encrypted but could not be \
                         unlocked with the supplied credential ({e}). Its contents are NOT \
                         present in this case: the absence of files under this volume is a \
                         decryption failure, not evidence the volume was empty or unencrypted."
                    ),
                    Some(("error", e.to_string())),
                )])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::ByteSliceDataSource;
    use std::sync::Arc;
    use uuid::Uuid;

    fn volume(bytes: Vec<u8>) -> Artifact {
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(ByteSliceDataSource::new(bytes))),
            json!({ "name": "C:" }),
        )
    }

    /// B3-060: the credential lives on the module, never in artifact metadata
    /// (which is persisted to `metadata_json` and served by the API).
    #[test]
    fn credential_is_held_in_memory_and_never_debug_printed() {
        let d = BitlockerDecryptor::from_secrets(Some("hunter2".into()), None);
        let shown = format!("{d:?}");
        assert!(
            !shown.contains("hunter2"),
            "Debug leaked the secret: {shown}"
        );
        assert!(shown.contains("password"));

        let d = BitlockerDecryptor::from_secrets(None, Some("111111-222222".into()));
        let shown = format!("{d:?}");
        assert!(
            !shown.contains("111111"),
            "Debug leaked the secret: {shown}"
        );
        assert!(shown.contains("recovery_key"));
    }

    /// A password wins over a recovery key when the operator supplied both.
    #[test]
    fn password_takes_priority_over_recovery_key() {
        let d = BitlockerDecryptor::from_secrets(Some("pw".into()), Some("rk".into()));
        assert!(matches!(d.credential, Some(Credential::Password(_))));
    }

    /// A 512-byte VBR carrying the BitLocker volume GUID at the Vista/7
    /// position, and no readable FVE metadata blocks — the worst case for the
    /// detection path, which must still report the volume.
    fn bitlocker_vbr() -> Vec<u8> {
        let mut boot = vec![0u8; 1024];
        boot[0x1a8..0x1b8].copy_from_slice(&[
            0x3b, 0xd6, 0x67, 0x49, 0x29, 0x2e, 0xd8, 0x4a, 0x83, 0x99, 0xf6, 0xa3, 0x39, 0xe3,
            0xd0, 0x01,
        ]);
        boot
    }

    /// Without a credential the module unlocks nothing — but a volume it can
    /// see is BitLocker is still reported.
    #[test]
    fn without_a_credential_nothing_is_unlocked_but_the_volume_is_reported() {
        let artifact = volume(bitlocker_vbr());
        let out = BitlockerDecryptor::new().process(&artifact).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["status"], "NotUnlocked");
        assert_eq!(out[0].metadata["subtype"], "detected_locked");
        assert_eq!(out[0].metadata["content_incomplete"], true);
        // No child volume: nothing was decrypted.
        assert!(out[0].data.is_none());
    }

    /// Unreadable FVE metadata must not suppress the detection. The VBR alone
    /// establishes that this is BitLocker; failing to describe the cipher is a
    /// fact about the image and no reason to report the volume as unencrypted.
    #[test]
    fn a_volume_with_unreadable_metadata_is_still_reported() {
        let artifact = volume(bitlocker_vbr());
        let out = BitlockerDecryptor::new().process(&artifact).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(
            out[0].metadata["bitlocker_encryption_method"],
            "unknown (FVE metadata unreadable)"
        );
        assert_eq!(out[0].metadata["bitlocker_key_protectors"], json!([]));
        let detail = out[0].metadata["detail"].as_str().unwrap();
        assert!(detail.contains("no credential was supplied"), "{detail}");
        assert!(
            detail.contains("key protectors could not be read"),
            "{detail}"
        );
    }

    /// A volume that is not BitLocker stays silent, with or without a
    /// credential: the credential may belong to another volume in the image,
    /// and every partition reaches this module.
    #[test]
    fn a_non_bitlocker_volume_produces_nothing() {
        let artifact = volume(vec![0u8; 1024]);
        assert!(BitlockerDecryptor::from_secrets(Some("pw".into()), None)
            .process(&artifact)
            .unwrap()
            .is_empty());
        assert!(BitlockerDecryptor::new()
            .process(&artifact)
            .unwrap()
            .is_empty());
    }

    /// An artifact with no data attached is nothing to look at, BitLocker or
    /// otherwise.
    #[test]
    fn an_artifact_without_data_produces_nothing() {
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            None,
            json!({ "name": "C:" }),
        );
        assert!(BitlockerDecryptor::new()
            .process(&artifact)
            .unwrap()
            .is_empty());
    }

    /// B3-084: both undecryptable outcomes used to return `Ok(vec![])` plus a
    /// `warn!`, which is byte-for-byte what an unencrypted volume produces. The
    /// status record must carry the standard incompleteness pair the API and
    /// export honesty paths read, so a failed unlock can never be mistaken for
    /// "this volume was never encrypted".
    #[test]
    fn undecrypted_record_carries_the_standard_incompleteness_pair() {
        let artifact = volume(vec![0u8; 1024]);
        let rec = BitlockerDecryptor::undecrypted_record(
            &artifact,
            "C:",
            "unlock_failed",
            "UnlockFailed",
            "unlock FAILED, contents not decrypted",
            "detail text".to_string(),
            Some((
                "error",
                "no volume master key could be unlocked".to_string(),
            )),
        );

        assert_eq!(rec.metadata["type"], "VolumeDecryption");
        assert_eq!(rec.metadata["status"], "UnlockFailed");
        assert_eq!(rec.metadata["scheme"], "BitLocker");
        assert_eq!(rec.metadata["volume_name"], "C:");
        assert_eq!(rec.metadata["content_incomplete"], true);
        assert_eq!(rec.metadata["content_incomplete_reason"], "encrypted");
        assert_eq!(rec.metadata["inventory_incomplete"], true);
        assert_eq!(rec.metadata["inventory_incomplete_reason"], "encrypted");
        assert_eq!(rec.metadata["subtype"], "unlock_failed");
        assert_eq!(rec.parent_id, Some(artifact.id));
        assert_eq!(
            rec.metadata["error"],
            "no volume master key could be unlocked"
        );
    }

    /// The keys-recovered-but-cipher-unsupported outcome is a distinct status,
    /// so an examiner can tell it apart from a wrong password.
    #[test]
    fn cipher_not_decryptable_is_a_distinct_status() {
        let artifact = volume(vec![0u8; 1024]);
        let rec = BitlockerDecryptor::undecrypted_record(
            &artifact,
            "C:",
            "unlock_failed",
            "CipherNotDecryptable",
            "keys recovered, cipher not decryptable in this build",
            "detail".to_string(),
            Some(("bitlocker_encryption_method", "AES-CBC 128-bit".to_string())),
        );
        assert_eq!(rec.metadata["status"], "CipherNotDecryptable");
        assert_eq!(rec.metadata["content_incomplete"], true);
        assert_eq!(
            rec.metadata["bitlocker_encryption_method"],
            "AES-CBC 128-bit"
        );
    }
}
