use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::read_full,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

use crate::entropy;

/// Detected encryption type
#[derive(Debug, Clone, PartialEq)]
pub enum EncryptionType {
    BitLocker,
    Luks,
    FileVault2,
    EncryptedZip,
    EfsEncrypted,
    HighEntropyUnknown,
}

impl EncryptionType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::BitLocker => "BitLocker",
            Self::Luks => "LUKS",
            Self::FileVault2 => "FileVault 2",
            Self::EncryptedZip => "Encrypted ZIP",
            Self::EfsEncrypted => "NTFS EFS",
            Self::HighEntropyUnknown => "Unknown (high entropy)",
        }
    }
}

/// Detects encrypted volumes, containers, and files.
///
/// Checks for:
/// - BitLocker: `-FVE-FS-` OEM ID at offset 3 in boot sector
/// - LUKS: `LUKS\xBA\xBE` magic at offset 0
/// - FileVault 2: Core Storage signature
/// - Encrypted ZIP: Local file header encryption flag
/// - EFS: the `efs_encrypted` key `plugin.ntfs.mft_parser` writes when the MFT
///   record carries a `$LOGGED_UTILITY_STREAM` attribute named `$EFS`
/// - High entropy, as a lead only: the record names the figure and does NOT
///   assert `is_encrypted`, because compressed and random data measure the
///   same (HUNT-180)
///
/// It does not detect VeraCrypt or TrueCrypt: a volume header is random by
/// design, and an entropy figure cannot tell one from a compressed file.
pub struct EncryptionDetector;

impl ForensicsModule for EncryptionDetector {
    fn id(&self) -> &str {
        "plugin.analysis.encryption_detector"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::Partition,
            ArtifactType::RawEvidence,
            ArtifactType::FileEntry,
            ArtifactType::Container,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(vec![]),
        };

        // Skip directories
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
        {
            return Ok(vec![]);
        }

        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        // Read header for signature detection
        let read_size = 512.min(data_source.size() as usize);
        if read_size < 6 {
            return Ok(vec![]);
        }

        // Loop over short reads: a windowed source returning a few bytes per call
        // would otherwise leave the tail of `header` as zeros, and a container
        // signature that sits past the first chunk (BitLocker's `-FVE-FS-` at
        // offset 3, a LUKS version at offset 6) would be missed — an encrypted
        // volume silently reported as unencrypted (B2-111).
        let mut header = vec![0u8; read_size];
        let bytes_read = read_full(data_source.as_ref(), 0, &mut header);
        header.truncate(bytes_read);

        if header.len() < 6 {
            return Ok(vec![]);
        }

        let mut results = Vec::new();

        // Check for volume-level encryption (Partition/RawEvidence)
        let is_volume = matches!(
            artifact.artifact_type,
            ArtifactType::Partition | ArtifactType::RawEvidence
        );

        if is_volume {
            // BitLocker: "-FVE-FS-" at offset 3 (OEM ID in NTFS boot sector)
            if header.len() >= 11 && &header[3..11] == b"-FVE-FS-" {
                results.push(make_detection_with_extra(
                    artifact,
                    name,
                    EncryptionType::BitLocker,
                    "BitLocker Drive Encryption detected (BDE boot sector)",
                    1.0,
                    // As for LUKS below: the BitLocker decryptor writes its
                    // own record for this volume — locked, unlock failed, or
                    // the decrypted child — and this one defers to it, tied by
                    // the volume's artifact id, which both carry (HUNT-239).
                    json!({
                        "volume_artifact_id": artifact.id.to_string(),
                        "unlock_status_reported_by": "plugin.crypto.bitlocker_decryptor",
                        "unlock_status_note": "This record says only that the volume is \
                            BitLocker. Whether it was unlocked is stated by the BitLocker \
                            decryptor: a VolumeDecryption record (not unlocked, unlock failed, \
                            or cipher not decryptable) or a decrypted child volume, carrying \
                            the same volume_artifact_id.",
                    }),
                ));
            }

            // LUKS: "LUKS\xBA\xBE" at offset 0
            if header.len() >= 6 && header[0..6] == [0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE] {
                // Read LUKS version from offset 6
                let luks_version = if header.len() >= 8 {
                    u16::from_be_bytes([header[6], header[7]])
                } else {
                    0
                };
                results.push(make_detection_with_extra(
                    artifact,
                    name,
                    EncryptionType::Luks,
                    &format!(
                        "LUKS encrypted partition detected (version {})",
                        luks_version
                    ),
                    1.0,
                    // The LUKS decryptor writes its own record for this
                    // volume — whether it was unlocked, with the
                    // incompleteness pair the Needs attention queue reads —
                    // and this one defers to it, tied by the volume's own
                    // artifact id, which both carry (HUNT-235).
                    json!({
                        "luks_version": luks_version,
                        "volume_artifact_id": artifact.id.to_string(),
                        "unlock_status_reported_by": "plugin.crypto.luks_decryptor",
                        "unlock_status_note": "This record says only that the volume is LUKS. \
                            Whether it was unlocked is stated by the LUKS decryptor: a \
                            VolumeDecryption record (not unlocked, or unlock failed) or a \
                            decrypted child volume, carrying the same volume_artifact_id.",
                    }),
                ));
            }

            // FileVault 2 / Core Storage: Check for Core Storage physical volume signature.
            // The "CS" (0x4353) header alone is too generic. Require additional validation:
            // Core Storage PV header has "CS" at offset 0, version at offset 2, and
            // block size at offset 8 which must be a reasonable power of 2.
            if header.len() >= 16
                && header[0..2] == [0x43, 0x53] // "CS"
                && header[2..4] != [0x00, 0x00]
            // version must be non-zero
            {
                let cs_block_size =
                    u32::from_be_bytes([header[8], header[9], header[10], header[11]]);
                if cs_block_size.is_power_of_two() && (512..=65536).contains(&cs_block_size) {
                    results.push(make_detection(
                        artifact,
                        name,
                        EncryptionType::FileVault2,
                        "Possible Core Storage / FileVault 2 encrypted volume",
                        0.7,
                    ));
                }
            }
        }

        // Check for encrypted containers/files
        let is_file = matches!(
            artifact.artifact_type,
            ArtifactType::FileEntry | ArtifactType::Container
        );

        if is_file {
            // Encrypted ZIP: Check local file header encryption flag
            // PK\x03\x04 at offset 0, general purpose bit flag at offset 6, bit 0 = encrypted
            if header.len() >= 8 && header[0..4] == [0x50, 0x4B, 0x03, 0x04] {
                let gp_flags = u16::from_le_bytes([header[6], header[7]]);
                if gp_flags & 0x0001 != 0 {
                    results.push(make_detection(
                        artifact,
                        name,
                        EncryptionType::EncryptedZip,
                        "ZIP archive with encrypted entries",
                        1.0,
                    ));
                }
            }

            // `plugin.ntfs.mft_parser` writes `efs_encrypted` when the record
            // carries a `$LOGGED_UTILITY_STREAM` attribute named `$EFS`.
            if artifact
                .metadata
                .get("efs_encrypted")
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                results.push(make_detection(
                    artifact,
                    name,
                    EncryptionType::EfsEncrypted,
                    "NTFS EFS-encrypted file",
                    1.0,
                ));
            }
        }

        // High entropy detection for all artifact types
        // Read more data for entropy computation (runs even if signature detected — entropy is still useful)
        let has_signature_match = !results.is_empty();
        if data_source.size() >= 64 {
            let entropy_read_size = (data_source.size() as usize).min(196_608);
            let mut entropy_buf = vec![0u8; entropy_read_size];
            let n = read_full(data_source.as_ref(), 0, &mut entropy_buf);
            entropy_buf.truncate(n);

            if n >= 64 {
                let ent = entropy::compute_entropy(&entropy_buf);

                if ent > 7.9 {
                    // Very high entropy - likely encrypted or compressed
                    // For volumes, this is more suspicious than for files
                    // (files might just be compressed media)
                    let lower_name = name.to_lowercase();
                    let is_known_compressed = lower_name.ends_with(".jpg")
                        || lower_name.ends_with(".jpeg")
                        || lower_name.ends_with(".png")
                        || lower_name.ends_with(".mp4")
                        || lower_name.ends_with(".mp3")
                        || lower_name.ends_with(".zip")
                        || lower_name.ends_with(".gz")
                        || lower_name.ends_with(".bz2")
                        || lower_name.ends_with(".xz")
                        || lower_name.ends_with(".7z")
                        || lower_name.ends_with(".rar")
                        || lower_name.ends_with(".webm")
                        || lower_name.ends_with(".flac")
                        || lower_name.ends_with(".aac")
                        || lower_name.ends_with(".avi")
                        || lower_name.ends_with(".mkv");

                    if !is_known_compressed && !has_signature_match {
                        let confidence = if is_volume { 0.8 } else { 0.5 };
                        let desc = if is_volume {
                            format!(
                                "Volume has very high entropy ({:.3}) — possibly encrypted",
                                ent
                            )
                        } else {
                            format!("File has very high entropy ({:.3}) — possibly encrypted or compressed", ent)
                        };

                        let mut lead = make_detection_with_extra(
                            artifact,
                            name,
                            EncryptionType::HighEntropyUnknown,
                            &desc,
                            confidence,
                            json!({"entropy": (ent * 1000.0).round() / 1000.0}),
                        );
                        // A lead, not a finding (HUNT-180): no signature says
                        // encrypted, and compressed or random bytes measure
                        // the same. `is_encrypted` is what
                        // `count_encrypted_files` folds onto the parent, so
                        // it is not asserted here.
                        if let Some(obj) = lead.metadata.as_object_mut() {
                            obj.remove("is_encrypted");
                        }
                        results.push(lead);
                    } else if has_signature_match {
                        // Append entropy data to existing detection artifacts
                        let entropy_rounded = (ent * 1000.0).round() / 1000.0;
                        for result in &mut results {
                            if let Some(obj) = result.metadata.as_object_mut() {
                                obj.insert("entropy".to_string(), json!(entropy_rounded));
                            }
                        }
                    }
                }
            }
        }

        if !results.is_empty() {
            let types: Vec<&str> = results
                .iter()
                .filter_map(|a| a.metadata.get("encryption_type").and_then(|v| v.as_str()))
                .collect();
            debug!("Encryption detected on {}: {:?}", name, types);
        }

        Ok(results)
    }
}

fn make_detection(
    artifact: &Artifact,
    name: &str,
    enc_type: EncryptionType,
    description: &str,
    confidence: f64,
) -> Artifact {
    make_detection_with_extra(artifact, name, enc_type, description, confidence, json!({}))
}

fn make_detection_with_extra(
    artifact: &Artifact,
    name: &str,
    enc_type: EncryptionType,
    description: &str,
    confidence: f64,
    extra: serde_json::Value,
) -> Artifact {
    let mut metadata = json!({
        "analysis_type": "encryption_detection",
        "subtype": "EncryptionDetection",
        "encryption_type": enc_type.as_str(),
        "description": description,
        "confidence": confidence,
        "source_name": name,
        "is_encrypted": true,
    });

    if let Some(obj) = extra.as_object() {
        if let Some(meta_obj) = metadata.as_object_mut() {
            for (k, v) in obj {
                meta_obj.insert(k.clone(), v.clone());
            }
        }
    }

    debug!("Encryption detection: {} on {}", enc_type.as_str(), name);

    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::DataSource;
    use std::sync::Arc;
    use uuid::Uuid;

    #[derive(Debug)]
    struct MemorySource {
        data: Vec<u8>,
    }

    impl DataSource for MemorySource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let start = offset as usize;
            if start >= self.data.len() {
                return Ok(0);
            }
            let end = (start + buf.len()).min(self.data.len());
            let len = end - start;
            buf[..len].copy_from_slice(&self.data[start..end]);
            Ok(len)
        }

        fn size(&self) -> u64 {
            self.data.len() as u64
        }
    }

    #[test]
    fn test_detect_bitlocker() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        data[3..11].copy_from_slice(b"-FVE-FS-");

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "Partition0"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["encryption_type"], "BitLocker");
        assert_eq!(results[0].metadata["confidence"], 1.0);
    }

    #[test]
    fn test_detect_luks() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        data[0..6].copy_from_slice(&[0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE]);
        data[6] = 0x00;
        data[7] = 0x02; // LUKS version 2

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "disk.img"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["encryption_type"], "LUKS");
        assert_eq!(results[0].metadata["luks_version"], 2);
    }

    /// HUNT-235. A LUKS volume reaches both this detector and the LUKS
    /// decryptor, and each writes a record for it: this one says the volume is
    /// LUKS, the decryptor's `VolumeDecryption` record says whether it was
    /// unlocked (and carries the incompleteness pair the Needs attention queue
    /// reads). Nothing tied the two together. This record now names the volume
    /// by the same `volume_artifact_id` the decryptor's records carry, names
    /// the module that states the unlock status, and does not itself claim to
    /// be the whole story.
    #[test]
    fn a_luks_detection_names_the_volume_and_defers_the_unlock_status_to_the_decryptor() {
        let mut data = vec![0u8; 512];
        data[0..6].copy_from_slice(&[0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE]);
        data[7] = 0x01;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "vol0"}),
        );
        let results = EncryptionDetector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        let md = &results[0].metadata;
        assert_eq!(md["volume_artifact_id"], artifact.id.to_string());
        assert_eq!(
            md["unlock_status_reported_by"],
            "plugin.crypto.luks_decryptor"
        );
        assert!(md["unlock_status_note"]
            .as_str()
            .is_some_and(|s| s.contains("VolumeDecryption")));
        // The decryptor's record is the one on the attention queue; a second
        // incompleteness pair here would list one volume twice.
        assert!(md.get("content_incomplete").is_none());
    }

    /// HUNT-239, the HUNT-235 shape for BitLocker. A `-FVE-FS-` volume
    /// reaches both this detector and the BitLocker decryptor, and each writes
    /// a record for it; nothing tied the two together. This record names the
    /// volume by the same `volume_artifact_id` the decryptor's records carry,
    /// names the module that states the unlock status, and carries no
    /// incompleteness pair — the decryptor's record is the one on the Needs
    /// attention queue, and a second pair here would list one volume twice.
    #[test]
    fn a_bitlocker_detection_names_the_volume_and_defers_the_unlock_status_to_the_decryptor() {
        let mut data = vec![0u8; 512];
        data[3..11].copy_from_slice(b"-FVE-FS-");
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "vol0"}),
        );
        let results = EncryptionDetector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        let md = &results[0].metadata;
        assert_eq!(md["encryption_type"], "BitLocker");
        assert_eq!(md["volume_artifact_id"], artifact.id.to_string());
        assert_eq!(
            md["unlock_status_reported_by"],
            "plugin.crypto.bitlocker_decryptor"
        );
        assert!(md["unlock_status_note"]
            .as_str()
            .is_some_and(|s| s.contains("VolumeDecryption")));
        assert!(md.get("content_incomplete").is_none());
        assert!(md.get("inventory_incomplete").is_none());
    }

    /// The same, on the real Windows 11 25H2 XTS-AES-256 system volume
    /// (`test_data/win11_bitlocker/win11-bitlocker-xts256.raw`, the partition
    /// at byte 407,896,064 per its GPT). Skips, saying so, when the corpus is
    /// not present.
    #[test]
    fn the_real_windows_11_bitlocker_volume_is_detected_and_named_by_its_volume_reference() {
        use seance_core::data_source::{FileDataSource, WindowSource};
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("test_data/win11_bitlocker/win11-bitlocker-xts256.raw");
        let Ok(disk) = FileDataSource::new(root.clone()) else {
            eprintln!("SKIPPED (no corpus): {} is not present", root.display());
            return;
        };
        let volume: Arc<dyn DataSource> = Arc::new(WindowSource::new(
            Arc::new(disk),
            407_896_064,
            66_060_288_000,
        ));
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(volume),
            json!({"name": "Partition 3"}),
        );
        let results = EncryptionDetector.process(&artifact).unwrap();
        let bitlocker: Vec<_> = results
            .iter()
            .filter(|a| a.metadata["encryption_type"] == "BitLocker")
            .collect();
        assert_eq!(bitlocker.len(), 1, "{results:?}");
        let md = &bitlocker[0].metadata;
        assert_eq!(md["volume_artifact_id"], artifact.id.to_string());
        assert_eq!(
            md["unlock_status_reported_by"],
            "plugin.crypto.bitlocker_decryptor"
        );
        assert!(md.get("content_incomplete").is_none());
    }

    #[test]
    fn test_detect_encrypted_zip() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        // PK\x03\x04 local file header
        data[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        // General purpose flag with encryption bit set
        data[6] = 0x01;
        data[7] = 0x00;

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "secret.zip"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["encryption_type"], "Encrypted ZIP");
    }

    #[test]
    fn test_no_false_positive_on_normal_file() {
        let detector = EncryptionDetector;
        // Low entropy data - should not trigger
        let data = vec![0x41u8; 512];

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "readme.txt"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    // === FileVault 2 edge cases ===

    #[test]
    fn test_filevault2_false_positive_prevention() {
        let detector = EncryptionDetector;
        // "CS" at offset 0 but with zero version (should NOT detect)
        let mut data = vec![0u8; 512];
        data[0] = 0x43; // 'C'
        data[1] = 0x53; // 'S'
        data[2] = 0x00; // zero version
        data[3] = 0x00;

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "Partition0"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "CS with zero version should not trigger FileVault 2"
        );
    }

    #[test]
    fn test_filevault2_valid_detection() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        data[0] = 0x43; // 'C'
        data[1] = 0x53; // 'S'
        data[2] = 0x00;
        data[3] = 0x01; // version = 1
                        // Block size at offset 8-11: 4096 (0x1000) in big-endian
        data[8] = 0x00;
        data[9] = 0x00;
        data[10] = 0x10;
        data[11] = 0x00;

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "Partition0"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["encryption_type"], "FileVault 2");
    }

    #[test]
    fn test_filevault2_invalid_block_size() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        data[0] = 0x43;
        data[1] = 0x53;
        data[2] = 0x00;
        data[3] = 0x01; // version = 1
                        // Block size = 777 (not power of 2)
        data[8..12].copy_from_slice(&777u32.to_be_bytes());

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "Partition0"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "Non-power-of-2 block size should not trigger"
        );
    }

    // === LUKS version 1 ===

    #[test]
    fn test_detect_luks_v1() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        data[0..6].copy_from_slice(&[0x4C, 0x55, 0x4B, 0x53, 0xBA, 0xBE]);
        data[6] = 0x00;
        data[7] = 0x01; // LUKS version 1

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "disk.img"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["encryption_type"], "LUKS");
        assert_eq!(results[0].metadata["luks_version"], 1);
    }

    // === EFS detection ===

    #[test]
    fn test_detect_efs_from_metadata() {
        let detector = EncryptionDetector;
        let data = vec![0u8; 512]; // Normal data content

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "secret.docx", "efs_encrypted": true}),
        );

        let results = detector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["encryption_type"], "NTFS EFS");
    }

    // === High entropy edge cases ===

    #[test]
    fn test_high_entropy_not_triggered_for_compressed_extension() {
        let detector = EncryptionDetector;
        // Generate pseudo-random data (high entropy)
        let mut data = vec![0u8; 512];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = ((i * 97 + 13) % 256) as u8;
        }

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "video.mp4"}),
        );

        let results = detector.process(&artifact).unwrap();
        // Should not flag known compressed formats even with high entropy
        let has_unknown_high_entropy = results
            .iter()
            .any(|a| a.metadata["encryption_type"] == "Unknown (high entropy)");
        assert!(
            !has_unknown_high_entropy,
            "Known compressed formats should not trigger high entropy warning"
        );
    }

    // === HUNT-180: entropy alone is a lead, not an encryption finding ===

    /// 64 KiB of xorshift output: entropy just under 8 bits per byte, the
    /// shape a compressed or random file has — and an encrypted one.
    fn high_entropy_bytes() -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..65_536)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Red before the fix: the entropy-only record carried `is_encrypted:
    /// true`, which `count_encrypted_files` folds onto the parent and counts
    /// as an encrypted file with no signature saying so.
    #[test]
    fn entropy_only_record_does_not_assert_encryption() {
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource {
                data: high_entropy_bytes(),
            }) as Arc<dyn DataSource>),
            json!({"name": "blob.bin"}),
        );
        let results = EncryptionDetector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1, "one high-entropy lead");
        let meta = &results[0].metadata;
        assert_eq!(meta["encryption_type"], "Unknown (high entropy)");
        assert!(
            meta.get("is_encrypted").is_none(),
            "an entropy-only record must not assert is_encrypted: {meta}"
        );
    }

    /// A signature-backed record still asserts it, and still gets the figure.
    #[test]
    fn signature_record_still_asserts_encryption() {
        let mut data = high_entropy_bytes();
        data[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        data[6] = 0x01;
        data[7] = 0x00;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "secret.bin"}),
        );
        let results = EncryptionDetector.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].metadata["encryption_type"], "Encrypted ZIP");
        assert_eq!(results[0].metadata["is_encrypted"], true);
    }

    // === Skips directories ===

    #[test]
    fn test_skips_directories() {
        let detector = EncryptionDetector;

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "some_dir", "is_directory": true}),
        );

        let results = detector.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    // === Small file handling ===

    #[test]
    fn test_skip_tiny_file() {
        let detector = EncryptionDetector;
        let data = vec![0xFFu8; 5]; // Only 5 bytes — below 6-byte minimum

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "tiny.dat"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    // === No data source ===

    #[test]
    fn test_no_data_source() {
        let detector = EncryptionDetector;

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "file.bin"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    // === Encrypted ZIP with non-encrypted flag ===

    #[test]
    fn test_non_encrypted_zip_no_detection() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        data[0..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]);
        data[6] = 0x00; // No encryption bit
        data[7] = 0x00;

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "normal.zip"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert!(
            results.is_empty(),
            "Normal ZIP should not trigger encryption detection"
        );
    }

    // === BitLocker on wrong artifact type ===

    #[test]
    fn test_bitlocker_only_on_volumes() {
        let detector = EncryptionDetector;
        let mut data = vec![0u8; 512];
        data[3..11].copy_from_slice(b"-FVE-FS-");

        // BitLocker signature on a FileEntry (not Partition) — should not detect
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "file.bin"}),
        );

        let results = detector.process(&artifact).unwrap();
        let has_bitlocker = results
            .iter()
            .any(|a| a.metadata["encryption_type"] == "BitLocker");
        assert!(
            !has_bitlocker,
            "BitLocker should only be detected on volume artifact types"
        );
    }

    // === Entropy appended to signature match ===

    #[test]
    fn test_entropy_appended_to_bitlocker() {
        let detector = EncryptionDetector;
        // BitLocker signature + high entropy data
        let mut data = vec![0u8; 512];
        data[3..11].copy_from_slice(b"-FVE-FS-");
        // Fill rest with pseudo-random for high entropy
        for (i, byte) in data.iter_mut().enumerate().skip(11) {
            *byte = ((i * 97 + 13) % 256) as u8;
        }

        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::Partition,
            Some(Arc::new(MemorySource { data }) as Arc<dyn DataSource>),
            json!({"name": "Partition0"}),
        );

        let results = detector.process(&artifact).unwrap();
        assert_eq!(
            results.len(),
            1,
            "Should have BitLocker detection only (not HighEntropyUnknown duplicate)"
        );
        assert_eq!(results[0].metadata["encryption_type"], "BitLocker");
        // Entropy should be appended if it's high enough
        // (depends on exact entropy of the synthetic data)
    }
}
