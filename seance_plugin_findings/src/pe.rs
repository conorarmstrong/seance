//! Leads from a Windows executable's own analysis record (§2.2, detections 5
//! and 7).
//!
//! Four patterns, all of them read straight off the `PeSignature` record the PE
//! plugin already wrote. Nothing here parses a PE, recomputes a digest or
//! measures entropy — `seance_plugin_pe` did all three, and a second opinion
//! from this crate could only disagree with the record it points at.
//!
//! The four are deliberately spread across the whole confidence range, because
//! they are not equally interesting:
//!
//! * **The signature does not match the bytes.** [`Confidence::Strong`]. The
//!   file carries a certificate whose digest is not the digest of the file. An
//!   executable does not acquire that by being used.
//! * **A PE living in an alternate data stream.** [`Confidence::Notable`].
//!   Nothing an ordinary install does puts an executable in a `:stream`, but
//!   `:Zone.Identifier` and a handful of backup and antivirus products use
//!   streams legitimately, so the stream's name is part of the evidence.
//! * **An executable carved out of another file's slack.** [`Confidence::Notable`].
//!   Slack is where a deleted file's bytes survive, so this is ordinarily the
//!   remains of something deleted — which is worth seeing and is not, on its
//!   own, concealment.
//! * **A packed or encrypted section.** [`Confidence::Weak`], and the reason
//!   the [`Confidence`] scale needs a bottom rung at all. Legitimate software
//!   is packed constantly — installers, protected commercial binaries, anything
//!   built with an obfuscator — so this fires on clean machines and earns its
//!   place only because it is cheap to check and clusters with the others.
//!
//! # Why the mismatch is graded Strong and still qualified
//!
//! `signature_integrity` is Séance's own comparison: the PE plugin recomputes
//! the Authenticode hash and compares it to the digest inside the PKCS#7 blob.
//! Its own documentation records what is at stake — a wrong answer here is not
//! a missing finding but a fabricated allegation of tampering. So the finding
//! names the mechanism, and its qualification names the two ordinary ways a
//! genuine signature stops matching: bytes appended after the certificate table
//! (some self-extracting installers do this to themselves) and a partial read,
//! which the PE plugin already withdraws the verdict for.

use crate::prelude::*;

/// The record type the PE plugin writes.
const PE_RECORD_TYPE: &str = "PeSignature";

/// Raises leads from a `PeSignature` record.
#[derive(Debug, Default)]
pub struct PeFindings;

impl PeFindings {
    pub fn new() -> Self {
        Self
    }

    /// The findings for one PE analysis record, or none.
    pub fn findings_for(&self, artifact: &Artifact) -> Vec<Finding> {
        if meta_str(artifact, "type").as_deref() != Some(PE_RECORD_TYPE) {
            return Vec::new();
        }
        let name = meta_str(artifact, "source_name")
            .or_else(|| meta_str(artifact, "name"))
            .unwrap_or_else(|| "an unnamed executable".to_string());
        let subject = subject_of(artifact);
        let offset = device_offset_of(artifact);

        let mut out = Vec::new();
        if let Some(f) = self.signature_mismatch(artifact, &name, subject, offset) {
            out.push(f);
        }
        if let Some(f) = self.in_alternate_data_stream(artifact, &name, subject, offset) {
            out.push(f);
        }
        if let Some(f) = self.carved_from_slack(artifact, &name, subject, offset) {
            out.push(f);
        }
        if let Some(f) = self.packed_section(artifact, &name, subject, offset) {
            out.push(f);
        }
        out
    }

    /// The file does not match the signature it carries.
    fn signature_mismatch(
        &self,
        artifact: &Artifact,
        name: &str,
        subject: uuid::Uuid,
        offset: Option<u64>,
    ) -> Option<Finding> {
        let integrity = meta_str(artifact, "signature_integrity")?;
        // The PE plugin writes every inconclusive outcome as "unverified
        // (why)". Only the one positive statement of mismatch counts, and it is
        // matched on the prefix the plugin writes rather than by searching for
        // a word that also appears in its explanations.
        if !integrity.starts_with("MISMATCH") {
            return None;
        }
        // A file read short cannot produce a trustworthy digest. The PE plugin
        // already withdraws the `signed` verdict in that case; this refuses to
        // raise the far stronger claim from it.
        if artifact
            .metadata
            .get("analysis_incomplete")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return None;
        }

        let mut evidence = vec![EvidenceItem::new("signature_integrity", integrity)];
        for key in [
            "publisher",
            "cert_issuer",
            "digest_algorithm",
            "cert_not_before",
            "cert_not_after",
            "imphash",
        ] {
            if let Some(v) = meta_str(artifact, key) {
                evidence.push(EvidenceItem::new(key, v));
            }
        }

        Some(Finding {
            kind: "pe_signature_mismatch".to_string(),
            title: format!("Signature does not match the bytes of {name}"),
            subject_artifact: subject,
            confidence: Confidence::Strong,
            observation: format!(
                "{name} carries an Authenticode signature, and the Authenticode digest \
                 recomputed from the file's bytes does not equal the digest inside that \
                 signature."
            ),
            evidence,
            inference: Some(
                "A signed executable whose bytes no longer hash to the signed digest was \
                 modified after it was signed."
                    .to_string(),
            ),
            qualification:
                "This does not establish who modified the file, or that the modification was \
                 malicious. Two ordinary causes produce the same result: bytes appended after \
                 the certificate table, which some self-extracting installers do to themselves, \
                 and a truncated or partially acquired image — though a partial read withdraws \
                 the verdict rather than reaching this finding. The comparison is Séance's own \
                 recomputation of the Authenticode hash, not an operating-system trust \
                 decision: it says the bytes differ from what was signed, and nothing about \
                 whether the signer was ever trusted."
                    .to_string(),
            device_offset: offset,
            source_module: PE_MODULE_ID.to_string(),
        })
    }

    /// An executable living in an alternate data stream.
    fn in_alternate_data_stream(
        &self,
        artifact: &Artifact,
        name: &str,
        subject: uuid::Uuid,
        offset: Option<u64>,
    ) -> Option<Finding> {
        if artifact
            .metadata
            .get("in_alternate_data_stream")
            .and_then(|v| v.as_bool())
            != Some(true)
        {
            return None;
        }
        let stream = meta_str(artifact, "stream_name");
        let host = meta_str(artifact, "parent_file");

        let mut evidence = Vec::new();
        if let Some(s) = &stream {
            evidence.push(EvidenceItem::new("stream_name", s.clone()));
        }
        if let Some(h) = &host {
            evidence.push(EvidenceItem::new("parent_file", h.clone()));
        }
        for key in ["signature_integrity", "publisher", "imphash", "subsystem"] {
            if let Some(v) = meta_str(artifact, key) {
                evidence.push(EvidenceItem::new(key, v));
            }
        }
        if let Some(true) = artifact
            .metadata
            .get("source_deleted")
            .and_then(|v| v.as_bool())
        {
            evidence.push(EvidenceItem::new("source_deleted", "true"));
        }

        let where_ = match (&stream, &host) {
            (Some(s), Some(h)) => format!("the alternate data stream `{h}:{s}`"),
            (Some(s), None) => format!("an alternate data stream named `{s}`"),
            _ => "an alternate data stream".to_string(),
        };

        Some(Finding {
            kind: "pe_in_alternate_data_stream".to_string(),
            title: format!("Executable in an alternate data stream: {name}"),
            subject_artifact: subject,
            confidence: Confidence::Notable,
            observation: format!(
                "The content of {where_} parses as a Windows PE executable. A directory \
                 listing shows the host file's own size and gives no indication the stream is \
                 there."
            ),
            evidence,
            inference: Some(
                "An alternate data stream is a place to keep an executable where an ordinary \
                 listing does not show it."
                    .to_string(),
            ),
            qualification:
                "This does not establish that the stream was created to hide anything, or that \
                 the executable in it ever ran. Alternate data streams have legitimate users: \
                 `Zone.Identifier` records a download's origin, and some backup, antivirus and \
                 build products keep real payloads in named streams. Read the stream's name and \
                 the host file it hangs off before relying on it. An executable in a stream is \
                 also not evidence of execution — nothing here examined prefetch, Amcache or \
                 any other execution artifact."
                    .to_string(),
            device_offset: offset,
            source_module: PE_MODULE_ID.to_string(),
        })
    }

    /// An executable recovered from another file's slack space.
    fn carved_from_slack(
        &self,
        artifact: &Artifact,
        name: &str,
        subject: uuid::Uuid,
        offset: Option<u64>,
    ) -> Option<Finding> {
        if meta_str(artifact, "carving_source").as_deref() != Some("slack") {
            return None;
        }
        let host = meta_str(artifact, "parent_file");
        let mut evidence = vec![EvidenceItem::new("carving_source", "slack")];
        if let Some(h) = &host {
            evidence.push(EvidenceItem::new("parent_file", h.clone()));
        }
        for key in ["signature_integrity", "publisher", "imphash", "machine"] {
            if let Some(v) = meta_str(artifact, key) {
                evidence.push(EvidenceItem::new(key, v));
            }
        }
        if let Some(o) = offset {
            evidence.push(EvidenceItem::new("device_offset", o.to_string()));
        }

        Some(Finding {
            kind: "carved_executable_in_slack".to_string(),
            title: format!("Executable carved from slack space: {name}"),
            subject_artifact: subject,
            confidence: Confidence::Notable,
            observation: format!(
                "A Windows PE image was recovered from the slack space past the logical end of \
                 {}, where no live file accounts for it.",
                host.as_deref().unwrap_or("a file")
            ),
            evidence,
            // A file system starts a file at a cluster boundary, and the start
            // of the cluster holding this slack is the live owner's content.
            // So, under this volume's cluster size, a PE header in slack is
            // not the start of a former file: it is part of a former file's
            // content, or it was put there. That holds only for files written
            // under the current geometry — a reformat with larger clusters, or
            // an earlier file system, can leave a former file starting at an
            // old boundary inside a current cluster — so the inference says so.
            inference: Some(
                "Slack holds bytes left from whatever occupied this cluster before the live \
                 file, or bytes written there deliberately. A file starts at a cluster \
                 boundary, and the start of this cluster is the live file's own content, so \
                 under this volume's cluster size the executable found here is not the start \
                 of a former file: it is an executable embedded in a former file's content (an \
                 archive, an installer, a document, a memory or page file), or it was placed in \
                 slack deliberately. If the volume was reformatted with a larger cluster size, \
                 or once held a different file system, a file written before that could have \
                 started here, at an old cluster boundary; nothing here excludes that."
                    .to_string(),
            ),
            qualification:
                "This does not establish that the executable ever ran, that it was ever a file \
                 of its own, or that anyone hid it — former content in slack is left by \
                 ordinary deletion and reuse. Nor is the carved image complete: the carve \
                 cannot run past the slack, so it stops at the end of the cluster, and its \
                 signature and imphash describe the bytes recovered, not a whole executable. \
                 Check the carved record's own completeness before quoting either."
                    .to_string(),
            device_offset: offset,
            source_module: PE_MODULE_ID.to_string(),
        })
    }

    /// A packed or encrypted section — the entropy half of §2.3.
    fn packed_section(
        &self,
        artifact: &Artifact,
        name: &str,
        subject: uuid::Uuid,
        offset: Option<u64>,
    ) -> Option<Finding> {
        if artifact
            .metadata
            .get("likely_packed")
            .and_then(|v| v.as_bool())
            != Some(true)
        {
            return None;
        }
        let entropy = artifact
            .metadata
            .get("max_section_entropy")
            .and_then(|v| v.as_f64())?;
        let section = meta_str(artifact, "max_entropy_section")
            .unwrap_or_else(|| "an unnamed section".to_string());

        let mut evidence = vec![
            EvidenceItem::new("max_entropy_section", section.clone()),
            EvidenceItem::new("max_section_entropy", format!("{entropy:.3} bits/byte")),
        ];
        for key in ["publisher", "signature_integrity", "imphash"] {
            if let Some(v) = meta_str(artifact, key) {
                evidence.push(EvidenceItem::new(key, v));
            }
        }
        if let Some(ver) = artifact.metadata.get("version_info") {
            // A dropper with no version resource is part of the picture; so is
            // a packed binary that carries a full one.
            evidence.push(EvidenceItem::new("version_info", ver.to_string()));
        } else {
            evidence.push(EvidenceItem::new(
                "version_info",
                "absent — the image carries no version resource",
            ));
        }

        Some(Finding {
            kind: "high_entropy_executable".to_string(),
            title: format!("Packed or encrypted section in {name}"),
            subject_artifact: subject,
            confidence: Confidence::Weak,
            observation: format!(
                "Section `{section}` of {name} has a Shannon entropy of {entropy:.3} bits per \
                 byte, above the 7.2 threshold at which a section's contents are \
                 indistinguishable from compressed or encrypted data."
            ),
            inference: Some(
                "Code is not this uniform. A section at this entropy holds compressed, packed \
                 or encrypted data rather than instructions, which is how an executable's real \
                 contents are kept out of reach of a static look at it."
                    .to_string(),
            ),
            evidence,
            qualification:
                "This is the weakest lead Séance raises and it is graded accordingly. Packing \
                 is ordinary: installers, self-extracting archives, commercially protected \
                 software and anything built with an obfuscator all look like this, and on a \
                 normal Windows machine a number of files will. It establishes only that a \
                 section's bytes are not code — nothing about what they decompress to, and \
                 nothing about whether the file ran. It is worth reading next to this file's \
                 other findings and close to worthless on its own."
                    .to_string(),
            device_offset: offset,
            source_module: PE_MODULE_ID.to_string(),
        })
    }
}

/// The module id, written once so the findings all cite the same source.
const PE_MODULE_ID: &str = "plugin.findings.pe";

impl ForensicsModule for PeFindings {
    fn id(&self) -> &str {
        PE_MODULE_ID
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::ParsedRecord]
    }

    /// Reads no bytes at all, only the metadata the PE plugin wrote. See
    /// `TimestompFindings::input_capability` for why `Stream` is declared.
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        emit(artifact, self.findings_for(artifact))
    }
}
