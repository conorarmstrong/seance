//! Timestamps reordered on a file: `$SI` against `$FN` (§2.2, detection 2).
//!
//! The signal is entirely the MFT parser's. `seance_core::ntfs_timestamps`
//! weighs five indicators and calls only two of them strong, because the naive
//! rule — "`$SI` modified precedes `$FN` created, therefore tampering" —
//! flagged **4,054 of 25,018 files on a stock Windows XP install**, 4,026 of
//! them for that one comparison, concentrated in `system32`, `Cursors` and
//! installer directories (`HUNT-051`). A copy produces it. A move produces it.
//! An indicator that fires on a sixth of a clean disk teaches its reader to
//! ignore it, and then the one file that *was* stomped is indistinguishable
//! from the four thousand that were not.
//!
//! So this module does not re-derive anything. It reads the verdict and the
//! indicators the parser already wrote onto the file's `FileEntry` and turns
//! them into a ranked lead:
//!
//! * a **strong** indicator — one no ordinary copy, move or rename produces —
//!   becomes a [`Confidence::Notable`] finding. Not `Strong`: "no *ordinary*
//!   operation produces this" is not "a person did this", and a restore from
//!   backup, an archive extraction and a filesystem-level copy tool all remain
//!   available as explanations.
//! * weak indicators alone raise **nothing**. They are on the record for an
//!   examiner who goes looking; promoting them to the triage list is exactly
//!   the mistake `HUNT-051` recorded.

use crate::prelude::*;

/// Raises a finding for a file the MFT parser flagged as timestomped.
#[derive(Debug, Default)]
pub struct TimestompFindings;

impl TimestompFindings {
    pub fn new() -> Self {
        Self
    }

    /// The findings for one MFT parser `FileEntry`, or none.
    ///
    /// Separate from `process` so the rule is testable against a metadata
    /// document without building a module pipeline.
    pub fn findings_for(&self, artifact: &Artifact) -> Vec<Finding> {
        // The verdict, not the indicators: `timestomp_suspected` is true only
        // for a strong signal, and that distinction is the whole of HUNT-051.
        if artifact.metadata.get("timestomp_suspected") != Some(&serde_json::Value::Bool(true)) {
            return Vec::new();
        }

        let name = meta_str(artifact, "name")
            .or_else(|| meta_str(artifact, "file_name"))
            .unwrap_or_else(|| "an unnamed file".to_string());

        // The reasons behind the verdict — the strong ones only, which is what
        // the parser puts in this key. Without them the finding would assert a
        // verdict and not say what it rests on.
        let reasons: Vec<String> = artifact
            .metadata
            .get("timestomp_reasons")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|r| r.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();

        // A verdict with no reasons recorded is a finding this module will not
        // make: it could state only "the parser said so", which is not
        // something an examiner can check or an opponent can test.
        if reasons.is_empty() {
            return Vec::new();
        }

        let mut evidence = vec![EvidenceItem::new("indicator", reasons.join("; "))];
        // The timestamps themselves, so the observation is checkable without
        // opening the record. The MFT parser writes the `$SI` set under the
        // plain names, so each is labelled with the attribute it came from.
        for (label, key) in [
            ("si_created", "created"),
            ("si_modified", "modified"),
            ("si_mft_modified", "mft_modified"),
            ("si_accessed", "accessed"),
            ("fn_created", "fn_created"),
            ("fn_modified", "fn_modified"),
            ("fn_mft_modified", "fn_mft_modified"),
            ("fn_accessed", "fn_accessed"),
        ] {
            if let Some(v) = meta_str(artifact, key) {
                evidence.push(EvidenceItem::new(label, v));
            }
        }
        // Every indicator the parser found, strong or weak, named as such —
        // the weak ones do not justify the finding and they do inform a reader
        // who is now looking at this file.
        if let Some(all) = artifact
            .metadata
            .get("timestamp_indicators")
            .and_then(|v| v.as_array())
        {
            for ind in all {
                let reason = ind.get("reason").and_then(|v| v.as_str()).unwrap_or("");
                let strength = ind.get("strength").and_then(|v| v.as_str()).unwrap_or("");
                if reason.is_empty() {
                    continue;
                }
                evidence.push(EvidenceItem::new(
                    format!("indicator ({strength})"),
                    reason.to_string(),
                ));
            }
        }

        vec![Finding {
            kind: "timestomp".to_string(),
            title: format!("Timestamps reordered on {name}"),
            // The file itself: this record is the file, not a record about it.
            subject_artifact: artifact.id,
            // Notable, not Strong: see the module documentation. "No ordinary
            // operation produces this" is not "a person did this".
            confidence: Confidence::Notable,
            observation: format!(
                "The $STANDARD_INFORMATION and $FILE_NAME timestamps of {name} are inconsistent \
                 in a way ordinary file operations do not produce: {}.",
                reasons.join("; ")
            ),
            evidence,
            inference: Some(
                "Rewriting a file's $SI timestamps is how the time of an action is hidden, and \
                 it leaves $FN — which the Win32 API cannot reach — holding the original."
                    .to_string(),
            ),
            qualification:
                "This does not establish that anyone altered the timestamps. A restore from \
                 backup, an extraction from an archive and some filesystem-level copy tools \
                 reorder these fields the same way. The weaker $SI/$FN asymmetries are NOT the \
                 grounds for this finding — on a stock Windows install they occur on roughly a \
                 sixth of all files — so only an indicator no copy, move or rename produces was \
                 counted. Read the named indicator and the timestamps themselves before relying \
                 on it."
                    .to_string(),
            device_offset: device_offset_of(artifact),
            source_module: "plugin.findings.timestomp".to_string(),
        }]
    }
}

impl ForensicsModule for TimestompFindings {
    fn id(&self) -> &str {
        "plugin.findings.timestomp"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    /// Subscribes to file entries: the MFT parser writes the verdict onto the
    /// file's own `FileEntry` (HUNT-152).
    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    /// This module reads **no bytes at all** — only the metadata a parser
    /// already wrote. The enum has no variant for that (and is advisory rather
    /// than dispatched, see `CORE_DESIGN.md` §3.2), so `Stream` is declared as
    /// the least-demanding of the two real options; nothing here opens the
    /// artifact's data source.
    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        emit(artifact, self.findings_for(artifact))
    }
}
