#![forbid(unsafe_code)]
//! Android ADB backup (`.ab`) container unpacker.
//!
//! Parses the archive produced by `adb backup`. An `.ab` file is a short,
//! newline-delimited ASCII header followed by a payload:
//!
//! ```text
//! ANDROID BACKUP\n
//! <version>\n              e.g. 1..5
//! <compressed 0|1>\n
//! <encryption none|AES-256>\n
//! <payload...>
//! ```
//!
//! For an unencrypted, compressed backup the payload is a raw zlib (RFC1950)
//! stream that inflates to a POSIX `tar` archive. Each regular file in the tar
//! is emitted as a [`ArtifactType::FileEntry`] carrying a
//! [`ByteSliceDataSource`], so extracted databases (`mmssms.db`,
//! `msgstore.db`, `contacts2.db`, browser `History`, ...) chain to their
//! existing parsers.
//!
//! Encrypted backups (`AES-256`) require the user's password and are out of
//! scope: a single warning artifact is emitted and processing stops.
//!
//! # Untrusted input
//!
//! Every code path treats the input as hostile. The inflated payload, the
//! entry count, and each entry's materialized size are bounded so a
//! decompression bomb or a malicious header can never trigger unbounded
//! allocation, and no path panics on malformed input.

use flate2::read::ZlibDecoder;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::{ByteSliceDataSource, DataSource, SourceCursor, WindowSource},
    io::{read_exact_or_fail, read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::cell::Cell;
use std::io::Read;
use std::rc::Rc;
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Magic line at the very start of every `.ab` file.
const AB_MAGIC: &[u8] = b"ANDROID BACKUP\n";

/// Length of [`AB_MAGIC`] ("ANDROID BACKUP" + `\n`).
const AB_MAGIC_LEN: usize = 15;

/// Bytes scanned for the four header lines. The real header is ~40 bytes; this
/// bounds the scan so a header without newlines can never be searched
/// unboundedly.
const HEADER_SCAN_LEN: usize = 512;

/// Cap on total inflated payload bytes (2 GiB). Bounds a decompression bomb:
/// the tar stream is `take()`-limited to this, so the sum of all entry bytes
/// can never exceed it.
const MAX_DECOMPRESSED_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Cap on the number of emitted tar entries, bounding artifact fan-out.
const MAX_ENTRIES: usize = 100_000;

/// Per-file materialization cap (512 MiB). A file larger than this is emitted
/// as a metadata-only FileEntry (no in-memory data source) rather than
/// truncated, keeping extracted evidence honest and memory bounded.
const MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;

/// A byte ceiling that remembers whether it cut the stream.
///
/// Reads at most `remaining` bytes. At the ceiling it asks the stream for one
/// more byte: if there is one — or the stream fails, so its end was never
/// seen — the ceiling fired. A payload that ends exactly at the ceiling did
/// not lose anything and does not set the flag.
struct CeilingReader<R> {
    inner: R,
    remaining: u64,
    fired: Rc<Cell<bool>>,
}

impl<R: Read> Read for CeilingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.remaining == 0 {
            if !self.fired.get() {
                let mut probe = [0u8; 1];
                let more = loop {
                    match self.inner.read(&mut probe) {
                        Ok(n) => break n > 0,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break true,
                    }
                };
                if more {
                    self.fired.set(true);
                }
            }
            return Ok(0);
        }
        let max = buf
            .len()
            .min(usize::try_from(self.remaining).unwrap_or(usize::MAX));
        let n = self.inner.read(&mut buf[..max])?;
        self.remaining -= n as u64;
        Ok(n)
    }
}

/// Unpacks Android `adb backup` (`.ab`) archives into `FileEntry` artifacts.
pub struct AndroidBackupModule;

impl AndroidBackupModule {
    /// True if the data source begins with the `ANDROID BACKUP\n` magic.
    ///
    /// Fills a fixed 15-byte buffer, tolerating short reads from data sources
    /// that return fewer bytes than requested per call.
    fn has_magic(data: &dyn DataSource) -> bool {
        let mut buf = [0u8; AB_MAGIC_LEN];
        read_exact_or_fail(data, 0, &mut buf, "Android backup magic").is_ok()
            && &buf[..] == AB_MAGIC
    }

    /// The container-level statement that this backup did not unpack in full.
    ///
    /// Everything that stops the walk early routes through here. The reason it
    /// exists: a backup that unpacks 40 of 4000 entries before a corrupt tar
    /// header lands in the case as 40 files and nothing else, and "not in the
    /// case" is read by an examiner as "not on the device" — 3960 app databases
    /// that were never looked at become 3960 app databases that supposedly never
    /// existed. Both the standard content pair and `inventory_incomplete` are
    /// written, because what is short here is the *listing* as well as the bytes.
    fn extraction_status(
        artifact: &Artifact,
        status: &str,
        reason: IncompleteReason,
        entries_extracted: usize,
        message: &str,
    ) -> Artifact {
        let metadata = json!({
            "type": "AndroidBackupWarning",
            "record_type": "android_backup_status",
            "status": status,
            "content_incomplete": true,
            "content_incomplete_reason": reason.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": reason.as_str(),
            // The sentence has to land on the keys the examiner-facing reader
            // shows: `frontend/src/lib/incompleteness.ts` keys it off
            // `<flag>_detail` and reads nothing named `message`. Without these,
            // the examiner meets `unresolved_structure` and is never told that
            // entries after the Nth were not examined. `message` stays for the
            // existing consumers.
            "content_incomplete_detail": message,
            "inventory_incomplete_detail": message,
            "entries_extracted": entries_extracted,
            "message": message,
            "name": format!("Android backup ({status})"),
        });
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
    }

    /// The record that a walk reached the archive's own end: its header's
    /// format version, whether it was compressed, and what came out — file
    /// entries and the distinct `apps/<package>` directories among them. Every
    /// other way out of the walk writes a warning instead, so the inventory is
    /// whole here. The content may not be: an entry over the per-entry cap, or
    /// one whose bytes could not be read or came up short, is listed with its
    /// own incompleteness flag. Those are counted, and a walk with any says it
    /// was "walked to its end" (`WalkedToEnd`), never that it "unpacked whole"
    /// (`Extracted`).
    fn extracted_summary(
        artifact: &Artifact,
        version: &str,
        compressed: bool,
        entries: usize,
        produced: &[Artifact],
    ) -> Artifact {
        let packages: std::collections::BTreeSet<&str> = produced
            .iter()
            .filter_map(|a| a.metadata.get("path").and_then(|v| v.as_str()))
            .filter_map(|p| p.strip_prefix("/apps/"))
            .filter_map(|rest| rest.split('/').next())
            .filter(|p| !p.is_empty())
            .collect();
        let content_incomplete = produced
            .iter()
            .filter(|a| {
                a.metadata
                    .get("content_incomplete")
                    .and_then(|v| v.as_bool())
                    == Some(true)
                    || a.metadata.get("content_omitted").is_some()
            })
            .count();
        let (status, name) = if content_incomplete == 0 {
            (
                "Extracted",
                format!("Android backup ({entries} file(s) unpacked whole)"),
            )
        } else {
            (
                "WalkedToEnd",
                format!(
                    "Android backup (walked to its end: {entries} file(s) listed, \
                     {content_incomplete} with content not read whole)"
                ),
            )
        };
        let mut metadata = json!({
            "type": "AndroidBackupSummary",
            "subtype": "android_backup_summary",
            "status": status,
            "format_version": version,
            "compressed": compressed,
            "encryption": "none",
            "entries_extracted": entries,
            "entries_content_incomplete": content_incomplete,
            "app_packages": packages.len(),
            "name": name,
        });
        if content_incomplete > 0 {
            metadata["message"] = json!(format!(
                "The walk reached the archive's own end, so every entry is listed; \
                 {content_incomplete} of the {entries} entries carry their own \
                 content_incomplete flag (over the per-entry size cap, unreadable, or \
                 shorter than the size the archive claims), and their content is not \
                 in this case whole"
            ));
        }
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
    }

    /// Builds the container-level artifact stating that the entry cap stopped
    /// the extraction, so a partial unpack is never mistaken for a whole one.
    fn entry_cap_warning(artifact: &Artifact, extracted: usize) -> Artifact {
        let message = "Android backup holds more entries than the extraction cap; later \
                       entries were not extracted";
        let metadata = json!({
            "type": "AndroidBackupWarning",
            "record_type": "android_backup_status",
            "status": "EntryCapReached",
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::CapReached.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::CapReached.as_str(),
            // The keys the examiner-facing reader shows the sentence from.
            "content_incomplete_detail": message,
            "inventory_incomplete_detail": message,
            "entries_extracted": extracted,
            "max_entries": MAX_ENTRIES,
            "message": message,
            "name": "Android backup (partially extracted)",
        });
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
    }

    /// The container-level statement that the payload ceiling stopped the walk.
    ///
    /// Names the ceiling, how many entries were extracted before it, and the
    /// entry it fell inside when it fell inside one — with that entry's
    /// declared size and the bytes extracted of it.
    fn ceiling_status(
        artifact: &Artifact,
        ceiling: u64,
        entries_extracted: usize,
        cut_entry: Option<&(String, u64, u64)>,
    ) -> Artifact {
        let place = match cut_entry {
            Some((path, declared, extracted)) => format!(
                "It fell inside {path}, which declares {declared} bytes; {extracted} of them \
                 were extracted"
            ),
            None => "It fell between entries".to_string(),
        };
        let message = format!(
            "The Android backup's payload reached this build's {ceiling}-byte decompression \
             ceiling and was not read past it. {place}. {entries_extracted} entries were \
             extracted; anything after the ceiling was never examined, and its absence from \
             this case is not evidence it was absent from the device. The ceiling is fixed \
             in this build"
        );
        let mut metadata = json!({
            "type": "AndroidBackupWarning",
            "record_type": "android_backup_status",
            "status": "CapReached",
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::CapReached.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::CapReached.as_str(),
            "content_incomplete_detail": message,
            "inventory_incomplete_detail": message,
            "entries_extracted": entries_extracted,
            "max_decompressed_bytes": ceiling,
            "message": message,
            "name": "Android backup (stopped at the decompression ceiling)",
        });
        if let Some((path, declared, extracted)) = cut_entry {
            metadata["cut_entry_path"] = json!(path);
            metadata["cut_entry_declared_size"] = json!(declared);
            metadata["cut_entry_bytes_extracted"] = json!(extracted);
        }
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
    }

    /// Builds the single warning artifact emitted for an encrypted backup.
    ///
    /// The backup's whole contents are absent from the case. Without the
    /// standard incompleteness pair the completeness census and the court
    /// report's "not recovered" section never see it (B5-018).
    fn encrypted_warning(artifact: &Artifact, encryption: &str) -> Artifact {
        let message = "Encrypted Android backup requires a password; extraction skipped. \
                       Nothing from this backup is in the case";
        let metadata = json!({
            "type": "AndroidBackupWarning",
            "record_type": "android_backup_status",
            "status": "EncryptedNotSupported",
            "encryption": encryption,
            "content_incomplete": true,
            "content_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            "inventory_incomplete": true,
            "inventory_incomplete_reason": IncompleteReason::Encrypted.as_str(),
            // The keys the examiner-facing reader shows the sentence from.
            "content_incomplete_detail": message,
            "inventory_incomplete_detail": message,
            "entries_extracted": 0,
            "message": message,
            "name": "Android backup (encrypted, not extracted)",
        });
        Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
            .with_parent(artifact.id)
    }
}

impl ForensicsModule for AndroidBackupModule {
    fn id(&self) -> &str {
        "container.android_backup"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        // Top-level ingestion of a `.ab` file lands as RawEvidence; a `.ab`
        // extracted from another container arrives as a FileEntry.
        vec![ArtifactType::RawEvidence, ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        self.process_with_ceiling(artifact, MAX_DECOMPRESSED_BYTES)
    }
}

impl AndroidBackupModule {
    /// [`ForensicsModule::process`] under a given payload ceiling.
    ///
    /// Production always passes [`MAX_DECOMPRESSED_BYTES`]. The parameter
    /// exists so both places a ceiling can fall — on a header boundary and
    /// inside an entry — are pinned by tests without a 2 GiB fixture.
    fn process_with_ceiling(
        &self,
        artifact: &Artifact,
        ceiling: u64,
    ) -> Result<Vec<Artifact>, ModuleError> {
        self.process_with_limits(artifact, ceiling, MAX_ENTRY_BYTES)
    }

    /// [`Self::process_with_ceiling`] under a given per-entry materialisation
    /// cap as well. Production always passes [`MAX_ENTRY_BYTES`]; the parameter
    /// lets a whole walk with an over-cap entry be pinned without a 512 MiB
    /// fixture.
    fn process_with_limits(
        &self,
        artifact: &Artifact,
        ceiling: u64,
        max_entry_bytes: u64,
    ) -> Result<Vec<Artifact>, ModuleError> {
        let name = artifact
            .metadata
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        let data_source = match artifact.data.as_ref() {
            Some(d) => d,
            None => return Ok(Vec::new()), // Cannot unpack without bytes.
        };

        // Cheap gate: a FileEntry must be named `.ab` to be considered, so the
        // flood of ordinary extracted files never triggers a header read.
        // RawEvidence is always sniffed (there is ~one per case).
        let name_is_ab = name.to_lowercase().ends_with(".ab");
        let is_raw = artifact.artifact_type == ArtifactType::RawEvidence;
        if !name_is_ab && !is_raw {
            return Ok(Vec::new());
        }

        // Authoritative check: content must actually begin with the magic.
        if !Self::has_magic(data_source.as_ref()) {
            return Ok(Vec::new());
        }

        info!("AndroidBackupModule processing: {}", name);

        // Read the fixed header window and locate the four line breaks.
        // A short read is tolerable here (a small `.ab` is shorter than the scan
        // window), but the scan must be bounded by what was actually read rather
        // than by the zero tail, so use the looping honest-count read.
        let mut scan = vec![0u8; HEADER_SCAN_LEN];
        let got = read_full(data_source.as_ref(), 0, &mut scan);
        scan.truncate(got);

        let mut nl = [0usize; 4];
        let mut found = 0usize;
        for (i, b) in scan.iter().enumerate() {
            if *b == b'\n' {
                nl[found] = i;
                found += 1;
                if found == 4 {
                    break;
                }
            }
        }
        if found < 4 {
            warn!(
                "Android backup {}: header truncated within scan window",
                name
            );
            // The magic already matched: this IS a backup, and it is truncated
            // inside its own header. Returning nothing would present it as a
            // file that simply is not a backup.
            return Ok(vec![Self::extraction_status(
                artifact,
                "HeaderTruncated",
                IncompleteReason::ShortRead,
                0,
                "Android backup header is truncated; no entries could be extracted",
            )]);
        }

        let version = String::from_utf8_lossy(&scan[nl[0] + 1..nl[1]]).into_owned();
        let compressed = &scan[nl[1] + 1..nl[2]] == b"1";
        let encryption = &scan[nl[2] + 1..nl[3]];
        let payload_offset = (nl[3] + 1) as u64;

        debug!(
            "Android backup {}: version={} compressed={} encryption={}",
            name,
            version,
            compressed,
            String::from_utf8_lossy(encryption)
        );

        if encryption != b"none" {
            let enc = String::from_utf8_lossy(encryption).into_owned();
            warn!(
                "Android backup {} is encrypted ({}); emitting warning only",
                name, enc
            );
            return Ok(vec![Self::encrypted_warning(artifact, &enc)]);
        }

        let total = data_source.size();
        if payload_offset >= total {
            debug!("Android backup {}: no payload after header", name);
            // A backup header with nothing behind it is a truncated backup, not
            // a device with no data.
            return Ok(vec![Self::extraction_status(
                artifact,
                "PayloadMissing",
                IncompleteReason::ShortRead,
                0,
                "Android backup header is present but the archive payload is absent; \
                 no entries could be extracted",
            )]);
        }

        // Bounded view of the payload, decompressed if the header says so.
        let window = Arc::new(WindowSource::new(
            data_source.clone(),
            payload_offset,
            total - payload_offset,
        ));
        let cursor = SourceCursor::new(window);
        let reader: Box<dyn Read> = if compressed {
            Box::new(ZlibDecoder::new(cursor))
        } else {
            Box::new(cursor)
        };
        // The ceiling has to be able to say it fired. A bare `take` ends the
        // stream at the ceiling exactly as the archive's own end would, so a
        // cut on a header boundary read as a complete backup and a cut inside
        // an entry as an archive that "ended early" (HUNT-172).
        let fired = Rc::new(Cell::new(false));
        let bounded = CeilingReader {
            inner: reader,
            remaining: ceiling,
            fired: fired.clone(),
        };

        let mut archive = tar::Archive::new(bounded);
        let entries = match archive.entries() {
            Ok(e) => e,
            Err(e) => {
                warn!("Android backup {}: cannot read tar payload: {}", name, e);
                // The magic and header already identified this as a real
                // backup. An unreadable payload is not an empty backup (B5-015).
                return Ok(vec![Self::extraction_status(
                    artifact,
                    "PayloadUnreadable",
                    IncompleteReason::UnresolvedStructure,
                    0,
                    &format!(
                        "Android backup payload could not be read as a tar archive: {e}. \
                         No entries were extracted; this is not evidence the backup was empty"
                    ),
                )]);
            }
        };

        let mut produced: Vec<Artifact> = Vec::new();
        let mut entry_cap_reached = false;
        // A mid-stream tar error ends the walk. Whatever follows it — which on a
        // real backup is most of the device — is simply absent (B5-016).
        let mut stream_error: Option<String> = None;
        // The entry the ceiling fell inside, when it fell inside one.
        let mut cut_entry: Option<(String, u64, u64)> = None;
        for entry_res in entries {
            if produced.len() >= MAX_ENTRIES {
                warn!(
                    "Android backup {}: entry cap {} reached, stopping",
                    name, MAX_ENTRIES
                );
                entry_cap_reached = true;
                break;
            }

            let mut entry = match entry_res {
                Ok(e) => e,
                Err(e) => {
                    // Corrupt/truncated payload: stop, keep what we have, and
                    // record that the rest of the archive was never examined.
                    warn!("Android backup {}: tar entry error: {}", name, e);
                    stream_error = Some(e.to_string());
                    break;
                }
            };

            if !entry.header().entry_type().is_file() {
                continue; // directories, symlinks, etc. are skipped
            }

            // `Entry::size` is the size the reader is actually bounded by: it
            // honours a PAX `size=` override, which the header field does not.
            // Reading the header field instead lets a crafted archive publish
            // one size while a different number of bytes is extracted (tar-rs
            // guards this exact divergence).
            let size = entry.size();
            let full_path = entry
                .path()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let trimmed = full_path.trim_end_matches('/');
            if trimmed.is_empty() {
                continue;
            }

            let base = trimmed.rsplit('/').next().unwrap_or(trimmed).to_string();
            let normalized = format!("/{}", trimmed);
            let parent_path = match trimmed.rfind('/') {
                Some(i) => format!("/{}", &trimmed[..i]),
                None => "/".to_string(),
            };

            // Materialize small files; skip data (metadata only) for oversized
            // ones so a lying/huge entry cannot exhaust memory.
            let mut materialized_len: Option<u64> = None;
            let mut read_error: Option<String> = None;
            let child_data: Option<Arc<dyn DataSource>> = if size <= max_entry_bytes {
                let mut buf = Vec::new();
                match (&mut entry).take(max_entry_bytes).read_to_end(&mut buf) {
                    Ok(_) => {
                        materialized_len = Some(buf.len() as u64);
                        Some(Arc::new(ByteSliceDataSource::new(buf)))
                    }
                    Err(e) => {
                        warn!("Android backup {}: failed reading {}: {}", name, base, e);
                        read_error = Some(e.to_string());
                        None
                    }
                }
            } else {
                warn!(
                    "Android backup {}: entry {} too large ({} bytes), metadata only",
                    name, base, size
                );
                None
            };

            let mut metadata = json!({
                "name": base,
                "path": normalized,
                "parent_path": parent_path,
                "size": size,
                "is_directory": false,
                "container": "android_backup",
                "container_path": name,
            });

            // An entry over the materialization cap is emitted with its claimed
            // size and NO data source. Without a flag that reads as "an empty
            // file of size N" rather than "we chose not to extract this", so the
            // cap is declared explicitly (BUG-278).
            if size > max_entry_bytes {
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] =
                    json!(IncompleteReason::CapReached.as_str());
                metadata["content_omitted"] = json!("entry_over_size_cap");
                metadata["max_entry_bytes"] = json!(max_entry_bytes);
            }

            // The entry's bytes could not be read at all. It keeps its claimed
            // size and gets no data source, which unflagged reads as "we
            // extracted this file and it was empty" (B5-017).
            if let Some(err) = read_error {
                metadata["content_incomplete"] = json!(true);
                metadata["content_incomplete_reason"] = json!(IncompleteReason::ShortRead.as_str());
                metadata["content_omitted"] = json!("entry_read_failed");
                metadata["read_error"] = json!(err);
            }

            // Reconcile the tar-claimed size against what was actually
            // materialized. A truncated backup yields fewer payload bytes than
            // the header claims; flag it so the short payload is never treated as
            // complete content (the `size` field would otherwise over-report it).
            if let Some(actual) = materialized_len {
                if actual != size && fired.get() {
                    // Not a short archive: the ceiling stopped the read.
                    warn!(
                        "Android backup {}: entry {} cut at the {}-byte payload ceiling \
                         ({} of {} bytes)",
                        name, base, ceiling, actual, size
                    );
                    metadata["materialized_size"] = json!(actual);
                    metadata["content_incomplete"] = json!(true);
                    metadata["content_incomplete_reason"] =
                        json!(IncompleteReason::CapReached.as_str());
                    metadata["content_omitted"] = json!("payload_ceiling_reached");
                    metadata["max_decompressed_bytes"] = json!(ceiling);
                    cut_entry = Some((normalized.clone(), size, actual));
                } else if actual != size {
                    warn!(
                        "Android backup {}: entry {} claims {} bytes but materialized {}; marking incomplete",
                        name, base, size, actual
                    );
                    metadata["materialized_size"] = json!(actual);
                    metadata["content_incomplete"] = json!(true);
                    // Consumers that key off the reason (the completeness census,
                    // the court report's section attribution) ignore a flag with
                    // no reason beside it.
                    metadata["content_incomplete_reason"] =
                        json!(IncompleteReason::ShortRead.as_str());
                }
            }

            let child = Artifact::new(
                artifact.case_id,
                ArtifactType::FileEntry,
                child_data,
                metadata,
            )
            .with_parent(artifact.id);
            produced.push(child);
        }

        if fired.get() {
            // Checked first: once the ceiling fires, whatever error or quiet
            // end followed is its consequence, not a fault in the archive.
            produced.push(Self::ceiling_status(
                artifact,
                ceiling,
                produced.len(),
                cut_entry.as_ref(),
            ));
        } else if entry_cap_reached {
            // The remaining entries are simply absent from the case; say so at
            // container level rather than leaving a silently short extraction.
            produced.push(Self::entry_cap_warning(artifact, produced.len()));
        } else if let Some(err) = stream_error {
            // Same disclosure for the other way the walk can stop early. Without
            // it, a backup that broke after 40 of 4000 entries is 40 files in the
            // case and no statement anywhere that 3960 were never examined.
            let extracted = produced.len();
            produced.push(Self::extraction_status(
                artifact,
                "PayloadTruncated",
                IncompleteReason::UnresolvedStructure,
                extracted,
                &format!(
                    "Android backup archive ended early: {err}. Entries after the {extracted} \
                     extracted were never examined; their absence from this case is not \
                     evidence they were absent from the device"
                ),
            ));
        } else {
            // The walk reached the archive's own end: say what was read, so a
            // backup that unpacked whole is recognisable as a backup and not
            // only as the files that came out of it (ROADMAP §1.4).
            let entries = produced.len();
            produced.push(Self::extracted_summary(
                artifact, &version, compressed, entries, &produced,
            ));
        }

        info!(
            "Android backup {}: extracted {} file entries",
            name,
            produced.len()
        );
        Ok(produced)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::io::read_capped;
    use serde_json::Value;
    use std::io::Write;
    use uuid::Uuid;

    /// Build a `.ab` container in memory. When `encryption` is not "none" the
    /// payload is irrelevant (the parser bails before reading it).
    fn build_ab(compressed: bool, encryption: &str, files: &[(&str, &[u8])]) -> Vec<u8> {
        // 1. Build an uncompressed tar of the given files.
        let mut tar_buf: Vec<u8> = Vec::new();
        {
            let mut builder = tar::Builder::new(&mut tar_buf);
            for (path, body) in files {
                let mut header = tar::Header::new_gnu();
                header.set_size(body.len() as u64);
                header.set_mode(0o644);
                header.set_entry_type(tar::EntryType::Regular);
                builder.append_data(&mut header, path, *body).unwrap();
            }
            builder.finish().unwrap();
        }

        // 2. Optionally zlib-compress (RFC1950), matching the real format.
        let payload = if compressed {
            use flate2::write::ZlibEncoder;
            use flate2::Compression;
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
            enc.write_all(&tar_buf).unwrap();
            enc.finish().unwrap()
        } else {
            tar_buf
        };

        // 3. Prepend the ASCII header lines.
        let mut out = Vec::new();
        out.extend_from_slice(b"ANDROID BACKUP\n1\n");
        out.extend_from_slice(if compressed { b"1\n" } else { b"0\n" });
        out.extend_from_slice(encryption.as_bytes());
        out.push(b'\n');
        out.extend_from_slice(&payload);
        out
    }

    fn make_artifact(atype: ArtifactType, name: &str, bytes: Vec<u8>) -> Artifact {
        let ds: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Artifact::new(Uuid::new_v4(), atype, Some(ds), json!({ "name": name }))
    }

    /// Read the whole content of an emitted FileEntry's data source (capped at
    /// the same per-entry ceiling the extractor materializes with).
    fn read_all(a: &Artifact) -> Vec<u8> {
        let ds = a.data.as_ref().expect("expected an attached data source");
        read_capped(ds.as_ref(), MAX_ENTRY_BYTES)
    }

    #[test]
    fn module_identity() {
        let m = AndroidBackupModule;
        assert_eq!(m.id(), "container.android_backup");
        assert_eq!(m.version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(
            m.subscribes_to(),
            vec![ArtifactType::RawEvidence, ArtifactType::FileEntry]
        );
        assert_eq!(m.input_capability(), InputCapability::Stream);
    }

    #[test]
    fn emits_file_entry_from_synthetic_ab() {
        let ab = build_ab(
            true,
            "none",
            &[("apps/com.test.app/db/mmssms.db", b"hello-sms")],
        );
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);

        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 1, "expected one regular file entry");

        let entry = &out[0];
        assert_eq!(entry.artifact_type, ArtifactType::FileEntry);
        assert_eq!(entry.parent_id, Some(art.id));
        assert_eq!(entry.case_id, art.case_id);
        // Basename must be exact so downstream parsers (e.g. android_sms) match.
        assert_eq!(entry.metadata["name"], Value::from("mmssms.db"));
        assert_eq!(
            entry.metadata["path"],
            Value::from("/apps/com.test.app/db/mmssms.db")
        );
        assert_eq!(entry.metadata["container"], Value::from("android_backup"));
        assert_eq!(entry.metadata["container_path"], Value::from("backup.ab"));
        assert_eq!(entry.metadata["size"], Value::from(9u64));
        // Attached bytes must round-trip exactly.
        assert_eq!(read_all(entry), b"hello-sms");
    }

    #[test]
    fn processes_ab_arriving_as_file_entry() {
        let ab = build_ab(true, "none", &[("shared/0/notes.txt", b"note")]);
        let art = make_artifact(ArtifactType::FileEntry, "backup.ab", ab);

        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["name"], Value::from("notes.txt"));
        assert_eq!(read_all(&out[0]), b"note");
    }

    #[test]
    fn detects_raw_evidence_by_magic_without_ab_extension() {
        // A renamed backup: RawEvidence, wrong extension, but valid magic.
        let ab = build_ab(true, "none", &[("apps/x/db/contacts2.db", b"c")]);
        let art = make_artifact(ArtifactType::RawEvidence, "evidence.bin", ab);

        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["name"], Value::from("contacts2.db"));
    }

    use seance_core::test_support::DribbleSource;

    #[test]
    fn short_reading_source_still_detects_magic_and_header() {
        // Both the magic check and the header-line scan must loop: a source that
        // returns 4 bytes per call still carries a complete, valid `.ab` header.
        let ab = build_ab(false, "none", &[("apps/x/db/msgstore.db", b"wa")]);
        let ds: Arc<dyn DataSource> = Arc::new(DribbleSource::new(ab, 4));
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            Some(ds),
            json!({ "name": "backup.ab" }),
        );

        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 1, "header must survive a 4-byte-per-call source");
        assert_eq!(out[0].metadata["name"], Value::from("msgstore.db"));
    }

    #[test]
    fn uncompressed_ab_is_supported() {
        let ab = build_ab(false, "none", &[("apps/x/db/msgstore.db", b"wa")]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);

        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["name"], Value::from("msgstore.db"));
        assert_eq!(read_all(&out[0]), b"wa");
    }

    #[test]
    fn multiple_files_only_regular_entries() {
        let ab = build_ab(
            true,
            "none",
            &[
                ("apps/x/db/a.db", b"aaa"),
                ("apps/x/db/b.db", b"bbbb"),
                ("apps/x/f/c.bin", b"cc"),
            ],
        );
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);

        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 3);
        let names: Vec<&str> = out
            .iter()
            .filter_map(|a| a.metadata["name"].as_str())
            .collect();
        assert!(names.contains(&"a.db"));
        assert!(names.contains(&"b.db"));
        assert!(names.contains(&"c.bin"));
    }

    #[test]
    fn encrypted_ab_emits_warning_only() {
        // Encryption != none: parser must warn and stop, not attempt payload.
        let ab = build_ab(true, "AES-256", &[("apps/x/db/a.db", b"secret")]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);

        let out = AndroidBackupModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(out[0].metadata["type"], Value::from("AndroidBackupWarning"));
        assert_eq!(out[0].metadata["encryption"], Value::from("AES-256"));
        assert_eq!(out[0].parent_id, Some(art.id));
    }

    /// B5-018: an encrypted backup contributes nothing to the case. A status
    /// string alone is invisible to every consumer that keys on the standard
    /// incompleteness pair, so the backup reads as examined-and-empty.
    #[test]
    fn encrypted_ab_carries_the_standard_incompleteness_pair() {
        let ab = build_ab(true, "AES-256", &[("apps/x/db/a.db", b"secret")]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);
        let out = AndroidBackupModule.process(&art).unwrap();
        assert_eq!(out[0].metadata["content_incomplete"], Value::from(true));
        assert_eq!(
            out[0].metadata["content_incomplete_reason"],
            Value::from("encrypted")
        );
        assert_eq!(out[0].metadata["inventory_incomplete"], Value::from(true));
    }

    /// B5-015: magic and header matched, so this IS a backup. A payload that
    /// will not open as tar must not land in the case as "nothing extracted".
    #[test]
    fn unreadable_payload_emits_a_status_not_silence() {
        // Valid header, then bytes that are neither zlib nor tar.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ANDROID BACKUP\n1\n0\nnone\n");
        bytes.extend_from_slice(&[0xDE; 4096]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", bytes);

        let out = AndroidBackupModule.process(&art).unwrap();
        assert_eq!(out.len(), 1, "a status record, not an empty result");
        let m = &out[0].metadata;
        assert_eq!(m["type"], Value::from("AndroidBackupWarning"));
        assert_eq!(m["content_incomplete"], Value::from(true));
        assert_eq!(m["inventory_incomplete"], Value::from(true));
        assert_eq!(m["entries_extracted"], Value::from(0u64));
    }

    /// B5-016: the worst shape in this crate. A mid-stream tar error stops the
    /// walk and keeps what was produced; unflagged, a backup that broke after
    /// two of many entries is two files in the case and no statement anywhere
    /// that the rest were never looked at.
    #[test]
    fn mid_stream_tar_error_emits_a_status_alongside_the_partial_entries() {
        let mut ab = build_ab(
            false,
            "none",
            &[
                ("apps/x/db/a.db", b"aaa"),
                ("apps/x/db/b.db", b"bbb"),
                ("apps/x/db/c.db", b"ccc"),
            ],
        );
        // Uncompressed layout: `.ab` header (24 bytes) then 512-byte tar blocks,
        // one header + one data block per small file. The third entry's header
        // block therefore starts at 24 + 4*512 = 2072. Fill it with 0x41 so it
        // is neither a valid header nor the all-zero end-of-archive marker: the
        // walk breaks there with entries 1-2 already extracted.
        assert!(ab.len() >= 2584);
        for b in ab[2072..2584].iter_mut() {
            *b = 0x41;
        }
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);

        let out = AndroidBackupModule.process(&art).unwrap();
        let status: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.metadata["type"] == "AndroidBackupWarning")
            .collect();
        assert_eq!(
            status.len(),
            1,
            "a truncated tar stream must leave exactly one container-level status; got {:?}",
            out.iter().map(|a| &a.metadata).collect::<Vec<_>>()
        );
        let m = &status[0].metadata;
        assert_eq!(m["status"], Value::from("PayloadTruncated"));
        assert_eq!(m["content_incomplete"], Value::from(true));
        assert_eq!(m["inventory_incomplete"], Value::from(true));
        assert_eq!(
            m["content_incomplete_reason"],
            Value::from("unresolved_structure")
        );
        // The entries that did survive are still in the case.
        let files = out.len() - status.len();
        assert!(files >= 1, "surviving entries are kept");
        assert_eq!(m["entries_extracted"], Value::from(files as u64));
    }

    /// A clean backup must NOT carry a status record: the marker only means
    /// something if the healthy path does not raise it.
    #[test]
    fn clean_backup_emits_no_status_record() {
        let ab = build_ab(true, "none", &[("apps/x/db/a.db", b"aaa")]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);
        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].artifact_type, ArtifactType::FileEntry);
    }

    #[test]
    fn garbage_ab_without_magic_returns_empty() {
        // Named .ab but content is random junk: no magic -> nothing, no panic.
        let art = make_artifact(ArtifactType::RawEvidence, "x.ab", vec![0xDE; 256]);
        let out = AndroidBackupModule.process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn truncated_payload_does_not_panic() {
        // Valid header, then a bogus/truncated zlib stream.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"ANDROID BACKUP\n1\n1\nnone\n");
        bytes.extend_from_slice(&[0x78, 0x9c, 0x01, 0x02, 0x03]); // zlib magic + junk
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", bytes);

        // Must not panic; returns Ok (possibly empty).
        let out = AndroidBackupModule.process(&art).unwrap();
        assert!(out.len() <= 1);
    }

    #[test]
    fn truncated_entry_is_flagged_incomplete() {
        // Uncompressed backup with a single 100-byte file, then the `.ab` is
        // truncated inside that file's data. The tar header still claims 100
        // bytes, so the parser must materialize the short payload and flag the
        // size mismatch rather than reporting it as complete.
        let body = vec![b'A'; 100];
        let mut ab = build_ab(false, "none", &[("apps/x/db/short.db", &body)]);

        // `.ab` header = "ANDROID BACKUP\n1\n0\nnone\n" (24 bytes); tar header is
        // 512 bytes; the file data begins at 24 + 512 = 536. Keep 60 of 100
        // body bytes.
        ab.truncate(536 + 60);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);

        let out = AndroidBackupModule.process(&art).unwrap();
        let entry = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("the (truncated) entry is still emitted");
        assert_eq!(entry.metadata["name"], Value::from("short.db"));
        // Claimed size is the header value; materialized is the short payload.
        assert_eq!(entry.metadata["size"], Value::from(100u64));
        assert_eq!(entry.metadata["content_incomplete"], Value::from(true));
        // B5-017: the flag needs its reason, or reason-keyed consumers skip it.
        assert_eq!(
            entry.metadata["content_incomplete_reason"],
            Value::from("short_read")
        );
        assert_eq!(entry.metadata["materialized_size"], Value::from(60u64));
        assert_eq!(read_all(entry).len(), 60);
    }

    #[test]
    fn complete_entry_has_no_incomplete_flag() {
        // A well-formed backup must NOT carry the incomplete flag.
        let ab = build_ab(false, "none", &[("apps/x/db/ok.db", b"exactly-ten")]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);
        let out = whole(AndroidBackupModule.process(&art).unwrap());
        assert_eq!(out.len(), 1);
        assert!(out[0].metadata.get("content_incomplete").is_none());
        assert!(out[0].metadata.get("materialized_size").is_none());
        assert_eq!(out[0].metadata["size"], Value::from(11u64));
    }

    #[test]
    fn oversized_entry_declares_that_its_content_was_omitted() {
        // BUG-278: an entry past the materialization cap is emitted with its
        // claimed size and no data source. Unflagged, that is indistinguishable
        // from a file we extracted and found empty.
        let mut header = tar::Header::new_gnu();
        header.set_path("apps/x/db/huge.db").unwrap();
        header.set_size(MAX_ENTRY_BYTES + 1);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();

        let mut ab = Vec::new();
        ab.extend_from_slice(b"ANDROID BACKUP\n1\n0\nnone\n");
        ab.extend_from_slice(&header.as_bytes()[..]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);

        let out = AndroidBackupModule.process(&art).unwrap();
        // The archive is a lone header claiming a body it does not carry, so
        // the walk also stops with a tar error and says so. That second record
        // is the truncation disclosure, not a file entry: find the entry rather
        // than assuming it is alone.
        // Exactly one file entry, as before: the count assertion this replaced
        // also guarded against a second, unflagged copy of the same entry being
        // emitted somewhere down the path, and a bare `find` would not notice
        // one. Only the extra record is new, so scope the count to the entries.
        let entries: Vec<&Artifact> = out
            .iter()
            .filter(|a| a.artifact_type == ArtifactType::FileEntry)
            .collect();
        assert_eq!(entries.len(), 1, "{out:?}");
        let entry = entries[0];
        assert!(entry.data.is_none(), "oversized entries carry no bytes");
        assert_eq!(entry.metadata["size"], Value::from(MAX_ENTRY_BYTES + 1));
        assert_eq!(entry.metadata["content_incomplete"], Value::from(true));
        assert_eq!(
            entry.metadata["content_incomplete_reason"],
            Value::from("cap_reached")
        );
        assert_eq!(
            entry.metadata["content_omitted"],
            Value::from("entry_over_size_cap")
        );

        // And the walk that ended mid-archive is disclosed too: entries after
        // this one were never examined, and that must not read as a device that
        // held nothing else.
        let status = out
            .iter()
            .find(|a| a.metadata["status"] == "PayloadTruncated")
            .expect("a tar stream that ends early must say so");
        assert_eq!(status.metadata["content_incomplete"], Value::from(true));
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            Value::from("unresolved_structure")
        );
    }

    #[test]
    fn entry_cap_warning_states_the_extraction_stopped_early() {
        // The cap that bounds artifact fan-out must leave an examiner-facing
        // marker; hitting it used to only write a log line.
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", Vec::new());
        let warning = AndroidBackupModule::entry_cap_warning(&art, MAX_ENTRIES);
        assert_eq!(warning.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(warning.parent_id, Some(art.id));
        assert_eq!(warning.metadata["status"], Value::from("EntryCapReached"));
        assert_eq!(warning.metadata["content_incomplete"], Value::from(true));
        assert_eq!(
            warning.metadata["content_incomplete_reason"],
            Value::from("cap_reached")
        );
        assert_eq!(
            warning.metadata["entries_extracted"],
            Value::from(MAX_ENTRIES)
        );
    }

    /// A header with no payload behind it is a truncated backup. Emitting
    /// nothing would present it as a device that held no data.
    #[test]
    fn header_only_no_payload_reports_the_missing_payload() {
        let art = make_artifact(
            ArtifactType::RawEvidence,
            "backup.ab",
            b"ANDROID BACKUP\n1\n1\nnone\n".to_vec(),
        );
        let out = AndroidBackupModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["status"], Value::from("PayloadMissing"));
        assert_eq!(out[0].metadata["content_incomplete"], Value::from(true));
        assert_eq!(out[0].metadata["inventory_incomplete"], Value::from(true));
    }

    /// The same for a header cut off inside its own four lines.
    #[test]
    fn truncated_header_reports_instead_of_vanishing() {
        let art = make_artifact(
            ArtifactType::RawEvidence,
            "backup.ab",
            b"ANDROID BACKUP\n1\n1\n".to_vec(),
        );
        let out = AndroidBackupModule.process(&art).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metadata["status"], Value::from("HeaderTruncated"));
        assert_eq!(out[0].metadata["content_incomplete"], Value::from(true));
    }

    // -----------------------------------------------------------------------
    // HUNT-172: the payload ceiling. Production runs under 2 GiB; these pin
    // both places a ceiling can fall by running the same code under a small
    // one. Uncompressed layout: 24-byte `.ab` header, then per small file one
    // 512-byte tar header and one 512-byte data block, then two zero blocks.
    // -----------------------------------------------------------------------

    fn three_entry_ab(compressed: bool) -> Vec<u8> {
        build_ab(
            compressed,
            "none",
            &[
                ("apps/x/db/a.db", b"aaa"),
                ("apps/x/db/b.db", b"bbb"),
                ("apps/x/db/c.db", b"ccc"),
            ],
        )
    }

    /// The file entries of a backup that unpacked whole, after checking the
    /// one success summary that closes the list (ROADMAP §1.4).
    fn whole(mut out: Vec<Artifact>) -> Vec<Artifact> {
        let last = out.pop().expect("a whole backup ends with its summary");
        assert_eq!(last.metadata["type"], "AndroidBackupSummary", "{last:?}");
        assert_eq!(last.metadata["entries_extracted"], out.len());
        assert_eq!(last.metadata["status"], "Extracted", "{last:?}");
        assert!(out
            .iter()
            .all(|a| a.metadata["type"] != "AndroidBackupSummary"));
        out
    }

    fn statuses(out: &[Artifact]) -> Vec<&Artifact> {
        out.iter()
            .filter(|a| a.metadata["type"] == "AndroidBackupWarning")
            .collect()
    }

    /// The ceiling falls exactly after the first entry, where the second
    /// header should begin. tar reads that as end-of-archive, so one of three
    /// app databases reached the case and nothing said the walk was cut.
    #[test]
    fn a_ceiling_on_a_header_boundary_is_named_not_read_as_the_end() {
        for compressed in [false, true] {
            let art = make_artifact(
                ArtifactType::RawEvidence,
                "backup.ab",
                three_entry_ab(compressed),
            );
            let out = AndroidBackupModule
                .process_with_ceiling(&art, 1024)
                .unwrap();
            let files = out
                .iter()
                .filter(|a| a.artifact_type == ArtifactType::FileEntry)
                .count();
            assert_eq!(files, 1, "compressed={compressed}");
            let status = statuses(&out);
            assert_eq!(status.len(), 1, "compressed={compressed}: {out:?}");
            let m = &status[0].metadata;
            assert_eq!(m["status"], Value::from("CapReached"));
            assert_eq!(m["content_incomplete_reason"], Value::from("cap_reached"));
            assert_eq!(m["inventory_incomplete_reason"], Value::from("cap_reached"));
            assert_eq!(m["max_decompressed_bytes"], Value::from(1024u64));
            assert_eq!(m["entries_extracted"], Value::from(1u64));
            assert!(m.get("cut_entry_path").is_none());
        }
    }

    /// The ceiling falls 50 bytes into the first entry's 100. The entry was
    /// flagged `short_read` and the walk `PayloadTruncated` — "the archive
    /// ended early" — when the archive was whole and the ceiling cut it.
    #[test]
    fn a_ceiling_inside_an_entry_is_named_on_the_entry_and_the_backup() {
        let body = vec![b'A'; 100];
        let ab = build_ab(false, "none", &[("apps/x/db/big.db", &body)]);
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);
        let out = AndroidBackupModule
            .process_with_ceiling(&art, 512 + 50)
            .unwrap();

        let entry = out
            .iter()
            .find(|a| a.artifact_type == ArtifactType::FileEntry)
            .expect("the cut entry is still emitted");
        assert_eq!(entry.metadata["size"], Value::from(100u64));
        assert_eq!(entry.metadata["materialized_size"], Value::from(50u64));
        assert_eq!(
            entry.metadata["content_incomplete_reason"],
            Value::from("cap_reached")
        );
        assert_eq!(
            entry.metadata["content_omitted"],
            Value::from("payload_ceiling_reached")
        );

        let status = statuses(&out);
        assert_eq!(status.len(), 1, "{out:?}");
        let m = &status[0].metadata;
        assert_eq!(m["status"], Value::from("CapReached"));
        assert_eq!(m["max_decompressed_bytes"], Value::from(562u64));
        assert_eq!(m["cut_entry_path"], Value::from("/apps/x/db/big.db"));
        assert_eq!(m["cut_entry_declared_size"], Value::from(100u64));
        assert!(!m["message"].as_str().unwrap().contains("ended early"));
    }

    /// A payload exactly the ceiling's size, end-of-archive blocks included,
    /// was read whole: no record, so the record means something.
    #[test]
    fn a_payload_that_fits_the_ceiling_exactly_is_not_called_capped() {
        let ab = three_entry_ab(false);
        let payload_len = (ab.len() - 24) as u64;
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);
        let out = whole(
            AndroidBackupModule
                .process_with_ceiling(&art, payload_len)
                .unwrap(),
        );
        assert_eq!(out.len(), 3, "{out:?}");
        assert!(statuses(&out).is_empty());
    }

    /// ROADMAP §1.4 (owner decision 2026-09-26, 1a): a backup that unpacked
    /// whole says so in a record of its own, so a backup that was READ is
    /// recognisable as a backup — not only one that failed.
    #[test]
    fn a_backup_that_extracted_whole_emits_a_summary_record_naming_what_it_read() {
        for compressed in [false, true] {
            let ab = build_ab(
                compressed,
                "none",
                &[
                    ("apps/com.a/_manifest", b"m"),
                    ("apps/com.a/db/x.db", b"x"),
                    ("apps/com.b/f/y", b"y"),
                    ("shared/0/DCIM/z.jpg", b"z"),
                ],
            );
            let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);
            let out = AndroidBackupModule.process(&art).unwrap();
            let summaries: Vec<_> = out
                .iter()
                .filter(|a| a.metadata["type"] == "AndroidBackupSummary")
                .collect();
            assert_eq!(summaries.len(), 1, "compressed={compressed}: {out:?}");
            let m = &summaries[0].metadata;
            assert_eq!(m["status"], "Extracted");
            assert_eq!(m["entries_extracted"], 4);
            assert_eq!(m["app_packages"], 2);
            assert_eq!(m["compressed"], compressed);
            assert_eq!(m["encryption"], "none");
            assert_eq!(m["format_version"], "1");
            assert!(m.get("content_incomplete").is_none());
            assert_eq!(summaries[0].parent_id, Some(art.id));
            assert!(statuses(&out).is_empty());
        }
    }

    /// A walk that reached the archive's end with an entry whose content was
    /// not read (over the per-entry cap) still inventoried every entry, but it
    /// did not unpack whole, and the summary must not say it did.
    #[test]
    fn a_whole_walk_with_an_entry_over_the_size_cap_is_walked_to_its_end_not_unpacked_whole() {
        let ab = build_ab(
            false,
            "none",
            &[
                ("apps/com.a/db/small.db", b"abc"),
                ("apps/com.a/db/big.db", b"0123456789abcdef"),
            ],
        );
        let art = make_artifact(ArtifactType::RawEvidence, "backup.ab", ab);
        let out = AndroidBackupModule
            .process_with_limits(&art, MAX_DECOMPRESSED_BYTES, 8)
            .unwrap();
        let big = out
            .iter()
            .find(|a| a.metadata["name"] == "big.db")
            .expect("the over-cap entry is still listed");
        assert_eq!(big.metadata["content_omitted"], "entry_over_size_cap");
        let summaries: Vec<_> = out
            .iter()
            .filter(|a| a.metadata["type"] == "AndroidBackupSummary")
            .collect();
        assert_eq!(summaries.len(), 1, "{out:?}");
        let m = &summaries[0].metadata;
        assert_eq!(m["entries_extracted"], 2);
        assert_eq!(m["entries_content_incomplete"], 1, "{m}");
        assert_eq!(m["status"], "WalkedToEnd", "{m}");
        let name = m["name"].as_str().unwrap();
        assert!(!name.contains("unpacked whole"), "{name}");
        assert!(name.contains("walked to its end"), "{name}");
    }

    /// A failed walk keeps its warning and gets no success summary.
    #[test]
    fn a_backup_that_did_not_extract_whole_has_no_success_summary() {
        let art = make_artifact(
            ArtifactType::RawEvidence,
            "backup.ab",
            build_ab(true, "AES-256", &[]),
        );
        let out = AndroidBackupModule.process(&art).unwrap();
        assert!(out
            .iter()
            .all(|a| a.metadata["type"] != "AndroidBackupSummary"));
    }

    #[test]
    fn non_ab_file_entry_skipped_cheaply() {
        let art = make_artifact(ArtifactType::FileEntry, "document.txt", vec![1, 2, 3, 4]);
        let out = AndroidBackupModule.process(&art).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn no_data_source_returns_empty() {
        let art = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::RawEvidence,
            None,
            json!({ "name": "backup.ab" }),
        );
        let out = AndroidBackupModule.process(&art).unwrap();
        assert!(out.is_empty());
    }
}
