#![forbid(unsafe_code)]
pub mod format;

use format::{parse_dollar_i_v1, parse_dollar_i_v2, parse_info2};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::IncompleteReason,
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::{debug, info, warn};

/// Upper bound on how much of a Recycle Bin metadata file is buffered into RAM.
/// `$I` records are tiny and INFO2 files are small; a mis-detected or hostile
/// large input must not OOM the worker (BUG-132).
const MAX_RECYCLEBIN_BYTES: u64 = 64 * 1024 * 1024;

/// How much of the Recycle Bin metadata file this run actually saw.
///
/// Forensic meaning: the Recycle Bin is the record of what a user deleted. A
/// listing that stops early because the read was capped or the evidence is
/// short looks exactly like a Recycle Bin that never held those entries, and
/// "no record of deletion" is an argument people make in court. `reason` is
/// `None` only when every declared byte was read.
#[derive(Clone, Copy)]
struct ReadExtent {
    bytes_read: u64,
    bytes_declared: u64,
    reason: Option<&'static str>,
}

impl ReadExtent {
    fn measure(bytes_read: usize, bytes_declared: u64) -> Self {
        let bytes_read = bytes_read as u64;
        let reason = if bytes_read >= bytes_declared {
            None
        } else if bytes_declared > MAX_RECYCLEBIN_BYTES {
            // The file is larger than the load cap: the tail was never read.
            Some(IncompleteReason::CapReached.as_str())
        } else {
            // The source returned fewer bytes than it declares it holds.
            Some(IncompleteReason::ShortRead.as_str())
        };
        Self {
            bytes_read,
            bytes_declared,
            reason,
        }
    }
}

/// Build the examiner-facing record that says this Recycle Bin metadata file
/// was not fully decoded.
///
/// Forensic meaning: an examiner reading a Recycle Bin listing must be able to
/// tell "these are all the deletions" from "these are the deletions we could
/// read". Carries the standard `content_incomplete` pair plus
/// `inventory_incomplete`, because what is short here is a listing.
fn parse_status_artifact(
    artifact: &Artifact,
    name: &str,
    reason: &str,
    entries_parsed: usize,
    extent: ReadExtent,
    message: &str,
) -> Artifact {
    warn!(
        "RecycleBinParser: '{}' not fully decoded ({}): {} entries recovered from {} of {} bytes",
        name, reason, entries_parsed, extent.bytes_read, extent.bytes_declared
    );
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        json!({
            "type": "RecycleBinParseStatus",
            "record_type": "recycle_bin_parse_status",
            "name": format!("{name} (partially parsed)"),
            "content_incomplete": true,
            "content_incomplete_reason": reason,
            "inventory_incomplete": true,
            "entries_parsed": entries_parsed,
            "bytes_read": extent.bytes_read,
            "bytes_declared": extent.bytes_declared,
            "message": message,
        }),
    )
    .with_parent(artifact.id)
}

pub struct RecycleBinParser;

impl ForensicsModule for RecycleBinParser {
    fn id(&self) -> &str {
        "plugin.windows.recycle_bin_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![
            ArtifactType::FileEntry,
            // A shadow-copy prior version only (HUNT-277).
            ArtifactType::ParsedRecord,
        ]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::Stream
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        seance_core::shadow_copy::parse_with_shadow_copy(artifact, |a| self.parse_file(a))
    }
}

impl RecycleBinParser {
    fn parse_file(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(Vec::new()),
        };

        let name = seance_core::shadow_copy::original_name(artifact).unwrap_or_default();

        let name_upper = name.to_uppercase();

        // Check for $I files (Vista+) or INFO2 (legacy)
        let is_dollar_i = name_upper.starts_with("$I");
        let is_info2 = name_upper == "INFO2";

        if !is_dollar_i && !is_info2 {
            return Ok(Vec::new());
        }

        // Read file content (bounded: never allocate more than the cap).
        let declared = data_source.size();
        let buffer = seance_core::io::read_capped(data_source.as_ref(), MAX_RECYCLEBIN_BYTES);
        let extent = ReadExtent::measure(buffer.len(), declared);

        if buffer.len() < 8 {
            // Too small to even read the header. Two distinct reasons, and both
            // have to be stated: the file DECLARES more than we got (evidence we
            // could not read), or every declared byte was read and there are
            // still fewer than eight of them (a carved or truncated fragment
            // that names a deletion this case cannot describe).
            //
            // The one case that stays silent is a source that declares nothing
            // and returns nothing: there is no fragment and no shortfall, so
            // there is nothing to be honest about and a record here would be
            // noise on every zero-length placeholder in the tree.
            let reason = extent
                .reason
                .or((!buffer.is_empty()).then_some(IncompleteReason::UnresolvedStructure.as_str()));
            if let Some(reason) = reason {
                return Ok(vec![parse_status_artifact(
                    artifact,
                    name,
                    reason,
                    0,
                    extent,
                    "This Recycle Bin metadata file could not be read far enough to decode \
                     even its header: any deletions it records are absent from this case",
                )]);
            }
            return Ok(Vec::new());
        }

        if is_info2 {
            return self.process_info2(&buffer, artifact, name, extent);
        }

        // $I file processing
        self.process_dollar_i(&buffer, name, artifact, extent)
    }
}

impl RecycleBinParser {
    fn process_dollar_i(
        &self,
        buffer: &[u8],
        name: &str,
        artifact: &Artifact,
        extent: ReadExtent,
    ) -> Result<Vec<Artifact>, ModuleError> {
        // Detect version from first 8 bytes
        let version = u64::from_le_bytes([
            buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5], buffer[6], buffer[7],
        ]);

        let entry = match version {
            1 => parse_dollar_i_v1(buffer, name),
            2 => parse_dollar_i_v2(buffer, name),
            _ => {
                debug!(
                    "RecycleBinParser: Unknown $I version {} in '{}'",
                    version, name
                );
                // A `$I` this parser cannot decode still proves a file was sent
                // to the Recycle Bin. Producing nothing would leave the case
                // saying that deletion never happened.
                return Ok(vec![parse_status_artifact(
                    artifact,
                    name,
                    IncompleteReason::UnresolvedStructure.as_str(),
                    0,
                    extent,
                    "This $I record declares a header version this build does not decode: \
                     the file it describes was deleted but its original path, size and \
                     deletion time are absent from this case",
                )]);
            }
        };

        match entry {
            Ok(entry) => {
                info!(
                    "RecycleBinParser: Parsed '{}' -> original: '{}', size: {}",
                    name, entry.original_path, entry.file_size
                );

                let filename = entry
                    .original_path
                    .rsplit('\\')
                    .next()
                    .unwrap_or(&entry.original_path);
                let short_desc = format!("Deleted: {}", filename);

                let timestamp_str = entry
                    .deleted_time
                    .map(|dt| dt.to_rfc3339())
                    .unwrap_or_default();

                // A `$I` whose declared path did not fit in the file yields a
                // prefix of the deleted file's location. Say so on the record:
                // a shortened path still looks like a real one, and an examiner
                // would otherwise treat the wrong directory as established fact.
                if entry.path_truncated {
                    warn!(
                        "RecycleBinParser: '{}' declares a longer original path than the \
                         $I file holds; the recovered path is a prefix",
                        name
                    );
                }

                let mut parsed_metadata = json!({
                    "type": "RecycleBinEntry",
                    "original_path": entry.original_path,
                    "deleted_time": timestamp_str,
                    "file_size": entry.file_size,
                    "recycle_bin_path": entry.recycle_bin_path,
                    "version": version,
                    "short_desc": short_desc,
                });
                // Every way this record can be short, on one flag pair. The
                // outer buffer shortfall matters as much as the declared-path
                // shortfall: a $I read that stopped early can leave a path,
                // size or timestamp that is a fragment of the real value.
                let mut reasons: Vec<&str> = Vec::new();
                if entry.path_truncated {
                    parsed_metadata["original_path_truncated"] = json!(true);
                    reasons.push("original_path_truncated");
                }
                if let Some(reason) = extent.reason {
                    parsed_metadata["bytes_read"] = json!(extent.bytes_read);
                    parsed_metadata["bytes_declared"] = json!(extent.bytes_declared);
                    reasons.push(reason);
                }
                if !reasons.is_empty() {
                    parsed_metadata["content_incomplete"] = json!(true);
                    parsed_metadata["content_incomplete_reason"] = json!(reasons.join(","));
                }

                let parsed = Artifact::new(
                    artifact.case_id,
                    ArtifactType::ParsedRecord,
                    None,
                    parsed_metadata,
                )
                .with_parent(artifact.id);

                let mut artifacts = vec![];

                if entry.deleted_time.is_some() {
                    let timeline = Artifact::new(
                        artifact.case_id,
                        ArtifactType::TimelineEvent,
                        None,
                        json!({
                            "timestamp": timestamp_str,
                            "timestamp_desc": "File Deletion",
                            "source_module": "plugin.windows.recycle_bin_parser",
                            "short_desc": short_desc,
                            "full_details": json!({
                                "original_path": entry.original_path,
                                "file_size": entry.file_size,
                            }).to_string(),
                        }),
                    )
                    .with_parent(parsed.id);

                    artifacts.push(parsed);
                    artifacts.push(timeline);
                } else {
                    artifacts.push(parsed);
                }

                Ok(artifacts)
            }
            Err(e) => {
                debug!("RecycleBinParser: Failed to parse '{}': {}", name, e);
                // Same reasoning as the unknown-version arm: a $I that exists
                // but will not decode is a deletion this case cannot describe.
                Ok(vec![parse_status_artifact(
                    artifact,
                    name,
                    IncompleteReason::UnresolvedStructure.as_str(),
                    0,
                    extent,
                    "This $I record could not be decoded: the file it describes was deleted \
                     but its original path, size and deletion time are absent from this case",
                )])
            }
        }
    }

    fn process_info2(
        &self,
        buffer: &[u8],
        artifact: &Artifact,
        name: &str,
        extent: ReadExtent,
    ) -> Result<Vec<Artifact>, ModuleError> {
        match parse_info2(buffer) {
            Ok(scan) => {
                let entries = scan.entries;
                info!(
                    "RecycleBinParser: Parsed INFO2 with {} entries",
                    entries.len()
                );

                let mut artifacts = Vec::new();
                for entry in &entries {
                    let filename = entry
                        .original_path
                        .rsplit('\\')
                        .next()
                        .unwrap_or(&entry.original_path);
                    let short_desc = format!("Deleted (legacy): {}", filename);

                    let timestamp_str = entry
                        .deleted_time
                        .map(|dt| dt.to_rfc3339())
                        .unwrap_or_default();

                    let mut parsed_metadata = json!({
                        "type": "RecycleBinEntry",
                        "original_path": entry.original_path,
                        "deleted_time": timestamp_str,
                        "file_size": entry.file_size,
                        "format": "INFO2",
                        "short_desc": short_desc,
                    });
                    // An INFO2 record with no Unicode path stores the location
                    // as raw ANSI bytes carrying no encoding declaration. When
                    // the field held a byte outside ASCII the path above is
                    // this build's reading of those bytes under an assumed code
                    // page, not text read off the disk: the same bytes on a
                    // volume written under a Cyrillic or Japanese ANSI code
                    // page name a different directory entirely. Say which table
                    // was used, so the string is not taken as literal.
                    if let Some(code_page) = entry.path_decode {
                        parsed_metadata["path_decode"] = json!(code_page);
                    }

                    let parsed = Artifact::new(
                        artifact.case_id,
                        ArtifactType::ParsedRecord,
                        None,
                        parsed_metadata,
                    )
                    .with_parent(artifact.id);

                    if entry.deleted_time.is_some() {
                        let timeline = Artifact::new(
                            artifact.case_id,
                            ArtifactType::TimelineEvent,
                            None,
                            json!({
                                "timestamp": timestamp_str,
                                "timestamp_desc": "File Deletion (INFO2)",
                                "source_module": "plugin.windows.recycle_bin_parser",
                                "short_desc": short_desc,
                                "full_details": json!({
                                    "original_path": entry.original_path,
                                    "file_size": entry.file_size,
                                }).to_string(),
                            }),
                        )
                        .with_parent(parsed.id);

                        artifacts.push(parsed);
                        artifacts.push(timeline);
                    } else {
                        artifacts.push(parsed);
                    }
                }

                // Two independent ways this table can be short: the outer read
                // stopped before the end of the file, or the last record in
                // what we read is a fragment. Either way the entries past that
                // point are deletions this case cannot show.
                //
                // They are NOT the same reason. `short_read` says the evidence
                // could not deliver bytes it claimed to hold, and sends an
                // examiner after an acquisition fault. A file delivered whole
                // that ends inside a record is a truncated table — the fault is
                // in the artifact, not in the image (B7-028).
                let (reason, message) = match extent.reason {
                    Some(reason) => (
                        Some(reason),
                        "This INFO2 table was not read to its end: deletions recorded past \
                         that point are absent from this case and their absence is not \
                         evidence that nothing else was deleted",
                    ),
                    None if scan.trailing_partial_record => (
                        Some(IncompleteReason::UnresolvedStructure.as_str()),
                        "This INFO2 file was read in full but ends inside a record: the table \
                         itself is truncated, so deletions past that point are absent from \
                         this case and their absence is not evidence that nothing else was \
                         deleted",
                    ),
                    None => (None, ""),
                };
                if let Some(reason) = reason {
                    artifacts.push(parse_status_artifact(
                        artifact,
                        name,
                        reason,
                        entries.len(),
                        extent,
                        message,
                    ));
                }

                Ok(artifacts)
            }
            Err(e) => {
                debug!("RecycleBinParser: Failed to parse INFO2: {}", e);
                // An INFO2 that will not parse is a whole deletion table this
                // case cannot show; silence would read as an empty Recycle Bin.
                Ok(vec![parse_status_artifact(
                    artifact,
                    name,
                    IncompleteReason::UnresolvedStructure.as_str(),
                    0,
                    extent,
                    "This INFO2 table could not be decoded: none of the deletions it records \
                     are in this case",
                )])
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource, FileDataSource};
    use seance_core::module::ForensicsModule;
    use seance_core::test_support::TruncatedSource;
    use std::path::PathBuf;
    use std::sync::Arc;

    fn make_artifact(path: &str, name: &str) -> Option<Artifact> {
        let p = PathBuf::from(path);
        if !p.exists() {
            return None;
        }
        let ds = Arc::new(FileDataSource::new(p).unwrap());
        Some(Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(ds),
            json!({ "name": name }),
        ))
    }

    #[test]
    fn test_dollar_i_jpg() {
        let artifact = match make_artifact("test_data/recycler/$I103S5F.jpg", "$I103S5F.jpg") {
            Some(a) => a,
            None => {
                eprintln!("Skipping: $I103S5F.jpg not found");
                return;
            }
        };
        let parser = RecycleBinParser;
        let results = parser.process(&artifact).unwrap();
        assert!(!results.is_empty(), "Should extract data from $I file");

        // Check we have a ParsedRecord
        let parsed = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .unwrap();
        let meta = &parsed.metadata;
        assert_eq!(meta["type"], "RecycleBinEntry");
        let orig_path = meta["original_path"].as_str().unwrap();
        assert!(!orig_path.is_empty(), "Should extract original path");
    }

    #[test]
    fn test_dollar_i_zip() {
        let artifact = match make_artifact("test_data/recycler/$II3DF3L.zip", "$II3DF3L.zip") {
            Some(a) => a,
            None => {
                eprintln!("Skipping: $II3DF3L.zip not found");
                return;
            }
        };
        let parser = RecycleBinParser;
        let results = parser.process(&artifact).unwrap();
        assert!(!results.is_empty(), "Should extract data from $I file");
    }

    #[test]
    fn test_info2() {
        let artifact = match make_artifact("test_data/recycler/INFO2", "INFO2") {
            Some(a) => a,
            None => {
                eprintln!("Skipping: INFO2 not found");
                return;
            }
        };
        let parser = RecycleBinParser;
        let results = parser.process(&artifact).unwrap();
        // INFO2 may or may not have entries; just ensure no crash
        eprintln!("INFO2 produced {} artifacts", results.len());
    }

    #[test]
    fn test_non_recycle_file_skipped() {
        use seance_core::data_source::ByteSliceDataSource;

        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(vec![0u8; 100]))),
            json!({ "name": "somefile.txt" }),
        );

        let parser = RecycleBinParser;
        let results = parser.process(&artifact).unwrap();
        assert!(results.is_empty(), "Non-$I file should be skipped");
    }

    /// Build a Windows 10 (`$I` v2) record: version, size, FILETIME, the path
    /// length in UTF-16 characters, then the path itself. `path_chars_declared`
    /// lets a test declare a longer path than it stores, which is what a
    /// truncated acquisition or a capped read leaves behind.
    fn dollar_i_v2(path: &str, path_chars_declared: u32) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2u64.to_le_bytes());
        buf.extend_from_slice(&4096u64.to_le_bytes());
        // 2020-01-01T00:00:00Z
        buf.extend_from_slice(&132_223_104_000_000_000u64.to_le_bytes());
        buf.extend_from_slice(&path_chars_declared.to_le_bytes());
        for unit in path.encode_utf16() {
            buf.extend_from_slice(&unit.to_le_bytes());
        }
        buf.extend_from_slice(&0u16.to_le_bytes()); // trailing null
        buf
    }

    #[test]
    fn a_complete_v2_record_is_not_marked_truncated() {
        let path = r"C:\Users\bob\report.docx";
        let declared = path.encode_utf16().count() as u32 + 1;
        let entry = crate::format::parse_dollar_i_v2(&dollar_i_v2(path, declared), "$IABCDEF")
            .expect("well-formed v2 record must parse");
        assert_eq!(entry.original_path, path);
        assert!(!entry.path_truncated);
    }

    #[test]
    fn a_v2_record_cut_short_reports_its_path_as_a_prefix_not_as_the_original() {
        let path = r"C:\Users\bob\report.docx";
        // The record claims a much longer path than the file holds: the tail was
        // lost to a truncated image or a capped read.
        let entry = crate::format::parse_dollar_i_v2(&dollar_i_v2(path, 400), "$IABCDEF")
            .expect("a short record still yields its timestamp and size");
        assert!(
            entry.path_truncated,
            "a declared path longer than the file must be reported as truncated"
        );
        assert_eq!(
            entry.original_path, path,
            "keep what was actually recovered"
        );
    }

    #[test]
    fn a_truncated_recycle_bin_path_is_flagged_on_the_emitted_record() {
        use seance_core::data_source::ByteSliceDataSource;

        let data = dollar_i_v2(r"C:\Users\bob\rep", 400);
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(Arc::new(ByteSliceDataSource::new(data))),
            json!({ "name": "$IABCDEF.docx" }),
        );
        let results = RecycleBinParser.process(&artifact).unwrap();
        let parsed = results
            .iter()
            .find(|a| a.artifact_type == ArtifactType::ParsedRecord)
            .expect("a short $I still produces a record");
        assert_eq!(parsed.metadata["original_path_truncated"], true);
        assert_eq!(parsed.metadata["content_incomplete"], true);
        assert_eq!(
            parsed.metadata["content_incomplete_reason"],
            "original_path_truncated"
        );
    }

    /// HUNT-277: a `$I` file inside a shadow copy is decoded and what it yields
    /// says so; a `ParsedRecord` that is not a prior version is not read.
    #[test]
    fn a_shadow_copy_prior_version_is_decoded_and_stamped() {
        use seance_core::data_source::ByteSliceDataSource;

        let source: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(dollar_i_v2(
            r"C:\Users\bob\a.docx",
            400,
        )));
        let prior = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(source.clone()),
            json!({
                "type": "VssPriorVersion",
                "name": "$IABCDEF.docx [shadow copy 2015-03-23T00:00:00Z]",
                "file_name": "$IABCDEF.docx",
                "is_snapshot_version": true,
                "vss_snapshot_id": "snap-1",
                "vss_creation_time": "2015-03-23T00:00:00Z",
            }),
        );
        let out = RecycleBinParser.process(&prior).unwrap();
        assert!(
            out.iter().any(|a| a.metadata["type"] == "RecycleBinEntry"),
            "the prior version is decoded"
        );
        assert!(out
            .iter()
            .all(|a| a.metadata["vss_snapshot_id"] == json!("snap-1")));

        let other = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::ParsedRecord,
            Some(source),
            json!({ "type": "SomethingElse", "name": "$IABCDEF.docx" }),
        );
        assert!(RecycleBinParser.process(&other).unwrap().is_empty());
    }

    /// Build an INFO2 table: 20-byte header declaring an 800-byte record size,
    /// then one 800-byte Unicode record per path.
    fn info2(paths: &[&str]) -> Vec<u8> {
        let mut buf = vec![0u8; 20];
        buf[0..4].copy_from_slice(&5u32.to_le_bytes());
        buf[12..16].copy_from_slice(&800u32.to_le_bytes());
        for path in paths {
            let mut rec = vec![0u8; 800];
            // Deletion FILETIME (2021-01-01) at 268, size at 276.
            rec[268..276].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
            rec[276..280].copy_from_slice(&4096u32.to_le_bytes());
            for (i, unit) in path.encode_utf16().enumerate() {
                let off = 280 + i * 2;
                rec[off..off + 2].copy_from_slice(&unit.to_le_bytes());
            }
            buf.extend_from_slice(&rec);
        }
        buf
    }

    /// Attach a source declaring `declared` bytes while holding only `data`.
    ///
    /// Both halves of this suite matter. When `declared` exceeds what is held,
    /// this is a capped read or a truncated acquisition and the parser must say
    /// so; when the two agree the source is honest and the parser must NOT
    /// claim incompleteness, which is what stops the marker crying wolf. The
    /// shared `TruncatedSource` refuses a declaration that is not short — by
    /// design, since such a double proves nothing — so the honest cases use the
    /// real byte-slice source, whose `read_at` is the same code.
    fn run(name: &str, data: Vec<u8>, declared: u64) -> Vec<Artifact> {
        let source: Arc<dyn DataSource> = if declared > data.len() as u64 {
            Arc::new(TruncatedSource::new(data, declared))
        } else {
            assert_eq!(
                declared,
                data.len() as u64,
                "a source declaring FEWER bytes than it holds is not a shape this suite models"
            );
            Arc::new(ByteSliceDataSource::new(data))
        };
        let artifact = Artifact::new(
            uuid::Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({ "name": name }),
        );
        RecycleBinParser.process(&artifact).unwrap()
    }

    fn status_of(arts: &[Artifact]) -> Option<&Artifact> {
        arts.iter()
            .find(|a| a.metadata["type"] == "RecycleBinParseStatus")
    }

    #[test]
    fn an_info2_table_cut_off_by_the_read_cap_says_so() {
        // The file holds three deletions; the read stopped after the first.
        let full = info2(&[r"C:\a.txt", r"C:\b.txt", r"C:\c.txt"]);
        let declared = full.len() as u64;
        let arts = run("INFO2", full[..820].to_vec(), declared);

        assert_eq!(
            arts.iter()
                .filter(|a| a.metadata["type"] == "RecycleBinEntry")
                .count(),
            1,
            "the deletion that was read is still recovered"
        );
        let status = status_of(&arts).expect(
            "a Recycle Bin table read short of its declared size must emit a status record",
        );
        assert_eq!(status.metadata["content_incomplete"], true);
        assert_eq!(status.metadata["content_incomplete_reason"], "short_read");
        assert_eq!(status.metadata["inventory_incomplete"], true);
        assert_eq!(status.metadata["entries_parsed"], 1);
        assert_eq!(status.metadata["bytes_read"], 820);
        assert_eq!(status.metadata["bytes_declared"], declared);
    }

    #[test]
    fn a_fully_read_info2_table_carries_no_incompleteness() {
        let full = info2(&[r"C:\a.txt", r"C:\b.txt"]);
        let declared = full.len() as u64;
        let arts = run("INFO2", full, declared);

        assert_eq!(
            arts.iter()
                .filter(|a| a.metadata["type"] == "RecycleBinEntry")
                .count(),
            2
        );
        assert!(
            status_of(&arts).is_none(),
            "a complete table must not claim to be incomplete"
        );
    }

    #[test]
    fn an_info2_table_ending_mid_record_says_so() {
        // Every declared byte was read, but the last record is a fragment.
        let mut full = info2(&[r"C:\a.txt"]);
        full.extend_from_slice(&[0x41u8; 100]);
        let declared = full.len() as u64;
        let arts = run("INFO2", full, declared);

        let status = status_of(&arts)
            .expect("a table ending part-way through a record must emit a status record");
        assert_eq!(status.metadata["content_incomplete"], true);
        // B7-028: every declared byte arrived, so this is a truncated table and
        // not an acquisition shortfall. Calling it `short_read` sends an
        // examiner hunting an image fault that does not exist.
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert_eq!(
            status.metadata["bytes_read"],
            status.metadata["bytes_declared"]
        );
    }

    /// The random part of a `$I` name is six characters from `0-9A-Z`, so one
    /// deletion in thirty-six is named `$ID…`. The parser skipped every one of
    /// them (`!name.starts_with("$ID")`): on the NIST CFReDS Data Leakage image
    /// 13 of the 14 `$I` files read and `$IDOI3HE.jpg` (Tulips.jpg, deleted
    /// 2015-03-24 16:11:42) did not, with no record and no status.
    #[test]
    fn a_dollar_i_whose_random_name_begins_with_d_is_read() {
        let path = r"C:\Users\bob\Tulips.jpg";
        let declared_chars = path.encode_utf16().count() as u32 + 1;
        let arts = run("$IDOI3HE.jpg", dollar_i_v2(path, declared_chars), 4096);
        let parsed = arts
            .iter()
            .find(|a| a.metadata["type"] == "RecycleBinEntry")
            .expect("a $ID... file is an ordinary $I file");
        assert_eq!(parsed.metadata["original_path"], path);
    }

    /// The real `$IDOI3HE.jpg` from the NIST CFReDS Data Leakage PC (MFT entry
    /// 74766, 544 bytes, SHA-256 `610ec17f…b3f4a`), read whole. The key's
    /// question 51 lists it: Tulips.jpg, deleted 2015-03-24 16:11:42 local.
    #[test]
    fn the_real_data_leakage_dollar_id_file_is_read() {
        let data = include_bytes!("../tests/fixtures/IDOI3HE_dollar_i.bin").to_vec();
        let n = data.len() as u64;
        let arts = run("$IDOI3HE.jpg", data, n);
        let parsed = arts
            .iter()
            .find(|a| a.metadata["type"] == "RecycleBinEntry")
            .expect("a record for the real $IDOI3HE.jpg");
        assert_eq!(
            parsed.metadata["original_path"],
            r"C:\Users\informant\AppData\Local\Microsoft\Windows\Burn\Burn\Tulips.jpg"
        );
        assert_eq!(parsed.metadata["file_size"], 620_888);
        assert_eq!(
            parsed.metadata["deleted_time"],
            "2015-03-24T20:11:42.851+00:00"
        );
    }

    #[test]
    fn a_dollar_i_read_short_of_its_declared_size_is_flagged_on_the_record() {
        let path = r"C:\Users\bob\report.docx";
        let declared_chars = path.encode_utf16().count() as u32 + 1;
        let data = dollar_i_v2(path, declared_chars);
        // The source claims 4 KiB but hands over only what it has.
        let arts = run("$IABCDEF.docx", data, 4096);

        let parsed = arts
            .iter()
            .find(|a| a.metadata["type"] == "RecycleBinEntry")
            .expect("a short $I still produces a record");
        assert_eq!(
            parsed.metadata["content_incomplete"], true,
            "a $I whose file was not read in full must not present as complete"
        );
        assert_eq!(parsed.metadata["content_incomplete_reason"], "short_read");
        assert_eq!(parsed.metadata["bytes_declared"], 4096);
    }

    #[test]
    fn a_dollar_i_fragment_too_short_for_a_header_is_not_silently_dropped() {
        // A carved or truncated `$I` of four bytes: every byte the source has
        // was read, so there is no shortfall to report, but the record still
        // will not decode. Returning nothing would leave the case saying this
        // deletion never happened.
        let arts = run("$IFRAGME.bin", vec![0x02, 0x00, 0x00, 0x00], 4);

        let status =
            status_of(&arts).expect("a $I fragment too small to decode must still be declared");
        assert_eq!(status.metadata["content_incomplete"], true);
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
        assert_eq!(status.metadata["bytes_read"], 4);
    }

    #[test]
    fn a_zero_length_source_produces_no_record_at_all() {
        // Nothing was declared and nothing was read: there is no fragment and
        // no shortfall, so claiming incompleteness here would cry wolf on every
        // empty placeholder entry.
        assert!(run("$IEMPTY0.bin", Vec::new(), 0).is_empty());
    }

    /// What an examiner learns: the full original location of a deleted file,
    /// read off the emitted record rather than out of the parser. A path this
    /// build interpreted under an assumed code page must arrive stamped with
    /// that code page; otherwise the string reads as literal disk content, and
    /// a volume written under a different ANSI code page silently names the
    /// wrong directory.
    #[test]
    fn an_ansi_info2_record_is_emitted_decoded_and_stamped_with_its_code_page() {
        // Unicode path field left zeroed: the ANSI field at offset 0 is the
        // only record of where the file lived.
        let mut data = vec![0u8; 20];
        data[0..4].copy_from_slice(&5u32.to_le_bytes());
        data[12..16].copy_from_slice(&800u32.to_le_bytes());
        let mut rec = vec![0u8; 800];
        let ansi = b"C:\\Users\\Jos\xe9\\R\xe9sum\xe9.doc";
        rec[0..ansi.len()].copy_from_slice(ansi);
        rec[268..276].copy_from_slice(&132_539_328_000_000_000u64.to_le_bytes());
        rec[276..280].copy_from_slice(&4096u32.to_le_bytes());
        data.extend_from_slice(&rec);

        let declared = data.len() as u64;
        let arts = run("INFO2", data, declared);
        let parsed = arts
            .iter()
            .find(|a| a.metadata["type"] == "RecycleBinEntry")
            .expect("an ANSI INFO2 record must still be emitted");
        assert_eq!(
            parsed.metadata["original_path"], "C:\\Users\\José\\Résumé.doc",
            "the ANSI path must be decoded, not replaced with U+FFFD"
        );
        assert_eq!(parsed.metadata["path_decode"], "cp1252");
    }

    /// Anti-cry-wolf: a Unicode INFO2 path assumed no code page, so the record
    /// must not carry a decode stamp suggesting one was applied.
    #[test]
    fn a_unicode_info2_record_carries_no_code_page_stamp() {
        let full = info2(&[r"C:\a.txt"]);
        let declared = full.len() as u64;
        let arts = run("INFO2", full, declared);
        let parsed = arts
            .iter()
            .find(|a| a.metadata["type"] == "RecycleBinEntry")
            .expect("a Unicode INFO2 record is emitted");
        assert!(parsed.metadata.get("path_decode").is_none());
    }

    #[test]
    fn an_undecodable_dollar_i_version_produces_a_status_record_not_silence() {
        let mut data = vec![0u8; 64];
        // Version 9 is not a $I header version this build decodes.
        data[0..8].copy_from_slice(&9u64.to_le_bytes());
        let declared = data.len() as u64;
        let arts = run("$IZZZZZZ.bin", data, declared);

        let status = status_of(&arts)
            .expect("an undecodable $I must not vanish: the deletion still happened");
        assert_eq!(status.metadata["content_incomplete"], true);
        assert_eq!(
            status.metadata["content_incomplete_reason"],
            "unresolved_structure"
        );
    }
}
