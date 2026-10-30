#![forbid(unsafe_code)]
pub mod encryption;
pub mod entropy;
pub mod magic;
pub mod overlay;

use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_full, IncompleteReason},
    module::{ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use tracing::debug;

/// How far into an OOXML package the analyser reads to name its family when
/// the first 512 bytes do not (see `magic::ooxml_family`).
const OOXML_HEADER_WINDOW: usize = 16 * 1024;

/// Analyzes FileEntry artifacts for:
/// - File signature (magic bytes) vs extension mismatch detection
/// - Shannon entropy computation
pub struct FileAnalyzer;

/// The outcome of the overlay ("trailing data") check, stated on every record.
///
/// The check walks a file to its format's logical end and reports anything
/// appended past it — the classic way a payload is concealed inside a picture.
/// Three of its four outcomes used to leave the record looking identical: a
/// file walked clean wrote `trailing_data: false`, a file whose walk was
/// stopped wrote `trailing_data_undetermined` that nothing read, and a file
/// whose format this build cannot walk wrote no key at all. All three arrived
/// in the Analysis viewer as a blank em-dash and a "Signature OK" tile. Only
/// the first is evidence that nothing is hidden.
///
/// So the outcome is now a single declared field. The vocabulary is the one
/// `frontend/src/pages/memory/normalize.ts` already uses for a value that is
/// absent for a stated reason, so an examiner meets one set of words across the
/// product rather than a third invented here.
///
/// Read by `frontend/src/pages/analysis/viewers.tsx` (`trailingCheck`).
/// Renaming a variant without changing that reader puts "could not determine"
/// back on screen looking like "nothing was hidden".
pub mod trailing_check {
    /// The key every `FileSignatureAnalysis` record carries.
    pub const KEY: &str = "trailing_data_check";
    /// Why the check did not run, when it did not. Free vocabulary.
    pub const NOT_APPLICABLE_REASON_KEY: &str = "trailing_data_not_applicable_reason";
    /// Bytes were found past the format's logical end.
    pub const FOUND: &str = "found";
    /// The file was walked to its logical end and nothing followed it.
    pub const NONE: &str = "none";
    /// The walk was attempted and could not establish an answer either way.
    pub const UNDETERMINED: &str = "undetermined";
    /// There was no walk to attempt: no logical end this build knows how to find.
    pub const NOT_APPLICABLE: &str = "not_applicable";
    /// `NOT_APPLICABLE` because the content type was never identified.
    pub const REASON_TYPE_NOT_IDENTIFIED: &str = "content_type_not_identified";
    /// `NOT_APPLICABLE` because no walker exists for the identified type.
    pub const REASON_NO_WALKER: &str = "no_logical_end_walker_for_format";
}

impl ForensicsModule for FileAnalyzer {
    fn id(&self) -> &str {
        "plugin.analysis.file_analyzer"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        InputCapability::RandomAccess
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Get filename from metadata
        let name = match artifact.metadata.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
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

        // Extract file extension
        let extension = name
            .rsplit('.')
            .next()
            .filter(|ext| ext.len() < 10 && *ext != name) // avoid treating extensionless files
            .map(|ext| ext.to_lowercase());

        // Read first 512 bytes for magic detection
        let data_source = match artifact.data.as_ref() {
            Some(ds) => ds,
            None => return Ok(vec![]),
        };

        let read_size = 512.min(data_source.size() as usize);
        if read_size < 4 {
            return Ok(vec![]);
        }

        // Loop over short reads: a windowed source may return a handful of bytes
        // per call, and a 6-byte "header" would mis-detect the file type.
        let mut buf = vec![0u8; read_size];
        let bytes_read = read_full(data_source.as_ref(), 0, &mut buf);
        buf.truncate(bytes_read);

        if buf.len() < 4 {
            return Ok(vec![]);
        }

        // Detect content type from magic bytes
        let mut detected = magic::detect_content_type(&buf);

        // An OOXML package whose family is named only inside its first member:
        // Word pads that member's local header with a 520-byte extra field, so
        // the part's bytes start past the 512-byte header window. Read far
        // enough to inflate it rather than leave the family undetermined
        // (HUNT-181).
        if matches!(detected, Some(("OOXML", _))) && data_source.size() > buf.len() as u64 {
            let window = (data_source.size() as usize).min(OOXML_HEADER_WINDOW);
            let mut wider = vec![0u8; window];
            let n = read_full(data_source.as_ref(), 0, &mut wider);
            wider.truncate(n);
            detected = magic::detect_content_type(&wider).or(detected);
        }

        // Compute entropy on available data
        // For entropy, read more data if available
        // How much of the file this measurement is entitled to look at. Kept
        // separately from what came back, so "we only ask for 192 KiB" and "the
        // bytes we asked for were not all there" stay distinguishable.
        let file_bytes = data_source.size();
        let entropy_window = (file_bytes as usize).min(196_608); // max 192KB
        let entropy_data = if file_bytes > 512 {
            let mut entropy_buf = vec![0u8; entropy_window];
            let n = read_full(data_source.as_ref(), 0, &mut entropy_buf);
            entropy_buf.truncate(n);
            entropy_buf
        } else {
            buf.clone()
        };

        let entropy_value = entropy::compute_entropy(&entropy_data);
        let entropy_class = entropy::classify_entropy(entropy_value);
        // The entropy figure comes from at most the first 192 KiB. On a large
        // mixed file — an installer with a plaintext manifest ahead of a packed
        // payload, an archive with a stored first member — the prefix is not
        // the file, and "low entropy: not encrypted" read off a prefix is a
        // claim about bytes nobody measured. The sample is therefore stated
        // beside the number (B7-031).
        let entropy_bytes = entropy_data.len() as u64;
        let entropy_sampled = (entropy_window as u64) < file_bytes;
        // Distinct from sampling: the bytes this measurement DID ask for were
        // not all there. That is content that could not be read whole, and it
        // is the only one of the two that earns the standard pair.
        let entropy_short_read = entropy_bytes < entropy_window as u64;

        // Determine mismatch
        let (signature_mismatch, detected_type, detected_ext) = match detected {
            Some((type_name, canonical_ext)) => {
                let mismatch = match &extension {
                    Some(ext) => !magic::extension_matches_type(ext, type_name),
                    None => false, // No extension => can't call it a mismatch
                };
                (mismatch, Some(type_name), Some(canonical_ext))
            }
            None => (false, None, None),
        };

        // Build magic bytes hex string (first 8 bytes)
        let magic_hex: String = buf.iter().take(8).map(|b| format!("{:02x}", b)).collect();

        // Build analysis result metadata
        let mut analysis = json!({
            // `type` is the discriminator the Analysis UI groups on; without it
            // these records bucket as "Unknown". `analysis_type`/`subtype` are
            // kept for backward compatibility.
            "type": "FileSignatureAnalysis",
            "analysis_type": "file_analysis",
            "subtype": "FileSignatureAnalysis",
            "filename": name,
            "entropy": (entropy_value * 1000.0).round() / 1000.0,
            "entropy_classification": entropy_class,
            "entropy_bytes": entropy_bytes,
            "entropy_file_bytes": file_bytes,
            "entropy_sampled": entropy_sampled,
            "magic_bytes_hex": magic_hex,
        });

        // Both shortfalls can hold at once — a huge file whose 192 KiB window
        // also came back short — and each says something the other does not:
        // one names the file's real size, the other names the bytes that were
        // asked for and missing. Collected rather than assigned, because the
        // second assignment used to overwrite the first and the file's true
        // size then went unstated.
        let mut entropy_notes: Vec<String> = Vec::new();

        if entropy_sampled {
            // Stated on the record beside the figure, and deliberately WITHOUT
            // the `content_incomplete` pair. That pair is counted case-wide and
            // rendered in the report as "N artifact(s) were parsed from content
            // that could not be read or decoded in full". Sampling a prefix by
            // design is not that: the file was read fine, and stamping the pair
            // here would put every file over 192 KiB — most of a disk image —
            // into the court-facing incompleteness count, burying the artifacts
            // whose bytes really were missing.
            entropy_notes.push(format!(
                "entropy was measured over the first {entropy_bytes} of {file_bytes} bytes; it \
                 describes that prefix and not the whole file"
            ));
        }

        if entropy_short_read {
            // The standard pair, so the API, export and court completeness
            // paths see it. A bespoke key alone is read by nobody.
            analysis["content_incomplete"] = json!(true);
            analysis["content_incomplete_reason"] = json!(IncompleteReason::ShortRead.as_str());
            let note = format!(
                "entropy was measured over {entropy_bytes} byte(s); {entropy_window} were \
                 requested and the rest could not be read, so the figure describes only the \
                 bytes that were there"
            );
            // The examiner-facing reader takes the incompleteness sentence from
            // `<flag>_detail` (`frontend/src/lib/incompleteness.ts`), so without
            // this the stamp arrives as `short_read` with no statement of what
            // was short.
            analysis["content_incomplete_detail"] = json!(note);
            entropy_notes.push(note);
        }

        if !entropy_notes.is_empty() {
            // `entropy_sampled` / `entropy_bytes` / `entropy_file_bytes` /
            // `entropy_note` are read by the Analysis viewer through
            // `frontend/src/lib/measuredScope.ts` (`ENTROPY_SCOPE`), which
            // prints the sample beside the figure. Renaming any of these four
            // keys without changing that spec puts the figure back on screen
            // looking like the whole file's entropy.
            analysis["entropy_note"] = json!(entropy_notes.join("; "));
        }

        if let Some(type_name) = detected_type {
            analysis["detected_type"] = json!(type_name);
        }
        // An empty canonical extension means the type names no single one
        // (an OOXML package whose family was not read): say nothing rather
        // than name one (HUNT-209).
        if let Some(ext) = detected_ext.filter(|e| !e.is_empty()) {
            analysis["detected_extension"] = json!(ext);
        }
        if let Some(ref ext) = extension {
            analysis["actual_extension"] = json!(ext);
        }
        analysis["signature_mismatch"] = json!(signature_mismatch);

        if signature_mismatch {
            debug!(
                "Signature mismatch: {} (detected: {:?}, extension: {:?})",
                name, detected_type, extension
            );
        }

        // Overlay / trailing-data detection: for image formats with a definite
        // terminator, decode where the image logically ends and flag any bytes
        // that follow (a file concatenated on the end — a classic hiding trick
        // that a header-only check cannot see). Only pull the whole file when the
        // format is one we can walk, and cap the read so a giant file can't blow
        // memory (an over-cap file is reported as undetermined, never "clean").
        if let Some(type_name) = detected_type {
            const OVERLAY_SCAN_CAP: u64 = 128 * 1024 * 1024;
            let size = data_source.size();
            if overlay::supports(type_name) {
                if !(4..=OVERLAY_SCAN_CAP).contains(&size) {
                    // Never claim "clean": the file was not walked at all.
                    analysis["trailing_data_undetermined"] = json!(true);
                    analysis["trailing_data_undetermined_reason"] =
                        json!(IncompleteReason::CapReached.as_str());
                    analysis[trailing_check::KEY] = json!(trailing_check::UNDETERMINED);
                } else {
                    let mut full = vec![0u8; size as usize];
                    // Short reads are looped over. A single `read_at` could stop
                    // before the image terminator, and the concatenated payload
                    // that a suspect appended past that point would then never be
                    // seen: the file would be reported `trailing_data: false`,
                    // i.e. clean (B2-111).
                    let n = read_full(data_source.as_ref(), 0, &mut full);
                    full.truncate(n);
                    if (n as u64) < size {
                        // The tail we would have to inspect is exactly the part we
                        // could not read. "Could not determine" must not render as
                        // "no trailing data".
                        analysis["trailing_data_undetermined"] = json!(true);
                        analysis["trailing_data_undetermined_reason"] =
                            json!(IncompleteReason::ShortRead.as_str());
                        analysis[trailing_check::KEY] = json!(trailing_check::UNDETERMINED);
                        analysis["bytes_read"] = json!(n);
                        analysis["declared_size"] = json!(size);
                    } else if let Some(end) = overlay::image_logical_end(type_name, &full) {
                        if (end as u64) < full.len() as u64 {
                            let trailing = &full[end..];
                            let trailing_type =
                                magic::detect_content_type(trailing).map(|(t, _)| t);
                            analysis["trailing_data"] = json!(true);
                            analysis[trailing_check::KEY] = json!(trailing_check::FOUND);
                            analysis["trailing_offset"] = json!(end);
                            analysis["trailing_size"] = json!(trailing.len());
                            if let Some(tt) = trailing_type {
                                analysis["trailing_detected_type"] = json!(tt);
                            }
                            debug!(
                                "Trailing data after {}: {} byte(s) at offset {} (looks like {:?})",
                                name,
                                trailing.len(),
                                end,
                                trailing_type
                            );
                        } else {
                            analysis["trailing_data"] = json!(false);
                            analysis[trailing_check::KEY] = json!(trailing_check::NONE);
                        }
                    } else {
                        // The walker could not locate the logical end, so the
                        // presence of an overlay is unknown, not absent.
                        analysis["trailing_data_undetermined"] = json!(true);
                        analysis["trailing_data_undetermined_reason"] =
                            json!(IncompleteReason::UnresolvedStructure.as_str());
                        analysis[trailing_check::KEY] = json!(trailing_check::UNDETERMINED);
                    }
                }
            } else {
                // A type we recognise but have no logical-end walker for. The
                // check did not run; saying nothing here is what made "not
                // checked" and "checked, clean" render alike.
                analysis[trailing_check::KEY] = json!(trailing_check::NOT_APPLICABLE);
                analysis[trailing_check::NOT_APPLICABLE_REASON_KEY] =
                    json!(trailing_check::REASON_NO_WALKER);
            }
        } else {
            // No content type was identified, so there is no format terminator
            // to walk to and nothing to compare a tail against.
            analysis[trailing_check::KEY] = json!(trailing_check::NOT_APPLICABLE);
            analysis[trailing_check::NOT_APPLICABLE_REASON_KEY] =
                json!(trailing_check::REASON_TYPE_NOT_IDENTIFIED);
        }

        let child = Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, analysis)
            .with_parent(artifact.id);

        Ok(vec![child])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use seance_core::data_source::{ByteSliceDataSource, DataSource};
    use std::sync::Arc;
    use uuid::Uuid;

    /// Simple in-memory DataSource for testing
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

    fn make_file_entry(name: &str, data: Vec<u8>) -> Artifact {
        let source = Arc::new(MemorySource { data }) as Arc<dyn DataSource>;
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({"name": name, "size": 1024}),
        )
    }

    #[test]
    fn test_jpeg_with_correct_extension() {
        let analyzer = FileAnalyzer;
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        let artifact = make_file_entry("photo.jpg", data);

        let results = analyzer.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);

        let meta = &results[0].metadata;
        assert_eq!(meta["detected_type"], "JPEG");
        assert_eq!(meta["signature_mismatch"], false);
    }

    #[test]
    fn test_jpeg_with_wrong_extension() {
        let analyzer = FileAnalyzer;
        let data = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46];
        let artifact = make_file_entry("document.docx", data);

        let results = analyzer.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);

        let meta = &results[0].metadata;
        assert_eq!(meta["detected_type"], "JPEG");
        assert_eq!(meta["signature_mismatch"], true);
        assert_eq!(meta["actual_extension"], "docx");
    }

    /// HUNT-181, red before the fix: a LibreOffice Impress presentation (the
    /// tool's own output) opens with `_rels/.rels`; it was labelled "OOXML",
    /// which accepted only docx/docm, so its own `.pptx` was a mismatch.
    #[test]
    fn libreoffice_pptx_is_not_a_signature_mismatch() {
        let data = include_bytes!("../tests/fixtures/libreoffice_impress.pptx").to_vec();
        let results = FileAnalyzer
            .process(&make_file_entry("slides.pptx", data))
            .unwrap();
        let meta = &results[0].metadata;
        assert_eq!(meta["signature_mismatch"], false, "{meta}");
        assert_eq!(meta["detected_type"], "PPTX");
    }

    /// HUNT-181: Word's layout — `[Content_Types].xml` first, its local header
    /// padded with a 520-byte extra field (as in the Word-written
    /// `Document.docx` in plaso's test data), so the part begins past the
    /// 512-byte header window. The family is still read, and a Word document
    /// renamed `.xlsx` is still a mismatch.
    #[test]
    fn word_layout_content_types_past_512_bytes_names_the_family() {
        use std::io::Write;
        let content_types = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/></Types>"#;
        let mut enc =
            flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
        enc.write_all(content_types).unwrap();
        let compressed = enc.finish().unwrap();
        let name = b"[Content_Types].xml";
        let mut zip = Vec::new();
        zip.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00, 0x08, 0x00]);
        zip.extend_from_slice(&[0u8; 8]); // time, date, crc (not checked)
        zip.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(content_types.len() as u32).to_le_bytes());
        zip.extend_from_slice(&(name.len() as u16).to_le_bytes());
        zip.extend_from_slice(&520u16.to_le_bytes());
        zip.extend_from_slice(name);
        zip.extend_from_slice(&[0u8; 520]);
        zip.extend_from_slice(&compressed);
        zip.extend_from_slice(&[0u8; 256]); // the next member, not read

        let meta = FileAnalyzer
            .process(&make_file_entry("report.docx", zip.clone()))
            .unwrap()[0]
            .metadata
            .clone();
        assert_eq!(meta["detected_type"], "DOCX", "{meta}");
        assert_eq!(meta["signature_mismatch"], false);

        let renamed = FileAnalyzer
            .process(&make_file_entry("report.xlsx", zip))
            .unwrap()[0]
            .metadata
            .clone();
        assert_eq!(renamed["signature_mismatch"], true, "{renamed}");
    }

    #[test]
    fn test_entropy_computed() {
        let analyzer = FileAnalyzer;
        // All zeros = low entropy
        let mut data = vec![0xFF, 0xD8, 0xFF, 0xE0]; // JPEG header
        data.extend(vec![0u8; 508]);
        let artifact = make_file_entry("test.jpg", data);

        let results = analyzer.process(&artifact).unwrap();
        assert_eq!(results.len(), 1);

        let meta = &results[0].metadata;
        assert!(meta["entropy"].as_f64().unwrap() < 1.0);
        assert_eq!(meta["entropy_classification"], "low");
    }

    #[test]
    fn test_skips_directories() {
        let analyzer = FileAnalyzer;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({"name": "somedir", "is_directory": true}),
        );

        let results = analyzer.process(&artifact).unwrap();
        assert!(results.is_empty());
    }

    // --- Overlay determination must fail open, never "clean" (B2-111) -------

    /// A source that serves fewer bytes than it declares, and only a few per
    /// call — a windowed/run-list source over a truncated image.
    #[derive(Debug)]
    struct ChunkedShortSource {
        bytes: Vec<u8>,
        declared: u64,
        chunk: usize,
    }

    impl DataSource for ChunkedShortSource {
        fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
            let off = offset as usize;
            if off >= self.bytes.len() {
                return Ok(0);
            }
            let n = buf.len().min(self.bytes.len() - off).min(self.chunk);
            buf[..n].copy_from_slice(&self.bytes[off..off + n]);
            Ok(n)
        }
        fn size(&self) -> u64 {
            self.declared
        }
    }

    /// A complete JPEG with a payload appended after its EOI marker: the classic
    /// hiding trick the overlay check exists to catch.
    fn jpeg_with_overlay() -> Vec<u8> {
        // SOI, then an APP0 segment whose declared length (16) covers its own
        // two length bytes plus 14 payload bytes, then EOI, then the payload.
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        v.extend_from_slice(b"JFIF\0");
        v.extend(std::iter::repeat_n(0x00, 9));
        v.extend_from_slice(&[0xFF, 0xD9]); // EOI
        v.extend_from_slice(b"PK\x03\x04hidden archive payload");
        v
    }

    /// The baseline: the appended payload is found and reported.
    #[test]
    fn a_payload_appended_after_the_image_terminator_is_reported() {
        let artifact = make_file_entry("photo.jpg", jpeg_with_overlay());
        let out = FileAnalyzer.process(&artifact).unwrap();
        let md = &out[0].metadata;
        assert_eq!(md["trailing_data"], json!(true));
        assert!(md.get("trailing_data_undetermined").is_none());
    }

    /// When the file could not be read to its declared end, the tail we would
    /// have to inspect is exactly the part we never saw. Reporting
    /// `trailing_data: false` there would clear a file nobody examined.
    #[test]
    fn an_unreadable_tail_is_undetermined_not_clean() {
        let bytes = jpeg_with_overlay();
        let declared = bytes.len() as u64 * 4;
        let source = Arc::new(ChunkedShortSource {
            bytes,
            declared,
            chunk: 7,
        }) as Arc<dyn DataSource>;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({ "name": "photo.jpg" }),
        );
        let out = FileAnalyzer.process(&artifact).unwrap();
        let md = &out[0].metadata;
        assert_eq!(md["trailing_data_undetermined"], json!(true));
        assert_eq!(md["trailing_data_undetermined_reason"], "short_read");
        assert_eq!(md["declared_size"], json!(declared));
        assert!(
            md.get("trailing_data").is_none(),
            "an unexamined tail must not be reported as clean"
        );
    }

    /// A chunked-but-complete source must still detect the type from its magic:
    /// a single-shot probe would have seen a 7-byte header.
    #[test]
    fn a_chunked_source_still_detects_the_content_type() {
        let bytes = jpeg_with_overlay();
        let declared = bytes.len() as u64;
        let source = Arc::new(ChunkedShortSource {
            bytes,
            declared,
            chunk: 7,
        }) as Arc<dyn DataSource>;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({ "name": "photo.jpg" }),
        );
        let out = FileAnalyzer.process(&artifact).unwrap();
        assert_eq!(out[0].metadata["detected_type"], "JPEG");
        assert_eq!(out[0].metadata["trailing_data"], json!(true));
    }

    /// A complete JPEG with nothing after its EOI marker.
    fn clean_jpeg() -> Vec<u8> {
        let mut v = vec![0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        v.extend_from_slice(b"JFIF\0");
        v.extend(std::iter::repeat_n(0x00, 9));
        v.extend_from_slice(&[0xFF, 0xD9]); // EOI
        v
    }

    /// The four outcomes of the overlay check must be four distinct records.
    ///
    /// Before `trailing_data_check` existed, three of them were the same
    /// record: "walked it, nothing appended" wrote `trailing_data: false`,
    /// "the walk was stopped" wrote a key nothing read, and "no walker for
    /// this format" wrote nothing at all. The Analysis viewer showed all three
    /// as a blank cell in a row tiled "Signature OK" — a clean bill of health
    /// on two files whose tails were never inspected.
    #[test]
    fn every_record_states_whether_the_hidden_data_check_ran() {
        // 1. Walked, payload found.
        let found = FileAnalyzer
            .process(&make_file_entry("photo.jpg", jpeg_with_overlay()))
            .unwrap();
        assert_eq!(found[0].metadata[trailing_check::KEY], "found");

        // 2. Walked, nothing appended. The only one of the four that is
        //    evidence the file hides nothing.
        let clean = FileAnalyzer
            .process(&make_file_entry("photo.jpg", clean_jpeg()))
            .unwrap();
        assert_eq!(clean[0].metadata["trailing_data"], json!(false));
        assert_eq!(clean[0].metadata[trailing_check::KEY], "none");

        // 3. A format this build has no logical-end walker for. Not checked —
        //    which must not read like checked-and-clean.
        let mut pdf = b"%PDF-1.4\n".to_vec();
        pdf.extend_from_slice(b"1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n");
        let na = FileAnalyzer
            .process(&make_file_entry("report.pdf", pdf))
            .unwrap();
        assert_eq!(na[0].metadata["detected_type"], "PDF");
        assert_eq!(na[0].metadata[trailing_check::KEY], "not_applicable");
        assert_eq!(
            na[0].metadata[trailing_check::NOT_APPLICABLE_REASON_KEY],
            "no_logical_end_walker_for_format"
        );
        assert!(
            na[0].metadata.get("trailing_data").is_none(),
            "a file that was never walked must not carry an overlay verdict"
        );

        // 4. Content type never identified: there was no terminator to walk to.
        let unknown = FileAnalyzer
            .process(&make_file_entry("blob.dat", vec![0x5A; 4096]))
            .unwrap();
        assert!(unknown[0].metadata.get("detected_type").is_none());
        assert_eq!(unknown[0].metadata[trailing_check::KEY], "not_applicable");
        assert_eq!(
            unknown[0].metadata[trailing_check::NOT_APPLICABLE_REASON_KEY],
            "content_type_not_identified"
        );
    }

    /// A walk that was attempted and could not finish is `undetermined`, and
    /// says so on the same key as the other three outcomes — so a reader that
    /// only knows `trailing_data_check` cannot miss it.
    #[test]
    fn a_stopped_walk_is_undetermined_on_the_declared_key() {
        let bytes = jpeg_with_overlay();
        let declared = bytes.len() as u64 * 4;
        let source = Arc::new(ChunkedShortSource {
            bytes,
            declared,
            chunk: 7,
        }) as Arc<dyn DataSource>;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({ "name": "photo.jpg" }),
        );
        let md = &FileAnalyzer.process(&artifact).unwrap()[0].metadata;
        assert_eq!(md[trailing_check::KEY], "undetermined");
        assert_eq!(md["trailing_data_undetermined_reason"], "short_read");
    }

    /// Entropy measured over a prefix must say so.
    ///
    /// What an examiner learns: whether a file is encrypted or packed. The
    /// figure comes from at most the first 192 KiB, and an installer with a
    /// plaintext manifest ahead of a packed payload measures low over that
    /// prefix. Reported bare, that is "not encrypted" said about bytes nobody
    /// measured (B7-031).
    #[test]
    fn entropy_over_a_prefix_is_declared_as_sampled() {
        // Just over the 192 KiB entropy window, so the sample is a prefix.
        let mut bytes = b"\xff\xd8\xff\xe0".to_vec();
        bytes.resize(196_608 + 4096, 0x41);
        let declared = bytes.len() as u64;
        let source = Arc::new(ByteSliceDataSource::new(bytes)) as Arc<dyn DataSource>;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({ "name": "installer.bin" }),
        );

        let out = FileAnalyzer.process(&artifact).unwrap();
        let md = &out[0].metadata;
        assert_eq!(md["entropy_sampled"], json!(true));
        assert_eq!(md["entropy_bytes"], json!(196_608u64));
        assert_eq!(md["entropy_file_bytes"], json!(declared));
        // The sentence, not just the flag: the note names both figures so the
        // examiner reads what the number describes.
        let note = md["entropy_note"]
            .as_str()
            .expect("the sample is explained");
        assert!(note.contains("196608"), "{note}");
        assert!(note.contains(&declared.to_string()), "{note}");
        // And the disclaimer itself, not just two numbers side by side: the
        // figure must be stated as describing the prefix rather than the file,
        // because "low entropy: not encrypted" read off a prefix is a claim
        // about bytes nobody measured.
        assert!(note.contains("not the whole file"), "{note}");
        // Deliberately NOT the `content_incomplete` pair. That pair is counted
        // case-wide and rendered in the report as artifacts parsed from content
        // that could not be read in full. This file was read fine; only the
        // measurement is over a prefix, by design. Stamping it here would put
        // every file over 192 KiB — most of a disk image — into the
        // court-facing incompleteness count and bury the artifacts whose bytes
        // really were missing. Sampling is declared on its own keys instead.
        assert!(
            md.get("content_incomplete").is_none(),
            "sampling by design is not unreadable content"
        );
        assert!(md.get("content_incomplete_reason").is_none());
    }

    /// When the measurement is both a prefix sample AND short of the prefix it
    /// asked for, the note must state both.
    ///
    /// What an examiner learns: how far the entropy figure reaches. The two
    /// shortfalls answer different questions — how big the file really is, and
    /// how much of the window was actually readable — and a note carrying only
    /// the second leaves the file's true size unstated, which is the figure the
    /// "is this whole file encrypted?" question turns on.
    #[test]
    fn a_sampled_and_short_entropy_measurement_states_both_shortfalls() {
        // Declares 4 MB, serves 100 000 bytes: past the 192 KiB window (so the
        // measurement is a prefix sample) and short of it (so the prefix asked
        // for was not all there).
        let mut bytes = b"\xff\xd8\xff\xe0".to_vec();
        bytes.resize(100_000, 0x41);
        let declared = 4_000_000u64;
        let source = Arc::new(ChunkedShortSource {
            bytes,
            declared,
            chunk: 65_536,
        }) as Arc<dyn DataSource>;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({ "name": "installer.bin" }),
        );

        let out = FileAnalyzer.process(&artifact).unwrap();
        let md = &out[0].metadata;
        assert_eq!(md["entropy_sampled"], json!(true));
        assert_eq!(md["entropy_bytes"], json!(100_000u64));
        assert_eq!(md["entropy_file_bytes"], json!(declared));
        let note = md["entropy_note"].as_str().expect("both are explained");
        // The sampling sentence, which is the only one naming the real size.
        assert!(note.contains(&declared.to_string()), "{note}");
        assert!(note.contains("not the whole file"), "{note}");
        // And the short-read sentence, which names the window that was asked
        // for and not delivered.
        assert!(note.contains("196608"), "{note}");
        assert!(note.contains("could not be read"), "{note}");
        // The short read — unlike the sampling — is genuinely unreadable
        // content, so it earns the standard pair with its own sentence.
        assert_eq!(md["content_incomplete"], json!(true));
        assert_eq!(md["content_incomplete_reason"], "short_read");
        assert!(md["content_incomplete_detail"]
            .as_str()
            .expect("the stamp says what was short")
            .contains("196608"));
    }

    /// A file that fits inside the window is measured whole, and claims nothing
    /// about being incomplete.
    #[test]
    fn entropy_over_a_whole_small_file_is_not_declared_sampled() {
        let bytes = vec![0x41u8; 2048];
        let source = Arc::new(ByteSliceDataSource::new(bytes)) as Arc<dyn DataSource>;
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(source),
            json!({ "name": "small.bin" }),
        );

        let out = FileAnalyzer.process(&artifact).unwrap();
        let md = &out[0].metadata;
        assert_eq!(md["entropy_sampled"], json!(false));
        assert_eq!(md["entropy_bytes"], json!(2048u64));
        assert!(md.get("content_incomplete").is_none());
    }
}
