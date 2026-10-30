#![forbid(unsafe_code)]
//! Optical character recognition (OCR) over raster image files.
//!
//! [`OcrParser`] inspects every [`FileEntry`](ArtifactType::FileEntry) /
//! [`FileContent`](ArtifactType::FileContent) that enters the pipeline,
//! self-selects raster images (by filename extension **or** content magic bytes,
//! the same signal the EXIF module uses), and recognizes any text baked into the
//! pixels. Recognized text is emitted as a single `OcrText`
//! [`ParsedRecord`](ArtifactType::ParsedRecord) child parented to the image, so
//! text inside screenshots (passwords, notes, chat captures) becomes full-text
//! searchable.
//!
//! # Self-contained, pure-Rust engine
//!
//! Recognition runs entirely in-process on [`ocrs`], which itself runs on the
//! [`rten`] machine-learning runtime. There is **no** external `tesseract`
//! binary and **no** native library dependency. The two neural network models
//! (text detection and text recognition) are compiled directly into the binary
//! with [`include_bytes!`], so an examiner's machine needs nothing installed.
//!
//! The engine (models parsed once) is built lazily on first use and shared for
//! the life of the process behind a [`Mutex`]. Serializing OCR calls is
//! deliberate: `rten` already parallelizes a single inference internally, so
//! running many images concurrently would oversubscribe the CPU.
//!
//! # Graceful degradation
//!
//! Oversized images, undecodable bytes, and (the theoretical case of) a model
//! that fails to load never fail the pipeline and never panic — but they do not
//! emit nothing either. Each leaves an `OcrParseStatus` record saying the image
//! was not examined and why, because an image this tool could not read must not
//! be indistinguishable from a picture with no writing in it.
//!
//! # Registration
//!
//! ```rust,ignore
//! orchestrator.register_module(std::sync::Arc::new(seance_plugin_ocr::OcrParser::new()));
//! ```

use ocrs::{ImageSource, OcrEngine, OcrEngineParams};
use rten::Model;
use seance_core::{
    artifact::{Artifact, ArtifactType},
    io::{read_full, IncompleteReason},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::json;
use std::sync::{Mutex, OnceLock};
use tracing::{debug, warn};
use uuid::Uuid;

/// Hard cap on the number of bytes read from an image before OCR, bounding
/// memory and the work handed to the recognition engine.
///
/// An image over the cap is NOT skipped silently: it yields a `not_examined`
/// record saying that it was over the limit and was not read. This comment used
/// to say "skipped entirely (returning no record)", which described the worse
/// behaviour — an absence a reader cannot tell from an image with no text — and
/// not the one the code has.
const MAX_IMAGE_BYTES: u64 = 32 * 1024 * 1024;

/// Raster image extensions this module will attempt to OCR.
const IMAGE_EXTS: &[&str] = &["jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff"];

/// Text-detection model (finds word bounding boxes). Compiled into the binary.
static DETECTION_MODEL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/models/text-detection.rten"
));

/// Text-recognition model (reads characters within a line). Compiled in.
static RECOGNITION_MODEL: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/models/text-recognition.rten"
));

/// Runs OCR over raster image files using the embedded, pure-Rust engine.
pub struct OcrParser;

impl OcrParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for OcrParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for OcrParser {
    fn id(&self) -> &str {
        "plugin.media.ocr"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry, ArtifactType::FileContent]
    }

    fn input_capability(&self) -> InputCapability {
        // We read the raw bytes ourselves (capped) and decode them in-process.
        InputCapability::RandomAccess
    }

    fn execution_mode(&self) -> ExecutionMode {
        // OCR is expensive (a full text-detection + recognition pass per image),
        // so it does not run on every image during ingest — the examiner triggers
        // it on demand (e.g. across the picture gallery), like Belkasoft.
        ExecutionMode::OptIn
    }

    fn process(&self, artifact: &Artifact) -> Result<Vec<Artifact>, ModuleError> {
        // Directories have no content.
        if artifact
            .metadata
            .get("is_directory")
            .and_then(|v| v.as_bool())
            == Some(true)
        {
            return Ok(Vec::new());
        }

        let Some(data) = artifact.data.as_ref() else {
            return Ok(Vec::new());
        };

        // Self-select raster images by extension OR content magic bytes.
        let name = source_image_name(artifact);
        let ext_ok = image_extension_is_supported(&name);
        // The magic probe loops over short reads: a windowed source returning a
        // few bytes per call would otherwise fail the gate and a real image
        // would never be OCR'd (B2-109).
        let mut head = [0u8; 16];
        let n = read_full(data.as_ref(), 0, &mut head);
        let magic_ok = is_supported_image(&head[..n]);
        if !ext_ok && !magic_ok {
            return Ok(Vec::new());
        }

        // Bound the read: skip images over the cap, skip empties. An over-cap
        // image is NOT silently dropped — a picture that was never examined must
        // not look like a picture with no text in it (B2-109).
        let size = data.size();
        if size == 0 {
            return Ok(Vec::new());
        }
        if size > MAX_IMAGE_BYTES {
            return Ok(vec![not_examined_record(
                artifact,
                &name,
                "OverSizeCap",
                IncompleteReason::CapReached,
                size,
                0,
                "Image exceeds the OCR size cap; no text recognition was attempted",
            )]);
        }

        let mut buf = vec![0u8; size as usize];
        let read = read_full(data.as_ref(), 0, &mut buf);
        buf.truncate(read);
        if buf.len() < 8 {
            return Ok(Vec::new());
        }
        // A short read means the decoder sees a truncated image: it may recognise
        // only part of the page, or nothing at all. Either way the result is not
        // "this image contains no text".
        if (buf.len() as u64) < size {
            return Ok(vec![not_examined_record(
                artifact,
                &name,
                "ShortRead",
                IncompleteReason::ShortRead,
                size,
                buf.len() as u64,
                "Image ended before its declared size; OCR was not attempted on a truncated image",
            )]);
        }

        debug!("OcrParser inspecting artifact ID: {}", artifact.id);

        let text = match run_ocr(&buf) {
            Ok(t) => t,
            // No text is a real answer about a picture, and produces no record.
            Err(OcrFailure::NoText) => return Ok(Vec::new()),
            // Everything else is a failure to look. Returning nothing for it
            // made an image the tool could not decode, or could not run the
            // engine over, indistinguishable from a photograph with no writing
            // in it — and "no text in this picture" is a statement an examiner
            // may be asked to stand over (B6-014).
            Err(failure) => {
                return Ok(vec![not_examined_record(
                    artifact,
                    &name,
                    failure.status(),
                    IncompleteReason::UnresolvedStructure,
                    size,
                    buf.len() as u64,
                    &failure.message(),
                )])
            }
        };

        Ok(
            build_ocr_record(artifact.case_id, artifact.id, &name, &text)
                .into_iter()
                .collect(),
        )
    }
}

/// Best-effort human-readable name for the source image.
fn source_image_name(artifact: &Artifact) -> String {
    artifact
        .metadata
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| artifact.metadata.get("path").and_then(|v| v.as_str()))
        .map(|s| s.to_string())
        .unwrap_or_else(|| artifact.id.to_string())
}

/// Extension-based image gate. Case-insensitive; requires an actual `.ext`.
fn image_extension_is_supported(name: &str) -> bool {
    if !name.contains('.') {
        return false;
    }
    match name.rsplit('.').next() {
        Some(ext) => {
            let ext = ext.to_ascii_lowercase();
            IMAGE_EXTS.contains(&ext.as_str())
        }
        None => false,
    }
}

/// Content-based raster-image detection by magic bytes.
fn is_supported_image(head: &[u8]) -> bool {
    // JPEG: FF D8 FF
    if head.len() >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF {
        return true;
    }
    // PNG signature
    if head.len() >= 8 && head[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return true;
    }
    // GIF: "GIF87a" / "GIF89a"
    if head.len() >= 6 && (&head[..6] == b"GIF87a" || &head[..6] == b"GIF89a") {
        return true;
    }
    // BMP: "BM"
    if head.len() >= 2 && &head[..2] == b"BM" {
        return true;
    }
    // TIFF little-endian "II*\0" / big-endian "MM\0*"
    if head.len() >= 4
        && (head[..4] == [0x49, 0x49, 0x2A, 0x00] || head[..4] == [0x4D, 0x4D, 0x00, 0x2A])
    {
        return true;
    }
    // WEBP: "RIFF" .... "WEBP"
    if head.len() >= 12 && &head[..4] == b"RIFF" && &head[8..12] == b"WEBP" {
        return true;
    }
    false
}

/// Build the `OcrText` [`ParsedRecord`] from a raw OCR string.
///
/// Returns `None` when the recognized text is empty or whitespace-only (the
/// "empty OCR -> no record" rule). Short but non-whitespace text is kept.
fn build_ocr_record(
    case_id: Uuid,
    parent_id: Uuid,
    source_image: &str,
    ocr_text: &str,
) -> Option<Artifact> {
    let trimmed = ocr_text.trim();
    if trimmed.is_empty() {
        return None;
    }
    let char_count = trimmed.chars().count();
    let metadata = json!({
        // `type` is the discriminator the Analysis UI / search indexer group on.
        // `analysis_type` / `subtype` are kept for consistency with sibling plugins.
        "type": "OcrText",
        "analysis_type": "ocr",
        "subtype": "OcrText",
        "text": trimmed,
        "char_count": char_count,
        "source_image": source_image,
    });
    Some(Artifact::new(case_id, ArtifactType::ParsedRecord, None, metadata).with_parent(parent_id))
}

/// A record stating that an image was selected for OCR but not examined.
///
/// Forensic meaning: an OCR sweep is read as "these pictures were searched for
/// text". An image that produced no record is indistinguishable from an image
/// that held no text — so a screenshot too large to load, or one that could not
/// be read whole, must say so rather than silently leaving the gallery.
fn not_examined_record(
    artifact: &Artifact,
    source_image: &str,
    status: &str,
    reason: IncompleteReason,
    declared_size: u64,
    bytes_read: u64,
    message: &str,
) -> Artifact {
    let metadata = json!({
        "type": "OcrParseStatus",
        "analysis_type": "ocr",
        "subtype": "ocr_not_examined",
        "status": status,
        "content_incomplete": true,
        "content_incomplete_reason": reason.as_str(),
        "source_image": source_image,
        "declared_size": declared_size,
        "bytes_read": bytes_read,
        "max_image_bytes": MAX_IMAGE_BYTES,
        "message": message,
        "name": format!("OCR not performed: {source_image}"),
    });
    Artifact::new(artifact.case_id, ArtifactType::ParsedRecord, None, metadata)
        .with_parent(artifact.id)
}

/// Process-wide OCR engine. `None` if the embedded models fail to parse (a build
/// bug rather than a runtime condition). Built lazily on first OCR and shared for
/// the life of the process; the `Mutex` serializes inference (see module docs).
static ENGINE: OnceLock<Option<Mutex<OcrEngine>>> = OnceLock::new();

/// Build the OCR engine from the two embedded models.
fn build_engine() -> anyhow::Result<OcrEngine> {
    // `load_static_slice` borrows the embedded bytes directly (no heap copy).
    let detection_model = Model::load_static_slice(DETECTION_MODEL)?;
    let recognition_model = Model::load_static_slice(RECOGNITION_MODEL)?;
    let engine = OcrEngine::new(OcrEngineParams {
        detection_model: Some(detection_model),
        recognition_model: Some(recognition_model),
        ..Default::default()
    })?;
    Ok(engine)
}

/// Return the shared engine, building it on first use. `None` only if the
/// embedded models fail to load.
fn engine() -> Option<&'static Mutex<OcrEngine>> {
    ENGINE
        .get_or_init(|| match build_engine() {
            Ok(e) => Some(Mutex::new(e)),
            Err(e) => {
                warn!("OCR engine failed to initialize from embedded models: {e}");
                None
            }
        })
        .as_ref()
}

/// Why an image yielded no recognized text.
///
/// Four outcomes and not one, because they support opposite conclusions.
/// [`OcrFailure::NoText`] is a finding about the picture; the other three are
/// findings about this tool, and must never be reported as the first.
#[derive(Debug, Clone, PartialEq, Eq)]
enum OcrFailure {
    /// The recognition engine could not be built, so no image in this run was
    /// examined at all.
    EngineUnavailable,
    /// The bytes do not decode as an image this build can read.
    DecodeFailed(String),
    /// The engine ran and errored.
    InferenceFailed(String),
    /// The engine ran and found no text. The only one of the four that says
    /// something about the evidence.
    NoText,
}

impl OcrFailure {
    /// Stable identifier for the status record.
    fn status(&self) -> &'static str {
        match self {
            OcrFailure::EngineUnavailable => "EngineUnavailable",
            OcrFailure::DecodeFailed(_) => "DecodeFailed",
            OcrFailure::InferenceFailed(_) => "InferenceFailed",
            OcrFailure::NoText => "NoText",
        }
    }

    /// What an examiner is told.
    fn message(&self) -> String {
        match self {
            OcrFailure::EngineUnavailable => {
                "The text-recognition engine could not be started, so this image was not \
                 examined; this is not a finding that the image holds no text"
                    .to_string()
            }
            OcrFailure::DecodeFailed(e) => format!(
                "The file was selected as an image and could not be decoded, so no text \
                 recognition was attempted: {e}"
            ),
            OcrFailure::InferenceFailed(e) => format!(
                "Text recognition ran on this image and failed, so nothing here says whether it \
                 holds text: {e}"
            ),
            OcrFailure::NoText => {
                "Text recognition ran on this image and found no text".to_string()
            }
        }
    }
}

/// Decode `image_bytes` and recognize any text in them.
///
/// `Err` distinguishes "no text in this picture" from "this tool did not look",
/// which the caller turns into a record or into silence accordingly. This is
/// the single seam behind which the neural engine lives, keeping record-building
/// logic testable.
fn run_ocr(image_bytes: &[u8]) -> Result<String, OcrFailure> {
    let Some(engine) = engine() else {
        return Err(OcrFailure::EngineUnavailable);
    };

    // Decode to RGB8 (the format `ImageSource::from_bytes` expects).
    let img = match image::load_from_memory(image_bytes) {
        Ok(img) => img.into_rgb8(),
        Err(e) => {
            debug!("OCR: image failed to decode: {e}");
            return Err(OcrFailure::DecodeFailed(e.to_string()));
        }
    };
    let dims = img.dimensions();

    // Lock is held across a single image's inference. `rten` parallelizes
    // internally, so this bounds total CPU use rather than throttling it.
    let guard = match engine.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    };

    let text = (|| -> anyhow::Result<String> {
        let source = ImageSource::from_bytes(img.as_raw(), dims)?;
        let input = guard.prepare_input(source)?;
        guard.get_text(&input)
    })();

    match text {
        Ok(t) if !t.trim().is_empty() => Ok(t),
        Ok(_) => Err(OcrFailure::NoText),
        Err(e) => {
            debug!("OCR inference failed: {e}");
            Err(OcrFailure::InferenceFailed(e.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Only the tests build a `DataSource`; the module itself reads through the
    // artifact it is handed.
    use seance_core::data_source::ByteSliceDataSource;
    use seance_core::data_source::DataSource;
    use serde_json::json;
    use std::sync::Arc;
    use uuid::Uuid;

    fn file_entry(bytes: Vec<u8>, name: &str) -> Artifact {
        let data: Arc<dyn DataSource> = Arc::new(ByteSliceDataSource::new(bytes));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(data),
            json!({ "name": name }),
        )
    }

    // ---- module metadata ---------------------------------------------------

    #[test]
    fn module_metadata_is_stable() {
        let p = OcrParser::new();
        assert_eq!(p.id(), "plugin.media.ocr");
        assert_eq!(
            p.subscribes_to(),
            vec![ArtifactType::FileEntry, ArtifactType::FileContent]
        );
        assert_eq!(p.input_capability(), InputCapability::RandomAccess);
        // OCR is opt-in: it must not run automatically during ingest.
        assert_eq!(p.execution_mode(), ExecutionMode::OptIn);
    }

    // ---- extension gate ----------------------------------------------------

    #[test]
    fn extension_gate_accepts_known_image_extensions() {
        for name in [
            "shot.png",
            "photo.JPG",
            "a.jpeg",
            "b.gif",
            "c.bmp",
            "d.webp",
            "e.tif",
            "f.tiff",
        ] {
            assert!(
                image_extension_is_supported(name),
                "{name} should be accepted"
            );
        }
    }

    #[test]
    fn extension_gate_rejects_non_images_and_extensionless() {
        for name in ["notes.txt", "archive.zip", "README", "png", "binary.exe"] {
            assert!(
                !image_extension_is_supported(name),
                "{name} should be rejected"
            );
        }
    }

    // ---- magic gate --------------------------------------------------------

    #[test]
    fn magic_gate_detects_raster_formats() {
        assert!(is_supported_image(&[0xFF, 0xD8, 0xFF, 0xE0])); // JPEG
        assert!(is_supported_image(&[
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
        ])); // PNG
        assert!(is_supported_image(b"GIF89a....")); // GIF
        assert!(is_supported_image(b"BM....")); // BMP
        assert!(is_supported_image(&[0x49, 0x49, 0x2A, 0x00])); // TIFF LE
        assert!(is_supported_image(b"RIFF\0\0\0\0WEBPVP8 ")); // WEBP
    }

    #[test]
    fn magic_gate_rejects_non_images() {
        assert!(!is_supported_image(&[0x00, 0x01, 0x02, 0x03]));
        assert!(!is_supported_image(b"%PDF-1.7"));
        assert!(!is_supported_image(&[]));
    }

    // ---- record construction ----------------------------------------------

    #[test]
    fn build_record_from_ocr_string_has_expected_shape() {
        let case_id = Uuid::new_v4();
        let parent_id = Uuid::new_v4();
        let rec = build_ocr_record(
            case_id,
            parent_id,
            "screenshot.png",
            "  Passw0rd: hunter2\n",
        )
        .expect("non-empty text yields a record");

        assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(rec.case_id, case_id);
        assert_eq!(rec.parent_id, Some(parent_id));
        assert_eq!(rec.metadata["type"], "OcrText");
        assert_eq!(rec.metadata["analysis_type"], "ocr");
        assert_eq!(rec.metadata["subtype"], "OcrText");
        assert_eq!(rec.metadata["text"], "Passw0rd: hunter2");
        assert_eq!(rec.metadata["char_count"], 17);
        assert_eq!(rec.metadata["source_image"], "screenshot.png");
    }

    #[test]
    fn build_record_keeps_short_nonwhitespace_text() {
        let rec = build_ocr_record(Uuid::new_v4(), Uuid::new_v4(), "img.png", "  hi  ")
            .expect("short non-whitespace text is kept");
        assert_eq!(rec.metadata["text"], "hi");
        assert_eq!(rec.metadata["char_count"], 2);
    }

    #[test]
    fn empty_or_whitespace_ocr_yields_no_record() {
        assert!(build_ocr_record(Uuid::new_v4(), Uuid::new_v4(), "img.png", "").is_none());
        assert!(build_ocr_record(Uuid::new_v4(), Uuid::new_v4(), "img.png", "   \n\t  ").is_none());
    }

    // ---- process gating ----------------------------------------------------

    #[test]
    fn process_is_noop_for_non_image_artifact() {
        let artifact = file_entry(
            vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07],
            "notes.txt",
        );
        let out = OcrParser::new().process(&artifact).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn process_is_noop_for_directory() {
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "pics", "is_directory": true }),
        );
        let out = OcrParser::new().process(&artifact).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn process_is_noop_when_data_source_missing() {
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            None,
            json!({ "name": "ghost.png" }),
        );
        let out = OcrParser::new().process(&artifact).unwrap();
        assert!(out.is_empty());
    }

    /// An over-cap image is skipped without OCR — but it must not vanish. The
    /// case has to show that this picture was never examined, otherwise a
    /// skipped screenshot is indistinguishable from one with no text on it
    /// (B2-109).
    #[test]
    fn process_reports_an_oversized_image_as_not_examined() {
        #[derive(Debug)]
        struct HugePng;
        impl DataSource for HugePng {
            fn read_at(&self, offset: u64, buf: &mut [u8]) -> std::io::Result<usize> {
                // Serve a valid PNG signature at offset 0, zeros elsewhere.
                const SIG: [u8; 8] = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
                for (i, b) in buf.iter_mut().enumerate() {
                    let pos = offset as usize + i;
                    *b = if pos < SIG.len() { SIG[pos] } else { 0 };
                }
                Ok(buf.len())
            }
            fn size(&self) -> u64 {
                MAX_IMAGE_BYTES + 1
            }
        }
        let data: Arc<dyn DataSource> = Arc::new(HugePng);
        let artifact = Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(data),
            json!({ "name": "huge.png" }),
        );
        let out = OcrParser::new().process(&artifact).unwrap();
        assert_eq!(out.len(), 1, "a skipped image must still leave a record");
        let md = &out[0].metadata;
        assert_eq!(md["type"], "OcrParseStatus");
        assert_eq!(md["status"], "OverSizeCap");
        assert_eq!(md["content_incomplete"], json!(true));
        assert_eq!(md["content_incomplete_reason"], "cap_reached");
        assert!(md.get("text").is_none(), "no text may be claimed");
    }

    #[test]
    fn run_ocr_names_a_decode_failure_rather_than_reporting_no_text() {
        // Bytes that pass no image decoder must not panic — and must not come
        // back as "no text". The two answers support opposite conclusions
        // (B6-014).
        let err = run_ocr(b"this is definitely not an image file at all")
            .expect_err("undecodable bytes are not a recognition result");
        assert!(
            matches!(err, OcrFailure::DecodeFailed(_)),
            "expected a decode failure, got {err:?}"
        );
        assert_eq!(err.status(), "DecodeFailed");
        assert!(
            err.message().contains("could not be decoded"),
            "{}",
            err.message()
        );
        assert_ne!(err, OcrFailure::NoText);
    }

    /// An image the tool could not read leaves a record saying so.
    ///
    /// What an examiner learns: whether "there is no text in this picture" is
    /// supportable. A file selected as an image and then not decodable produced
    /// no record at all, which reads on the page as a picture that was examined
    /// and found blank (B6-014).
    #[test]
    fn an_undecodable_image_leaves_a_record_saying_it_was_not_examined() {
        // PNG magic so the module selects it, followed by bytes no decoder can
        // make an image out of.
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&[0x41u8; 512]);
        let artifact = file_entry(bytes, "corrupt.png");

        let out = OcrParser::new().process(&artifact).unwrap();
        assert_eq!(out.len(), 1, "{out:?}");
        let md = &out[0].metadata;
        assert_eq!(md["type"], "OcrParseStatus");
        assert_eq!(md["status"], "DecodeFailed");
        assert_eq!(md["content_incomplete"], json!(true));
        assert_eq!(md["content_incomplete_reason"], "unresolved_structure");
        assert_eq!(md["source_image"], "corrupt.png");
        assert!(md.get("text").is_none(), "no text may be claimed");
    }

    // ---- real end-to-end recognition (embedded models, no external deps) ---
    //
    // This is the proof the engine is genuinely self-contained: it decodes a
    // real rendered-text PNG, runs the embedded detection+recognition models,
    // and asserts the known words come back. It needs nothing installed on the
    // host. It loads ~12 MB of models and runs inference, so it is the slowest
    // test in this crate (~1-2s), but it exercises the whole pipeline.

    #[test]
    fn ocr_recovers_text_from_rendered_png() {
        // 640x160 PNG rendered with Arial: two lines of black-on-white text.
        let png = include_bytes!("../tests/fixtures/ocr_sample.png");
        let text = run_ocr(png).expect("OCR should recover rendered text");
        let upper = text.to_uppercase();
        // Assert on distinctive tokens; exact spacing/casing from the recognizer
        // is not guaranteed, so match on content that must be present.
        assert!(
            upper.contains("FELT") && upper.contains("2026"),
            "recovered text was {text:?}"
        );
        assert!(upper.contains("WAREHOUSE"), "recovered text was {text:?}");
    }

    #[test]
    fn process_emits_ocr_record_for_real_image() {
        // End-to-end through `process`: a real PNG FileEntry yields one OcrText
        // ParsedRecord parented to the image, with the recognized text.
        let png = include_bytes!("../tests/fixtures/ocr_sample.png").to_vec();
        let artifact = file_entry(png, "screenshot.png");
        let out = OcrParser::new().process(&artifact).unwrap();
        assert_eq!(out.len(), 1, "expected exactly one OcrText record");
        let rec = &out[0];
        assert_eq!(rec.artifact_type, ArtifactType::ParsedRecord);
        assert_eq!(rec.parent_id, Some(artifact.id));
        assert_eq!(rec.metadata["type"], "OcrText");
        assert_eq!(rec.metadata["source_image"], "screenshot.png");
        let text = rec.metadata["text"].as_str().unwrap().to_uppercase();
        assert!(text.contains("FELT"), "recovered text was {text:?}");
    }

    // ---- images that were never examined (B2-109) --------------------------

    use seance_core::test_support::TruncatedSource;

    fn short_artifact(bytes: Vec<u8>, declared: u64, name: &str) -> Artifact {
        let data: Arc<dyn DataSource> = Arc::new(TruncatedSource::new(bytes, declared));
        Artifact::new(
            Uuid::new_v4(),
            ArtifactType::FileEntry,
            Some(data),
            json!({ "name": name }),
        )
    }

    /// A truncated image is not OCR'd as if whole; the shortfall is reported.
    #[test]
    fn a_truncated_image_reports_that_ocr_was_not_attempted() {
        let png = b"\x89PNG\r\n\x1a\nmore bytes here".to_vec();
        let declared = png.len() as u64 * 4;
        let art = short_artifact(png.clone(), declared, "cut.png");
        let out = OcrParser::new().process(&art).unwrap();
        assert_eq!(out.len(), 1);
        let md = &out[0].metadata;
        assert_eq!(md["status"], "ShortRead");
        assert_eq!(md["content_incomplete_reason"], "short_read");
        assert_eq!(md["bytes_read"], json!(png.len() as u64));
        assert_eq!(md["declared_size"], json!(declared));
    }
}
