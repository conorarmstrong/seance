#![forbid(unsafe_code)]
//! Image EXIF / metadata extraction module.
//!
//! [`ExifParser`] inspects every [`FileEntry`](ArtifactType::FileEntry) that
//! enters the pipeline, self-selects images by **content magic bytes** (JPEG,
//! TIFF, HEIF/HEIC, PNG) rather than filename, and reads their EXIF metadata via
//! the pure-Rust `kamadak-exif` crate. For each image carrying usable metadata it
//! emits a single `exif` [`ParsedRecord`](ArtifactType::ParsedRecord) child whose
//! `parent_id` is the source file, giving the UI a dedicated metadata / GPS
//! viewer surface.
//!
//! # GPS
//!
//! `GPSLatitude`/`GPSLongitude` rational degree-minute-second triples are combined
//! with their `N`/`S`/`E`/`W` reference into signed decimal-degree floats
//! (`gps_lat` / `gps_lon`). `GPSAltitude` is signed by its reference byte (below
//! sea level is negative). When both latitude and longitude resolve, `has_gps` is
//! `true`; otherwise it is `false` and no `gps_*` keys are emitted.
//!
//! # Timestamps
//!
//! EXIF `DateTimeOriginal` / `DateTime` are stored with no time zone and are
//! conventionally local wall-clock time. They are emitted verbatim (e.g.
//! `"2021:07:04 15:30:00"`); the zone is unknown / local and is not fabricated.
//!
//! # Honesty & robustness
//!
//! Absent tags are omitted, never fabricated. Malformed, truncated, or corrupt
//! images never panic and never fail the pipeline. An image with no Exif
//! segment yields an `exif_status: "not_present"` record when its pixels decode
//! (else nothing); an image whose EXIF could not be read yields an
//! `exif_status: "exif_unreadable"` record carrying the error and the
//! incompleteness pair, never a "no EXIF" claim. `width`/`height` always carry
//! `dimensions_source` — `decoded` or `exif_declared`. A readable Exif segment
//! with zero usable tags emits nothing.
//!
//! # Registration
//!
//! Register with the orchestrator like any other automatic module:
//!
//! ```rust,ignore
//! orchestrator.register_module(std::sync::Arc::new(seance_plugin_exif::ExifParser::new()));
//! ```

#[cfg(test)]
mod tests;

use exif::{In, Reader, Tag, Value};
use seance_core::{
    artifact::{Artifact, ArtifactType},
    data_source::SourceCursor,
    io::{read_full, IncompleteReason},
    module::{ExecutionMode, ForensicsModule, InputCapability, ModuleError},
};
use serde_json::{json, Map, Value as JsonValue};
use std::io::BufReader;
use tracing::debug;

/// `dimensions_source` when `width`/`height` were decoded from the bitstream.
const DIMENSIONS_DECODED: &str = "decoded";
/// `dimensions_source` when `width`/`height` are the EXIF `PixelXDimension` /
/// `PixelYDimension` the file declares, because the bitstream could not be
/// decoded (HEIC, TIFF): what the header claims, not what was measured.
const DIMENSIONS_DECLARED: &str = "exif_declared";

/// Extracts EXIF / camera / GPS metadata from image files.
pub struct ExifParser;

impl ExifParser {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ExifParser {
    fn default() -> Self {
        Self::new()
    }
}

impl ForensicsModule for ExifParser {
    fn id(&self) -> &str {
        "plugin.media.exif_parser"
    }

    fn version(&self) -> &str {
        env!("CARGO_PKG_VERSION")
    }

    fn subscribes_to(&self) -> Vec<ArtifactType> {
        vec![ArtifactType::FileEntry]
    }

    fn input_capability(&self) -> InputCapability {
        // EXIF parsing (especially HEIF box walking) seeks freely.
        InputCapability::RandomAccess
    }

    fn execution_mode(&self) -> ExecutionMode {
        ExecutionMode::Automatic
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

        // Self-select by content magic bytes, not filename. The read loops over
        // short reads: a windowed source that returns four bytes per call would
        // otherwise fail the magic check and a real photograph would be skipped
        // as a non-image (B2-053).
        let mut head = [0u8; 16];
        let n = read_full(data.as_ref(), 0, &mut head);
        if !is_supported_image(&head[..n]) {
            return Ok(Vec::new());
        }

        debug!("ExifParser inspecting artifact ID: {}", artifact.id);

        // Stream through a seekable cursor; kamadak-exif reads only what it needs.
        let cursor = SourceCursor::new(data.clone());
        let mut reader = BufReader::new(cursor);

        // No Exif segment (metadata stripped in transport, or never written).
        // Don't go blank: the bitstream still proves the true pixel dimensions,
        // and the *absence* of EXIF is itself a documented forensic fact.
        // Only `NotFound` means the container has no Exif segment. Every other
        // error — a damaged APP1, a broken marker chain, a read that stopped —
        // means the metadata could not be read, and saying "no EXIF" for it
        // would report the thing an examiner most wants told about as absent
        // (HUNT-200).
        let exif = match Reader::new().read_from_container(&mut reader) {
            Ok(e) => e,
            Err(exif::Error::NotFound(_)) => {
                return Ok(stripped_image_record(artifact, data.clone()))
            }
            Err(e) => return Ok(vec![unreadable_exif_record(artifact, data.clone(), &e)]),
        };

        let mut fields: Map<String, JsonValue> = Map::new();

        // Camera identity.
        let make = ascii_field(&exif, Tag::Make);
        let model = ascii_field(&exif, Tag::Model);
        if let Some(v) = &make {
            fields.insert("make".into(), json!(v));
        }
        if let Some(v) = &model {
            fields.insert("model".into(), json!(v));
        }
        if let Some(v) = ascii_field(&exif, Tag::LensModel) {
            fields.insert("lens".into(), json!(v));
        }

        // Timestamps (local / unknown zone, emitted verbatim).
        if let Some(v) = ascii_field(&exif, Tag::DateTimeOriginal) {
            fields.insert("datetime_original".into(), json!(v));
        }
        if let Some(v) = ascii_field(&exif, Tag::DateTime) {
            fields.insert("modify_date".into(), json!(v));
        }

        // Orientation.
        if let Some(v) = uint_field(&exif, Tag::Orientation) {
            fields.insert("orientation".into(), json!(v));
        }

        // Dimensions. EXIF's PixelXDimension/PixelYDimension are self-declared
        // metadata an editor can set to anything; the authoritative size comes
        // from decoding the image bitstream. Surface both and flag a mismatch so
        // a doctored image cannot misreport its own dimensions unnoticed.
        let exif_w = uint_field(&exif, Tag::PixelXDimension);
        let exif_h = uint_field(&exif, Tag::PixelYDimension);
        let actual = decode_true_dimensions(data.clone());
        if let Some((aw, ah)) = actual {
            fields.insert("width".into(), json!(aw));
            fields.insert("height".into(), json!(ah));
            fields.insert("actual_width".into(), json!(aw));
            fields.insert("actual_height".into(), json!(ah));
            fields.insert("dimensions_source".into(), json!(DIMENSIONS_DECODED));
        } else {
            // Undecodable format (e.g. HEIC, TIFF): fall back to the declared
            // values, marked `exif_declared` so the UI does not present them as
            // measured (HUNT-200).
            if let Some(v) = exif_w {
                fields.insert("width".into(), json!(v));
            }
            if let Some(v) = exif_h {
                fields.insert("height".into(), json!(v));
            }
            if exif_w.is_some() || exif_h.is_some() {
                fields.insert("dimensions_source".into(), json!(DIMENSIONS_DECLARED));
            }
        }
        if let Some(v) = exif_w {
            fields.insert("exif_width".into(), json!(v));
        }
        if let Some(v) = exif_h {
            fields.insert("exif_height".into(), json!(v));
        }
        // A mismatch is only meaningful when both a declared and a decoded value
        // exist; report it explicitly so it can be surfaced as a tamper signal.
        if let (Some(ew), Some(eh), Some((aw, ah))) = (exif_w, exif_h, actual) {
            let mismatch = ew != aw || eh != ah;
            fields.insert("dimensions_mismatch".into(), json!(mismatch));
        }

        // Exposure settings.
        if let Some(v) = exif.get_field(Tag::ExposureTime, In::PRIMARY) {
            let disp = v.display_value().to_string();
            if !disp.is_empty() {
                fields.insert("exposure".into(), json!(disp));
            }
        }
        if let Some(v) = rational_field(&exif, Tag::FNumber) {
            fields.insert("fnumber".into(), json!(v));
        }
        if let Some(v) = uint_field(&exif, Tag::PhotographicSensitivity) {
            fields.insert("iso".into(), json!(v));
        }
        if let Some(v) = rational_field(&exif, Tag::FocalLength) {
            fields.insert("focal_length".into(), json!(v));
        }

        if let Some(v) = ascii_field(&exif, Tag::Software) {
            fields.insert("software".into(), json!(v));
        }

        // GPS: DMS rationals + hemisphere reference -> signed decimal degrees.
        let gps_lat = gps_coordinate(&exif, Tag::GPSLatitude, Tag::GPSLatitudeRef, b"S");
        let gps_lon = gps_coordinate(&exif, Tag::GPSLongitude, Tag::GPSLongitudeRef, b"W");
        let has_gps = gps_lat.is_some() && gps_lon.is_some();
        if has_gps {
            fields.insert("gps_lat".into(), json!(gps_lat.unwrap()));
            fields.insert("gps_lon".into(), json!(gps_lon.unwrap()));
            if let Some(alt) = gps_altitude(&exif) {
                fields.insert("gps_altitude".into(), json!(alt));
            }
            if let Some(dt) = gps_datetime(&exif) {
                fields.insert("gps_datetime".into(), json!(dt));
            }
        }

        // Full raw dump: every field the container carries, keyed by tag name,
        // so an examiner sees ALL of the metadata, not only the curated subset
        // above. Thumbnail-IFD tags are suffixed so they don't collide with the
        // primary image's.
        let mut raw: Map<String, JsonValue> = Map::new();
        for f in exif.fields() {
            let mut key = f.tag.to_string();
            if f.ifd_num == In::THUMBNAIL {
                key = format!("{key} (thumbnail)");
            }
            let val = f.display_value().with_unit(&exif).to_string();
            raw.entry(key).or_insert_with(|| json!(val));
        }

        // Nothing usable at all: emit nothing.
        if fields.is_empty() && raw.is_empty() {
            return Ok(Vec::new());
        }

        // Assemble the record.
        let mut record: Map<String, JsonValue> = Map::new();
        record.insert("type".into(), json!("exif"));
        record.insert("has_exif".into(), json!(true));
        record.insert("exif_status".into(), json!("read"));
        if let Some(name) = artifact.metadata.get("name").and_then(|v| v.as_str()) {
            record.insert("source_name".into(), json!(name));
        }
        for (k, v) in fields {
            record.insert(k, v);
        }
        record.insert("raw_exif".into(), JsonValue::Object(raw));
        record.insert("has_gps".into(), json!(has_gps));
        // camera = "<make> <model>" from whichever parts exist.
        let camera = match (&make, &model) {
            (Some(mk), Some(md)) => Some(format!("{} {}", mk, md)),
            (Some(mk), None) => Some(mk.clone()),
            (None, Some(md)) => Some(md.clone()),
            (None, None) => None,
        };
        if let Some(cam) = camera {
            let cam = cam.trim().to_string();
            if !cam.is_empty() {
                record.insert("camera".into(), json!(cam));
            }
        }

        let parsed = Artifact::new(
            artifact.case_id,
            ArtifactType::ParsedRecord,
            None,
            JsonValue::Object(record),
        )
        .with_parent(artifact.id);

        Ok(vec![parsed])
    }
}

/// Content-based image detection by magic bytes.
/// Decode the true pixel dimensions from the image bitstream (JPEG SOF, PNG
/// IHDR, etc.) rather than trusting EXIF's self-declared PixelXDimension. Reads
/// only the header, never a full decode. Returns `None` for formats the decoder
/// does not cover (e.g. HEIC/TIFF) or unreadable data — the caller then treats
/// the size as unverified rather than asserting a mismatch it cannot prove.
fn decode_true_dimensions(
    data: std::sync::Arc<dyn seance_core::data_source::DataSource>,
) -> Option<(u32, u32)> {
    let reader = BufReader::new(SourceCursor::new(data));
    image::ImageReader::new(reader)
        .with_guessed_format()
        .ok()?
        .into_dimensions()
        .ok()
}

/// Record for an image that carries no Exif segment. Surfaces the authoritative
/// pixel dimensions decoded from the bitstream plus an explicit "no EXIF"
/// status, so a metadata-stripped image (typical of WhatsApp/Messenger
/// transport, which re-encode and drop EXIF) is documented rather than blank.
/// Emits nothing when even the dimensions can't be decoded (e.g. HEIC).
fn stripped_image_record(
    artifact: &Artifact,
    data: std::sync::Arc<dyn seance_core::data_source::DataSource>,
) -> Vec<Artifact> {
    let Some((w, h)) = decode_true_dimensions(data) else {
        return Vec::new();
    };
    let mut record: Map<String, JsonValue> = Map::new();
    record.insert("type".into(), json!("exif"));
    record.insert("has_exif".into(), json!(false));
    record.insert("exif_status".into(), json!("not_present"));
    record.insert(
        "metadata_status".into(),
        json!("No EXIF metadata present (stripped in transport or never written)"),
    );
    if let Some(name) = artifact.metadata.get("name").and_then(|v| v.as_str()) {
        record.insert("source_name".into(), json!(name));
    }
    record.insert("width".into(), json!(w));
    record.insert("height".into(), json!(h));
    record.insert("actual_width".into(), json!(w));
    record.insert("actual_height".into(), json!(h));
    record.insert("dimensions_source".into(), json!(DIMENSIONS_DECODED));
    record.insert("has_gps".into(), json!(false));
    vec![Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        JsonValue::Object(record),
    )
    .with_parent(artifact.id)]
}

/// Record for an image whose EXIF could not be read (HUNT-200).
///
/// Emitted whatever else is known, because "the metadata could not be read" is
/// a finding and silence would read as "there was none". It carries
/// `exif_status: "exif_unreadable"`, the reader's error, and the standard
/// incompleteness pair — `short_read` when the source stopped answering,
/// `unresolved_structure` otherwise. `has_exif` is deliberately absent: an
/// error before the Exif segment was located leaves its presence unknown. The
/// decoded pixel dimensions are added when the bitstream still decodes.
fn unreadable_exif_record(
    artifact: &Artifact,
    data: std::sync::Arc<dyn seance_core::data_source::DataSource>,
    error: &exif::Error,
) -> Artifact {
    let reason = match error {
        exif::Error::Io(_) => IncompleteReason::ShortRead,
        _ => IncompleteReason::UnresolvedStructure,
    };
    let status = format!("EXIF metadata could not be read ({error}); it may be damaged or truncated, and is not shown to be absent");
    let mut record: Map<String, JsonValue> = Map::new();
    record.insert("type".into(), json!("exif"));
    record.insert("exif_status".into(), json!("exif_unreadable"));
    record.insert("exif_error".into(), json!(error.to_string()));
    record.insert("metadata_status".into(), json!(status));
    record.insert("content_incomplete".into(), json!(true));
    record.insert("content_incomplete_reason".into(), json!(reason.as_str()));
    record.insert("content_incomplete_detail".into(), json!(status));
    if let Some(name) = artifact.metadata.get("name").and_then(|v| v.as_str()) {
        record.insert("source_name".into(), json!(name));
    }
    if let Some((w, h)) = decode_true_dimensions(data) {
        record.insert("width".into(), json!(w));
        record.insert("height".into(), json!(h));
        record.insert("actual_width".into(), json!(w));
        record.insert("actual_height".into(), json!(h));
        record.insert("dimensions_source".into(), json!(DIMENSIONS_DECODED));
    }
    record.insert("has_gps".into(), json!(false));
    Artifact::new(
        artifact.case_id,
        ArtifactType::ParsedRecord,
        None,
        JsonValue::Object(record),
    )
    .with_parent(artifact.id)
}

fn is_supported_image(head: &[u8]) -> bool {
    // JPEG: FF D8 FF
    if head.len() >= 3 && head[0] == 0xFF && head[1] == 0xD8 && head[2] == 0xFF {
        return true;
    }
    // TIFF little-endian "II*\0" / big-endian "MM\0*"
    if head.len() >= 4
        && (head[..4] == [0x49, 0x49, 0x2A, 0x00] || head[..4] == [0x4D, 0x4D, 0x00, 0x2A])
    {
        return true;
    }
    // PNG signature
    if head.len() >= 8 && head[..8] == [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A] {
        return true;
    }
    // HEIF/HEIC: ISO-BMFF "ftyp" box with an image brand.
    if head.len() >= 12 && &head[4..8] == b"ftyp" {
        let brand = &head[8..12];
        const BRANDS: [&[u8; 4]; 4] = [b"heic", b"heix", b"mif1", b"mif2"];
        if BRANDS.iter().any(|b| brand == b.as_slice()) {
            return true;
        }
    }
    false
}

/// Extract a trimmed ASCII string field, or `None` if absent/empty.
fn ascii_field(exif: &exif::Exif, tag: Tag) -> Option<String> {
    let field = exif.get_field(tag, In::PRIMARY)?;
    let s = match &field.value {
        Value::Ascii(vecs) => {
            let bytes = vecs.first()?;
            String::from_utf8_lossy(bytes).into_owned()
        }
        _ => field.display_value().to_string(),
    };
    let trimmed = s
        .trim_matches(|c: char| c == '\0' || c.is_whitespace())
        .to_string();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// Extract an unsigned integer field (Byte/Short/Long), or `None`.
fn uint_field(exif: &exif::Exif, tag: Tag) -> Option<u32> {
    exif.get_field(tag, In::PRIMARY)?.value.get_uint(0)
}

/// Extract the first rational as an `f64`, guarding zero denominators.
fn rational_field(exif: &exif::Exif, tag: Tag) -> Option<f64> {
    let field = exif.get_field(tag, In::PRIMARY)?;
    match &field.value {
        Value::Rational(v) => {
            let r = v.first()?;
            if r.denom == 0 {
                None
            } else {
                Some(r.to_f64())
            }
        }
        Value::SRational(v) => {
            let r = v.first()?;
            if r.denom == 0 {
                None
            } else {
                Some(r.to_f64())
            }
        }
        _ => None,
    }
}

/// Convert a GPS DMS rational triple + hemisphere reference into signed decimal degrees.
///
/// `neg_ref` is the reference byte that flips the sign (`S` for latitude, `W` for
/// longitude).
fn gps_coordinate(exif: &exif::Exif, coord: Tag, reference: Tag, neg_ref: &[u8]) -> Option<f64> {
    let field = exif.get_field(coord, In::PRIMARY)?;
    let dms = match &field.value {
        Value::Rational(v) if v.len() >= 3 => v,
        _ => return None,
    };
    let deg = safe_ratio(&dms[0])?;
    let min = safe_ratio(&dms[1])?;
    let sec = safe_ratio(&dms[2])?;
    let mut decimal = deg + min / 60.0 + sec / 3600.0;

    if let Some(field) = exif.get_field(reference, In::PRIMARY) {
        if let Value::Ascii(vecs) = &field.value {
            if let Some(bytes) = vecs.first() {
                let r = bytes.first().copied().unwrap_or(0).to_ascii_uppercase();
                if neg_ref.first().map(|b| b.to_ascii_uppercase()) == Some(r) {
                    decimal = -decimal;
                }
            }
        }
    }
    Some(decimal)
}

/// GPS altitude signed by its reference byte (0 = above, 1 = below sea level).
fn gps_altitude(exif: &exif::Exif) -> Option<f64> {
    let alt = rational_field(exif, Tag::GPSAltitude)?;
    let below = exif
        .get_field(Tag::GPSAltitudeRef, In::PRIMARY)
        .and_then(|f| f.value.get_uint(0))
        == Some(1);
    Some(if below { -alt } else { alt })
}

/// Combine GPSDateStamp ("YYYY:MM:DD") and GPSTimeStamp (h,m,s rationals) into
/// "YYYY:MM:DD HH:MM:SS". Both must be present.
fn gps_datetime(exif: &exif::Exif) -> Option<String> {
    let date = ascii_field(exif, Tag::GPSDateStamp)?;
    let field = exif.get_field(Tag::GPSTimeStamp, In::PRIMARY)?;
    let hms = match &field.value {
        Value::Rational(v) if v.len() >= 3 => v,
        _ => return None,
    };
    let h = safe_ratio(&hms[0])?;
    let m = safe_ratio(&hms[1])?;
    let s = safe_ratio(&hms[2])?;
    Some(format!(
        "{} {:02}:{:02}:{:02}",
        date, h as u32, m as u32, s as u32
    ))
}

/// Rational to f64 with a zero-denominator guard.
fn safe_ratio(r: &exif::Rational) -> Option<f64> {
    if r.denom == 0 {
        None
    } else {
        Some(r.to_f64())
    }
}
